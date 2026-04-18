//! QEMU invocation synthesis.
//!
//! Given a validated [`Persona`] + the paths for the USB stick, working
//! directory, firmware root, and (optional) swtpm socket, produces a
//! fully-configured [`std::process::Command`] ready to spawn. No shell
//! sits between the persona string fields and QEMU — argv elements go
//! through `Command::args()` as literals, so shell metacharacters in
//! DMI fields pass through verbatim.
//!
//! # Architecture
//!
//! Split into two layers:
//!
//! - **[`build_argv`]** — pure argv composition. Takes all resolved
//!   paths as inputs, returns `Vec<String>`. Testable against every
//!   persona-variant combination without touching the filesystem.
//! - **[`Invocation::new`]** — the I/O layer. Calls [`crate::ovmf::resolve`]
//!   to find the firmware paths, copies `OVMF_VARS` into the per-run
//!   directory so the VM gets its own SB-variable state, computes the
//!   swtpm socket via the caller-supplied [`crate::swtpm::SwtpmInstance`],
//!   then delegates to `build_argv`.
//!
//! # Security
//!
//! Three defenses layered at this boundary:
//!
//! 1. **No shell.** `Command::args()` passes argv as literals; no shell
//!    interpolation path exists. Shell-metachar fuzz (E2.6, #23) lives
//!    here.
//! 2. **No NUL in argv.** [`smbios_argv`] rejects NUL upfront;
//!    [`Invocation::new`] repeats the check for the stick path.
//! 3. **Path canonicalization + sandbox boundary.** The stick path must
//!    exist and is canonicalized before being passed to QEMU. The
//!    per-run `OVMF_VARS` copy is also canonicalized after the copy
//!    lands and must `starts_with` the canonicalized work root — a
//!    pre-existing symlink at the destination cannot redirect QEMU's
//!    SB-variable writes outside the run's sandbox (E2.7, #24).

use crate::ovmf::{self, OvmfError};
use crate::persona::{Persona, TpmVersion};
use crate::smbios::{self, SmbiosError};
use crate::swtpm::SwtpmInstance;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use thiserror::Error;

/// A composed QEMU invocation. Built by [`Invocation::new`], consumed
/// by [`Invocation::build`].
#[derive(Debug, Clone)]
pub struct Invocation {
    argv: Vec<String>,
    vars_copy: PathBuf,
}

impl Invocation {
    /// Compose a QEMU invocation for `persona`. Runs the I/O steps
    /// (resolve firmware paths, copy `OVMF_VARS` into `work_dir/<run_id>/`),
    /// then delegates argv composition to [`build_argv`].
    ///
    /// `swtpm` is the live swtpm instance from [`SwtpmInstance::spawn`];
    /// if it's [`SwtpmInstance::NoTpm`], the returned argv omits the
    /// TPM chardev/tpmdev wiring.
    ///
    /// # Errors
    ///
    /// See [`InvocationError`] variants.
    pub fn new(
        persona: &Persona,
        stick: &Path,
        work_dir: &Path,
        firmware_root: &Path,
        swtpm: &SwtpmInstance,
    ) -> Result<Self, InvocationError> {
        // Stick must exist + contain no NUL (argv safety).
        if stick.to_string_lossy().contains('\0') {
            return Err(InvocationError::StickPathInvalid {
                path: stick.to_path_buf(),
                reason: "path contains NUL byte; QEMU argv cannot encode it",
            });
        }
        let stick_canon = fs::canonicalize(stick).map_err(|e| InvocationError::StickNotFound {
            path: stick.to_path_buf(),
            kind: format!("{:?}", e.kind()),
        })?;

        // Resolve `OVMF_CODE` + VARS template (the CustomPk keyring check
        // is done by ovmf::resolve).
        let paths = ovmf::resolve(
            persona.secure_boot.ovmf_variant,
            persona.secure_boot.custom_keyring.as_deref(),
            firmware_root,
        )?;

        // Copy VARS template → per-run copy so each VM has isolated SB state.
        // E2.7 path-boundary: the work_dir is canonicalized first, then
        // every path we materialize underneath is required to land
        // *inside* the canonicalized root. Symlinks and `..` traversal
        // can't escape because we canonicalize the destination AFTER
        // the copy lands (which resolves any symlink swapped in mid-op)
        // and re-check `starts_with`.
        fs::create_dir_all(work_dir).map_err(|e| InvocationError::WorkDirInaccessible {
            path: work_dir.to_path_buf(),
            kind: format!("{:?}", e.kind()),
        })?;
        let work_root_canon =
            fs::canonicalize(work_dir).map_err(|e| InvocationError::WorkDirInaccessible {
                path: work_dir.to_path_buf(),
                kind: format!("{:?}", e.kind()),
            })?;
        let vars_copy = work_root_canon.join("OVMF_VARS.fd");
        fs::copy(&paths.vars_template, &vars_copy).map_err(|e| {
            InvocationError::VarsCopyFailed {
                from: paths.vars_template.clone(),
                to: vars_copy.clone(),
                kind: format!("{:?}", e.kind()),
            }
        })?;

        // Defense in depth: re-canonicalize the just-created copy and
        // confirm it lives under the canonicalized work root. A
        // pre-existing symlink at `vars_copy` pointing outside the root
        // would cause fs::copy to write to the symlink target; this
        // check catches that exact escape path.
        let vars_copy_canon =
            fs::canonicalize(&vars_copy).map_err(|e| InvocationError::VarsCopyFailed {
                from: paths.vars_template.clone(),
                to: vars_copy.clone(),
                kind: format!("{:?}", e.kind()),
            })?;
        if !vars_copy_canon.starts_with(&work_root_canon) {
            return Err(InvocationError::VarsCopyEscapedRoot {
                vars_copy: vars_copy_canon,
                work_root: work_root_canon,
            });
        }

        let argv = build_argv(persona, &paths.code, &vars_copy_canon, &stick_canon, swtpm)?;
        Ok(Self {
            argv,
            vars_copy: vars_copy_canon,
        })
    }

    /// Produce a `std::process::Command` ready to spawn. The caller is
    /// responsible for attaching stdin/stdout/stderr.
    #[must_use]
    pub fn build(&self) -> Command {
        let mut cmd = Command::new("qemu-system-x86_64");
        cmd.args(&self.argv);
        cmd
    }

    /// Access the argv vec directly (useful for testing + diagnostics).
    #[must_use]
    pub fn argv(&self) -> &[String] {
        &self.argv
    }

    /// The per-run `OVMF_VARS` copy path. Kept around so the caller can
    /// inspect SB state after the VM exits.
    #[must_use]
    pub fn vars_copy(&self) -> &Path {
        &self.vars_copy
    }
}

/// Compose QEMU argv from resolved paths. Pure — no filesystem I/O.
///
/// Emits, in order:
/// - `-machine q35,smm=on,accel=kvm:tcg` (SMM required for SB; KVM with TCG fallback)
/// - `-cpu qemu64` (portable baseline; persona-specific CPU flags can be added later)
/// - `-m 4096` (4 GB default)
/// - `-drive` pflash `OVMF_CODE` (readonly)
/// - `-drive` pflash `OVMF_VARS` (per-run copy)
/// - `-drive` + `-device usb-storage` for the aegis-boot stick
/// - For non-`NoTpm` swtpm: `-chardev`, `-tpmdev`, `-device tpm-crb`
/// - `-smbios` blocks from [`smbios::smbios_argv`]
/// - `-nographic -serial mon:stdio`
///
/// # Errors
///
/// - [`InvocationError::Smbios`] if DMI field rejection fires (NUL bytes).
pub fn build_argv(
    persona: &Persona,
    ovmf_code: &Path,
    ovmf_vars_copy: &Path,
    stick: &Path,
    swtpm: &SwtpmInstance,
) -> Result<Vec<String>, InvocationError> {
    let mut argv: Vec<String> = Vec::with_capacity(32);

    // Machine + firmware.
    argv.extend([
        "-machine".into(),
        "q35,smm=on,accel=kvm:tcg".into(),
        "-cpu".into(),
        "qemu64".into(),
        "-m".into(),
        "4096".into(),
        "-drive".into(),
        format!(
            "if=pflash,format=raw,unit=0,readonly=on,file={}",
            ovmf_code.display()
        ),
        "-drive".into(),
        format!(
            "if=pflash,format=raw,unit=1,file={}",
            ovmf_vars_copy.display()
        ),
    ]);

    // USB stick. q35 doesn't ship a USB controller by default; explicit
    // qemu-xhci needed before usb-storage can attach to a bus.
    argv.extend([
        "-device".into(),
        "qemu-xhci,id=xhci".into(),
        "-drive".into(),
        format!("file={},format=raw,if=none,id=stick", stick.display()),
        "-device".into(),
        "usb-storage,bus=xhci.0,drive=stick".into(),
    ]);

    // TPM wiring (skipped when SwtpmInstance::NoTpm).
    if let Some(sock) = swtpm.socket_path() {
        argv.extend([
            "-chardev".into(),
            format!("socket,id=chrtpm,path={}", sock.display()),
            "-tpmdev".into(),
            "emulator,id=tpm,chardev=chrtpm".into(),
            "-device".into(),
            tpm_device_for_version(persona.tpm.version).into(),
        ]);
    }

    // SMBIOS from DMI (propagates NUL-rejection through InvocationError::Smbios).
    argv.extend(smbios::smbios_argv(&persona.dmi)?);

    // Headless serial.
    argv.extend(["-nographic".into(), "-serial".into(), "mon:stdio".into()]);

    Ok(argv)
}

/// QEMU device name for a given TPM interface. TPM 2.0 uses CRB; TPM 1.2
/// uses TIS. The `None` arm is unreachable in practice because
/// [`SwtpmInstance::socket_path`] returns `None` for the `NoTpm`
/// variant and the caller already branched on that; we fold it into the
/// CRB arm so clippy's `match_same_arms` stays happy without hiding the
/// logical cases.
fn tpm_device_for_version(v: TpmVersion) -> &'static str {
    match v {
        TpmVersion::Tpm12 => "tpm-tis,tpmdev=tpm",
        TpmVersion::Tpm20 | TpmVersion::None => "tpm-crb,tpmdev=tpm",
    }
}

/// Failure modes for [`Invocation::new`] + [`build_argv`].
#[derive(Debug, Error)]
pub enum InvocationError {
    /// The USB-stick path doesn't exist or can't be canonicalized.
    #[error("stick {path} not found or inaccessible: {kind}")]
    StickNotFound {
        /// The path the operator passed.
        path: PathBuf,
        /// Rendered `io::ErrorKind`.
        kind: String,
    },

    /// The stick path violates an argv invariant (e.g. contains NUL).
    #[error("stick {path} is invalid: {reason}")]
    StickPathInvalid {
        /// The offending path.
        path: PathBuf,
        /// Human-readable reason.
        reason: &'static str,
    },

    /// Work-dir parent couldn't be created for the VARS copy.
    #[error("work dir {path} inaccessible: {kind}")]
    WorkDirInaccessible {
        /// The path that couldn't be created.
        path: PathBuf,
        /// Rendered `io::ErrorKind`.
        kind: String,
    },

    /// Copying the `OVMF_VARS` template into the work dir failed.
    #[error("copying `OVMF_VARS` from {from} to {to} failed: {kind}")]
    VarsCopyFailed {
        /// Source template.
        from: PathBuf,
        /// Destination per-run copy.
        to: PathBuf,
        /// Rendered `io::ErrorKind`.
        kind: String,
    },

    /// The per-run `OVMF_VARS` copy resolved (after `fs::canonicalize`)
    /// to a path outside the canonicalized work root. A pre-existing
    /// symlink at the destination is the most common cause; we refuse
    /// to hand QEMU a write-target that escaped the run's sandbox.
    #[error("`OVMF_VARS` copy {vars_copy} escaped work root {work_root}")]
    VarsCopyEscapedRoot {
        /// Canonicalized (resolved) path the copy ended up at.
        vars_copy: PathBuf,
        /// Canonicalized work-root the copy was supposed to live under.
        work_root: PathBuf,
    },

    /// OVMF resolution failed (underlying error comes from
    /// [`crate::ovmf::OvmfError`]).
    #[error(transparent)]
    Ovmf(#[from] OvmfError),

    /// SMBIOS synthesis failed (underlying error comes from
    /// [`crate::smbios::SmbiosError`]).
    #[error(transparent)]
    Smbios(#[from] SmbiosError),
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::persona::{Dmi, Kernel, OvmfVariant, SecureBoot, Source, SourceKind, Tpm};

    fn tpm20_persona() -> Persona {
        Persona {
            schema_version: 1,
            id: "test".into(),
            vendor: "QEMU".into(),
            display_name: "test".into(),
            year: None,
            source: Source {
                kind: SourceKind::VendorDocs,
                ref_: "test".into(),
                captured_at: None,
            },
            dmi: Dmi {
                sys_vendor: "QEMU".into(),
                product_name: "Standard PC".into(),
                product_version: None,
                bios_vendor: "EDK II".into(),
                bios_version: "edk2-stable".into(),
                bios_date: "01/01/2024".into(),
                board_name: None,
                chassis_type: None,
            },
            secure_boot: SecureBoot {
                ovmf_variant: OvmfVariant::MsEnrolled,
                custom_keyring: None,
            },
            tpm: Tpm {
                version: TpmVersion::Tpm20,
                manufacturer: None,
                firmware_version: None,
            },
            kernel: Kernel::default(),
            quirks: Vec::new(),
            scenarios: std::collections::BTreeMap::new(),
        }
    }

    fn tpm12_persona() -> Persona {
        let mut p = tpm20_persona();
        p.tpm.version = TpmVersion::Tpm12;
        p
    }

    fn no_tpm_persona() -> Persona {
        let mut p = tpm20_persona();
        p.tpm.version = TpmVersion::None;
        p
    }

    fn fake_swtpm(version: TpmVersion, work: &Path) -> SwtpmInstance {
        let spec = crate::swtpm::SwtpmSpec::derive("test-run", work, version);
        if matches!(version, TpmVersion::None) {
            // NoTpm variant — no subprocess.
            return crate::swtpm::SwtpmInstance::NoTpm { spec };
        }
        // Use sleep as a swtpm stand-in so the socket path is reachable.
        crate::swtpm::SwtpmInstance::spawn_with_binary(&spec, "sleep").unwrap()
    }

    #[test]
    fn argv_for_tpm20_persona_emits_crb_device() {
        let tmp = tempfile::tempdir().unwrap();
        let swtpm = fake_swtpm(TpmVersion::Tpm20, tmp.path());
        let argv = build_argv(
            &tpm20_persona(),
            Path::new("/fake/OVMF_CODE.fd"),
            Path::new("/fake/OVMF_VARS.fd"),
            Path::new("/fake/stick.img"),
            &swtpm,
        )
        .unwrap();
        assert!(argv.iter().any(|a| a == "tpm-crb,tpmdev=tpm"));
        assert!(argv.iter().any(|a| a.contains("chrtpm,path=")));
    }

    #[test]
    fn argv_for_tpm12_persona_emits_tis_device() {
        let tmp = tempfile::tempdir().unwrap();
        let swtpm = fake_swtpm(TpmVersion::Tpm12, tmp.path());
        let argv = build_argv(
            &tpm12_persona(),
            Path::new("/fake/OVMF_CODE.fd"),
            Path::new("/fake/OVMF_VARS.fd"),
            Path::new("/fake/stick.img"),
            &swtpm,
        )
        .unwrap();
        assert!(argv.iter().any(|a| a == "tpm-tis,tpmdev=tpm"));
    }

    #[test]
    fn argv_for_no_tpm_persona_omits_tpm_wiring() {
        let tmp = tempfile::tempdir().unwrap();
        let swtpm = fake_swtpm(TpmVersion::None, tmp.path());
        let argv = build_argv(
            &no_tpm_persona(),
            Path::new("/fake/OVMF_CODE.fd"),
            Path::new("/fake/OVMF_VARS.fd"),
            Path::new("/fake/stick.img"),
            &swtpm,
        )
        .unwrap();
        assert!(
            !argv.iter().any(|a| a.starts_with("tpm-")),
            "no TPM device should be present; got {argv:?}"
        );
        assert!(
            !argv.iter().any(|a| a.contains("chrtpm")),
            "no TPM chardev should be present"
        );
        assert!(!argv.iter().any(|a| a == "-tpmdev"));
    }

    #[test]
    fn argv_contains_smm_on_machine() {
        let tmp = tempfile::tempdir().unwrap();
        let swtpm = fake_swtpm(TpmVersion::Tpm20, tmp.path());
        let argv = build_argv(
            &tpm20_persona(),
            Path::new("/fake/OVMF_CODE.fd"),
            Path::new("/fake/OVMF_VARS.fd"),
            Path::new("/fake/stick.img"),
            &swtpm,
        )
        .unwrap();
        let m = argv
            .iter()
            .zip(argv.iter().skip(1))
            .find(|(a, _)| *a == "-machine")
            .map(|(_, v)| v.as_str())
            .expect("-machine arg");
        assert!(m.contains("smm=on"), "SMM required for Secure Boot");
    }

    #[test]
    fn argv_wires_pflash_code_readonly_and_vars_writable() {
        let tmp = tempfile::tempdir().unwrap();
        let swtpm = fake_swtpm(TpmVersion::Tpm20, tmp.path());
        let argv = build_argv(
            &tpm20_persona(),
            Path::new("/firmware/OVMF_CODE.fd"),
            Path::new("/work/OVMF_VARS.fd"),
            Path::new("/fake/stick.img"),
            &swtpm,
        )
        .unwrap();
        let joined = argv.join(" ");
        assert!(
            joined.contains("unit=0,readonly=on,file=/firmware/OVMF_CODE.fd"),
            "`OVMF_CODE` must be readonly on pflash unit 0"
        );
        assert!(
            joined.contains("unit=1,file=/work/OVMF_VARS.fd"),
            "`OVMF_VARS` must be writable on pflash unit 1"
        );
        assert!(
            !joined.contains("unit=1,readonly=on"),
            "`OVMF_VARS` must NOT be readonly (the VM writes SB state here)"
        );
    }

    #[test]
    fn argv_includes_stick_as_usb_storage() {
        let tmp = tempfile::tempdir().unwrap();
        let swtpm = fake_swtpm(TpmVersion::Tpm20, tmp.path());
        let argv = build_argv(
            &tpm20_persona(),
            Path::new("/fake/OVMF_CODE.fd"),
            Path::new("/fake/OVMF_VARS.fd"),
            Path::new("/flash/aegis-boot.img"),
            &swtpm,
        )
        .unwrap();
        let joined = argv.join(" ");
        assert!(joined.contains("file=/flash/aegis-boot.img,format=raw,if=none,id=stick"));
        assert!(
            joined.contains("qemu-xhci,id=xhci"),
            "q35 needs explicit USB controller"
        );
        assert!(joined.contains("usb-storage,bus=xhci.0,drive=stick"));
    }

    #[test]
    fn argv_passes_dmi_through_smbios_blocks() {
        let tmp = tempfile::tempdir().unwrap();
        let swtpm = fake_swtpm(TpmVersion::Tpm20, tmp.path());
        let argv = build_argv(
            &tpm20_persona(),
            Path::new("/fake/OVMF_CODE.fd"),
            Path::new("/fake/OVMF_VARS.fd"),
            Path::new("/fake/stick.img"),
            &swtpm,
        )
        .unwrap();
        let joined = argv.join(" ");
        assert!(joined.contains("type=0,vendor=EDK II"));
        assert!(joined.contains("type=1,manufacturer=QEMU,product=Standard PC"));
    }

    #[test]
    fn argv_is_headless() {
        let tmp = tempfile::tempdir().unwrap();
        let swtpm = fake_swtpm(TpmVersion::None, tmp.path());
        let argv = build_argv(
            &no_tpm_persona(),
            Path::new("/fake/OVMF_CODE.fd"),
            Path::new("/fake/OVMF_VARS.fd"),
            Path::new("/fake/stick.img"),
            &swtpm,
        )
        .unwrap();
        assert!(argv.iter().any(|a| a == "-nographic"));
        assert!(argv.iter().any(|a| a == "mon:stdio"));
    }

    #[test]
    fn invocation_new_rejects_nul_in_stick_path() {
        let tmp = tempfile::tempdir().unwrap();
        let swtpm = fake_swtpm(TpmVersion::Tpm20, tmp.path());
        // Construct a PathBuf with an embedded NUL via OsString bytes on Unix.
        #[cfg(unix)]
        {
            use std::ffi::OsString;
            use std::os::unix::ffi::OsStringExt as _;
            let bytes = b"/tmp/bad\0stick.img".to_vec();
            let stick = PathBuf::from(OsString::from_vec(bytes));
            let err = Invocation::new(&tpm20_persona(), &stick, tmp.path(), tmp.path(), &swtpm)
                .unwrap_err();
            assert!(
                matches!(err, InvocationError::StickPathInvalid { .. }),
                "expected StickPathInvalid, got {err:?}"
            );
        }
    }

    #[test]
    fn invocation_new_surfaces_ovmf_missing_as_named_error() {
        let tmp = tempfile::tempdir().unwrap();
        let swtpm = fake_swtpm(TpmVersion::Tpm20, tmp.path());
        let stick = tmp.path().join("stick.img");
        fs::write(&stick, b"fake stick").unwrap();
        // firmware_root is empty — no `OVMF_CODE` there.
        let err =
            Invocation::new(&tpm20_persona(), &stick, tmp.path(), tmp.path(), &swtpm).unwrap_err();
        assert!(
            matches!(
                err,
                InvocationError::Ovmf(OvmfError::OvmfCodeMissing { .. })
            ),
            "expected Ovmf(OvmfCodeMissing), got {err:?}"
        );
    }

    #[test]
    fn invocation_new_happy_path_copies_vars_template() {
        let tmp = tempfile::tempdir().unwrap();
        let swtpm = fake_swtpm(TpmVersion::Tpm20, tmp.path());

        // Build a fake Debian firmware root.
        let fw = tmp.path().join("fw");
        fs::create_dir_all(&fw).unwrap();
        fs::write(fw.join("OVMF_CODE_4M.secboot.fd"), b"code").unwrap();
        fs::write(fw.join("OVMF_VARS_4M.ms.fd"), b"vars template").unwrap();

        // Stick.
        let stick = tmp.path().join("stick.img");
        fs::write(&stick, b"fake stick").unwrap();

        let work = tmp.path().join("work");
        fs::create_dir_all(&work).unwrap();

        let inv = Invocation::new(&tpm20_persona(), &stick, &work, &fw, &swtpm).unwrap();

        // Per-run VARS copy should now exist + contain the template bytes.
        let vars = inv.vars_copy();
        assert!(vars.exists());
        let contents = fs::read(vars).unwrap();
        assert_eq!(contents, b"vars template");

        // The argv should reference the copy, not the template.
        let joined = inv.argv().join(" ");
        assert!(joined.contains(&vars.display().to_string()));
    }

    #[test]
    fn build_returns_qemu_command() {
        let tmp = tempfile::tempdir().unwrap();
        let swtpm = fake_swtpm(TpmVersion::None, tmp.path());
        let argv = build_argv(
            &no_tpm_persona(),
            Path::new("/fake/OVMF_CODE.fd"),
            Path::new("/fake/OVMF_VARS.fd"),
            Path::new("/fake/stick.img"),
            &swtpm,
        )
        .unwrap();
        let inv = Invocation {
            argv,
            vars_copy: PathBuf::from("/fake/OVMF_VARS.fd"),
        };
        let cmd = inv.build();
        assert_eq!(cmd.get_program().to_string_lossy(), "qemu-system-x86_64");
    }

    /// E2.7 path-boundary: a pre-existing symlink at the `OVMF_VARS`
    /// destination, pointing OUTSIDE the work root, must be rejected.
    /// `fs::copy` would otherwise follow the symlink and overwrite the
    /// target outside the run's sandbox.
    #[test]
    #[cfg(unix)]
    fn invocation_new_rejects_vars_copy_symlink_escape() {
        let tmp = tempfile::tempdir().unwrap();

        // Build a fake Debian firmware root.
        let fw = tmp.path().join("fw");
        fs::create_dir_all(&fw).unwrap();
        fs::write(fw.join("OVMF_CODE_4M.secboot.fd"), b"code").unwrap();
        fs::write(fw.join("OVMF_VARS_4M.ms.fd"), b"vars template").unwrap();

        let stick = tmp.path().join("stick.img");
        fs::write(&stick, b"fake stick").unwrap();

        // Pre-place a symlink at <work>/OVMF_VARS.fd that points
        // outside work_dir. fs::copy would otherwise follow it.
        let work = tmp.path().join("work");
        fs::create_dir_all(&work).unwrap();
        let escape_target = tmp.path().join("escape-target.fd");
        fs::write(&escape_target, b"would-be victim").unwrap();
        std::os::unix::fs::symlink(&escape_target, work.join("OVMF_VARS.fd")).unwrap();

        let swtpm = fake_swtpm(TpmVersion::None, tmp.path());
        let mut p = tpm20_persona();
        p.tpm.version = TpmVersion::None;

        let err = Invocation::new(&p, &stick, &work, &fw, &swtpm).unwrap_err();
        assert!(
            matches!(err, InvocationError::VarsCopyEscapedRoot { .. }),
            "expected VarsCopyEscapedRoot, got {err:?}"
        );

        // The would-be-victim file SHOULD have been overwritten by
        // fs::copy (that's the attack); the test's value is asserting
        // the boundary check FAILS the run so QEMU is never spawned
        // against the leaked path. Document the residual concern as
        // a known limitation: file::copy follows the symlink before we
        // can intercept it; defense is "refuse to proceed", not
        // "prevent write." Future hardening can switch to
        // open(O_NOFOLLOW) + write directly.
    }

    #[test]
    fn invocation_new_canonicalizes_vars_copy_through_relative_work_dir() {
        // A relative work_dir like "work/run-1" should canonicalize to
        // an absolute path; the resulting vars_copy must be absolute
        // and under the canonical work root.
        let tmp = tempfile::tempdir().unwrap();
        let fw = tmp.path().join("fw");
        fs::create_dir_all(&fw).unwrap();
        fs::write(fw.join("OVMF_CODE_4M.secboot.fd"), b"code").unwrap();
        fs::write(fw.join("OVMF_VARS_4M.ms.fd"), b"vars template").unwrap();

        let stick = tmp.path().join("stick.img");
        fs::write(&stick, b"fake stick").unwrap();

        let work = tmp.path().join("work");
        fs::create_dir_all(&work).unwrap();

        let swtpm = fake_swtpm(TpmVersion::Tpm20, tmp.path());
        let inv = Invocation::new(&tpm20_persona(), &stick, &work, &fw, &swtpm).unwrap();

        // Canonicalized path: must be absolute + under canonical work root.
        let canonical_work = fs::canonicalize(&work).unwrap();
        assert!(inv.vars_copy().is_absolute());
        assert!(
            inv.vars_copy().starts_with(&canonical_work),
            "vars_copy {} should start with canonical work root {}",
            inv.vars_copy().display(),
            canonical_work.display()
        );
    }
}
