//! OVMF firmware path resolution.
//!
//! Given an [`OvmfVariant`] and the firmware-root dir, resolves the
//! concrete `OVMF_CODE` + `OVMF_VARS` paths the caller should pass to QEMU
//! via `-drive if=pflash,format=raw,unit=0,readonly=on,file=...` (code)
//! and `-drive ...unit=1,file=...` (vars).
//!
//! Uses Debian's packaging layout for `ovmf` / `ovmf-ia32` today:
//!
//! | Variant       | CODE                              | VARS template          |
//! | ------------- | --------------------------------- | ---------------------- |
//! | `ms_enrolled` | `OVMF_CODE_4M.secboot.fd`         | `OVMF_VARS_4M.ms.fd`   |
//! | `custom_pk`   | `OVMF_CODE_4M.secboot.fd`         | caller-supplied keyring|
//! | `setup_mode`  | `OVMF_CODE_4M.secboot.fd`         | `OVMF_VARS_4M.fd`      |
//! | `disabled`    | `OVMF_CODE_4M.fd` (no secboot)    | `OVMF_VARS_4M.fd`      |
//!
//! Fedora layout is recognized via an explicit fallback list — see
//! [`FEDORA_CODE_CANDIDATES`]. Caller sets `firmware_root` to the dir
//! containing these files; in production that's `/usr/share/OVMF/` on
//! Debian/Ubuntu, `/usr/share/edk2/ovmf/` on Fedora.
//!
//! # Security
//!
//! `custom_keyring` (when set for `CustomPk`) is canonicalized and
//! required to live under `firmware_root`. This is the second-layer
//! check — [`crate::loader::load_all`] already enforces the same at
//! persona-load time. Defense in depth: if a future refactor bypasses
//! the loader, the QEMU boundary still refuses to pass an escape-path
//! to `-drive`.

use crate::persona::OvmfVariant;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Resolved firmware paths for a persona's `SecureBoot` posture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OvmfPaths {
    /// The `OVMF_CODE` image. Read-only, shared across runs.
    pub code: PathBuf,
    /// The `OVMF_VARS` template. The caller copies this into a per-run
    /// working directory (so each run has isolated SB variables) before
    /// passing the copy to QEMU. For `CustomPk` this is the
    /// persona-supplied keyring, pre-validated to live under
    /// `firmware_root`.
    pub vars_template: PathBuf,
}

/// Failure modes for path resolution.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum OvmfError {
    /// None of the known CODE paths under `firmware_root` exist.
    #[error(
        "`OVMF_CODE` image not found under {firmware_root}; tried: {tried:?}. \
         Install `ovmf` (Debian/Ubuntu) or `edk2-ovmf` (Fedora), or set a custom firmware_root."
    )]
    OvmfCodeMissing {
        /// The firmware root that was searched.
        firmware_root: PathBuf,
        /// The relative candidate paths that were tried.
        tried: Vec<&'static str>,
    },

    /// The VARS template path doesn't exist.
    #[error("`OVMF_VARS` template not found at {path}")]
    VarsTemplateMissing {
        /// The path that was expected.
        path: PathBuf,
    },

    /// `custom_keyring` for `CustomPk` escapes `firmware_root` after
    /// canonicalization. Rejected with the same variant the loader uses.
    #[error("custom_keyring {keyring} escapes firmware_root {firmware_root}")]
    CustomKeyringOutsideRoot {
        /// The offending keyring path.
        keyring: PathBuf,
        /// The firmware root it was required to sit under.
        firmware_root: PathBuf,
    },

    /// `CustomPk` was specified but no `custom_keyring` path was set on
    /// the persona's `secure_boot` block. Persona validation should have
    /// caught this; we repeat the check at the QEMU boundary.
    #[error("secure_boot.ovmf_variant=custom_pk requires a custom_keyring path; none set")]
    CustomKeyringRequired,

    /// Canonicalizing a user-supplied path failed (e.g. the file doesn't
    /// exist on disk). Wraps the underlying `io::Error` kind as a string
    /// so the variant stays `PartialEq` for test assertions.
    #[error("failed to canonicalize {path}: {kind}")]
    Canonicalize {
        /// The path that couldn't be canonicalized.
        path: PathBuf,
        /// Underlying `io::ErrorKind`, rendered as its `Debug` string.
        kind: String,
    },
}

/// Debian/Ubuntu CODE candidates, in preference order.
const DEBIAN_CODE_SECBOOT: &str = "OVMF_CODE_4M.secboot.fd";
const DEBIAN_CODE_NONSECBOOT: &str = "OVMF_CODE_4M.fd";
const DEBIAN_VARS_MS: &str = "OVMF_VARS_4M.ms.fd";
const DEBIAN_VARS_BLANK: &str = "OVMF_VARS_4M.fd";

/// Fedora CODE candidates. Fedora ships both 2M and 4M variants; we
/// prefer 4M (more recent, supports larger VARS blobs).
const FEDORA_CODE_CANDIDATES: &[&str] = &[
    "OVMF_CODE.secboot.4m.fd",
    "OVMF_CODE.secboot.fd",
    "OVMF_CODE.fd",
];

/// Resolve `OVMF_CODE` + `OVMF_VARS` paths for a `SecureBoot` posture.
///
/// # Errors
///
/// See [`OvmfError`] variants. The most common at first run is
/// [`OvmfError::OvmfCodeMissing`], which prints the install hint.
pub fn resolve(
    variant: OvmfVariant,
    custom_keyring: Option<&Path>,
    firmware_root: &Path,
) -> Result<OvmfPaths, OvmfError> {
    let want_secboot = matches!(
        variant,
        OvmfVariant::MsEnrolled | OvmfVariant::CustomPk | OvmfVariant::SetupMode
    );
    let code = find_code(firmware_root, want_secboot)?;

    let vars_template = match variant {
        OvmfVariant::MsEnrolled => resolve_vars(firmware_root, DEBIAN_VARS_MS)?,
        OvmfVariant::SetupMode | OvmfVariant::Disabled => {
            resolve_vars(firmware_root, DEBIAN_VARS_BLANK)?
        }
        OvmfVariant::CustomPk => {
            let keyring = custom_keyring.ok_or(OvmfError::CustomKeyringRequired)?;
            verify_keyring_under_root(keyring, firmware_root)?
        }
    };

    Ok(OvmfPaths {
        code,
        vars_template,
    })
}

/// Find the first existing CODE image under `firmware_root`.
fn find_code(firmware_root: &Path, want_secboot: bool) -> Result<PathBuf, OvmfError> {
    let mut tried: Vec<&'static str> = Vec::new();

    // Debian first (this project's primary target).
    if want_secboot {
        tried.push(DEBIAN_CODE_SECBOOT);
        let p = firmware_root.join(DEBIAN_CODE_SECBOOT);
        if p.exists() {
            return Ok(p);
        }
    } else {
        tried.push(DEBIAN_CODE_NONSECBOOT);
        let p = firmware_root.join(DEBIAN_CODE_NONSECBOOT);
        if p.exists() {
            return Ok(p);
        }
    }

    // Fedora fallback — iterate preference list, filter by secboot expectation.
    for name in FEDORA_CODE_CANDIDATES {
        let has_secboot = name.contains("secboot");
        if has_secboot != want_secboot {
            continue;
        }
        tried.push(name);
        let p = firmware_root.join(name);
        if p.exists() {
            return Ok(p);
        }
    }

    Err(OvmfError::OvmfCodeMissing {
        firmware_root: firmware_root.to_path_buf(),
        tried,
    })
}

fn resolve_vars(firmware_root: &Path, name: &str) -> Result<PathBuf, OvmfError> {
    let p = firmware_root.join(name);
    if p.exists() {
        Ok(p)
    } else {
        Err(OvmfError::VarsTemplateMissing { path: p })
    }
}

/// Canonicalize `keyring` and require it to live under the (canonicalized)
/// `firmware_root`. Rejects `../` traversal, absolute paths outside root,
/// and symlink escapes.
fn verify_keyring_under_root(keyring: &Path, firmware_root: &Path) -> Result<PathBuf, OvmfError> {
    let keyring_canon = canonicalize_or_err(keyring)?;
    let root_canon = canonicalize_or_err(firmware_root)?;
    if keyring_canon.starts_with(&root_canon) {
        Ok(keyring_canon)
    } else {
        Err(OvmfError::CustomKeyringOutsideRoot {
            keyring: keyring.to_path_buf(),
            firmware_root: firmware_root.to_path_buf(),
        })
    }
}

fn canonicalize_or_err(path: &Path) -> Result<PathBuf, OvmfError> {
    std::fs::canonicalize(path).map_err(|e| OvmfError::Canonicalize {
        path: path.to_path_buf(),
        kind: format!("{:?}", e.kind()),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// Build a fake Debian-layout firmware root. Returns the temp dir
    /// (keep alive) and the path to it.
    fn debian_firmware_root() -> (TempDir, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        for name in [
            DEBIAN_CODE_SECBOOT,
            DEBIAN_CODE_NONSECBOOT,
            DEBIAN_VARS_MS,
            DEBIAN_VARS_BLANK,
        ] {
            fs::write(root.join(name), b"fake firmware blob\n").unwrap();
        }
        (tmp, root)
    }

    #[test]
    fn ms_enrolled_resolves_to_secboot_code_plus_ms_vars() {
        let (_tmp, root) = debian_firmware_root();
        let paths = resolve(OvmfVariant::MsEnrolled, None, &root).unwrap();
        assert_eq!(paths.code, root.join(DEBIAN_CODE_SECBOOT));
        assert_eq!(paths.vars_template, root.join(DEBIAN_VARS_MS));
    }

    #[test]
    fn setup_mode_resolves_to_secboot_code_plus_blank_vars() {
        let (_tmp, root) = debian_firmware_root();
        let paths = resolve(OvmfVariant::SetupMode, None, &root).unwrap();
        assert_eq!(paths.code, root.join(DEBIAN_CODE_SECBOOT));
        assert_eq!(paths.vars_template, root.join(DEBIAN_VARS_BLANK));
    }

    #[test]
    fn disabled_resolves_to_non_secboot_code_plus_blank_vars() {
        let (_tmp, root) = debian_firmware_root();
        let paths = resolve(OvmfVariant::Disabled, None, &root).unwrap();
        assert_eq!(paths.code, root.join(DEBIAN_CODE_NONSECBOOT));
        assert_eq!(paths.vars_template, root.join(DEBIAN_VARS_BLANK));
    }

    #[test]
    fn missing_code_image_yields_named_error_with_hint() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let err = resolve(OvmfVariant::MsEnrolled, None, &root).unwrap_err();
        match err {
            OvmfError::OvmfCodeMissing {
                firmware_root,
                tried,
            } => {
                assert_eq!(firmware_root, root);
                assert!(
                    tried.contains(&DEBIAN_CODE_SECBOOT),
                    "should have tried Debian secboot path first"
                );
            }
            other => panic!("expected OvmfCodeMissing, got {other:?}"),
        }
    }

    #[test]
    fn fedora_layout_resolves_when_debian_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        // Fedora ships OVMF_CODE.secboot.4m.fd
        fs::write(root.join("OVMF_CODE.secboot.4m.fd"), b"fedora fake\n").unwrap();
        fs::write(root.join(DEBIAN_VARS_MS), b"ms vars fake\n").unwrap();
        let paths = resolve(OvmfVariant::MsEnrolled, None, &root).unwrap();
        assert_eq!(paths.code, root.join("OVMF_CODE.secboot.4m.fd"));
    }

    #[test]
    fn missing_vars_template_yields_named_error() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        fs::write(root.join(DEBIAN_CODE_SECBOOT), b"fake\n").unwrap();
        let err = resolve(OvmfVariant::MsEnrolled, None, &root).unwrap_err();
        assert!(
            matches!(err, OvmfError::VarsTemplateMissing { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn custom_pk_without_keyring_rejected() {
        let (_tmp, root) = debian_firmware_root();
        let err = resolve(OvmfVariant::CustomPk, None, &root).unwrap_err();
        assert_eq!(err, OvmfError::CustomKeyringRequired);
    }

    #[test]
    fn custom_pk_with_keyring_under_root_resolves() {
        let (_tmp, root) = debian_firmware_root();
        let keyring = root.join("custom-pk-keyring.fd");
        fs::write(&keyring, b"test keyring\n").unwrap();
        let paths = resolve(OvmfVariant::CustomPk, Some(&keyring), &root).unwrap();
        // vars_template comes from the keyring for CustomPk, not the MS template
        assert_eq!(paths.vars_template, keyring.canonicalize().unwrap());
    }

    #[test]
    fn custom_pk_with_keyring_outside_root_rejected() {
        let (_tmp, root) = debian_firmware_root();
        // Create a keyring file in a sibling dir (outside firmware_root).
        let other = tempfile::tempdir().unwrap();
        let keyring = other.path().join("escape.fd");
        fs::write(&keyring, b"evil\n").unwrap();
        let err = resolve(OvmfVariant::CustomPk, Some(&keyring), &root).unwrap_err();
        assert!(
            matches!(err, OvmfError::CustomKeyringOutsideRoot { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn custom_pk_with_symlink_escape_rejected() {
        let (_tmp, root) = debian_firmware_root();
        // Place a symlink INSIDE root that points OUTSIDE root.
        let other = tempfile::tempdir().unwrap();
        let target = other.path().join("real.fd");
        fs::write(&target, b"outside\n").unwrap();
        let symlink = root.join("looks-inside.fd");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &symlink).unwrap();
        #[cfg(not(unix))]
        {
            let _ = symlink; // symlinks require elevated privs on Windows; skip
            return;
        }
        let err = resolve(OvmfVariant::CustomPk, Some(&symlink), &root).unwrap_err();
        assert!(
            matches!(err, OvmfError::CustomKeyringOutsideRoot { .. }),
            "symlink canonicalized should escape root; got {err:?}"
        );
    }

    #[test]
    fn canonicalize_failure_surfaced_as_named_error() {
        let (_tmp, root) = debian_firmware_root();
        let missing = root.join("does-not-exist.fd");
        let err = resolve(OvmfVariant::CustomPk, Some(&missing), &root).unwrap_err();
        assert!(matches!(err, OvmfError::Canonicalize { .. }), "got {err:?}");
    }
}
