//! `mok-enroll-alpine` — boot under MS-enrolled SB with `aegis.test=mok-enroll` on the kernel cmdline, assert aegis-boot's rescue-tui surfaces the MOK enrollment walkthrough STEP 1/3 (`sudo mokutil --import`) verbatim per [aegis-boot#202](https://github.com/aegis-boot/aegis-boot/pull/202) and [PR #681](https://github.com/aegis-boot/aegis-boot/pull/681).
//!
//! # What this scenario asserts
//!
//! 1. Persona boots successfully (shim → grub → kernel → init), same prerequisite chain as [`super::SignedBootUbuntu`].
//! 2. The initramfs detects `aegis.test=mok-enroll` on the kernel cmdline and exports `AEGIS_TEST=mok-enroll`. `init` prints `init: AEGIS_TEST=mok-enroll (cmdline-driven test mode)` per [aegis-boot `scripts/build-initramfs.sh`](https://github.com/aegis-boot/aegis-boot/pull/680).
//! 3. Rescue-tui's `dispatch_from_env` fires the `mok-enroll` test mode, which prints the canonical 3-step walkthrough body — same text the rescue-tui kexec-failure path renders, sourced from aegis-boot's `crate::state::build_mokutil_remedy`. This is a static-text mode (no kexec, no ISO) so the harness asserts the contract without driving a real unsigned-kernel boot.
//! 4. The walkthrough's STEP 1 surfaces the `sudo mokutil --import` command verbatim. Operators will literally copy-paste it; the harness asserts the exact string so a future drift in #202's text lights up here rather than confusing an operator at 2 AM.
//!
//! # Prerequisites
//!
//! - An aegis-boot stick whose grub.cfg adds `aegis.test=mok-enroll` to the kernel cmdline (same shape as [`super::KexecRefusesUnsigned`]). A stick that boots cleanly without the cmdline will Skip.
//! - Persona with `secure_boot.ovmf_variant: ms_enrolled`. `custom_pk` (operator owns root keys, mokutil's job is gone), `disabled` (no signature gate), and `setup_mode` (no PK enrolled) all Skip.
//!
//! # When this scenario skips vs fails
//!
//! - Stick / qemu / swtpm prereqs missing → Skip.
//! - Persona `ovmf_variant` isn't `ms_enrolled` → Skip.
//! - Boot didn't reach kernel-userspace handoff → Fail (harness pipeline broke).
//! - Kernel reached but `init: AEGIS_TEST=mok-enroll` didn't fire → Skip (cmdline wasn't injected).
//! - `init` saw the cmdline but rescue-tui didn't print the walkthrough header → Fail (`test_mode` dispatcher regressed).
//! - Walkthrough header fired but STEP 1/3 + the literal `sudo mokutil --import` command didn't appear → Fail (real bug — aegis-boot#202's text drifted; operators in the field would be stuck).

use crate::persona::OvmfVariant;
use crate::qemu::Invocation;
use crate::scenario::{Scenario, ScenarioContext, ScenarioError, ScenarioResult};
use crate::scenarios::common::binary_on_path;
use crate::serial::SerialCapture;
use crate::swtpm::{SwtpmInstance, SwtpmSpec};
use std::time::Duration;

/// Per-landmark wait timeout. Same 60s ceiling as the other scenarios — cold-boot OVMF + MS-enrolled SB chain + rescue-tui walkthrough is the slow path.
const LANDMARK_TIMEOUT: Duration = Duration::from_secs(60);

/// Pre-test landmark — kernel must reach userspace before the
/// initramfs can dispatch the test mode. We don't pin
/// `rescue-tui starting` here because under `aegis.test=...` the
/// dispatcher fires BEFORE the interactive TUI prints its banner
/// (see aegis-boot `crates/rescue-tui/src/main.rs` —
/// `test_mode::dispatch_from_env` returns before `run`).
const PREREQ_LANDMARKS: &[&str] = &["EFI stub: UEFI Secure Boot is enabled"];

/// MOK walkthrough landmarks — published contract from aegis-boot
/// `docs/rescue-tui-serial-format.md` (see PR #681). Order is
/// significant: cmdline detection → walkthrough header → step
/// marker → load-bearing copy-paste command.
///
/// 1. `init: AEGIS_TEST=mok-enroll` — `/init` saw the cmdline. Missing
///    this means the stick's grub.cfg didn't inject the param;
///    test isn't measuring anything → Skip.
/// 2. `MOK enrollment walkthrough` — rescue-tui's `mok-enroll` test
///    fn fired. Substring matches both the `starting` header and
///    the `complete` footer.
/// 3. `STEP 1/3` — section marker for the `mokutil --import` step.
///    Confirms the walkthrough body printed.
/// 4. `sudo mokutil --import` — the verbatim copy-paste payload.
///    Drift here would leave an operator at 2 AM with a non-working
///    command line — the harness exists to catch exactly this.
const TEST_LANDMARKS: &[&str] = &[
    "init: AEGIS_TEST=mok-enroll",
    "MOK enrollment walkthrough",
    "STEP 1/3",
    "sudo mokutil --import",
];

/// The scenario type. Stateless.
pub struct MokEnrollAlpine;

impl Scenario for MokEnrollAlpine {
    fn name(&self) -> &'static str {
        "mok-enroll-alpine"
    }

    fn description(&self) -> &'static str {
        "boot Alpine (unsigned kernel) under MS-enrolled SB; assert aegis-boot \
         rescue-tui's MOK walkthrough STEP 1/3 `sudo mokutil --import` appears \
         on serial verbatim per aegis-boot#202"
    }

    fn run(&self, ctx: &ScenarioContext) -> Result<ScenarioResult, ScenarioError> {
        // Skip: stick missing.
        if !ctx.stick.is_file() {
            return Ok(ScenarioResult::Skip {
                reason: format!(
                    "stick {} not found; provision via aegis-boot flash or set AEGIS_HWSIM_STICK",
                    ctx.stick.display()
                ),
            });
        }

        // Skip: qemu-system-x86_64 missing.
        if !binary_on_path("qemu-system-x86_64") {
            return Ok(ScenarioResult::Skip {
                reason: "qemu-system-x86_64 not on PATH (Debian: apt install qemu-system-x86)"
                    .to_string(),
            });
        }

        // Skip: persona's SB variant must be ms_enrolled. The MOK
        // enrollment walkthrough is specifically about the MS / shim
        // chain; under custom_pk the operator already controls the
        // root keys (mokutil's job is gone), and under disabled /
        // setup_mode there's no signature gate to fail.
        if !matches!(
            ctx.persona.secure_boot.ovmf_variant,
            OvmfVariant::MsEnrolled
        ) {
            return Ok(ScenarioResult::Skip {
                reason: format!(
                    "persona {} has ovmf_variant={:?}; MOK enrollment walkthrough \
                     applies to ms_enrolled only",
                    ctx.persona.id, ctx.persona.secure_boot.ovmf_variant
                ),
            });
        }

        // Skip: swtpm missing AND persona wants TPM.
        let needs_tpm = !matches!(ctx.persona.tpm.version, crate::persona::TpmVersion::None);
        if needs_tpm && !binary_on_path("swtpm") {
            return Ok(ScenarioResult::Skip {
                reason: "swtpm not on PATH (Debian: apt install swtpm); \
                         persona requires TPM emulation"
                    .to_string(),
            });
        }

        // Spawn swtpm (or NoTpm sentinel for personas that opt out).
        let swtpm_spec = SwtpmSpec::derive("mok-enroll", &ctx.work_dir, ctx.persona.tpm.version);
        let swtpm = SwtpmInstance::spawn(&swtpm_spec)?;

        let inv = Invocation::new(
            &ctx.persona,
            &ctx.stick,
            &ctx.work_dir,
            &ctx.firmware_root,
            &swtpm,
        )?;

        let log_path = ctx.work_dir.join("serial.log");
        let handle = SerialCapture::spawn(inv.build(), &log_path, None)?;

        // First wait for the kernel-userspace handoff under enforcing
        // SB. Without this, the boot didn't even reach the initramfs.
        for landmark in PREREQ_LANDMARKS {
            if handle.wait_for_line(landmark, LANDMARK_TIMEOUT).is_none() {
                return Ok(ScenarioResult::Fail {
                    reason: format!(
                        "prerequisite landmark '{landmark}' not seen within {}s. \
                         Boot didn't reach kernel-userspace handoff — MOK walkthrough can't fire. \
                         Serial log: {}.",
                        LANDMARK_TIMEOUT.as_secs(),
                        log_path.display(),
                    ),
                });
            }
        }

        // First test landmark — `/init` cmdline detection. Missing it
        // means the stick's grub.cfg didn't inject `aegis.test=mok-enroll`;
        // test isn't measuring anything → Skip (not Fail).
        match handle.wait_for_line(TEST_LANDMARKS[0], LANDMARK_TIMEOUT) {
            Some(_) => {}
            None => {
                return Ok(ScenarioResult::Skip {
                    reason: format!(
                        "kernel reached but `init: AEGIS_TEST=mok-enroll` did not fire. \
                         The stick's grub.cfg needs `aegis.test=mok-enroll` on the \
                         kernel cmdline (see aegis-boot scripts/build-initramfs.sh, PR #680). \
                         Serial log: {}.",
                        log_path.display()
                    ),
                });
            }
        }

        // Test mode entered. Remaining landmarks (walkthrough header,
        // STEP 1/3, mokutil command) MUST appear, otherwise either
        // (a) the rescue-tui dispatcher regressed (init saw the
        // cmdline but rescue-tui didn't fire the walkthrough), or
        // (b) aegis-boot#202's text drifted and operators in the
        // field would be stuck without a copy-pastable command.
        // Both are real defects, not Skip conditions.
        for landmark in &TEST_LANDMARKS[1..] {
            if handle.wait_for_line(landmark, LANDMARK_TIMEOUT).is_none() {
                return Ok(ScenarioResult::Fail {
                    reason: format!(
                        "init detected the cmdline but '{landmark}' not seen within {}s. \
                         Either rescue-tui's mok-enroll dispatcher regressed, or \
                         aegis-boot#202's MOK walkthrough text drifted (see \
                         docs/rescue-tui-serial-format.md substring contract). \
                         Serial log: {}.",
                        LANDMARK_TIMEOUT.as_secs(),
                        log_path.display(),
                    ),
                });
            }
        }

        Ok(ScenarioResult::Pass)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::persona::Persona;
    use std::path::PathBuf;

    fn ms_enrolled_persona_yaml() -> &'static str {
        r"
schema_version: 1
id: test-ms
vendor: QEMU
display_name: Test
source:
  kind: vendor_docs
  ref_: test
dmi:
  sys_vendor: QEMU
  product_name: Standard PC
  bios_vendor: EDK II
  bios_version: stable
  bios_date: 01/01/2024
secure_boot:
  ovmf_variant: ms_enrolled
tpm:
  version: none
"
    }

    fn make_persona(yaml: &str) -> Persona {
        serde_yaml_ng::from_str(yaml).unwrap()
    }

    fn fake_ctx(persona: Persona, stick: PathBuf) -> ScenarioContext {
        ScenarioContext {
            persona,
            stick,
            work_dir: tempfile::tempdir().unwrap().path().to_path_buf(),
            firmware_root: PathBuf::from("/usr/share/OVMF"),
        }
    }

    #[test]
    fn name_and_description_are_stable() {
        let s = MokEnrollAlpine;
        assert_eq!(s.name(), "mok-enroll-alpine");
        assert!(s.description().contains("mokutil"));
        assert!(s.description().contains("aegis-boot#202"));
    }

    #[test]
    fn skips_when_stick_missing() {
        let s = MokEnrollAlpine;
        let result = s
            .run(&fake_ctx(
                make_persona(ms_enrolled_persona_yaml()),
                PathBuf::from("/no/such/stick.img"),
            ))
            .unwrap();
        match result {
            ScenarioResult::Skip { reason } => {
                assert!(reason.contains("not found"), "got reason: {reason}");
            }
            other => panic!("expected Skip, got {other:?}"),
        }
    }

    #[test]
    fn skips_when_custom_pk() {
        // CustomPk persona — operator owns the root keys; mokutil
        // path is gone. Scenario must not pretend to test something
        // it isn't measuring.
        let tmp = tempfile::tempdir().unwrap();
        let stick = tmp.path().join("fake-stick.img");
        std::fs::write(&stick, b"placeholder").unwrap();
        let mut p = make_persona(ms_enrolled_persona_yaml());
        p.secure_boot.ovmf_variant = OvmfVariant::CustomPk;
        let s = MokEnrollAlpine;
        let result = s.run(&fake_ctx(p, stick)).unwrap();
        match result {
            ScenarioResult::Skip { reason } => {
                assert!(
                    reason.contains("ms_enrolled only"),
                    "expected ms_enrolled-only skip reason: {reason}"
                );
            }
            other => panic!("expected Skip, got {other:?}"),
        }
    }

    #[test]
    fn skips_when_setup_mode() {
        let tmp = tempfile::tempdir().unwrap();
        let stick = tmp.path().join("fake-stick.img");
        std::fs::write(&stick, b"placeholder").unwrap();
        let mut p = make_persona(ms_enrolled_persona_yaml());
        p.secure_boot.ovmf_variant = OvmfVariant::SetupMode;
        let s = MokEnrollAlpine;
        let result = s.run(&fake_ctx(p, stick)).unwrap();
        assert!(matches!(result, ScenarioResult::Skip { .. }));
    }

    #[test]
    fn skips_when_disabled() {
        let tmp = tempfile::tempdir().unwrap();
        let stick = tmp.path().join("fake-stick.img");
        std::fs::write(&stick, b"placeholder").unwrap();
        let mut p = make_persona(ms_enrolled_persona_yaml());
        p.secure_boot.ovmf_variant = OvmfVariant::Disabled;
        let s = MokEnrollAlpine;
        let result = s.run(&fake_ctx(p, stick)).unwrap();
        assert!(matches!(result, ScenarioResult::Skip { .. }));
    }
}
