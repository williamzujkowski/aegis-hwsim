//! `mok-enroll-alpine` — boot Alpine (unsigned kernel) under MS-enrolled Secure Boot, assert aegis-boot's rescue-tui surfaces the MOK enrollment walkthrough STEP 1/3 (`sudo mokutil --import`).
//!
//! # What this scenario asserts
//!
//! 1. Persona boots successfully (shim → grub → kernel rejected → fallback path → rescue-tui), same prerequisite chain as [`super::SignedBootUbuntu`].
//! 2. Rescue-tui detects an unsigned/unrecognized kernel was attempted and surfaces the MOK enrollment walkthrough — the operator-facing recovery path documented in aegis-boot#202.
//! 3. The walkthrough's STEP 1 surfaces the `sudo mokutil --import` command verbatim. Operators will literally copy-paste it; the harness asserts the exact string so a future drift in #202's docstring lights up here rather than confusing an operator at 2am.
//!
//! # Prerequisites
//!
//! - An aegis-boot stick with an Alpine ISO loaded (or an Alpine boot path the rescue-tui surfaces). The stick fixture path is supplied via [`ScenarioContext::stick`]; the operator stages it via `aegis-boot flash` or the `AEGIS_HWSIM_STICK` env var (matching the convention from `signed_boot_ubuntu`).
//! - Persona with `secure_boot.ovmf_variant: ms_enrolled`. `custom_pk` would also work but the MOK enrollment story is specifically about the MS-enrolled / vendor-shim path; `disabled` and `setup_mode` short-circuit because there's no signature gate to fail.
//!
//! # When this scenario skips
//!
//! - Stick missing on disk.
//! - `qemu-system-x86_64` not on PATH.
//! - `swtpm` missing AND the persona requests TPM.
//! - Persona's `secure_boot.ovmf_variant` isn't `ms_enrolled`.
//!
//! # When this scenario fails (vs skips)
//!
//! Boot didn't reach rescue-tui's prereq landmarks → `Fail` (the harness pipeline broke). Boot reached rescue-tui but the MOK walkthrough never fired → `Skip` (the stick wasn't built with the unsigned-Alpine path). Walkthrough fired but the literal `sudo mokutil --import` command didn't appear → `Fail` (real bug — aegis-boot#202's text drifted, an operator running this would be stuck).

use crate::persona::OvmfVariant;
use crate::qemu::Invocation;
use crate::scenario::{Scenario, ScenarioContext, ScenarioError, ScenarioResult};
use crate::scenarios::common::binary_on_path;
use crate::serial::SerialCapture;
use crate::swtpm::{SwtpmInstance, SwtpmSpec};
use std::time::Duration;

/// Per-landmark wait timeout. Same 60s ceiling as the other scenarios — cold-boot OVMF + MS-enrolled SB chain + rescue-tui walkthrough is the slow path.
const LANDMARK_TIMEOUT: Duration = Duration::from_secs(60);

/// Pre-walkthrough landmarks: the chain has to reach rescue-tui before the walkthrough can fire.
const PREREQ_LANDMARKS: &[&str] = &[
    "EFI stub: UEFI Secure Boot is enabled",
    "rescue-tui starting",
];

/// MOK enrollment walkthrough landmarks. Order is significant — STEP 1 must come before STEP 2/3.
///
/// 1. `MOK enrollment walkthrough` — rescue-tui's section header. Without this we can't tell whether the walkthrough actually ran (vs. the stick not having the Alpine/MOK hook compiled in).
///
/// 2. `STEP 1/3` — section marker for the `mokutil --import` step. aegis-boot#202 ships exactly three steps; the harness asserts step 1 because that's the load-bearing one (without it the operator can't proceed).
///
/// 3. `sudo mokutil --import` — the literal copy-paste command. This is the assertion the issue body specifically calls out: "assert the MOK walkthrough STEP 1/3 `sudo mokutil --import` command string appears in the serial log exactly as #202 ships it". A future drift in #202 lights up here.
const TEST_LANDMARKS: &[&str] = &[
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

        // Wait for rescue-tui to come up first. Without this the
        // walkthrough landmarks can never fire.
        for landmark in PREREQ_LANDMARKS {
            if handle.wait_for_line(landmark, LANDMARK_TIMEOUT).is_none() {
                return Ok(ScenarioResult::Fail {
                    reason: format!(
                        "prerequisite landmark '{landmark}' not seen within {}s. \
                         Boot didn't reach rescue-tui — MOK walkthrough can't fire. \
                         Serial log: {}.",
                        LANDMARK_TIMEOUT.as_secs(),
                        log_path.display(),
                    ),
                });
            }
        }

        // First walkthrough landmark — its absence means the stick
        // didn't actually trigger the MOK path. Skip (test wasn't
        // run), don't Fail.
        match handle.wait_for_line(TEST_LANDMARKS[0], LANDMARK_TIMEOUT) {
            Some(_) => {}
            None => {
                return Ok(ScenarioResult::Skip {
                    reason: format!(
                        "stick reached rescue-tui but the MOK enrollment walkthrough \
                         didn't fire. The stick needs an Alpine ISO entry that grub \
                         attempts under SB, OR an `aegis.test=mok-enroll` cmdline \
                         hook. Serial log: {}.",
                        log_path.display()
                    ),
                });
            }
        }

        // Walkthrough fired. Remaining landmarks (STEP 1/3 + the
        // exact mokutil command) MUST appear, otherwise aegis-boot#202
        // drifted and operators would be left without a copy-pastable
        // command — that's a real defect, not a Skip.
        for landmark in &TEST_LANDMARKS[1..] {
            if handle.wait_for_line(landmark, LANDMARK_TIMEOUT).is_none() {
                return Ok(ScenarioResult::Fail {
                    reason: format!(
                        "walkthrough started but '{landmark}' not seen within {}s. \
                         aegis-boot#202's MOK walkthrough drifted; an operator \
                         hitting this in the field would be stuck. Serial log: {}.",
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
