//! `signed-boot-ubuntu` — first end-to-end scenario.
//!
//! Boots the persona's firmware with the aegis-boot stick attached,
//! waits through the signed-chain landmarks (shim → grub → kernel →
//! kexec), and reports `Pass` if every landmark is observed within
//! the per-step timeout.
//!
//! # What it asserts
//!
//! 1. **`shim:`** — OVMF loaded shim (signed by MS or custom PK).
//! 2. **`grub`** — shim verified grub's signature and handed off.
//! 3. **`Linux version`** — grub loaded the kernel from the stick.
//! 4. **`kexec_core: Starting new kernel`** — initramfs `/init`
//!    (rescue-tui) reached and kexec'd the operator's chosen ISO.
//!
//! # When it skips
//!
//! - The stick file doesn't exist (developer running without
//!   provisioning a test stick).
//! - `qemu-system-x86_64` is missing on PATH.
//! - `swtpm` is missing on PATH (only when the persona requests TPM).
//!
//! These conditions return [`ScenarioResult::Skip`] with a specific
//! reason — never [`ScenarioResult::Fail`]. CI greps for `SKIP:` and
//! treats the run as N/A rather than failing the workflow.

use crate::qemu::Invocation;
use crate::scenario::{Scenario, ScenarioContext, ScenarioError, ScenarioResult};
use crate::scenarios::common::binary_on_path;
use crate::serial::SerialCapture;
use crate::swtpm::{SwtpmInstance, SwtpmSpec};
use std::time::Duration;

/// Per-landmark wait timeout. Generous because cold-boot OVMF can be
/// slow, especially under TCG (no KVM acceleration in CI).
const LANDMARK_TIMEOUT: Duration = Duration::from_secs(60);

/// The boot-chain landmarks we wait for, in order. Each one's
/// observation is necessary for the chain to be considered Pass.
const LANDMARKS: &[&str] = &[
    "shim",
    // grub may print as "grub", "GNU GRUB", or `Welcome to GRUB`. We
    // match the broadest substring to tolerate distro variation.
    "GRUB",
    "Linux version",
    "kexec_core: Starting new kernel",
];

/// The first end-to-end scenario. Stateless; all per-run state lives
/// in the `ScenarioContext`.
pub struct SignedBootUbuntu;

impl Scenario for SignedBootUbuntu {
    fn name(&self) -> &'static str {
        "signed-boot-ubuntu"
    }

    fn description(&self) -> &'static str {
        "boot OVMF + persona's firmware with the aegis-boot stick, \
         assert shim → grub → kernel → kexec landmarks reach the serial log"
    }

    fn run(&self, ctx: &ScenarioContext) -> Result<ScenarioResult, ScenarioError> {
        // Skip path: stick missing means the test wasn't provisioned.
        // Honest "N/A" beats a misleading FAIL.
        if !ctx.stick.is_file() {
            return Ok(ScenarioResult::Skip {
                reason: format!(
                    "stick {} not found; provision via aegis-boot flash or set AEGIS_HWSIM_STICK",
                    ctx.stick.display()
                ),
            });
        }

        // Skip path: qemu-system-x86_64 missing.
        if !binary_on_path("qemu-system-x86_64") {
            return Ok(ScenarioResult::Skip {
                reason: "qemu-system-x86_64 not on PATH (Debian: apt install qemu-system-x86)"
                    .to_string(),
            });
        }

        // Skip path: swtpm missing AND persona wants TPM.
        let needs_tpm = !matches!(ctx.persona.tpm.version, crate::persona::TpmVersion::None);
        if needs_tpm && !binary_on_path("swtpm") {
            return Ok(ScenarioResult::Skip {
                reason: "swtpm not on PATH (Debian: apt install swtpm); \
                         persona requires TPM emulation"
                    .to_string(),
            });
        }

        // Spawn swtpm (or NoTpm sentinel for personas that opt out).
        let swtpm_spec = SwtpmSpec::derive("scenario", &ctx.work_dir, ctx.persona.tpm.version);
        let swtpm = SwtpmInstance::spawn(&swtpm_spec)?;

        // Compose the QEMU invocation.
        let inv = Invocation::new(
            &ctx.persona,
            &ctx.stick,
            &ctx.work_dir,
            &ctx.firmware_root,
            &swtpm,
        )?;

        // Capture serial. Log alongside the per-run work dir.
        let log_path = ctx.work_dir.join("serial.log");
        let handle = SerialCapture::spawn(inv.build(), &log_path, None)?;

        // Walk the landmarks. First miss → Fail with the specific
        // landmark + how many succeeded before it.
        for (idx, landmark) in LANDMARKS.iter().enumerate() {
            if handle.wait_for_line(landmark, LANDMARK_TIMEOUT).is_none() {
                return Ok(ScenarioResult::Fail {
                    reason: format!(
                        "landmark {idx}/{} '{landmark}' not seen within {}s. \
                         Serial log saved to {}.",
                        LANDMARKS.len(),
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

    fn make_persona(yaml: &str) -> Persona {
        serde_yaml::from_str(yaml).unwrap()
    }

    fn base_persona_yaml() -> &'static str {
        r#"
schema_version: 1
id: test
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
  version: "2.0"
"#
    }

    fn fake_ctx(stick: PathBuf) -> ScenarioContext {
        ScenarioContext {
            persona: make_persona(base_persona_yaml()),
            stick,
            work_dir: tempfile::tempdir().unwrap().path().to_path_buf(),
            firmware_root: PathBuf::from("/usr/share/OVMF"),
        }
    }

    #[test]
    fn name_and_description_are_stable() {
        let s = SignedBootUbuntu;
        assert_eq!(s.name(), "signed-boot-ubuntu");
        assert!(s.description().contains("shim"));
    }

    #[test]
    fn skips_when_stick_missing() {
        let s = SignedBootUbuntu;
        let result = s
            .run(&fake_ctx(PathBuf::from("/no/such/stick.img")))
            .unwrap();
        match result {
            ScenarioResult::Skip { reason } => {
                assert!(
                    reason.contains("not found"),
                    "expected 'not found' in reason: {reason}"
                );
            }
            other => panic!("expected Skip, got {other:?}"),
        }
    }

    // PATH-based skip is exercised by `binary_on_path` tests in
    // `scenarios::common::tests`; not duplicated here.
}
