//! `qemu-boots-ovmf` — smoke scenario that proves the harness pipeline.
//!
//! Unlike [`super::SignedBootUbuntu`] this scenario does NOT need a
//! real signed `aegis-boot` stick. It feeds QEMU+OVMF an empty 1 MB
//! disk and asserts that OVMF's `BdsDxe` boot-selector emits its
//! "failed to load Boot0001 ..." message on serial within 60s.
//!
//! Why this matters: it lets CI exercise the full
//! `Persona` → `ovmf::resolve` → `Invocation` → `SerialCapture` pipeline
//! end-to-end without provisioning a signed stick artifact. If this
//! scenario goes Pass on a CI runner, the harness wiring is sound;
//! adding a real stick is then the only remaining variable.
//!
//! Skips: same as [`super::SignedBootUbuntu`] for missing
//! `qemu-system-x86_64`. swtpm is not exercised — the smoke uses a
//! `TpmVersion::None` persona by convention.

use crate::qemu::Invocation;
use crate::scenario::{Scenario, ScenarioContext, ScenarioError, ScenarioResult};
use crate::scenarios::common::binary_on_path;
use crate::serial::SerialCapture;
use crate::swtpm::{SwtpmInstance, SwtpmSpec};
use std::time::Duration;

/// Wait this long for OVMF's `BdsDxe` message to reach serial. Cold-boot
/// OVMF under TCG (no KVM) can take ~10s on slow CI; 60s is generous.
const BDSDXE_TIMEOUT: Duration = Duration::from_secs(60);

/// The substring that proves OVMF reached the boot-device-selector
/// stage (i.e. firmware fully initialized, USB enumerated, no
/// bootable image found — which is expected for an empty stick).
///
/// Format observed:
///   `BdsDxe: failed to load Boot0001 "UEFI QEMU QEMU USB HARDDRIVE ..."`
const BDSDXE_LANDMARK: &str = "BdsDxe";

/// Smoke scenario. Stateless.
pub struct QemuBootsOvmf;

impl Scenario for QemuBootsOvmf {
    fn name(&self) -> &'static str {
        "qemu-boots-ovmf"
    }

    fn description(&self) -> &'static str {
        "boot OVMF with the persona's firmware over an empty stick; \
         assert OVMF's `BdsDxe` boot-selector emits a 'failed to load' \
         marker on serial. Proves the harness pipeline without needing \
         a signed `aegis-boot` stick artifact."
    }

    fn run(&self, ctx: &ScenarioContext) -> Result<ScenarioResult, ScenarioError> {
        // `qemu-system-x86_64` is required.
        if !binary_on_path("qemu-system-x86_64") {
            return Ok(ScenarioResult::Skip {
                reason: "`qemu-system-x86_64` not on PATH (Debian: apt install qemu-system-x86)"
                    .to_string(),
            });
        }

        // The persona MUST opt out of TPM. The smoke scenario is the
        // harness self-test; mixing in swtpm would just expand the
        // failure surface without adding signal. Skip (not Fail) when
        // a TPM persona is handed in so the coverage grid renders this
        // as N/A — most personas legitimately request TPM, and that
        // shouldn't pollute the grid with FAIL/ERROR noise.
        if !matches!(ctx.persona.tpm.version, crate::persona::TpmVersion::None) {
            return Ok(ScenarioResult::Skip {
                reason: format!(
                    "scenario is no-TPM only; persona {} requests TPM {:?}. \
                     The qemu-smoke-no-tpm persona exercises this scenario.",
                    ctx.persona.id, ctx.persona.tpm.version
                ),
            });
        }

        // The "stick" is an empty 1 MB file — OVMF will enumerate it
        // and fail to find a bootable image, emitting `BdsDxe` on serial.
        // We provision it under the work dir so concurrent scenarios
        // don't collide.
        std::fs::create_dir_all(&ctx.work_dir).map_err(|e| ScenarioError::Io {
            kind: format!("{:?}", e.kind()),
            context: format!("create work_dir {}", ctx.work_dir.display()),
        })?;
        let stick = ctx.work_dir.join("smoke-empty-stick.img");
        // 1 MB empty file. Truncate-to-size; create if missing.
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&stick)
            .map_err(|e| ScenarioError::Io {
                kind: format!("{:?}", e.kind()),
                context: format!("create empty stick {}", stick.display()),
            })?;
        file.set_len(1024 * 1024).map_err(|e| ScenarioError::Io {
            kind: format!("{:?}", e.kind()),
            context: format!("size empty stick {}", stick.display()),
        })?;
        drop(file);

        // NoTpm sentinel — no swtpm spawned.
        let swtpm_spec = SwtpmSpec::derive("smoke", &ctx.work_dir, ctx.persona.tpm.version);
        let swtpm = SwtpmInstance::spawn(&swtpm_spec)?;

        let inv = Invocation::new(
            &ctx.persona,
            &stick,
            &ctx.work_dir,
            &ctx.firmware_root,
            &swtpm,
        )?;

        let log_path = ctx.work_dir.join("serial.log");
        let handle = SerialCapture::spawn(inv.build(), &log_path, None)?;

        if handle
            .wait_for_line(BDSDXE_LANDMARK, BDSDXE_TIMEOUT)
            .is_some()
        {
            Ok(ScenarioResult::Pass)
        } else {
            Ok(ScenarioResult::Fail {
                reason: format!(
                    "'{BDSDXE_LANDMARK}' not seen within {}s. Serial log: {}.",
                    BDSDXE_TIMEOUT.as_secs(),
                    log_path.display()
                ),
            })
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::persona::Persona;
    use std::path::PathBuf;

    fn no_tpm_persona() -> Persona {
        serde_yaml_ng::from_str(
            "
schema_version: 1
id: smoke-test
vendor: QEMU
display_name: smoke
source:
  kind: vendor_docs
  ref_: smoke
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
",
        )
        .unwrap()
    }

    #[test]
    fn name_and_description_are_stable() {
        let s = QemuBootsOvmf;
        assert_eq!(s.name(), "qemu-boots-ovmf");
        assert!(s.description().contains("BdsDxe"));
    }

    #[test]
    fn skips_persona_with_tpm() {
        let s = QemuBootsOvmf;
        let mut p = no_tpm_persona();
        p.tpm.version = crate::persona::TpmVersion::Tpm20;
        let ctx = ScenarioContext {
            persona: p,
            stick: PathBuf::from("/unused-by-this-path"),
            work_dir: tempfile::tempdir().unwrap().path().to_path_buf(),
            firmware_root: PathBuf::from("/usr/share/OVMF"),
        };
        let result = s.run(&ctx).unwrap();
        match result {
            ScenarioResult::Skip { reason } => {
                assert!(reason.contains("no-TPM only"), "got reason: {reason}");
                assert!(reason.contains("qemu-smoke-no-tpm"));
            }
            other => panic!("expected Skip, got {other:?}"),
        }
    }
}
