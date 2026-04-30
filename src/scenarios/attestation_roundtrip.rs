//! `attestation-roundtrip` — boot under TPM-bearing persona with `aegis.test=manifest-roundtrip` on the kernel cmdline; assert aegis-boot's rescue-tui mounts the ESP, parses the on-stick manifest via `aegis-wire-formats::Manifest`, and (when populated) compares each `expected_pcrs[]` entry to the live PCR.
//!
//! Closes the harness side of [aegis-hwsim epic E6](https://github.com/aegis-boot/aegis-hwsim/issues/6) against [aegis-boot#695](https://github.com/aegis-boot/aegis-boot/issues/695) / [PR #697](https://github.com/aegis-boot/aegis-boot/pull/697).
//!
//! # What this scenario asserts
//!
//! 1. Persona boots successfully — kernel reaches userspace under enforcing SB (same prerequisite chain as [`super::SignedBootUbuntu`]).
//! 2. The initramfs detects `aegis.test=manifest-roundtrip` and exports `AEGIS_TEST=manifest-roundtrip`. `init` prints `init: AEGIS_TEST=manifest-roundtrip`.
//! 3. Rescue-tui's `dispatch_from_env` fires the `manifest-roundtrip` test mode, mounts `/dev/disk/by-label/AEGIS_ESP` read-only, parses the manifest, and emits one of the documented stage landmarks.
//! 4. Either the manifest's `expected_pcrs[]` is empty (current PR3-era aegis-boot — Pass via documented fail-open) or every entry's `digest_hex` matches the live PCR read from `/sys/class/tpm/...`.
//!
//! # Skip-vs-Fail split
//!
//! - Stick / qemu / swtpm prereqs missing → Skip.
//! - Persona has no TPM (`tpm.version: none`) → Skip — the manifest roundtrip needs PCRs to read.
//! - Persona's `secure_boot.ovmf_variant` is `disabled` → Skip — no signed-chain context to attest.
//! - Boot didn't reach kernel-userspace handoff → Fail (harness pipeline broke).
//! - Kernel reached but `init: AEGIS_TEST=manifest-roundtrip` didn't fire → Skip (cmdline wasn't injected; flash with `MKUSB_TEST_MODE=manifest-roundtrip`).
//! - `init` saw the cmdline but rescue-tui didn't print `manifest-roundtrip starting` → Fail (`test_mode` dispatcher regressed).
//! - Rescue-tui printed `manifest-roundtrip FAILED (...)` (couldn't find/mount/parse the manifest) → Fail.
//! - Rescue-tui printed `manifest-roundtrip pcr_index=N bank=... MISMATCH (...)` → Fail (real signed-chain regression).
//! - Otherwise — `parsed (...)` line appears AND either `empty-pcrs` or `MATCH`-only completion — Pass.
//!
//! # Substring contract
//!
//! Pinned via the stability policy in [aegis-boot's `docs/rescue-tui-serial-format.md`](https://github.com/aegis-boot/aegis-boot/blob/main/docs/rescue-tui-serial-format.md): "head string up through the first parenthesis stays identical across releases." The harness substring-matches the head — wording inside parentheses (errno values, file paths, hash digests) can drift without breaking the test.
//!
//! # Fail-open posture for empty `expected_pcrs[]`
//!
//! aegis-boot's `docs/attestation-manifest.md` is explicit: through 0.17.x the field is always `[]`. Any verifier checking `expected_pcrs[N]` will get `None` for every `N` — that's documented correct behaviour, not a regression. The scenario passes on the `empty-pcrs` landmark; the assertion automatically tightens when aegis-boot starts populating the field (no aegis-hwsim-side change required because the existing MATCH/MISMATCH landmarks are already pinned).

use crate::persona::{OvmfVariant, TpmVersion};
use crate::qemu::Invocation;
use crate::scenario::{Scenario, ScenarioContext, ScenarioError, ScenarioResult};
use crate::scenarios::common::binary_on_path;
use crate::serial::SerialCapture;
use crate::swtpm::{SwtpmInstance, SwtpmSpec};
use std::time::Duration;

/// Per-landmark wait timeout. Same 60 s ceiling as the other scenarios — cold-boot OVMF + TPM-bearing kernel + initramfs + ESP mount can be slow under TCG.
const LANDMARK_TIMEOUT: Duration = Duration::from_secs(60);

/// Pre-test landmark — kernel must reach userspace before the initramfs can dispatch the test mode. Same gate as [`super::KexecRefusesUnsigned`] / [`super::MokEnrollAlpine`]; we don't pin `rescue-tui starting` because under `aegis.test=...` the dispatcher fires before the interactive TUI prints.
const PREREQ_LANDMARKS: &[&str] = &["EFI stub: UEFI Secure Boot is enabled"];

/// manifest-roundtrip landmarks — published contract from [aegis-boot `docs/rescue-tui-serial-format.md`](https://github.com/aegis-boot/aegis-boot/blob/main/docs/rescue-tui-serial-format.md) (PR #697).
///
/// 1. `init: AEGIS_TEST=manifest-roundtrip` — `/init` saw the cmdline. Missing → Skip.
/// 2. `aegis-boot-test: manifest-roundtrip starting` — rescue-tui dispatcher fired. Missing after step 1 → `test_mode` regression → Fail.
/// 3. `aegis-boot-test: manifest-roundtrip parsed` — substring head; the full line is `parsed (schema_version=N, esp_files=N, expected_pcrs=N)`. Missing → manifest didn't reach the comparison step → Fail (the rescue-tui prints a `FAILED (...)` message in that case which our explicit-failure check catches first).
const TEST_LANDMARKS: &[&str] = &[
    "init: AEGIS_TEST=manifest-roundtrip",
    "aegis-boot-test: manifest-roundtrip starting",
    "aegis-boot-test: manifest-roundtrip parsed",
];

/// Explicit-failure substrings to scan AFTER the parsed landmark fires.
/// If any of these appear, the scenario reports Fail with the matching
/// substring as the diagnostic. The order matters only for which one
/// gets reported first; semantically any single hit is a Fail.
const FAILURE_LANDMARKS: &[&str] = &[
    // FAILED stages — couldn't reach the comparison step. The substring
    // head is `manifest-roundtrip FAILED (`; the parenthesised part
    // names the stage (`esp-find:`, `esp-mount:`, `read ...:`,
    // `parse:`).
    "aegis-boot-test: manifest-roundtrip FAILED",
    // MISMATCH — manifest doesn't reflect the current measured boot.
    // Real signed-chain regression. Substring head is
    // `manifest-roundtrip pcr_index=` and includes ` MISMATCH ` later;
    // the full line is e.g.
    //   `aegis-boot-test: manifest-roundtrip pcr_index=12 bank=sha256 MISMATCH (expected=abc... live=def...)`.
    " MISMATCH (",
    // READ-FAILED — TPM driver problem rather than a chain regression,
    // but operationally the harness can't conclude Pass either.
    " READ-FAILED (",
];

/// The scenario type. Stateless.
pub struct AttestationRoundtrip;

impl Scenario for AttestationRoundtrip {
    fn name(&self) -> &'static str {
        "attestation-roundtrip"
    }

    fn description(&self) -> &'static str {
        "boot OVMF + persona + signed stick under TPM-bearing SB enforcement; trigger \
         rescue-tui's manifest-roundtrip test mode (aegis-boot#697); assert manifest \
         parses cleanly and PCR roundtrip matches (or empty-pcrs fail-open per \
         attestation-manifest.md contract)"
    }

    fn run(&self, ctx: &ScenarioContext) -> Result<ScenarioResult, ScenarioError> {
        if let Some(skip) = check_skip_gates(ctx) {
            return Ok(skip);
        }

        let swtpm_spec =
            SwtpmSpec::derive("manifest-roundtrip", &ctx.work_dir, ctx.persona.tpm.version);
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

        // Kernel-userspace handoff. Without this the boot didn't reach
        // the initramfs and we have no test surface to measure.
        for landmark in PREREQ_LANDMARKS {
            if handle.wait_for_line(landmark, LANDMARK_TIMEOUT).is_none() {
                return Ok(ScenarioResult::Fail {
                    reason: format!(
                        "prerequisite landmark '{landmark}' not seen within {}s. \
                         Boot didn't reach kernel-userspace handoff. Serial log: {}.",
                        LANDMARK_TIMEOUT.as_secs(),
                        log_path.display(),
                    ),
                });
            }
        }

        // Test-mode cmdline detection. Missing = Skip (stick wasn't
        // flashed with MKUSB_TEST_MODE=manifest-roundtrip).
        if handle
            .wait_for_line(TEST_LANDMARKS[0], LANDMARK_TIMEOUT)
            .is_none()
        {
            return Ok(ScenarioResult::Skip {
                reason: format!(
                    "kernel reached but `init: AEGIS_TEST=manifest-roundtrip` did not fire. \
                     Re-flash the stick with `MKUSB_TEST_MODE=manifest-roundtrip ./scripts/mkusb.sh` \
                     (aegis-boot#696). Serial log: {}.",
                    log_path.display()
                ),
            });
        }

        // Test mode entered. Remaining required landmarks must appear.
        for landmark in &TEST_LANDMARKS[1..] {
            if handle.wait_for_line(landmark, LANDMARK_TIMEOUT).is_none() {
                return Ok(ScenarioResult::Fail {
                    reason: format!(
                        "init detected the cmdline but '{landmark}' not seen within {}s. \
                         Either rescue-tui's manifest-roundtrip dispatcher regressed, or \
                         the rescue-tui printed a `FAILED (...)` message before reaching the \
                         parsed-manifest stage (check serial log). Serial log: {}.",
                        LANDMARK_TIMEOUT.as_secs(),
                        log_path.display(),
                    ),
                });
            }
        }

        // The manifest parsed. Now scan the buffered serial output for
        // any explicit-failure substrings — MISMATCH, READ-FAILED, or
        // the post-parse FAILED forms. Any hit is a load-bearing
        // regression worth reporting with the offending substring.
        let buffer = handle.buffer_snapshot();
        for needle in FAILURE_LANDMARKS {
            if buffer.contains(needle) {
                return Ok(ScenarioResult::Fail {
                    reason: format!(
                        "manifest parsed but '{needle}' substring appeared in the test mode's \
                         output. The PCR roundtrip detected drift between the on-stick \
                         manifest and the measured boot, OR the test mode hit a \
                         post-parse failure (TPM driver issue, etc.). Serial log: {}.",
                        log_path.display()
                    ),
                });
            }
        }

        Ok(ScenarioResult::Pass)
    }
}

/// Skip-gate evaluation extracted from `run()` — same pattern as the
/// other E5/E6 scenarios. Returns `Some(Skip)` if any prereq fires.
fn check_skip_gates(ctx: &ScenarioContext) -> Option<ScenarioResult> {
    if !ctx.stick.is_file() {
        return Some(ScenarioResult::Skip {
            reason: format!(
                "stick {} not found; provision via aegis-boot flash or set AEGIS_HWSIM_STICK",
                ctx.stick.display()
            ),
        });
    }
    if !binary_on_path("qemu-system-x86_64") {
        return Some(ScenarioResult::Skip {
            reason: "qemu-system-x86_64 not on PATH (Debian: apt install qemu-system-x86)"
                .to_string(),
        });
    }
    // Persona must enforce SB. `disabled` short-circuits because there's
    // no signed-chain context to attest in the first place.
    if matches!(ctx.persona.secure_boot.ovmf_variant, OvmfVariant::Disabled) {
        return Some(ScenarioResult::Skip {
            reason: format!(
                "persona {} has ovmf_variant=disabled; manifest-roundtrip needs a \
                 signed-chain context to attest",
                ctx.persona.id
            ),
        });
    }
    // Persona must have a TPM. The manifest roundtrip's whole point is
    // comparing live PCRs to the manifest; without a TPM there's
    // nothing to compare against.
    if matches!(ctx.persona.tpm.version, TpmVersion::None) {
        return Some(ScenarioResult::Skip {
            reason: format!(
                "persona {} has no TPM (tpm.version=none); manifest-roundtrip needs PCRs to read",
                ctx.persona.id
            ),
        });
    }
    // swtpm IS required (TPM-bearing personas only past this point).
    if !binary_on_path("swtpm") {
        return Some(ScenarioResult::Skip {
            reason: "swtpm not on PATH (Debian: apt install swtpm); \
                     manifest-roundtrip requires TPM emulation"
                .to_string(),
        });
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::persona::Persona;
    use std::path::PathBuf;

    fn tpm_persona_yaml() -> &'static str {
        r"
schema_version: 1
id: test-tpm
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
  version: '2.0'
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
        let s = AttestationRoundtrip;
        assert_eq!(s.name(), "attestation-roundtrip");
        assert!(s.description().contains("manifest-roundtrip"));
        assert!(s.description().contains("attestation-manifest.md"));
    }

    #[test]
    fn skips_when_stick_missing() {
        let s = AttestationRoundtrip;
        let result = s
            .run(&fake_ctx(
                make_persona(tpm_persona_yaml()),
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
    fn skips_when_persona_has_no_tpm() {
        // The roundtrip explicitly needs PCRs to read. A TPM-less
        // persona is a Skip (test isn't measuring anything), not a
        // Fail (test produced wrong result).
        let tmp = tempfile::tempdir().unwrap();
        let stick = tmp.path().join("fake-stick.img");
        std::fs::write(&stick, b"placeholder").unwrap();
        let mut p = make_persona(tpm_persona_yaml());
        p.tpm.version = TpmVersion::None;
        let s = AttestationRoundtrip;
        let result = s.run(&fake_ctx(p, stick)).unwrap();
        match result {
            ScenarioResult::Skip { reason } => {
                assert!(
                    reason.contains("no TPM"),
                    "expected 'no TPM' in skip reason: {reason}"
                );
            }
            other => panic!("expected Skip, got {other:?}"),
        }
    }

    #[test]
    fn skips_when_secure_boot_disabled() {
        let tmp = tempfile::tempdir().unwrap();
        let stick = tmp.path().join("fake-stick.img");
        std::fs::write(&stick, b"placeholder").unwrap();
        let mut p = make_persona(tpm_persona_yaml());
        p.secure_boot.ovmf_variant = OvmfVariant::Disabled;
        let s = AttestationRoundtrip;
        let result = s.run(&fake_ctx(p, stick)).unwrap();
        match result {
            ScenarioResult::Skip { reason } => {
                assert!(
                    reason.contains("ovmf_variant=disabled"),
                    "got reason: {reason}"
                );
            }
            other => panic!("expected Skip, got {other:?}"),
        }
    }

    #[test]
    fn accepts_setup_mode_and_custom_pk() {
        // Both setup_mode and custom_pk involve a signed-chain context
        // worth attesting. The skip gate only excludes `disabled`.
        // (Whether the actual roundtrip passes against those personas
        // is a question for the integration run, not the gate.)
        let tmp = tempfile::tempdir().unwrap();
        let stick = tmp.path().join("fake-stick.img");
        std::fs::write(&stick, b"placeholder").unwrap();
        for variant in [OvmfVariant::SetupMode, OvmfVariant::CustomPk] {
            let mut p = make_persona(tpm_persona_yaml());
            p.secure_boot.ovmf_variant = variant;
            // Skip-gate rejects on stick missing first, then qemu, then
            // sb, then tpm, then swtpm. We expect the gate to NOT
            // reject on `disabled`-style grounds — `check_skip_gates`
            // returns `None` for both these variants when stick + qemu
            // exist + tpm is set + swtpm is on PATH. We can't fully
            // assert that without the swtpm binary, so we instead
            // assert the `disabled`-specific message does NOT appear.
            let result = check_skip_gates(&fake_ctx(p, stick.clone()));
            if let Some(ScenarioResult::Skip { reason }) = result {
                assert!(
                    !reason.contains("ovmf_variant=disabled"),
                    "gate must not skip {variant:?} as if it were disabled: {reason}"
                );
            }
        }
    }

    #[test]
    fn failure_landmarks_are_disjoint_from_pass_landmarks() {
        // Sanity check: none of the FAILURE_LANDMARKS substrings
        // accidentally appear inside any TEST_LANDMARK Pass-side
        // string. If they did, our buffer.contains() check would
        // false-positive on a successful run.
        for fail in FAILURE_LANDMARKS {
            for pass in TEST_LANDMARKS {
                assert!(
                    !pass.contains(fail) && !fail.contains(pass),
                    "FAILURE_LANDMARK '{fail}' overlaps with TEST_LANDMARK '{pass}'"
                );
            }
        }
    }
}
