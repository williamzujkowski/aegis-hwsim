//! Integration test: confirms `load_all()` accepts the 3 personas
//! shipped in `personas/` at the repo root. If one of them grows a
//! placeholder token, a quirk-tag syntax violation, or drifts between
//! filename and `id`, this test fails before CI does.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use aegis_hwsim::loader::{load_all, LoadOptions};
use std::path::PathBuf;

#[test]
fn shipped_personas_load_without_error() {
    let repo_root: PathBuf = env!("CARGO_MANIFEST_DIR").into();
    let opts = LoadOptions::default_at(&repo_root);
    let personas = load_all(&opts).unwrap_or_else(|e| panic!("load_all failed: {e}"));
    assert!(
        personas.len() >= 10,
        "expected ≥10 personas (Phase 2 + smoke + TPM 1.2 + disabled-SB + setup-mode), got {}",
        personas.len()
    );
    let ids: std::collections::HashSet<_> = personas.iter().map(|p| p.id.as_str()).collect();
    // Phase 1 personas (#1, E1).
    assert!(ids.contains("qemu-generic-minimal"));
    assert!(ids.contains("lenovo-thinkpad-x1-carbon-gen11"));
    assert!(ids.contains("framework-laptop-12gen"));
    // Phase 2 personas (#35).
    assert!(ids.contains("dell-xps-13-9320"));
    assert!(ids.contains("hp-elitebook-845-g10"));
    assert!(ids.contains("asus-zenbook-14-oled"));
    // Harness self-test (no TPM).
    assert!(ids.contains("qemu-smoke-no-tpm"));
    // TPM 1.2 coverage — exercises the qemu::Invocation tpm-tis path.
    assert!(ids.contains("lenovo-thinkpad-t440p-tpm12"));
    // Disabled-SB diagnostic — exercises the Disabled OvmfVariant
    // branch (non-secboot CODE).
    assert!(ids.contains("qemu-disabled-sb"));
    // Setup-mode diagnostic — exercises the SetupMode branch
    // (secboot CODE + blank VARS, no PK enrolled). Together with
    // qemu-disabled-sb + the 8 ms_enrolled personas, the matrix now
    // hits 3/4 OvmfVariants. Custom-PK still requires a test keyring.
    assert!(ids.contains("qemu-setup-mode-sb"));
}
