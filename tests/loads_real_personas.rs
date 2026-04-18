//! Integration test: confirms `load_all()` accepts the 3 personas
//! shipped in `personas/` at the repo root. If one of them grows a
//! placeholder token, a quirk-tag syntax violation, or drifts between
//! filename and `id`, this test fails before CI does.

use aegis_hwsim::loader::{load_all, LoadOptions};
use std::path::PathBuf;

#[test]
fn shipped_personas_load_without_error() {
    let repo_root: PathBuf = env!("CARGO_MANIFEST_DIR").into();
    let opts = LoadOptions::default_at(&repo_root);
    let personas = load_all(&opts).unwrap_or_else(|e| panic!("load_all failed: {e}"));
    assert!(
        personas.len() >= 3,
        "expected ≥3 personas, got {}",
        personas.len()
    );
    // Sorted by id — qemu-generic-minimal is last alphabetically among
    // the shipped set (lenovo- < framework- < qemu-) — wait, framework
    // < lenovo alphabetically. Just check the id set as a whole.
    let ids: std::collections::HashSet<_> = personas.iter().map(|p| p.id.as_str()).collect();
    assert!(ids.contains("qemu-generic-minimal"));
    assert!(ids.contains("lenovo-thinkpad-x1-carbon-gen11"));
    assert!(ids.contains("framework-laptop-12gen"));
}
