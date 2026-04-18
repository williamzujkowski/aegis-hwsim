//! End-to-end smoke: spawn QEMU+OVMF with the qemu-smoke-no-tpm
//! persona and assert the `BdsDxe` boot-selector reaches serial. No
//! signed `aegis-boot` stick required.
//!
//! On a runner without qemu-system-x86_64 or OVMF installed, the
//! scenario itself returns Skip; this test records that as success
//! (the harness is correctly identifying missing prerequisites).
//!
//! On a runner with both installed (CI installs them via apt; the
//! aegis-hwsim CI workflow handles this), the scenario should Pass.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use aegis_hwsim::loader::{load_all, LoadOptions};
use aegis_hwsim::scenario::{Registry, ScenarioContext, ScenarioResult};
use std::path::PathBuf;

#[test]
fn qemu_boots_ovmf_smoke_against_qemu_smoke_persona() {
    let repo_root: PathBuf = env!("CARGO_MANIFEST_DIR").into();
    let opts = LoadOptions::default_at(&repo_root);
    let personas = load_all(&opts).unwrap_or_else(|e| panic!("load_all failed: {e}"));

    let persona = personas
        .into_iter()
        .find(|p| p.id == "qemu-smoke-no-tpm")
        .expect("qemu-smoke-no-tpm persona must be present");

    let registry = Registry::default_set();
    let scenario = registry
        .find("qemu-boots-ovmf")
        .expect("qemu-boots-ovmf scenario must be registered");

    let work_dir = tempfile::tempdir().expect("tempdir");
    let firmware_root = std::env::var("AEGIS_HWSIM_FIRMWARE_ROOT")
        .map_or_else(|_| PathBuf::from("/usr/share/OVMF"), PathBuf::from);

    let ctx = ScenarioContext {
        persona,
        // The smoke scenario provisions its own empty stick under
        // work_dir; this PathBuf goes unused but keeps the type happy.
        stick: PathBuf::from("/unused-by-smoke"),
        work_dir: work_dir.path().to_path_buf(),
        firmware_root,
    };

    let result = scenario
        .run(&ctx)
        .unwrap_or_else(|e| panic!("scenario runner error: {e}"));

    match result {
        ScenarioResult::Pass => {
            // Harness pipeline confirmed end-to-end. The full QEMU →
            // OVMF → serial → wait_for_line chain is wired correctly.
        }
        ScenarioResult::Skip { reason } => {
            // Acceptable: runner is missing qemu/ovmf. Print the
            // reason so a human inspecting CI sees what was missing.
            eprintln!("smoke skipped: {reason}");
        }
        ScenarioResult::Fail { reason } => {
            panic!("smoke should not Fail on a properly-configured runner: {reason}");
        }
    }
}
