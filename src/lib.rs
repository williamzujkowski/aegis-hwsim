//! `aegis-hwsim` — QEMU+OVMF+swtpm hardware-persona matrix harness.
//!
//! Scaffolding phase. Real logic lands in Phase 1 per
//! [aegis-boot#226](https://github.com/williamzujkowski/aegis-boot/issues/226).
//! This crate currently exposes only the persona schema types so PR reviewers
//! can sanity-check the data model before the orchestrator lands.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod coverage_grid;
pub mod doctor;
pub mod loader;
pub mod ovmf;
pub mod persona;
pub mod qemu;
pub mod scenario;
pub mod scenarios;
pub mod serial;
pub mod smbios;
pub mod swtpm;
