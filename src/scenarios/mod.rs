//! Concrete scenarios. Each module here implements
//! [`crate::scenario::Scenario`] for one well-defined boot-flow assertion.

pub mod common;
pub mod qemu_boots_ovmf;
pub mod signed_boot_ubuntu;

pub use qemu_boots_ovmf::QemuBootsOvmf;
pub use signed_boot_ubuntu::SignedBootUbuntu;
