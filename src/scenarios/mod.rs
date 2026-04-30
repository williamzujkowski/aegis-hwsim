//! Concrete scenarios. Each module here implements
//! [`crate::scenario::Scenario`] for one well-defined boot-flow assertion.

pub mod attestation_roundtrip;
pub mod common;
pub mod kexec_refuses_unsigned;
pub mod mok_enroll_alpine;
pub mod qemu_boots_ovmf;
pub mod signed_boot_ubuntu;

pub use attestation_roundtrip::AttestationRoundtrip;
pub use kexec_refuses_unsigned::KexecRefusesUnsigned;
pub use mok_enroll_alpine::MokEnrollAlpine;
pub use qemu_boots_ovmf::QemuBootsOvmf;
pub use signed_boot_ubuntu::SignedBootUbuntu;
