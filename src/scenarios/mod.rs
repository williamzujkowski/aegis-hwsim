//! Concrete scenarios. Each module here implements
//! [`crate::scenario::Scenario`] for one well-defined boot-flow assertion.

pub mod signed_boot_ubuntu;

pub use signed_boot_ubuntu::SignedBootUbuntu;
