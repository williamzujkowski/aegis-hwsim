//! Persona schema types. Mirrors `docs/persona-schema.md` 1:1 — if one
//! changes, the other must too.
//!
//! No runtime logic in this module beyond `serde` derivations — the
//! schema is the contract, nothing more.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Top-level persona YAML. One persona = one shipping hardware configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Persona {
    /// Pins the parser to an exact schema version. Mismatched parsers refuse
    /// to load the file. Bumped on breaking changes; additive fields don't
    /// bump it.
    pub schema_version: u32,

    /// Stable kebab-case identifier. Must match the YAML filename (without
    /// the `.yaml` extension).
    pub id: String,

    /// SMBIOS `sys_vendor` value verbatim as the vendor ships it. Preserve
    /// case (e.g. "LENOVO", "Dell Inc.", "Framework").
    pub vendor: String,

    /// Human-readable name shown in the coverage-grid output.
    pub display_name: String,

    /// Year the SKU first shipped. Optional but recommended — helps
    /// contributors understand firmware-era context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub year: Option<u16>,

    /// Provenance record. Every persona must cite where its DMI + firmware
    /// values came from. See `Source` docs for accepted kinds.
    pub source: Source,

    /// DMI fields mapped 1:1 to `/sys/class/dmi/id/<field>` — QEMU's
    /// `-smbios` flags inject these at boot time.
    pub dmi: Dmi,

    /// Secure Boot posture to synthesize.
    pub secure_boot: SecureBoot,

    /// TPM version to emulate via swtpm (or skip entirely).
    pub tpm: Tpm,

    /// Kernel lockdown mode for the booted kernel.
    #[serde(default)]
    pub kernel: Kernel,

    /// Advisory list of vendor-specific quirks the harness can't simulate.
    /// Surfaced to the scenario runner so test reports can annotate
    /// "this would work here but not on real hardware because X".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub quirks: Vec<Quirk>,

    /// Per-scenario run/skip overrides. Opt-out is rare — prefer fixing the
    /// scenario over skipping it per-persona.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub scenarios: std::collections::BTreeMap<String, ScenarioDecision>,
}

/// Provenance citation for a persona. Every persona must cite its origin so
/// reviewers can trace fields back to a primary source. Matches the
/// `aegis-boot compat` DB's "verified outcomes only" stance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Source {
    /// Kind of citation. See `SourceKind`.
    pub kind: SourceKind,
    /// Free-form reference. URL, issue number, spec-sheet title — whatever
    /// a reviewer can use to verify the persona's claims.
    pub ref_: String,
    /// ISO-8601 date the persona's fields were captured/verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub captured_at: Option<String>,
}

/// Kind of provenance citation. Ordered from highest to lowest confidence.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    /// Closed `hardware-report` GitHub issue from a real operator who ran
    /// the full flash → boot → kexec chain. Highest confidence.
    CommunityReport,
    /// fwupd / LVFS firmware archive URL. Verified against vendor metadata.
    LvfsCatalog,
    /// Vendor-published spec sheet (Lenovo PSREF, Dell Product Support,
    /// Framework Marketplace). Lowest-confidence; use only for fields the
    /// other two don't cover.
    VendorDocs,
}

/// DMI fields mapped to `/sys/class/dmi/id/<field>`. Everything QEMU's
/// `-smbios type=0/1/2/3/...` injectors can populate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Dmi {
    /// Mapped to `/sys/class/dmi/id/sys_vendor`.
    pub sys_vendor: String,
    /// Mapped to `/sys/class/dmi/id/product_name`. SKU code or friendly name
    /// per vendor convention (Lenovo puts the friendly name in
    /// `product_version`; Dell/HP put it here).
    pub product_name: String,
    /// Mapped to `/sys/class/dmi/id/product_version`. Lenovo convention.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product_version: Option<String>,
    /// Mapped to `/sys/class/dmi/id/bios_vendor`.
    pub bios_vendor: String,
    /// Mapped to `/sys/class/dmi/id/bios_version`.
    pub bios_version: String,
    /// Mapped to `/sys/class/dmi/id/bios_date` (MM/DD/YYYY).
    pub bios_date: String,
    /// Mapped to `/sys/class/dmi/id/board_name`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub board_name: Option<String>,
    /// SMBIOS chassis type code (10 = notebook, 3 = desktop, 17 = main
    /// server chassis, etc.). See SMBIOS spec §7.4.1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chassis_type: Option<u8>,
}

/// Secure Boot posture the persona boots under.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecureBoot {
    /// Which OVMF variant to boot under.
    pub ovmf_variant: OvmfVariant,
    /// When `ovmf_variant == CustomPk`, path to the hwsim-generated test
    /// keyring. Must be under `$AEGIS_HWSIM_ROOT/firmware/` — validated at
    /// load time per aegis-boot#226 security-engineer constraint #2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_keyring: Option<PathBuf>,
}

/// OVMF firmware variant.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OvmfVariant {
    /// MS-enrolled VARs — the most common distro-shipped state.
    MsEnrolled,
    /// Custom PK/KEK/db from hwsim's test keyring. Tests the custom-CA
    /// enrollment path. Keys MUST carry `TEST_ONLY_NOT_FOR_PRODUCTION` in
    /// the CN per aegis-boot#226 security constraint #4.
    CustomPk,
    /// Setup mode — no PK enrolled. Operator MOK enrollment flow.
    SetupMode,
    /// SB off. Tests the "aegis-boot refuses to flash" diagnostic path.
    Disabled,
}

/// TPM emulation config. `None` variant means no TPM at all.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Tpm {
    /// TPM version, or `"none"` for no TPM. swtpm emulates 1.2 and 2.0.
    pub version: TpmVersion,
    /// TPM2 manufacturer code (IFX, NTC, AMD, STM, INTC, ...). Optional;
    /// most tests don't care. Set when validating TPM2-FW-bug-specific paths.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manufacturer: Option<String>,
    /// TPM2 firmware version string. Optional. Use when testing
    /// firmware-version-gated behavior.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firmware_version: Option<String>,
}

/// TPM version to emulate.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TpmVersion {
    /// No TPM present.
    None,
    /// TPM 1.2 (TIS interface).
    #[serde(rename = "1.2")]
    Tpm12,
    /// TPM 2.0 (TIS interface).
    #[serde(rename = "2.0")]
    Tpm20,
}

/// Kernel config for the booted kernel. `Default` leaves the initramfs
/// kernel's lockdown mode unchanged.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Kernel {
    /// Kernel lockdown mode. `Inherit` uses the initramfs kernel's default.
    #[serde(default)]
    pub lockdown: LockdownMode,
}

/// Kernel lockdown mode (see `Documentation/admin-guide/LSM/LoadPin.rst`
/// and the `lockdown` LSM).
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LockdownMode {
    /// Use the initramfs kernel's built-in default.
    #[default]
    Inherit,
    /// Lockdown disabled.
    None,
    /// Integrity mode — blocks kernel-integrity-breaking operations.
    Integrity,
    /// Confidentiality mode — integrity + blocks kernel-memory reads.
    Confidentiality,
}

/// A real-world quirk the harness can't simulate. Informational — exposed
/// to scenarios so coverage reports can annotate "this would work here
/// but not on real hardware because X".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Quirk {
    /// Short grep-able tag. Must match `^[a-z0-9][a-z0-9-]*[a-z0-9]$`.
    pub tag: String,
    /// Long-form description of the quirk and its operator impact.
    pub description: String,
}

/// Per-scenario run/skip decision.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioDecision {
    /// Scenario runs against this persona.
    Run,
    /// Scenario skipped for this persona. Should be rare — prefer fixing
    /// the scenario over blanket-skipping it.
    Skip,
}

/// Serde name-clash workaround: `ref` is a Rust keyword.
///
/// YAML uses `ref` as the field name per docs/persona-schema.md; Rust
/// forces `ref_` on the struct. The serde `rename = "ref"` attribute on the
/// field makes the YAML-side spelling authoritative.
impl Source {}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Smoke test: a minimal valid YAML round-trips through the type.
    #[test]
    fn minimal_persona_roundtrips() {
        let yaml = r#"
schema_version: 1
id: qemu-generic-minimal
vendor: QEMU
display_name: "QEMU generic (OVMF + swtpm reference)"
source:
  kind: vendor_docs
  ref_: "QEMU -smbios documentation"
dmi:
  sys_vendor: QEMU
  product_name: "Standard PC (Q35 + ICH9, 2009)"
  bios_vendor: EDK II
  bios_version: "edk2-stable202402"
  bios_date: 02/29/2024
secure_boot:
  ovmf_variant: ms_enrolled
tpm:
  version: "2.0"
"#;
        let p: Persona = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(p.id, "qemu-generic-minimal");
        assert_eq!(p.dmi.sys_vendor, "QEMU");
        assert!(matches!(
            p.secure_boot.ovmf_variant,
            OvmfVariant::MsEnrolled
        ));
        assert!(matches!(p.tpm.version, TpmVersion::Tpm20));
    }
}
