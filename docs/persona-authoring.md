# Authoring a new persona

A **persona** is a YAML fixture that captures the DMI fields, Secure Boot posture, TPM configuration, and vendor-specific quirks of one shipping hardware configuration. Adding one expands the harness coverage matrix without requiring physical hardware in CI.

## Where it lives

`personas/<id>.yaml`. The filename stem MUST equal the YAML's `id` field — the loader rejects drift.

## Schema reference

Authoritative schema: `schemas/persona.schema.json` (auto-generated from `src/persona.rs`). IDE YAML-LS plugins can pull this for autocomplete:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/williamzujkowski/aegis-hwsim/main/schemas/persona.schema.json
schema_version: 1
id: my-vendor-my-model
# ...
```

Drift between the source schema and the committed JSON is gated by CI; if you change `src/persona.rs`, regenerate via:

```bash
cargo run --bin aegis-hwsim -- gen-schema > schemas/persona.schema.json
```

## Required fields

```yaml
schema_version: 1
id: kebab-case-id-matching-filename
vendor: "Vendor Name (preserve as shipped)"
display_name: "Human-readable model name"
source:
  kind: vendor_docs   # or community_report, lvfs_catalog
  ref_: "URL or spec-sheet title — must be verifiable"
dmi:
  sys_vendor: ...
  product_name: ...
  bios_vendor: ...
  bios_version: ...
  bios_date: MM/DD/YYYY
secure_boot:
  ovmf_variant: ms_enrolled  # or custom_pk, setup_mode, disabled
tpm:
  version: "2.0"  # or "1.2", "none"
```

Optional fields: `year`, `dmi.product_version`, `dmi.board_name`, `dmi.chassis_type`, `tpm.manufacturer`, `tpm.firmware_version`, `kernel.lockdown`, `quirks[]`, `scenarios{}`.

## Source-citation policy (strict)

The `source` block decides whether a persona ships:

| `kind` | When to use | Required `ref_` content |
|---|---|---|
| `community_report` | A real operator ran the full flash → boot → kexec chain on physical hardware AND filed a hardware-report on aegis-boot. | URL of the closed hardware-report issue. |
| `lvfs_catalog` | DMI values verified against fwupd / LVFS firmware archive metadata. | Direct LVFS catalog URL. |
| `vendor_docs` | Vendor PSREF / spec sheet. **Lowest confidence; flag as PLACEHOLDER.** | Spec-sheet title + a comment in the YAML stating this needs replacement. |

A `vendor_docs` persona MUST include a comment block above `source:` like:

```yaml
source:
  # Placeholder citation. Do NOT ship to main until a real operator
  # files a hardware-report on aegis-boot covering the full flash → boot
  # → kexec chain on physical hardware. See aegis-boot CLAUDE.md and
  # HARDWARE_COMPAT.md "verified outcomes only" policy.
  kind: vendor_docs
  ref_: "Vendor spec sheet URL or title (placeholder)"
```

This matches the [aegis-boot compat DB](https://github.com/williamzujkowski/aegis-boot/blob/main/docs/HARDWARE_COMPAT.md) policy and prevents accidentally claiming verified coverage we don't have.

## DMI fields — capture-as-shipped

Preserve vendor strings **verbatim**, including trailing periods, capitalization, and whitespace:

| Vendor | sys_vendor (literal) | product_name convention |
|---|---|---|
| Lenovo | `LENOVO` | SKU code (`21HMCTO1WW`); friendly name in `product_version` (`ThinkPad X1 Carbon Gen 11`) |
| Dell | `Dell Inc.` (trailing period) | Friendly name (`XPS 13 9320`) |
| HP | `HP` | Full friendly name including `Notebook PC` suffix |
| ASUS | `ASUSTeK COMPUTER INC.` (trailing period) | Internal SKU (`ZenBook UX3405MA_UX3405MA`) |
| Framework | `Framework` | `Laptop` + chassis revision |
| QEMU | `QEMU` | `Standard PC (Q35 + ICH9, 2009)` etc. |

Capture these from `sudo dmidecode -t system -t bios -t baseboard -t chassis` on a real unit, not from marketing material.

## Quirk tags

Add a `quirks[]` entry for any vendor-specific behavior the harness can't simulate. Tags must match `^[a-z0-9][a-z0-9-]*[a-z0-9]$` (loader-enforced):

```yaml
quirks:
  - tag: boot-key-f12
    description: "Firmware boot-menu key is F12. rescue-tui's MOK walkthrough STEP 3/3 covers this."
  - tag: amd-ftpm-stuttering-pre-2024
    description: "Pre-2024 AMD fTPM firmware had PCR-extend stuttering on rapid boots."
```

Quirk tags live in the persona's `quirks[]` so future scenarios can opt out of a persona by tag (e.g., a TPM-stress test could skip personas tagged `amd-ftpm-stuttering-pre-2024`).

## Secure-Boot posture

| `ovmf_variant` | Meaning | When to use |
|---|---|---|
| `ms_enrolled` | OVMF VARS pre-loaded with the Microsoft UEFI CA + KEKs | Default. Most shipping laptops boot under this. |
| `custom_pk` | Persona ships a custom PK + KEK + db keyring | Tests the custom-CA enrollment path. Requires `secure_boot.custom_keyring` set to a path under `firmware/`. |
| `setup_mode` | OVMF in setup mode — no PK enrolled | Tests the operator-MOK-enrollment flow. |
| `disabled` | Secure Boot off | Tests the diagnostic path where aegis-boot refuses to flash. |

The `custom_pk` keyring path is canonicalized + verified against the firmware-root sandbox at both load time AND at QEMU-invocation time (defense in depth) — see `src/loader.rs` and `src/qemu.rs`.

## Test before shipping

```bash
# 1. Validate the YAML against the schema:
cargo run --bin aegis-hwsim -- validate

# 2. Confirm the loader accepts it:
cargo test --locked --test loads_real_personas

# 3. Confirm coverage-grid sees it:
cargo run --bin aegis-hwsim -- coverage-grid --dry-run | grep <your-persona-id>
```

Then update `tests/loads_real_personas.rs` to assert the new id is in the loaded set.

## PR checklist for a new persona

- [ ] `personas/<id>.yaml` matches its filename stem
- [ ] `source.kind` is the highest applicable confidence tier
- [ ] If `kind: vendor_docs`, the YAML carries a PLACEHOLDER comment block
- [ ] DMI fields are captured-as-shipped (no marketing-material guesses)
- [ ] Quirks have grep-able tags + operator-actionable descriptions
- [ ] `tests/loads_real_personas.rs` updated to assert the new id
- [ ] `cargo test --locked` passes
- [ ] CI green
