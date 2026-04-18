# Changelog

All notable changes to aegis-hwsim. Mirrors the [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) convention; the project follows [aegis-boot](https://github.com/williamzujkowski/aegis-boot)'s release cadence.

## [Unreleased]

### Added

- Phase 1 + Phase 2 in one cohesive push:
  - **Persona library** (E1): YAML schema with `serde` derives, `load_all()` with 5 guards (placeholder rejection, id/filename drift, quirk-tag regex, custom-keyring path-boundary, parse). 7 personas shipped — qemu-generic-minimal, lenovo-thinkpad-x1-carbon-gen11, framework-laptop-12gen, dell-xps-13-9320, hp-elitebook-845-g10, asus-zenbook-14-oled, qemu-smoke-no-tpm.
  - **JSONSchema export** (E1.5): `aegis-hwsim gen-schema [--check PATH]` emits `schemas/persona.schema.json`. CI drift gate prevents source/schema skew.
  - **QEMU synthesis layer** (E2, all 7 children): smbios::smbios_argv for `-smbios type=0/1/2/3` argv with QEMU comma-escape + NUL rejection; ovmf::resolve for OVMF_CODE/VARS firmware paths (Debian + Fedora layouts, custom_keyring path-boundary); swtpm::SwtpmInstance with per-run socket + drop-guard cleanup; qemu::Invocation builder composing everything into a `Command`; serial::SerialCapture with `wait_for_line` + bounded-buffer overflow handling; subprocess-safety fuzz (60k random inputs / commit covering shell metacharacters + UTF-8 RTL + NUL); per-run OVMF_VARS path-boundary defense.
  - **Scenario runner** (E3.1-E3.3): `Scenario` trait + `ScenarioResult` (Pass/Fail/Skip) + `Registry`; `signed-boot-ubuntu` scenario walking shim → grub → kernel → kexec landmarks; `aegis-hwsim run <persona> <scenario> <stick.img>` CLI subcommand + `aegis-hwsim list-scenarios`.
  - **`qemu-boots-ovmf` smoke scenario**: boots OVMF over an empty 1 MB stick, asserts BdsDxe boot-selector reaches serial. Runs end-to-end on CI without a signed stick artifact (1.69s local) — proves the harness pipeline every PR.
  - **Coverage-grid emitter** (E4.1): `aegis-hwsim coverage-grid [--format json|markdown] [--dry-run]` iterates personas × scenarios. CI publishes the result as a build artifact every PR with 30-day retention.
  - **`aegis-hwsim doctor`**: host-environment check mirroring aegis-boot doctor — reports per-check verdicts (PASS/WARN/FAIL) for qemu-system-x86_64, swtpm, OVMF firmware files, persona library presence. Surfaces all missing prereqs in one pass.
  - **Contributor docs**: CONTRIBUTING.md, docs/persona-authoring.md, docs/scenario-authoring.md.

### Security

- `unsafe_code = "forbid"` workspace-wide.
- `unwrap_used = "deny"` and `expect_used = "deny"` in production code; tests opt back out at the `#[cfg(test)] mod tests` boundary.
- All CLI subcommands shell out via `Command::args()` (no `sh -c`); persona DMI strings pass through as literal argv.
- NUL-byte rejection at every subprocess boundary (smbios, qemu::Invocation).
- Path-boundary defense: `custom_keyring` (`ovmf::resolve`) and per-run OVMF_VARS copy (`qemu::Invocation`) both canonicalized + verified `starts_with(root)` after the operation, defending against symlink swap-in attacks.
- HTTPS-only enforcement on any URL inputs (none in aegis-hwsim today, but contract noted for future scenarios).

### CI

- Lint + test on every PR under `-D warnings`.
- JSONSchema drift gate.
- `qemu-boots-ovmf` smoke runs against real QEMU+OVMF on Ubuntu runner.
- `coverage-grid` artifact (markdown + JSON) uploaded per PR.

### Deferred to future releases

- `mok-enroll-alpine` scenario — requires real-hardware MOK Manager UI flow.
- `attestation-roundtrip` scenario — blocked on aegis-boot manifest format pin.
- End-to-end `signed-boot-ubuntu` against a real signed aegis-boot stick — the scenario code is shipped; needs a stick artifact in CI.
- Phase 3 v1.0.0-rc1 release gate.
