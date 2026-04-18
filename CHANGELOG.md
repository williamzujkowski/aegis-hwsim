# Changelog

All notable changes to aegis-hwsim. Mirrors the [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) convention; the project follows [aegis-boot](https://github.com/williamzujkowski/aegis-boot)'s release cadence.

## [Unreleased]

### CI

- **Bump Node-20-based GitHub Actions to Node-24-compatible v5** (closes [#59](https://github.com/williamzujkowski/aegis-hwsim/issues/59)) — `actions/checkout@v4 → @v5` and `actions/upload-artifact@v4 → @v5` in `.github/workflows/ci.yml`. Closes the deprecation banner runners surface ("Node.js 20 actions are deprecated… Node.js 20 will be removed from the runner on September 16th, 2026"). Single-line changes; v5 is backward-compatible with the explicit `retention-days: 30` and `if-no-files-found: error` settings we use.

### Documentation

- **Research index gains a structured registry layer** — new `docs/research/INDEX.md` (frontmatter-bearing canonical entry point) plus `docs/research/registry/{sources,papers,projects}.yaml` for machine-readable enumeration of adjacent tools (14), academic papers (5), and 2025/2026 delta-scan projects (5). New `docs/research/registry/SCHEMA.json` (JSON Schema 2020-12) defines the contract — three `oneOf` variants for the three YAML types, with required `tie_in` (papers) and `notes` (sources, projects) so every entry justifies its inclusion. CI gains a `check-jsonschema`-based validation step. Mirrors the [nexus-agents](https://github.com/williamzujkowski/nexus-agents) pattern: human-readable narrative in `*.md`, machine-readable registry in `*.yaml`. The legacy `README.md` is preserved for back-compat with existing inbound links and now redirects to `INDEX.md` as the canonical entry.

## [0.0.2] — 2026-04-18

First post-scaffolding marker. Phase 1 + Phase 2 functionally complete: 11 personas covering all 4 OVMF variants and all 3 TPM versions, 2 scenarios (one of which runs end-to-end on every CI PR against real QEMU+OVMF), coverage-grid artifact published per PR, doctor + contributor docs + architecture overview shipped, family-convention `--json` sweep complete on every read-mostly subcommand. 113 tests including 60k random-input fuzz inputs per CI run.

### Added

- **Family-convention `--json` sweep** ([#52](https://github.com/williamzujkowski/aegis-hwsim/pull/52)) — `aegis-hwsim --version --json`, `doctor --json`, `list-scenarios --json` all emit `schema_version=1` envelopes. Matches [aegis-boot PR #191](https://github.com/williamzujkowski/aegis-boot/pull/191) + [#205](https://github.com/williamzujkowski/aegis-boot/pull/205) so scripted consumers parse uniformly across the family. `list-personas --json` already shipped (PR #14); `coverage-grid --format json` already shipped (PR #40); this finishes the sweep.
- **`docs/architecture.md`** ([#53](https://github.com/williamzujkowski/aegis-hwsim/pull/53)) — module dependency graph, pure-then-impure layering pattern table, why Skip is first-class, trust-boundary diagram with 4 enforcement rules, 9-step Invocation lifecycle, three constraints that drove the design. CONTRIBUTING.md links it.
- **Research index refresh** ([#49](https://github.com/williamzujkowski/aegis-hwsim/pull/49)) — new `docs/research/arxiv-papers.md` (5 verified arXiv/DOI entries: UEFI SoK 2311.03809, ARES 2024 boot integrity 10.1145/3664476.3670910, SEV-SNP e-vTPM 2303.16463, UEFI memory forensics 2501.16962, FUZZUER NDSS 2025); new `docs/research/recent-projects.md` (2025/2026 delta-scan: anpep/qemu-tpm-measurement, intel/tsffs, fwupd SBAT plugin, systemd-ukify ecosystem). Roadmap-implications note surfaces two future scenarios tracked as [#50](https://github.com/williamzujkowski/aegis-hwsim/issues/50) + [#51](https://github.com/williamzujkowski/aegis-hwsim/issues/51).

### Changed

- **`scenarios::common::binary_on_path`** ([#49](https://github.com/williamzujkowski/aegis-hwsim/pull/49)) — DRY extraction; both scenarios now import the shared helper.

### Initial Phase 1 + Phase 2 push
  - **Persona library** (E1): YAML schema with `serde` derives, `load_all()` with 5 guards (placeholder rejection, id/filename drift, quirk-tag regex, custom-keyring path-boundary, parse). 11 personas shipped — qemu-generic-minimal, qemu-smoke-no-tpm (harness self-test), qemu-disabled-sb (covers OvmfVariant::Disabled), qemu-setup-mode-sb (covers SetupMode), qemu-custom-pk-sb (covers CustomPk), lenovo-thinkpad-x1-carbon-gen11, lenovo-thinkpad-t440p-tpm12 (covers tpm-tis device path), framework-laptop-12gen, dell-xps-13-9320, hp-elitebook-845-g10, asus-zenbook-14-oled. **Full OVMF variant matrix coverage** (4/4) + both TPM versions + None.
  - **Relative `custom_keyring` resolution**: loader + `ovmf::resolve` resolve relative keyring paths against `firmware_root` before canonicalizing. Absolute paths stay as-is (preserves the existing /etc/passwd-traversal negative test). Documented in `firmware/test-keyring/README.md` + `docs/persona-authoring.md`.
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
