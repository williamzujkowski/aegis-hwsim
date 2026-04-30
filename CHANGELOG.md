# Changelog

All notable changes to aegis-hwsim. Mirrors the [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) convention; the project follows [aegis-boot](https://github.com/williamzujkowski/aegis-boot)'s release cadence.

## [Unreleased]

## [0.1.1] — 2026-04-30

UX patch for cargo-installed users.

### Fixed

- **`cargo install aegis-hwsim` now works from any cwd.** v0.1.0 surfaced a UX papercut: the binary always resolved `personas/` relative to cwd, so a `cargo install`-ed binary outside a checkout failed with `read "/some/cwd/personas": No such file or directory`. v0.1.1 adds a `--personas-dir DIR` global flag (and matching `--firmware-root DIR`) accepted by every persona-loading subcommand. Default behavior unchanged for in-repo runs. Help text updated to call out the cargo-installed flow + point at the github repo for fetching persona fixtures.

## [0.1.0] — 2026-04-30

First crates.io publish. Closes E5 (MOK + unsigned-kexec) and E6 (attestation roundtrip) structurally; partially closes E7 (v1.0 release gate — the trusted-publishing pipeline now publishes a real release). Five scenarios shipped, ~150 tests, CodeQL clean, full release-readiness gate (audit + `cargo publish --dry-run`) on every CI run.

### Why 0.1.0 and not 1.0.0

E7 ([#7](https://github.com/williamzujkowski/aegis-hwsim/issues/7)) calls for a real-hardware comparison study (`docs/research/hw-vs-sim-delta-2026.md`) running aegis-hwsim against three physical laptops and recording deltas. That study is gated on hardware availability we don't have today — it's an empirical claim, not a code milestone. Tagging 1.0.0 before that data exists would overclaim per the project's "verified outcomes only" ethos. 0.1.0 ships the harness, exercises the trusted-publishing pipeline end-to-end, and preserves the v1.0 milestone for when the study lands.

### Added — E5 (MOK + unsigned-kexec)

- **`scenarios/kexec_refuses_unsigned.rs`** ([#78](https://github.com/williamzujkowski/aegis-hwsim/pull/78), [#82](https://github.com/williamzujkowski/aegis-hwsim/pull/82)) — boots the persona under enforcing SB + lockdown, requires `aegis.test=kexec-unsigned` on the kernel cmdline (baked via aegis-boot's `MKUSB_TEST_MODE` flag), grep-pins `aegis-boot-test: kexec-unsigned starting` + `… REJECTED` from aegis-boot's published [`docs/rescue-tui-serial-format.md`](https://github.com/aegis-boot/aegis-boot/blob/main/docs/rescue-tui-serial-format.md) contract.
- **`scenarios/mok_enroll_alpine.rs`** ([#79](https://github.com/williamzujkowski/aegis-hwsim/pull/79), [#82](https://github.com/williamzujkowski/aegis-hwsim/pull/82)) — boots under MS-enrolled SB with `aegis.test=mok-enroll` cmdline; asserts the rescue-tui MOK walkthrough renders STEP 1/3 + the literal `sudo mokutil --import` payload verbatim per [aegis-boot#202](https://github.com/aegis-boot/aegis-boot/pull/202).
- **`aegis-hwsim gen-test-keyring`** ([#72](https://github.com/williamzujkowski/aegis-hwsim/pull/72), [#75](https://github.com/williamzujkowski/aegis-hwsim/pull/75)) — orchestrates `openssl` + `cert-to-efi-sig-list` + `sign-efi-sig-list` + `virt-fw-vars` to mint a PK/KEK/db keyring (every cert CN carries `TEST_ONLY_NOT_FOR_PRODUCTION`) and enroll it into a working `OVMF_VARS` file. Optional `--enroll-into <FILE>` flag does the full pipeline in one shot.
- **`scripts/audit-no-test-keys.sh`** ([#71](https://github.com/williamzujkowski/aegis-hwsim/pull/71)) — release-time audit that scans the cargo package list for the `TEST_ONLY_NOT_FOR_PRODUCTION` token in suspicious-extension files (`.fd .pem .key .crt .der .cer .efi .esl .auth`, anything under `firmware/`). Wired into `crates-publish.yml` BEFORE the OIDC token mint and into `ci.yml` on every PR. Source/doc/fixture references are allowlisted (the token IS the policy enforcement constant).
- **Loader guard**: reject `custom_keyring` on non-`custom_pk` variants ([#74](https://github.com/williamzujkowski/aegis-hwsim/pull/74)). Closes the footgun documented in `docs/research/gotchas.md#6` — operator thinks they're testing key enrollment but is observing a no-op against pre-enrolled keys.
- **`doctor` probes**: `openssl` / `sbsign` / `cert-to-efi-sig-list` / `virt-fw-vars` ([#70](https://github.com/williamzujkowski/aegis-hwsim/pull/70), [#75](https://github.com/williamzujkowski/aegis-hwsim/pull/75)) at Warn severity.

### Added — E6 (attestation roundtrip)

- **`scenarios/attestation_roundtrip.rs`** ([#83](https://github.com/williamzujkowski/aegis-hwsim/pull/83)) — boots TPM-bearing personas with `aegis.test=manifest-roundtrip` cmdline; rescue-tui mounts the ESP, parses the manifest via `aegis-wire-formats::Manifest`, and (when populated) compares each `expected_pcrs[]` entry to the live PCR. Currently fail-opens on the documented empty PCR list per the [`docs/attestation-manifest.md`](https://github.com/aegis-boot/aegis-boot/blob/main/docs/attestation-manifest.md) contract; auto-tightens to "Pass only on PCR MATCH" when aegis-boot starts populating the field.
- Cross-repo: aegis-boot pinned the manifest contract (`schema_version=1`, `expected_pcrs: Vec<PcrEntry>`) in [aegis-boot PR #682](https://github.com/aegis-boot/aegis-boot/pull/682) per our coordination request.

### Added — release infrastructure

- **`crates-publish.yml`** ([#66](https://github.com/williamzujkowski/aegis-hwsim/pull/66)) — Trusted Publishing via `rust-lang/crates-io-auth-action`. NO long-lived `CARGO_REGISTRY_TOKEN`; OIDC exchange mints a short-lived (~30 min) crates.io token. Per-step + per-job timeouts. `release` environment gate scoped to `v*` tag pushes.
- **`scripts/publish-if-new.sh`** — idempotent wrapper. Compares workspace version against crates.io's `max_version` and exits 0 cleanly if already published — prevents a re-tag from turning into a 400 cascade.
- **`cargo publish --dry-run` on every PR** ([#80](https://github.com/williamzujkowski/aegis-hwsim/pull/80)) — packages the crate exactly as it would ship and runs a full compile of the resulting tarball. Catches `Cargo.toml` metadata drift months before tag-push time.
- **CI hardening** ([#68](https://github.com/williamzujkowski/aegis-hwsim/pull/68)) — workflow-level `concurrency` block with `cancel-in-progress`; `timeout-minutes: 30` on the test job; `if: always()` cleanup step that pkills stray `swtpm` / `qemu-system-x86_64` and `rm -rf`s `/tmp/aegis-hwsim-*`.
- **CodeQL static analysis** ([#77](https://github.com/williamzujkowski/aegis-hwsim/pull/77)) — `security-extended` query suite on push/PR/weekly schedule. First analyses ran clean.
- **GitHub Actions SHA-pinned** ([#84](https://github.com/williamzujkowski/aegis-hwsim/pull/84)) — every `uses:` reference now points at a 40-char commit SHA with a `# v<TAG>` comment for grep-ability. Closes the floating-tag supply-chain risk with an OIDC-secrets workflow live.

### Added — observability + ergonomics

- **`scripts/visual-verify-boot.sh`** ([#73](https://github.com/williamzujkowski/aegis-hwsim/pull/73)) — operator-tooling that boots OVMF headless and captures a real framebuffer screenshot via QEMU's QMP `screendump`. Reference run committed at `docs/evidence/visual-verify-aegis-boot-stick-2026-04-29.png` shows GNU GRUB 2.12 with three `aegis-boot rescue` menu entries — proves the harness's QEMU+OVMF wiring boots a real signed-rescue stick end-to-end.
- **`crate::json::escape`** ([#81](https://github.com/williamzujkowski/aegis-hwsim/pull/81)) — extracted shared JSON-string-escaper. Three previous duplicate copies (in `bin/aegis-hwsim`, `coverage_grid`, `doctor`) now delegate.
- **`coverage_grid::render_markdown`** ([#81](https://github.com/williamzujkowski/aegis-hwsim/pull/81)) — `O(N²·M²) → O(N·M)` via `HashMap` lookup. Harmless on 11 personas × 5 scenarios but cubic-ish as the grid grows.
- **CLI**: `flag_value` / `flag_path_or` argv helpers ([#69](https://github.com/williamzujkowski/aegis-hwsim/pull/69)) — extracted from 3 duplicated `--flag VALUE` lookups; `--format` now exact-matches `{json, markdown}` instead of substring-matching.
- **`doctor`**: `read_dir` errors now surface in the FAIL message instead of silently mapping to "0 files" ([#81](https://github.com/williamzujkowski/aegis-hwsim/pull/81)).
- **I/O errors** in `qemu`/`swtpm`/`ovmf`: `e.to_string()` (e.g. "No such file or directory (os error 2)") instead of `format!("{:?}", e.kind())` (e.g. "NotFound") ([#81](https://github.com/williamzujkowski/aegis-hwsim/pull/81)).

### Fixed — security regressions

- **`loader.rs:179, 297, 307`** ([#67](https://github.com/williamzujkowski/aegis-hwsim/pull/67)) — three `unwrap_or_default` / `unwrap_or_else` fallbacks were silently masking errors that should surface as concrete `LoadError` variants. The L297 fallback weakened the path-traversal defense by accepting a non-canonical firmware root. New `FirmwareRootMissing` and `CustomKeyringMissing` variants surface canonicalization failures.

### Documentation

- **README**: post-E5+E6 accuracy sweep ([#80](https://github.com/williamzujkowski/aegis-hwsim/pull/80), [#83](https://github.com/williamzujkowski/aegis-hwsim/pull/83)) — status line, scenario table (5 entries), `MKUSB_TEST_MODE=<name>` operator walkthrough, persona-library blurb pointing at the generator instead of placeholder-only narrative.
- **`docs/visual-verification.md`** ([#73](https://github.com/williamzujkowski/aegis-hwsim/pull/73), [#76](https://github.com/williamzujkowski/aegis-hwsim/pull/76)) — operator recipe for `visual-verify-boot.sh` empty-stick smoke + real-USB-stick + `--vars-template` custom-PK modes.
- **`docs/evidence/`** — committed reference runs for the empty-stick smoke and the real aegis-boot signed-rescue-stick boot.
- **Research index**: structured registry layer ([#58](https://github.com/williamzujkowski/aegis-hwsim/pull/58)).
- **CI** — bumped Node-20-based actions to v5 ([#60](https://github.com/williamzujkowski/aegis-hwsim/pull/60)).

### Cross-repo coordination

This release closes 5 cross-repo coordination tickets on aegis-boot — all driven from the harness side once the harness work was structurally complete:

| aegis-boot # | Closes | What we needed | aegis-boot's response |
|---|---|---|---|
| [#675](https://github.com/aegis-boot/aegis-boot/issues/675) | E5.3 | rescue-tui kexec-unsigned test mode + serial-format docs | PR #680 — shipped + serial-format contract pinned |
| [#676](https://github.com/aegis-boot/aegis-boot/issues/676) | E5.4 | rescue-tui mok-enroll test mode | PR #681 — shipped |
| [#677](https://github.com/aegis-boot/aegis-boot/issues/677) | E6 | attestation manifest contract pin | PR #682 — `docs/attestation-manifest.md` published |
| [#694](https://github.com/aegis-boot/aegis-boot/issues/694) | E5+E6 operator UX | `MKUSB_TEST_MODE=<NAME>` env var on `mkusb`/`flash` | PR #696 — shipped |
| [#695](https://github.com/aegis-boot/aegis-boot/issues/695) | E6 | rescue-tui manifest-roundtrip test mode | PR #697 — shipped |

### Deferred to v0.2.0+

- **End-to-end test-mode visual evidence** — running aegis-boot's `mkusb` against a loopback `.img` requires aegis-boot's full build chain (signed shim + grub + kernel + initramfs). Not currently in aegis-hwsim's scope. Tracked as a v0.2.0 follow-up.
- **Real-hardware comparison study** ([#7](https://github.com/williamzujkowski/aegis-hwsim/issues/7)) — `docs/research/hw-vs-sim-delta-2026.md` requires running the harness + physical hardware on the same persona for ≥3 different laptops. Gated on hardware availability.
- **`signed-boot-uki` scenario** ([#50](https://github.com/williamzujkowski/aegis-hwsim/issues/50)) — blocked on a UKI-formatted aegis-boot stick artifact existing.
- **`sbat_generation` persona axis** ([#51](https://github.com/williamzujkowski/aegis-hwsim/issues/51)) — blocked on first real-world hardware report flagging SBAT failure.
- **`tests/fuzz_invocation.rs` parameterization** — six near-identical property tests; readable as-is, parameterizing them is pure polish.

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
