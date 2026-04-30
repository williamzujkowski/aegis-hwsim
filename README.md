# aegis-hwsim

[![crates.io](https://img.shields.io/crates/v/aegis-hwsim.svg)](https://crates.io/crates/aegis-hwsim)
[![docs.rs](https://img.shields.io/docsrs/aegis-hwsim)](https://docs.rs/aegis-hwsim)
[![CI](https://github.com/williamzujkowski/aegis-hwsim/actions/workflows/ci.yml/badge.svg)](https://github.com/williamzujkowski/aegis-hwsim/actions/workflows/ci.yml)
[![CodeQL](https://github.com/williamzujkowski/aegis-hwsim/actions/workflows/codeql.yml/badge.svg)](https://github.com/williamzujkowski/aegis-hwsim/actions/workflows/codeql.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-blue)](./Cargo.toml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](./LICENSE-MIT)

**Status:** v0.1.0 published to crates.io (2026-04-30). E5 (MOK + unsigned-kexec) and E6 (attestation roundtrip) structurally complete. 11 personas covering all 4 OVMF variants and all 3 TPM versions, 5 scenarios (`qemu-boots-ovmf` smoke + `signed-boot-ubuntu` end-to-end + `kexec-refuses-unsigned` + `mok-enroll-alpine` + `attestation-roundtrip`), coverage-grid artifact per PR, ~150 tests including 60k-input fuzz per CI run, CodeQL static analysis enabled, all GitHub Actions SHA-pinned, Trusted Publishing pipeline operational. Tracks [aegis-boot#226](https://github.com/williamzujkowski/aegis-boot/issues/226); v1.0 release gate tracked in [#7](https://github.com/williamzujkowski/aegis-hwsim/issues/7) (real-hardware comparison study pending).

A test harness that parameterizes **QEMU + OVMF + swtpm** over a matrix of **hardware personas** — YAML fixtures matching real shipping laptops/workstations — so [aegis-boot](https://github.com/williamzujkowski/aegis-boot)'s UEFI-Secure-Boot-preserving USB-rescue-stick flow can be validated across ~100 configurations without waiting on physical Framework / ThinkPad / Dell / HP / ASUS hardware.

```
personas/        YAML fixtures: DMI + SB posture + TPM version + quirks
scenarios/       Rust test cases that drive each persona through aegis-boot's chain
src/bin/         `aegis-hwsim` CLI (persona loader + QEMU orchestrator)
docs/            Design docs + research index
.github/         CI matrix (N personas × M scenarios → coverage grid)
```

## Scope

Covers the **Linux-visible surface**:

- DMI/SMBIOS strings the kernel exposes at `/sys/class/dmi/id/` (QEMU `-smbios type=0/1/2/3/4/17`)
- Secure Boot posture via OVMF variants (MS-enrolled / custom-PK / setup-mode / disabled)
- TPM 1.2 / 2.0 presence via swtpm socket
- Kernel lockdown modes (none / integrity / confidentiality)
- aegis-boot's specific assertions: signed-chain boot, MOK enrollment recipe accuracy, kexec signature verification, attestation roundtrip

Deliberately **not** in scope:

- Vendor-specific UEFI UI (Lenovo blue-screen MOK Manager, Dell F12 boot menu, HP Fast Boot timing). LAVA documented that "UEFI automation proved to be unworkable in automation due to complexity of the sequences and the changes in error handling between levels of the same menus" — that's a validated dead end.
- Kernel vendor-quirk paths (`thinkpad_acpi`, `dell-laptop`, etc.) — those check PCI IDs + ACPI SSDT, which QEMU's `-smbios` doesn't spoof.
- EC quirks, broken USB controller firmware, hardware errata.
- UEFI firmware fuzzing (that's [chipsec](https://github.com/chipsec/chipsec)'s lane).

## Relationship to adjacent tools

aegis-hwsim is **complementary** to, not replacing, these projects. See [docs/research/prior-art.md](docs/research/prior-art.md) for the full survey.

| Tool | Scope | Relationship |
|------|-------|--------------|
| [chipsec](https://github.com/chipsec/chipsec) | Live-system UEFI/platform security audit | Complementary — audits real platforms, we validate emulated flows |
| [fwts](https://github.com/fwts/fwts) | ACPI/UEFI/SMBIOS conformance (Canonical) | Complementary — firmware correctness, we test SB-chain boot |
| [edk2-SCT](https://github.com/tianocore/edk2-test) | UEFI spec conformance | Orthogonal — validates firmware, not OS-level flows |
| [fwupd](https://github.com/fwupd/fwupd) QEMU CI | Capsule-update testing on QEMU+OVMF+swtpm | **Integration target** — borrow scaffolding patterns |
| [LAVA](https://docs.lavasoftware.org) | Deployment orchestrator for lab boards + QEMU | Integration target — aegis-hwsim could ship LAVA job definitions |
| [labgrid](https://github.com/labgrid-project/labgrid) | pytest-style HW-in-loop harness | Same pattern, real-hardware focused; aegis-hwsim is QEMU-only + persona-driven |
| [openQA](https://open.qa) | VM-based distro regression (SUSE) | Adjacent — exercises shim/grub SB paths per distro; we exercise per laptop-vendor |
| [sbctl](https://github.com/Foxboron/sbctl) | Secure Boot key management | Complementary tool |
| [puzzleos/uefi-dev](https://github.com/puzzleos/uefi-dev) | Single-config dev scaffold for UEFI SB | Reference for base invocation |
| [tompreston/qemu-ovmf-swtpm](https://github.com/tompreston/qemu-ovmf-swtpm) | Setup scripts | Reference starter |

**Nothing else** ships a persona-matrix harness keyed on real shipping hardware. That's the differentiator.

## Fidelity honesty

fwupd/LVFS empirical data (Richard Hughes / Mario Limonciello) puts QEMU's coverage of capsule-flow bugs at ~60–70%; the rest are EC / firmware-vendor-specific, reproducible only on metal. Our scope is narrower (USB rescue-stick signed-chain flow, not capsule updates), so we estimate ~80% coverage of aegis-boot's testable failure modes — but **real-hardware shakedown is still required** for:

- Vendor UEFI UI paths
- EC / USB controller firmware errata
- Signed-shim-vs-signed-grub stepping mismatches on specific hardware revisions

See [aegis-boot#51](https://github.com/williamzujkowski/aegis-boot/issues/51), [#132](https://github.com/williamzujkowski/aegis-boot/issues/132), [#181](https://github.com/williamzujkowski/aegis-boot/issues/181) — all unblocked for the 80% they care about, still gated on real hardware for the remaining 20%.

## Quick start

### From crates.io

```bash
cargo install aegis-hwsim                         # Installs the orchestrator binary

# Persona fixtures + firmware/test-keyring don't ship in the cargo
# package by design. Clone the repo for the YAML library and pass
# its paths via the global flags:
git clone https://github.com/williamzujkowski/aegis-hwsim /tmp/aegis-hwsim

# Smoke-test the install
aegis-hwsim --version --json
aegis-hwsim list-personas \
    --personas-dir /tmp/aegis-hwsim/personas \
    --firmware-root /tmp/aegis-hwsim/firmware
```

`--personas-dir` and `--firmware-root` are accepted by every persona-loading subcommand. Default behavior (no flags) resolves both relative to cwd — that's the in-repo developer flow below.

### From a checkout (the harness's own dev flow)

```bash
git clone https://github.com/williamzujkowski/aegis-hwsim
cd aegis-hwsim
cargo build --release

# Health-check the host first — surfaces all missing apt packages in
# one pass instead of one-at-a-time via scenario Skip messages.
target/release/aegis-hwsim doctor               # Human-readable
target/release/aegis-hwsim doctor --json        # schema_version=1 envelope

# Inventory the shipped persona library
target/release/aegis-hwsim list-personas
target/release/aegis-hwsim list-personas --json

# List registered scenarios
target/release/aegis-hwsim list-scenarios
target/release/aegis-hwsim list-scenarios --json

# Version (matches aegis-boot --version --json convention for scriptable installs)
target/release/aegis-hwsim --version
target/release/aegis-hwsim --version --json

# Smoke-test the harness pipeline (no signed stick needed)
target/release/aegis-hwsim run qemu-smoke-no-tpm qemu-boots-ovmf /tmp/dummy.img
# Expected: PASS within ~2s, OVMF's BdsDxe message captured to work/.../serial.log

# Emit the persona × scenario coverage matrix
target/release/aegis-hwsim coverage-grid               # Markdown
target/release/aegis-hwsim coverage-grid --format json # schema_version=1 JSON
target/release/aegis-hwsim coverage-grid --dry-run     # fast: every cell SKIP

# Generate the PK/KEK/db test keyring for custom-PK scenarios (E5)
# Every cert carries TEST_ONLY_NOT_FOR_PRODUCTION in its CN; the
# release-gate audit refuses to publish anything containing it.
target/release/aegis-hwsim gen-test-keyring \
  --out firmware/test-keyring/generated \
  --enroll-into firmware/test-keyring/generated/custom-pk.fd

# Visually verify OVMF actually renders (operator tool, requires
# python3 + pnmtopng or imagemagick for PPM→PNG)
./scripts/visual-verify-boot.sh                # empty-stick smoke
sudo ./scripts/visual-verify-boot.sh \         # real USB stick (read-only)
  --usb /dev/disk/by-id/usb-...
# Output: work/visual/<timestamp>/screen.{ppm,png}, serial.log, metadata.json
# Reference run: docs/evidence/visual-verify-aegis-boot-stick-2026-04-29.png

# End-to-end against a real signed aegis-boot stick
# (build the stick on a Linux machine via aegis-boot's mkusb.sh first)
target/release/aegis-hwsim run \
  lenovo-thinkpad-x1-carbon-gen11 \
  signed-boot-ubuntu \
  /path/to/aegis-boot.img
```

Every read-mostly subcommand accepts `--json` and emits a `schema_version=1` envelope — matches the [aegis-boot family convention (PR #191)](https://github.com/williamzujkowski/aegis-boot/pull/191) so scripted consumers parse uniformly across the family.

### Exit codes

| Code | Meaning |
|------|---------|
| 0  | Pass — every assertion held |
| 1  | Fail — at least one assertion missed, or runner-level error |
| 2  | Usage error |
| 77 | Skip — prerequisites missing (operator-readable reason printed) |

### Persona library (11 entries today)

| ID | TPM | OVMF | Notes |
|----|-----|------|-------|
| `qemu-generic-minimal` | 2.0 | ms_enrolled | Reference persona |
| `qemu-smoke-no-tpm` | none | ms_enrolled | Harness self-test (smoke scenario target) |
| `qemu-disabled-sb` | none | disabled | Diagnostic — exercises non-secboot CODE path |
| `qemu-setup-mode-sb` | none | setup_mode | Diagnostic — pre-PK enrollment / MOK recovery flow |
| `qemu-custom-pk-sb` | none | custom_pk | Diagnostic — enterprise-CA enrollment flow (uses `firmware/test-keyring/` placeholder) |
| `framework-laptop-12gen` | 2.0 | ms_enrolled | Phase 1 |
| `lenovo-thinkpad-x1-carbon-gen11` | 2.0 | ms_enrolled | Phase 1 |
| `lenovo-thinkpad-t440p-tpm12` | 1.2 (ST33) | ms_enrolled | Exercises tpm-tis device path |
| `dell-xps-13-9320` | 2.0 (PTT) | ms_enrolled | Phase 2 |
| `hp-elitebook-845-g10` | 2.0 (fTPM) | ms_enrolled | Phase 2 |
| `asus-zenbook-14-oled` | 2.0 (PTT) | ms_enrolled | Phase 2 |

OVMF variant matrix coverage today: **4 of 4** — `ms_enrolled` (8 personas), `disabled` (1), `setup_mode` (1), `custom_pk` (1). The custom_pk persona references a 1 MB pseudo-random placeholder under `firmware/test-keyring/` for path-traversal-guard tests; real PK/KEK/db keyrings (with `TEST_ONLY_NOT_FOR_PRODUCTION` baked into each cert CN) are produced by `aegis-hwsim gen-test-keyring` (E5.1b/E5.1d) and live under `firmware/test-keyring/generated/` (gitignored).

All vendor-docs source citations are flagged PLACEHOLDER pending a real community hardware-report. See `personas/*.yaml` for the per-persona quirks captured (boot-key F8/F9/F12, vendor-specific MOK Manager rendering, AMD fTPM stuttering errata, TPM 1.2 SHA-1-only PCR bank, etc.).

### Scenarios (5 shipped today)

| Name | Asserts | Needs | Runs on CI? |
|------|---------|-------|---|
| `qemu-boots-ovmf` | OVMF emits `BdsDxe` boot-selector marker | qemu + ovmf | Yes — runs against `qemu-smoke-no-tpm` every PR |
| `signed-boot-ubuntu` | Full chain: shim → grub → kernel → kexec | qemu + ovmf + swtpm + signed `aegis-boot.img` | Skipped on CI (no signed stick artifact yet) |
| `kexec-refuses-unsigned` | Under enforcing SB + lockdown, an unsigned `kexec_file_load` is rejected with `EKEYREJECTED` and rescue-tui surfaces its `REJECTED (...)` diagnostic | qemu + ovmf + swtpm + signed stick flashed with `MKUSB_TEST_MODE=kexec-unsigned` (aegis-boot [#675](https://github.com/aegis-boot/aegis-boot/issues/675) + [#680](https://github.com/aegis-boot/aegis-boot/pull/680)) | Skipped on default-flashed sticks; Pass on test-mode-flashed sticks |
| `mok-enroll-alpine` | Booting under MS-enrolled SB triggers the rescue-tui MOK walkthrough; STEP 1/3's literal `sudo mokutil --import` appears verbatim per [aegis-boot#202](https://github.com/aegis-boot/aegis-boot/pull/202) | qemu + ovmf + signed stick flashed with `MKUSB_TEST_MODE=mok-enroll` (aegis-boot [#676](https://github.com/aegis-boot/aegis-boot/issues/676) + [#681](https://github.com/aegis-boot/aegis-boot/pull/681)) | Skipped on default-flashed sticks; Pass on test-mode-flashed sticks |
| `attestation-roundtrip` | Rescue-tui mounts the ESP, parses the on-stick manifest via `aegis-wire-formats::Manifest`, and (when populated) compares each `expected_pcrs[]` entry to the live PCR. Currently fail-opens on the empty PCR list per the [attestation-manifest.md contract](https://github.com/aegis-boot/aegis-boot/blob/main/docs/attestation-manifest.md). | qemu + ovmf + swtpm + TPM-bearing persona + signed stick flashed with `MKUSB_TEST_MODE=manifest-roundtrip` (aegis-boot [#677](https://github.com/aegis-boot/aegis-boot/issues/677) + [#697](https://github.com/aegis-boot/aegis-boot/pull/697)) | Skipped on default-flashed sticks; Pass on test-mode-flashed sticks |

#### Producing a Pass on E5/E6 scenarios

The four cross-repo-coordinated scenarios (`kexec-refuses-unsigned`, `mok-enroll-alpine`, `attestation-roundtrip`) all rely on the same trigger: an `aegis.test=<name>` parameter on the kernel cmdline. aegis-boot's [`MKUSB_TEST_MODE`](https://github.com/aegis-boot/aegis-boot/pull/696) env var bakes this into the flashed stick's `grub.cfg`:

```bash
# In aegis-boot's checkout:
MKUSB_TEST_MODE=kexec-unsigned    ./scripts/mkusb.sh /dev/sdX  # E5.3
MKUSB_TEST_MODE=mok-enroll        ./scripts/mkusb.sh /dev/sdX  # E5.4
MKUSB_TEST_MODE=manifest-roundtrip ./scripts/mkusb.sh /dev/sdX  # E6
```

Then run the harness against the resulting stick image:

```bash
target/release/aegis-hwsim run \
  lenovo-thinkpad-x1-carbon-gen11 \
  attestation-roundtrip \
  /path/to/aegis-boot-with-test-mode.img
```

Adding a scenario? See [docs/scenario-authoring.md](docs/scenario-authoring.md). Adding a persona? See [docs/persona-authoring.md](docs/persona-authoring.md). Either way, start with [CONTRIBUTING.md](CONTRIBUTING.md).

### CI artifacts published per PR

- **`coverage-grid`** — markdown + JSON of the persona × scenario matrix. Reviewers click the artifact in the GitHub Actions run summary to see the matrix shape for that change.
- The smoke scenario above runs against real QEMU+OVMF on the Ubuntu runner — proof-of-life that the harness wiring is sound.

## Build / dev requirements

- **swtpm ≥ 0.8.2** — earlier versions had PCR-extend race issues on fast reboots
- **qemu-system-x86_64 ≥ 7.2** — stable `-smbios type=4` support
- **ovmf** (Debian / Ubuntu packaging: `ovmf` + `ovmf-ia32`) — the MS-enrolled `OVMF_VARS_4M.ms.fd` variant
- **Rust 1.85+** — matches aegis-boot's pin

## License

Dual-licensed MIT / Apache-2.0, matching aegis-boot.

## Tracking

Primary: [aegis-boot#226](https://github.com/williamzujkowski/aegis-boot/issues/226) (epic + design). This repo's issues track Phase 1/2/3 execution.
