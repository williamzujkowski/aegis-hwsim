# aegis-hwsim

**Status:** Phase 1 working. CI exercises the full QEMU+OVMF+swtpm pipeline against the persona library on every PR via the `qemu-boots-ovmf` smoke scenario. Tracks [aegis-boot#226](https://github.com/williamzujkowski/aegis-boot/issues/226).

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

```bash
git clone https://github.com/williamzujkowski/aegis-hwsim
cd aegis-hwsim
cargo build --release

# Health-check the host first — surfaces all missing apt packages in
# one pass instead of one-at-a-time via scenario Skip messages.
target/release/aegis-hwsim doctor

# Inventory the shipped persona library
target/release/aegis-hwsim list-personas

# List registered scenarios
target/release/aegis-hwsim list-scenarios

# Smoke-test the harness pipeline (no signed stick needed)
target/release/aegis-hwsim run qemu-smoke-no-tpm qemu-boots-ovmf /tmp/dummy.img
# Expected: PASS within ~2s, OVMF's BdsDxe message captured to work/.../serial.log

# Emit the persona × scenario coverage matrix
target/release/aegis-hwsim coverage-grid               # Markdown
target/release/aegis-hwsim coverage-grid --format json # schema_version=1 JSON
target/release/aegis-hwsim coverage-grid --dry-run     # fast: every cell SKIP

# End-to-end against a real signed aegis-boot stick
# (build the stick on a Linux machine via aegis-boot's mkusb.sh first)
target/release/aegis-hwsim run \
  lenovo-thinkpad-x1-carbon-gen11 \
  signed-boot-ubuntu \
  /path/to/aegis-boot.img
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0  | Pass — every assertion held |
| 1  | Fail — at least one assertion missed, or runner-level error |
| 2  | Usage error |
| 77 | Skip — prerequisites missing (operator-readable reason printed) |

### Persona library (10 entries today)

| ID | TPM | OVMF | Notes |
|----|-----|------|-------|
| `qemu-generic-minimal` | 2.0 | ms_enrolled | Reference persona |
| `qemu-smoke-no-tpm` | none | ms_enrolled | Harness self-test (smoke scenario target) |
| `qemu-disabled-sb` | none | disabled | Diagnostic — exercises non-secboot CODE path |
| `qemu-setup-mode-sb` | none | setup_mode | Diagnostic — pre-PK enrollment / MOK recovery flow |
| `framework-laptop-12gen` | 2.0 | ms_enrolled | Phase 1 |
| `lenovo-thinkpad-x1-carbon-gen11` | 2.0 | ms_enrolled | Phase 1 |
| `lenovo-thinkpad-t440p-tpm12` | 1.2 (ST33) | ms_enrolled | Exercises tpm-tis device path |
| `dell-xps-13-9320` | 2.0 (PTT) | ms_enrolled | Phase 2 |
| `hp-elitebook-845-g10` | 2.0 (fTPM) | ms_enrolled | Phase 2 |
| `asus-zenbook-14-oled` | 2.0 (PTT) | ms_enrolled | Phase 2 |

OVMF variant matrix coverage today: **3 of 4** — `ms_enrolled` (8 personas), `disabled` (1), `setup_mode` (1). `custom_pk` is still future work — needs a test keyring under `firmware/` plus a relative-path resolution decision in the loader.

All vendor-docs source citations are flagged PLACEHOLDER pending a real community hardware-report. See `personas/*.yaml` for the per-persona quirks captured (boot-key F8/F9/F12, vendor-specific MOK Manager rendering, AMD fTPM stuttering errata, TPM 1.2 SHA-1-only PCR bank, etc.).

### Scenarios (2 shipped today)

| Name | Asserts | Needs | Runs on CI? |
|------|---------|-------|---|
| `qemu-boots-ovmf` | OVMF emits `BdsDxe` boot-selector marker | qemu + ovmf | Yes — runs against `qemu-smoke-no-tpm` every PR |
| `signed-boot-ubuntu` | Full chain: shim → grub → kernel → kexec | qemu + ovmf + swtpm + signed `aegis-boot.img` | Skipped on CI (no signed stick artifact yet) |

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
