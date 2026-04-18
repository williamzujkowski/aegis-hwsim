# Recent projects — 2025/2026 delta

Capture: 2026-04-18. Delta-scan against [prior-art.md](prior-art.md). Covers projects that have appeared or materially evolved in the ~18 months before this pass.

Honest summary: **the landscape is quiet**. The obvious tools (chipsec, fwts, edk2-SCT, LAVA, labgrid, openQA, fwupd CI, sbctl, puzzleos/uefi-dev, tompreston/qemu-ovmf-swtpm) remain the dominant set. No new persona-matrix harness has appeared.

## Projects

### anpep/qemu-tpm-measurement
- URL: <https://github.com/anpep/qemu-tpm-measurement>
- Language: shell / docs
- Relationship: **Reference** (narrow-scope analog of our attestation scenario)
- Why it matters: Minimal reproducer for QEMU+OVMF+swtpm boot-measurement + PCR-extend reads via `/sys/kernel/security/tpm0/binary_bios_measurements`. Useful sanity-check harness when debugging aegis-hwsim's TPM event-log capture path. Not a matrix — single config, manual.

### intel/tsffs
- URL: <https://github.com/intel/tsffs>
- Language: Rust
- Relationship: **Complementary** (orthogonal scope)
- Why it matters: Snapshotting coverage-guided UEFI/BIOS/firmware fuzzer on SIMICS. Adjacent to aegis-hwsim's testable surface — they fuzz firmware-internal paths, we drive OS-visible signed-chain flows. Would pair well if a future aegis-hwsim consumer wanted fuzz-and-conformance in one CI.

### fwupd SBAT plugin (new since fwupd 2.0.0, 2024)
- URL: <https://fwupd.github.io/libfwupdplugin/uefi-sbat-README.html>
- Language: C
- Relationship: **Integration target** (future)
- Why it matters: SBAT revocation delivery via LVFS became a real operational gap Jul 2024–Jan 2025. A future persona axis `sbat_generation:` would let aegis-hwsim assert rescue-stick behavior under stale-SBAT conditions — real-world failure mode currently untested.

### systemd-ukify + UKI ecosystem
- URL: <https://man.archlinux.org/man/ukify.1.en>, spec at <https://uapi-group.org/specifications/specs/unified_kernel_image/>
- Language: Python (ukify), C (systemd-stub)
- Relationship: **Integration target** (near-term)
- Why it matters: UKIs collapse kernel+initrd+cmdline into one signed PE — changes what "signed-chain" means in practice. aegis-boot's USB-rescue-stick path needs a UKI-aware scenario now that distros (Arch, Fedora 40+, Debian testing) ship ukify as first-class. Worth a scenario added alongside signed-boot-ubuntu.

## Explicit non-findings

- **No sbctl-rs** found. sbctl remains Go-only; no Rust rewrite in progress that we could verify.
- **No new persona-matrix harness** in the aegis-hwsim space. Existing tools still single-config.
- **Dasharo** (<https://docs.dasharo.com/variants/qemu_q35/hardware-matrix/>) publishes a QEMU hardware matrix, but it's a *supported-configurations* list for their coreboot-based firmware product — not a test harness. Noted for completeness.

## Implications for aegis-hwsim roadmap

Two near-term ideas surface from this scan:

1. **UKI scenario** — distros are shipping ukify-based kernels by default; aegis-boot's signed-chain assertion needs to cover `shim → systemd-stub → UKI` in addition to `shim → grub → kernel`. Worth a `signed-boot-uki` scenario alongside `signed-boot-ubuntu`.

2. **SBAT-generation persona axis** — current personas pin `bios_version` but not SBAT generation. Real-world rescue-stick failures during the Jul 2024–Jan 2025 SBAT-revocation window suggest this is a coverage gap. Could be a follow-up persona-schema field added when a real operator hits the issue.

Neither is urgent for v1.0; both are tracked here so future contributors find the rationale.
