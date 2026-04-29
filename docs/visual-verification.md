# Visual verification

The Rust scenarios under `tests/` and `src/scenarios/` exercise the harness's serial-log assertions, but they don't *see* the framebuffer. For Secure-Boot work in particular, "OVMF said the right thing on serial" and "OVMF actually rendered the firmware screen" are different claims — a misconfigured `-vga` flag or a missing `-display` device can leave the screen blank while serial still produces correct landmarks.

`scripts/visual-verify-boot.sh` closes that gap by capturing a real screenshot of the QEMU framebuffer at the OVMF banner checkpoint. It's a manual operator tool, not a CI step — running QEMU with a real USB device or a custom keyring is too host-specific for the standard `cargo test` flow.

## Empty-stick smoke (default)

The simplest run boots OVMF against a 1 MB pseudo-random "stick" file. OVMF gets to its boot manager screen, fails to find a bootable device, falls into PXE / HTTP boot retries, and exits when QEMU's `-no-reboot` fires. We capture the screenshot in the middle of that.

```bash
./scripts/visual-verify-boot.sh
```

Output appears under `work/visual/<UTC-timestamp>/`:

| File | What |
|------|------|
| `screen.ppm` | Raw QEMU framebuffer dump (lossless, large). |
| `screen.png` | PNG conversion via `pnmtopng` or ImageMagick `convert` (if installed). |
| `serial.log` | Serial console capture. Cross-checked for `BdsDxe` landmark. |
| `metadata.json` | `schema_version=1` envelope describing the run. |
| `OVMF_VARS.fd` | Per-run copy of the VARS template. Fresh each run. |
| `empty-stick.img` | The 1 MB pseudo-random stick. |

Exit codes:

- `0` — screenshot captured AND `BdsDxe` landmark present in serial.
- `1` — screenshot captured but landmark missing (still useful for debug).
- `2` — setup failure (missing tools, missing OVMF firmware, bad args).

### Reference run

`docs/evidence/visual-verify-empty-stick-2026-04-29.png` is a known-good snapshot from a clean Ubuntu 24.04 host with `qemu-system-x86 ovmf` installed. The matching serial log and metadata are in the same directory. New screenshots should look the same modulo MAC / GUID values that vary per run.

The expected screen contents:

- Top text: `BdsDxe: failed to load Boot0001 "UEFI QEMU QEMU USB HARDDRIVE 1-0000:00:03.0-1" from PciRoot(0x0)/Pci(0x3,0x0)/USB(0x0,0x0): Not Found` — proves OVMF reached the boot device selector and tried the USB stick.
- Bottom-center: TianoCore logo — proves the firmware is the Microsoft-enrolled `OVMF_CODE_4M.secboot.fd` variant.
- A `>>Start PXE over IPv4.` line — proves OVMF moved past the USB attempt to the PXE fallback.

Three things prove this isn't a stub or canned image:
- The `PciRoot` path string is the actual address of QEMU's USB EHCI controller; if you wire the stick via a different `-device` flag the address changes.
- The MAC in the PXE Boot0002/0003 entries is the QEMU default `52:54:00:12:34:56` — different MAC settings change it.
- The screenshot dimensions are 1280×800 because that's what OVMF's `Aspeed AST2400` defaults to under `-vga std`.

## Real USB stick mode (operator-run, requires root)

Pass `--usb /dev/disk/by-id/usb-...`. The block device is attached read-only via QEMU's `readonly=on` drive flag. Reading raw block devices needs `disk` group membership or `sudo`; the script will emit a clear error if it can't open the device.

```bash
sudo ./scripts/visual-verify-boot.sh --usb /dev/disk/by-id/usb-SanDisk_Cruzer_4C530001240922109173-0:0
```

QEMU's `readonly=on` is a host-side contract enforced by the QEMU process; it isn't a kernel-level write barrier. **Do not run this against a stick whose contents you can't afford to risk.** For routine harness work, the empty-stick mode is preferred — the existing Rust scenarios already exercise the qcow2/raw stick path, and visual verification doesn't need a real device to confirm the OVMF variant and framebuffer are wired correctly.

## How the script works

1. Probes for `qemu-system-x86_64` + `python3` + the OVMF firmware files. Bails fast if any are missing.
2. Copies `OVMF_VARS_4M.ms.fd` into a per-run scratch dir so QEMU never writes back to the host's template.
3. Spawns QEMU with `-display none` (headless) + `-vga std` (so the framebuffer still exists for screendump) + a Unix-socket QMP monitor.
4. A short Python helper connects to the QMP socket, sends `qmp_capabilities`, sleeps a few seconds for OVMF to settle, then issues `screendump filename`. Then `quit` to drop QEMU cleanly.
5. Converts PPM → PNG with `pnmtopng` or `convert` if available; otherwise leaves the PPM.
6. Writes `metadata.json` so the screenshot is self-describing in archives.
7. Greps the serial log for `BdsDxe` to confirm OVMF actually booted (not a black screen + dead firmware).

## Pairing with the test-keyring generator

The visual-verify script doesn't currently boot OVMF with a custom-PK keyring loaded — the harness's path for that runs through `Invocation::new()` with the persona's `OvmfVariant::CustomPk`, not via this script. Once E5.1d (`virt-fw-vars` enrollment) lands, the recipe here will grow a `--vars-template <path>` flag so an operator can visually confirm a generated test keyring is being honored by OVMF.

For now, the workflow is:

1. `aegis-hwsim gen-test-keyring --out firmware/test-keyring/generated/` — produces PK/KEK/db material.
2. `./scripts/visual-verify-boot.sh` — confirms the *base* OVMF variant boots and shows TianoCore.
3. Future (E5.1d): combine the two — boot with the custom-PK VARS, screenshot, confirm Secure Boot enforces the test keyring.

## Limitations

- **Not in CI.** The script needs a graphical-capable QEMU build and ~2 GB of RAM on the runner; both are present on `ubuntu-latest` GitHub runners but the test would add ~30 s per CI run for marginal value over the existing serial-landmark tests. The script is operator-run only.
- **No interactive automation.** The script captures one screenshot at a single checkpoint. It doesn't drive the boot manager, type into shell, or chain screenshots across boot stages. A future scenario could send keystrokes via `sendkey` and screenshot at multiple checkpoints.
- **Empty-stick is empty.** OVMF boots, fails to find a bootloader, and exits. To verify a full GRUB / kernel handoff, you need a real signed-rescue stick image (or wire one up via the harness's existing `signed-boot-ubuntu` scenario, which uses serial-landmark assertions instead of screenshots).
