#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# visual-verify-boot.sh — boot OVMF in QEMU and capture a screenshot
# at the OVMF banner checkpoint. Used to confirm the harness's QEMU
# args produce a real OVMF firmware screen (not a black framebuffer)
# and that the persona's ovmf_variant is actually selected.
#
# Two modes:
#
#   1. Empty-stick smoke (default) — boots OVMF against a 1 MB
#      pseudo-random stick. OVMF gets to its boot manager screen
#      ("Press ESC to enter setup") before failing to find a bootable
#      device. We capture the banner; that's enough to prove the OVMF
#      variant is loading.
#
#   2. Real USB stick (--usb /dev/disk/by-id/...) — passes the named
#      block device through as a USB drive. Useful for verifying an
#      aegis-boot signed-rescue stick visually. CAUTION: the device
#      is attached READ-ONLY (-readonly + -drive readonly=on), but
#      QEMU has been known to bypass this on some block-device
#      backends — DO NOT use this mode against a stick whose contents
#      you can't afford to risk. The harness's normal Rust scenarios
#      use a stick image file (qcow2 / raw), not a real device.
#
# Output:
#
#   work/visual/<timestamp>/
#     screen.ppm                 # raw QEMU framebuffer dump
#     screen.png                 # PNG conversion if pnmtopng/imagemagick available
#     serial.log                 # serial console capture for cross-check
#     metadata.json              # qemu cmdline + config used
#
# Exit codes:
#   0  screenshot captured + serial landmark seen
#   1  screenshot captured but landmark missed (still useful for debug)
#   2  setup failure (qemu/ovmf/python missing, args wrong)

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Defaults — match what the harness's qemu_boots_ovmf_smoke scenario uses.
OVMF_DIR="${OVMF_DIR:-/usr/share/OVMF}"
OVMF_CODE="${OVMF_DIR}/OVMF_CODE_4M.secboot.fd"
OVMF_VARS="${OVMF_DIR}/OVMF_VARS_4M.ms.fd"
VARS_TEMPLATE_OVERRIDE=""
USB_DEVICE=""
TIMEOUT_SECS=30

usage() {
    cat <<EOF
visual-verify-boot.sh — boot OVMF + capture screenshot at firmware banner.

USAGE:
  $0 [--ovmf-dir DIR] [--vars-template FILE] [--usb /dev/disk/by-id/usb-...] [--timeout N]

OPTIONS:
  --ovmf-dir DIR        Override OVMF dir (default: \$OVMF_DIR or /usr/share/OVMF)
  --vars-template FILE  Use this VARS template instead of OVMF_VARS_4M.ms.fd. Useful
                        for booting against a custom-PK keyring produced by
                        \`aegis-hwsim gen-test-keyring --enroll-into FILE\`.
  --usb DEV             Pass through a real USB block device (read-only). Omit for
                        empty-stick smoke mode (recommended for unattended runs).
  --timeout N           Boot timeout in seconds (default: 30).
  -h | --help           This message.

OUTPUT under work/visual/<timestamp>/:
  screen.ppm     - raw framebuffer
  screen.png     - PNG (if pnmtopng/imagemagick is available)
  serial.log     - serial console output
  metadata.json  - qemu config used
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ovmf-dir)
            OVMF_DIR="$2"
            OVMF_CODE="${OVMF_DIR}/OVMF_CODE_4M.secboot.fd"
            OVMF_VARS="${OVMF_DIR}/OVMF_VARS_4M.ms.fd"
            shift 2 ;;
        --vars-template)
            VARS_TEMPLATE_OVERRIDE="$2"
            shift 2 ;;
        --usb)       USB_DEVICE="$2"; shift 2 ;;
        --timeout)   TIMEOUT_SECS="$2"; shift 2 ;;
        -h|--help)   usage; exit 0 ;;
        *)           echo "visual-verify-boot: unknown arg '$1'" >&2; usage >&2; exit 2 ;;
    esac
done

# Resolve the actual VARS template after argv parsing so --vars-template
# overrides any --ovmf-dir-derived default cleanly.
if [[ -n "$VARS_TEMPLATE_OVERRIDE" ]]; then
    OVMF_VARS="$VARS_TEMPLATE_OVERRIDE"
fi

# 1) Tooling probes.
for tool in qemu-system-x86_64 python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "visual-verify-boot: ERROR — '$tool' not on PATH" >&2
        exit 2
    fi
done
for f in "$OVMF_CODE" "$OVMF_VARS"; do
    if [[ ! -r "$f" ]]; then
        echo "visual-verify-boot: ERROR — OVMF file missing: $f" >&2
        echo "                          (apt install ovmf, or set --ovmf-dir)" >&2
        exit 2
    fi
done

# 2) Scratch dir.
TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="${REPO_ROOT}/work/visual/${TS}"
mkdir -p "$OUT_DIR"

VARS_COPY="${OUT_DIR}/OVMF_VARS.fd"
cp "$OVMF_VARS" "$VARS_COPY"

# 3) Stick image.
if [[ -n "$USB_DEVICE" ]]; then
    if [[ ! -b "$USB_DEVICE" ]]; then
        echo "visual-verify-boot: ERROR — --usb $USB_DEVICE is not a block device" >&2
        exit 2
    fi
    if [[ ! -r "$USB_DEVICE" ]]; then
        echo "visual-verify-boot: ERROR — cannot read $USB_DEVICE (need root or disk group)" >&2
        exit 2
    fi
    STICK_ARG="$USB_DEVICE"
    STICK_MODE="real-usb-readonly"
else
    STICK_ARG="${OUT_DIR}/empty-stick.img"
    : > "$STICK_ARG"
    truncate -s 1M "$STICK_ARG"
    STICK_MODE="empty-1mib-pseudo-random"
fi

# 4) Compose QEMU args.
SERIAL_LOG="${OUT_DIR}/serial.log"
QMP_SOCK="${OUT_DIR}/qmp.sock"

QEMU_ARGS=(
    -machine "q35,smm=on,accel=tcg"
    -cpu qemu64
    -m 1024
    -nographic
    -display none
    -vga std
    -drive "if=pflash,format=raw,readonly=on,file=$OVMF_CODE"
    -drive "if=pflash,format=raw,file=$VARS_COPY"
    -drive "id=stick,if=none,format=raw,readonly=on,file=$STICK_ARG"
    -device usb-ehci
    -device "usb-storage,drive=stick"
    -serial "file:$SERIAL_LOG"
    -qmp "unix:$QMP_SOCK,server,nowait"
    -no-reboot
)

# 5) Spawn QEMU in the background; wait for QMP socket.
echo "visual-verify-boot: launching QEMU (mode: $STICK_MODE, timeout: ${TIMEOUT_SECS}s)..."
qemu-system-x86_64 "${QEMU_ARGS[@]}" &
QEMU_PID=$!
trap 'kill -TERM $QEMU_PID 2>/dev/null || true; wait $QEMU_PID 2>/dev/null || true' EXIT

# Wait for the QMP socket to appear (QEMU creates it after init).
for _ in $(seq 1 50); do
    [[ -S "$QMP_SOCK" ]] && break
    sleep 0.1
done
if [[ ! -S "$QMP_SOCK" ]]; then
    echo "visual-verify-boot: ERROR — QMP socket never appeared" >&2
    exit 2
fi

# 6) Drive QMP via Python — emit `screendump` after a short settle delay.
SCREEN_PPM="${OUT_DIR}/screen.ppm"
python3 - "$QMP_SOCK" "$SCREEN_PPM" "$TIMEOUT_SECS" <<'PYEOF'
import json, os, socket, sys, time

sock_path, screen_path, timeout_secs = sys.argv[1], sys.argv[2], int(sys.argv[3])

def send(s, msg):
    s.sendall((json.dumps(msg) + "\n").encode())
    # Drain one event/response.
    return s.recv(65536)

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sock_path)
greeting = s.recv(65536)  # QMP capabilities greeting
send(s, {"execute": "qmp_capabilities"})

# Settle: OVMF takes a few seconds to render the banner.
deadline = time.time() + timeout_secs
time.sleep(min(8, max(2, timeout_secs // 4)))

# Screendump. QMP returns immediately with success once it queues the
# write; the file may take a beat to settle on disk.
resp = send(s, {"execute": "screendump", "arguments": {"filename": screen_path}})
print(f"qmp screendump response: {resp.decode(errors='replace').strip()}", file=sys.stderr)

# Wait for the file to be non-empty before returning.
while time.time() < deadline:
    if os.path.exists(screen_path) and os.path.getsize(screen_path) > 0:
        break
    time.sleep(0.2)

# Quit QEMU cleanly.
send(s, {"execute": "quit"})
s.close()
PYEOF

# 7) Wait for QEMU to exit.
wait $QEMU_PID 2>/dev/null || true
trap - EXIT

if [[ ! -s "$SCREEN_PPM" ]]; then
    echo "visual-verify-boot: ERROR — screendump produced no output at $SCREEN_PPM" >&2
    exit 2
fi

# 8) PPM → PNG if a converter is available. Operators get the PNG; we
#    also keep the PPM for archival (lossless, no dep on a converter).
SCREEN_PNG="${OUT_DIR}/screen.png"
if command -v pnmtopng >/dev/null 2>&1; then
    pnmtopng "$SCREEN_PPM" > "$SCREEN_PNG" 2>/dev/null || rm -f "$SCREEN_PNG"
elif command -v convert >/dev/null 2>&1; then
    # ImageMagick. -strip drops EXIF; not strictly needed but keeps
    # output deterministic for evidence-archive comparisons.
    convert "$SCREEN_PPM" -strip "$SCREEN_PNG" 2>/dev/null || rm -f "$SCREEN_PNG"
fi

# 9) Metadata sidecar so the screenshot is self-describing.
cat > "${OUT_DIR}/metadata.json" <<JSON
{
  "schema_version": 1,
  "tool": "aegis-hwsim/visual-verify-boot.sh",
  "captured_at": "${TS}",
  "stick_mode": "${STICK_MODE}",
  "ovmf_dir": "${OVMF_DIR}",
  "ovmf_code": "${OVMF_CODE}",
  "ovmf_vars": "${OVMF_VARS}",
  "vars_template_override": "${VARS_TEMPLATE_OVERRIDE}",
  "usb_device": "${USB_DEVICE}",
  "timeout_secs": ${TIMEOUT_SECS},
  "screen_ppm": "screen.ppm",
  "screen_png": "screen.png",
  "serial_log": "serial.log"
}
JSON

# 10) Cross-check serial: did OVMF actually boot? `BdsDxe` is the
#     boot-device-select stage from EDK II — same landmark the harness's
#     qemu_boots_ovmf scenario uses.
if grep -q "BdsDxe" "$SERIAL_LOG" 2>/dev/null; then
    echo "visual-verify-boot: PASS — screenshot at $SCREEN_PPM"
    [[ -f "$SCREEN_PNG" ]] && echo "                   PNG  at $SCREEN_PNG"
    echo "                   serial landmark 'BdsDxe' present"
    exit 0
else
    echo "visual-verify-boot: PARTIAL — screenshot captured but BdsDxe landmark missing" >&2
    echo "                   review $SERIAL_LOG to diagnose" >&2
    exit 1
fi
