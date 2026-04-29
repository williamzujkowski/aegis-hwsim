#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# audit-no-test-keys.sh — release-gate audit refusing publish if any
# `TEST_ONLY_NOT_FOR_PRODUCTION` keyring material would ship to crates.io.
#
# Why a script (not build.rs):
#   build.rs runs on every `cargo build`/`cargo test` — wrong layer for
#   a release-time guard. It would also fight with local development
#   (a contributor with a generated test keyring under firmware/ would
#   see their builds fail). This script runs at the publish boundary,
#   exactly where the security constraint matters.
#
# Per CLAUDE.md "Security constraints #4" + aegis-hwsim epic E5 (#5):
#   "Test Secure Boot keys — PK/KEK/db MUST carry
#    `TEST_ONLY_NOT_FOR_PRODUCTION` in CN. Generated on first run.
#    Never ship in published artifacts."
#
# This audit verifies BOTH halves of the contract:
#   1. Cargo.toml's `exclude` list still keeps firmware/test-keyring/**
#      out of the cargo package. (Drift detection.)
#   2. No file inside the would-be-published artifact contains the
#      `TEST_ONLY_NOT_FOR_PRODUCTION` token. (Defense in depth — catches
#      a forgotten test fixture or copy-pasted CN that snuck out of the
#      excluded directory.)
#
# Usage:
#   ./scripts/audit-no-test-keys.sh [package-list-file]
#
#   With no argument, runs `cargo package --list --allow-dirty` and
#   audits the resulting file list. With an argument, treats the file
#   as a pre-computed `cargo package --list` output (one path per line).
#
# Exit codes:
#   0  no forbidden material would publish
#   1  forbidden material detected — refuses publish
#   2  audit failed to run (cargo missing, etc.)

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

FORBIDDEN_TOKEN="TEST_ONLY_NOT_FOR_PRODUCTION"
EXCLUDED_DIR_PREFIX="firmware/test-keyring/"

# 1) Enumerate the file list cargo would publish.
PACKAGE_LIST="${1:-}"
if [[ -z "$PACKAGE_LIST" ]]; then
    if ! command -v cargo >/dev/null 2>&1; then
        echo "audit-no-test-keys: ERROR — cargo not on PATH" >&2
        exit 2
    fi
    # `--allow-dirty` lets the audit run on uncommitted CI checkouts.
    # `--list` prints the file paths cargo would tar; no actual archive
    # is produced. `cargo package --list` exits 0 even on clean repos
    # and emits one path per line relative to crate root.
    PACKAGE_LIST_TMP="$(mktemp)"
    trap 'rm -f "$PACKAGE_LIST_TMP"' EXIT
    if ! cargo package --list --allow-dirty >"$PACKAGE_LIST_TMP" 2>/dev/null; then
        echo "audit-no-test-keys: ERROR — \`cargo package --list\` failed" >&2
        exit 2
    fi
    PACKAGE_LIST="$PACKAGE_LIST_TMP"
fi

if [[ ! -r "$PACKAGE_LIST" ]]; then
    echo "audit-no-test-keys: ERROR — package list not readable: $PACKAGE_LIST" >&2
    exit 2
fi

# 2) Drift check: no path under the excluded directory should appear.
EXCLUDED_HITS="$(grep -E "^${EXCLUDED_DIR_PREFIX}" "$PACKAGE_LIST" || true)"
if [[ -n "$EXCLUDED_HITS" ]]; then
    echo "audit-no-test-keys: FAIL — Cargo.toml exclude list drift" >&2
    echo "" >&2
    echo "The following files under '${EXCLUDED_DIR_PREFIX}' are about to" >&2
    echo "be packaged. They must stay excluded — they're test keyring" >&2
    echo "material with TEST_ONLY_NOT_FOR_PRODUCTION CNs." >&2
    echo "" >&2
    echo "$EXCLUDED_HITS" >&2
    echo "" >&2
    echo "Fix: re-check Cargo.toml [package].exclude includes" >&2
    echo "     'firmware/test-keyring/**' (and rebuild Cargo.lock if needed)." >&2
    exit 1
fi

# 3) Token sweep: scan suspicious-extension files in the package list
#    for the placeholder marker. Catches a leaked cert, a generated
#    keyring blob, or a UEFI VARS fixture that escaped the excluded
#    directory.
#
#    Scope is deliberately narrow — we DON'T audit every .rs, .md, .yaml,
#    or .json file because the token legitimately appears in:
#    * src/loader.rs (defines the PLACEHOLDER_TOKEN constant — the
#      string IS the policy)
#    * src/persona.rs + schemas/persona.schema.json (docstrings
#      explaining the security constraint)
#    * tests/fixtures/bad-placeholder-token.yaml (negative test
#      that deliberately includes the token)
#
#    The risk this audit guards against is binary key material with
#    a `TEST_ONLY_NOT_FOR_PRODUCTION` CN slipping into the package —
#    that's `.fd` / `.pem` / `.key` / `.crt` / `.der` / `.cer` / `.efi`
#    / `.esl` files plus anything under firmware/ regardless of
#    extension. We sweep that subset for the token.
#
#    `grep -l` (well, `quiet --fixed-strings`) reports presence, not
#    contents, so we don't accidentally dump secrets into CI logs.
suspicious_path() {
    local path="$1"
    case "$path" in
        firmware/*) return 0 ;;
        *.fd|*.pem|*.key|*.crt|*.der|*.cer|*.efi|*.esl|*.auth) return 0 ;;
        *) return 1 ;;
    esac
}

TOKEN_HITS=()
while IFS= read -r path; do
    [[ -z "$path" ]] && continue
    [[ ! -f "$path" ]] && continue
    if ! suspicious_path "$path"; then
        continue
    fi
    if grep --binary-files=text --quiet --fixed-strings -- "$FORBIDDEN_TOKEN" "$path"; then
        TOKEN_HITS+=("$path")
    fi
done < "$PACKAGE_LIST"

if [[ ${#TOKEN_HITS[@]} -gt 0 ]]; then
    echo "audit-no-test-keys: FAIL — TEST_ONLY_NOT_FOR_PRODUCTION token in package" >&2
    echo "" >&2
    echo "The following files would publish to crates.io with the test-only" >&2
    echo "marker token in them. This violates CLAUDE.md security constraint" >&2
    echo "#4 — test keyring material must never ship." >&2
    echo "" >&2
    for f in "${TOKEN_HITS[@]}"; do
        echo "  - $f" >&2
    done
    echo "" >&2
    echo "Fix: either remove the test material from these files, or add" >&2
    echo "     them to Cargo.toml [package].exclude." >&2
    exit 1
fi

echo "audit-no-test-keys: PASS — no test keyring material in cargo package"
exit 0
