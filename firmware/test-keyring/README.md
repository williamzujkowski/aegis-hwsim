# Test keyring directory

This directory holds **placeholder** OVMF VARS blobs used by personas that exercise the `custom_pk` Secure Boot variant. Files here are NOT real Secure Boot keyrings — they're 1 MB pseudo-random binaries committed to:

1. Exercise the loader's `custom_keyring` path-boundary check (the file must exist + canonicalize under `firmware/`).
2. Exercise `qemu::Invocation`'s OVMF_VARS copy logic for the `CustomPk` variant.
3. Exercise `coverage-grid`'s ability to enumerate every persona without erroring.

A persona referencing one of these files cannot actually boot — OVMF will reject a malformed VARS blob during firmware init. Real test keyrings (with `TEST_ONLY_NOT_FOR_PRODUCTION` baked into the CN per `aegis-boot#226` security-engineer constraint #4) are a follow-up; generation requires `openssl` + `virt-fw-vars` (or equivalent) to enroll PK + KEK + db. Tracked separately.

## Files

| File | Purpose |
|------|---------|
| `OVMF_VARS_test_pk.fd` | 1 MB pseudo-random placeholder. Referenced by `personas/qemu-custom-pk-sb.yaml`. |

## Why "test-keyring/" sub-path

Keeps test-only artifacts visually separated from real firmware files (which would live directly under `firmware/` if/when the harness ships its own OVMF builds). Also matches the per-persona convention of using a sub-path so `personas/<id>.yaml` can reference `test-keyring/<file>.fd` and the loader resolves it against `firmware_root`.

## Path resolution

The loader (`src/loader.rs::check_custom_keyring`) and the QEMU boundary (`src/ovmf.rs::verify_keyring_under_root`) both:

1. If `custom_keyring` is absolute, use as-is.
2. If relative, prepend `firmware_root` (default: `<repo>/firmware/`).
3. `fs::canonicalize` the result (resolves symlinks).
4. Require `canon.starts_with(firmware_root_canon)` — escape paths are rejected.
