# Contributing to aegis-hwsim

Thanks for considering a contribution. This is the test harness for [aegis-boot](https://github.com/williamzujkowski/aegis-boot)'s signed-chain USB-rescue flow; the bar for changes is "would you trust this in your boot path?"

## Quickstart for first-time contributors

```bash
# Verify your host has everything we need
cargo run --release --bin aegis-hwsim -- doctor

# Build + test
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --locked

# See the matrix this build would run
cargo run --release --bin aegis-hwsim -- coverage-grid
```

If `doctor` flags FAIL, fix that first; most issues are missing apt packages (`qemu-system-x86`, `ovmf`, `swtpm`).

Then read [docs/architecture.md](docs/architecture.md) before opening a non-trivial PR — it explains how persona → ovmf → swtpm → Invocation → SerialCapture → scenario fits together, what the trust boundaries are, and why the harness is shaped the way it is.

## What we accept

| Type of change | Accepted? | Notes |
|---|---|---|
| New persona for a real shipping laptop | Yes | See [docs/persona-authoring.md](docs/persona-authoring.md). Source citation required. |
| New scenario asserting a boot-flow invariant | Yes | See [docs/scenario-authoring.md](docs/scenario-authoring.md). Must register in `Registry::default_set`. |
| New test for an existing module | Yes | Especially edge cases the fuzz didn't catch. |
| Refactor that improves clarity | Yes | Must keep all existing tests green + add a test if it caught a real defect. |
| Refactor "for cleanness" with no test improvement | No | We avoid churn. See aegis-boot CLAUDE.md "refactor threshold" §. |
| New dependency | Discuss first | Open an issue. The crate currently uses serde, serde_json, serde_yaml, schemars, thiserror, and tempfile (dev). Each addition is justified. |
| New CLI subcommand | Yes if scoped | Must have a `--help` line + `print_help` entry. |

## Source-citation policy

Every external claim — README, design docs, persona quirks — links to a primary source. The `personas/` policy is strict:

- Real persona = `kind: community_report` with a closed `hardware-report` issue URL on the aegis-boot repo, AND a real operator confirmed the full flash → boot → kexec chain works.
- Otherwise = `kind: vendor_docs` with the source flagged as "PLACEHOLDER pending a real community hardware-report" in a comment.

This matches the [aegis-boot compat DB policy](https://github.com/williamzujkowski/aegis-boot/blob/main/docs/HARDWARE_COMPAT.md): **verified outcomes only**.

## Lint policy

- `unsafe_code = "forbid"` (workspace).
- `unwrap_used = "deny"` and `expect_used = "deny"` in production code. Tests opt back out at the `#[cfg(test)] mod tests` boundary with `#![allow(clippy::unwrap_used, clippy::expect_used)]`.
- All clippy lints must pass under `-D warnings`. CI runs `cargo clippy --all-targets -- -D warnings`.
- `cargo fmt --check` must pass. Run `cargo fmt` before pushing — CI's nightly rustfmt sometimes wraps long lines that local stable rustfmt doesn't, so your local fmt may not catch everything until CI.

## Pull request flow

1. Branch off `main`: `git checkout -b feat/<short-description>` or `fix/<short>` or `docs/<short>`.
2. Commit with a Conventional-Commits prefix: `feat(persona):`, `fix(qemu):`, `test(fuzz):`, `docs(readme):`, etc.
3. Run the full local validation: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test --locked`.
4. Push + open the PR. Title in present tense, summary under 200 characters.
5. The PR description should include a **Test plan** checklist mirroring the family pattern; see merged PRs for examples.

## Co-author footer

The aegis family uses a `Co-Authored-By:` footer on every commit. Pick the form matching your contribution:

```
Co-Authored-By: Your Name <your@email>
```

For AI-assisted contributions, use the upstream form (we use Claude in this project):

```
Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
```

## CI matrix

Every PR runs:

- `cargo fmt --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test --locked` (90+ tests including 60k random-input fuzz)
- `aegis-hwsim gen-schema --check schemas/persona.schema.json` — drift gate
- `aegis-hwsim coverage-grid` — outputs the matrix as a build artifact (markdown + JSON)
- The `qemu-boots-ovmf` smoke scenario actually spawns QEMU+OVMF and asserts BdsDxe reaches serial — proves the harness wiring on every PR

CI install footprint: `qemu-system-x86 ovmf` via apt. We deliberately don't install `swtpm` in CI yet because the smoke scenario uses a `TpmVersion::None` persona — when we add a TPM-bearing scenario that runs without a signed stick, we'll add swtpm to CI then.

## Scope reminders

We **do** validate:

- DMI / SMBIOS strings the kernel exposes at `/sys/class/dmi/id/`
- Secure Boot postures via OVMF variants (MS-enrolled / custom-PK / setup-mode / disabled)
- TPM 1.2 / 2.0 presence via swtpm
- Kernel lockdown modes
- aegis-boot's signed-chain assertions

We **do not** validate (out of scope):

- Vendor UEFI UI flows (Lenovo blue MOK Manager, Dell F12, HP Fast Boot)
- Kernel vendor-quirk paths (`thinkpad_acpi`, `dell-laptop`, etc.)
- EC quirks, USB controller firmware, hardware errata
- UEFI firmware fuzzing (use [chipsec](https://github.com/chipsec/chipsec))

If you propose a change that crosses into out-of-scope territory, that's not necessarily a no — but please open a discussion issue first so we can decide if it warrants expanding scope.
