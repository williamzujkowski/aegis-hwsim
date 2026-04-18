# Authoring a new scenario

A **scenario** is a Rust struct that takes a `ScenarioContext` (persona + stick + work_dir + firmware_root) and asserts a specific boot-flow invariant. Adding one extends the harness to cover a new failure mode.

## The contract

```rust
pub trait Scenario {
    fn name(&self) -> &'static str;          // kebab-case, stable forever once published
    fn description(&self) -> &'static str;    // shown by `aegis-hwsim list-scenarios`
    fn run(&self, ctx: &ScenarioContext) -> Result<ScenarioResult, ScenarioError>;
}
```

Three invariants the trait enforces:

1. **Never panic.** Every code path returns a Result. A scenario that crashes the runner is a defect.
2. **Skip is first-class.** Returning `Ok(ScenarioResult::Skip { reason })` for missing prerequisites (no qemu, no stick, no swtpm) is the right choice — Skips don't pollute the matrix with FAIL/ERROR noise.
3. **Runner errors are distinct from test failures.** `ScenarioError` (Err) means the runner couldn't get far enough to attempt the assertion — bad input, missing binary, I/O problem. `ScenarioResult::Fail { reason }` (Ok) means the assertion was attempted and didn't hold.

## Where it lives

`src/scenarios/<name>.rs`. Add a `pub mod <name>;` line + `pub use <name>::<Type>;` to `src/scenarios/mod.rs`. Register in `src/scenario.rs::Registry::default_set` and update the `registry_default_set_includes_shipped_scenarios` test count.

## Two reference implementations

Read these before writing a new scenario:

- **`src/scenarios/qemu_boots_ovmf.rs`** — minimal, no-stick. Provisions a 1 MB empty file, spawns OVMF, asserts BdsDxe reaches serial. Self-contained; runs on CI without any signed artifact.
- **`src/scenarios/signed_boot_ubuntu.rs`** — full pipeline. Walks 4 boot-chain landmarks (shim → grub → kernel → kexec) with per-landmark timeouts. Skips on missing stick / qemu / swtpm.

## Standard skip gates

Every scenario should check, in order:

```rust
// 1. Required binaries on PATH.
if !binary_on_path("qemu-system-x86_64") {
    return Ok(ScenarioResult::Skip {
        reason: "qemu-system-x86_64 not on PATH (Debian: apt install qemu-system-x86)".into(),
    });
}

// 2. Persona compatibility — Skip rather than Fail when the persona
//    doesn't apply (e.g. a no-TPM scenario handed a TPM persona).
if !matches!(ctx.persona.tpm.version, TpmVersion::None) {
    return Ok(ScenarioResult::Skip {
        reason: format!("scenario is no-TPM only; persona {} requests TPM", ctx.persona.id),
    });
}

// 3. Stick prerequisites (if applicable).
if !ctx.stick.is_file() {
    return Ok(ScenarioResult::Skip {
        reason: format!("stick {} not found", ctx.stick.display()),
    });
}
```

Skipping over Failing for a scenario-doesn't-apply case keeps the coverage-grid clean.

## Composition pattern

Use the existing modules — don't roll your own QEMU invocation:

```rust
use crate::qemu::Invocation;
use crate::serial::SerialCapture;
use crate::swtpm::{SwtpmInstance, SwtpmSpec};

let swtpm_spec = SwtpmSpec::derive("scenario-name", &ctx.work_dir, ctx.persona.tpm.version);
let swtpm = SwtpmInstance::spawn(&swtpm_spec)?;

let inv = Invocation::new(
    &ctx.persona,
    &ctx.stick,
    &ctx.work_dir,
    &ctx.firmware_root,
    &swtpm,
)?;

let log_path = ctx.work_dir.join("serial.log");
let handle = SerialCapture::spawn(inv.build(), &log_path, None)?;

if handle.wait_for_line("expected marker", Duration::from_secs(60)).is_some() {
    Ok(ScenarioResult::Pass)
} else {
    Ok(ScenarioResult::Fail {
        reason: format!("'expected marker' not seen within 60s. Serial log: {}.", log_path.display()),
    })
}
```

The `?` operator on `Invocation::new`, `SwtpmInstance::spawn`, and `SerialCapture::spawn` propagates runner errors via `ScenarioError` (the `#[from]` impls handle the conversion).

## Registering

`src/scenarios/mod.rs`:

```rust
pub mod my_new_scenario;
pub use my_new_scenario::MyNewScenario;
```

`src/scenario.rs::Registry::default_set`:

```rust
pub fn default_set() -> Self {
    let mut r = Self::empty();
    r.register(Box::new(crate::scenarios::QemuBootsOvmf));
    r.register(Box::new(crate::scenarios::SignedBootUbuntu));
    r.register(Box::new(crate::scenarios::MyNewScenario));  // ← add here
    r
}
```

Update the test that pins the registry size:

```rust
fn registry_default_set_includes_shipped_scenarios() {
    let r = Registry::default_set();
    assert_eq!(r.len(), 3);  // ← bump
    assert!(r.find("my-new-scenario").is_some());  // ← add
    // ...
}
```

## Tests inside the scenario file

Mirror the reference scenarios:

```rust
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    // ...
    #[test]
    fn name_and_description_are_stable() {
        let s = MyNewScenario;
        assert_eq!(s.name(), "my-new-scenario");
        assert!(s.description().contains("relevant-keyword"));
    }
    #[test]
    fn skips_when_<prerequisite>_missing() { /* ... */ }
}
```

For scenarios that actually spawn QEMU (like `qemu-boots-ovmf`), also add a corresponding integration test under `tests/<name>_smoke.rs` that the CI workflow will exercise.

## CI

Once registered, your scenario shows up in:

- `aegis-hwsim list-scenarios`
- `aegis-hwsim coverage-grid` (tested against every persona)
- The CI `coverage-grid` artifact published per PR

If your scenario can run end-to-end on Ubuntu CI without a signed stick (like `qemu-boots-ovmf`), add a corresponding `tests/<name>_smoke.rs` integration test — it'll automatically run as part of `cargo test --locked` in CI.

## PR checklist

- [ ] Scenario in `src/scenarios/<name>.rs` with stable `name()`
- [ ] Re-exported from `src/scenarios/mod.rs`
- [ ] Registered in `Registry::default_set`
- [ ] `registry_default_set_includes_shipped_scenarios` test updated
- [ ] Standard skip gates for missing binaries / prerequisites
- [ ] `name_and_description_are_stable` test
- [ ] Skip-path test for at least one prerequisite
- [ ] If runnable without a signed stick, integration test under `tests/<name>_smoke.rs`
- [ ] `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test --locked` all pass
- [ ] CI green; check the coverage-grid artifact for sane cells
