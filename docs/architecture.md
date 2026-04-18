# aegis-hwsim architecture

How the modules fit together. Read this before [persona-authoring.md](persona-authoring.md) or [scenario-authoring.md](scenario-authoring.md) — those tell you HOW to extend the harness; this tells you WHY it's shaped the way it is.

## Module dependency graph

```
              ┌────────────────┐
              │  persona.rs    │  YAML schema types (serde + JsonSchema)
              └────────┬───────┘
                       │
              ┌────────▼───────┐
              │   loader.rs    │  scan personas/*.yaml + 5 guards
              └────────┬───────┘
                       │
                       │ (validated Persona)
                       │
        ┌──────────────┼──────────────┐
        │              │              │
┌───────▼──────┐ ┌─────▼──────┐ ┌─────▼──────┐
│  smbios.rs   │ │  ovmf.rs   │ │  swtpm.rs  │  pure transforms +
│  Dmi → argv  │ │  variant → │ │  per-run   │  per-run subprocess
│              │ │  CODE+VARS │ │  lifecycle │
└──────┬───────┘ └─────┬──────┘ └─────┬──────┘
       │               │              │
       └───────────────┼──────────────┘
                       │
              ┌────────▼───────┐
              │   qemu.rs      │  Invocation::new composes everything
              │  Invocation    │  into a std::process::Command
              └────────┬───────┘
                       │
                       │ (Command, ready to spawn)
                       │
              ┌────────▼───────┐
              │   serial.rs    │  spawns + tees stdout to log + buffer
              │  SerialCapture │  wait_for_line() polling API
              └────────┬───────┘
                       │
                       │ (live process + buffer access)
                       │
              ┌────────▼───────┐
              │  scenario.rs   │  Scenario trait + Registry + ScenarioResult
              │  + scenarios/  │  concrete scenarios consume serial → assert
              └────────┬───────┘
                       │
                       │ (Pass / Fail / Skip)
                       │
       ┌───────────────┼───────────────┐
       │               │               │
┌──────▼─────┐ ┌──────▼──────┐ ┌──────▼─────┐
│ bin/aegis- │ │ coverage_   │ │ doctor.rs  │  Aggregators —
│ hwsim.rs   │ │ grid.rs     │ │            │  read from registry,
│  CLI       │ │  matrix     │ │  host env  │  emit reports.
└────────────┘ └─────────────┘ └────────────┘
```

## Two design discipline rules

### 1. Pure-then-impure layering

Every module that does I/O has a pure inner function and a thin I/O wrapper:

| Module | Pure function | Impure wrapper |
|---|---|---|
| `smbios` | `smbios_argv(&Dmi) -> Result<Vec<String>>` (no I/O at all) | n/a — pure end-to-end |
| `ovmf` | (resolution is essentially pure path math) | `resolve()` does `fs::canonicalize` for the path-boundary check |
| `swtpm` | `SwtpmSpec::derive(run_id, work_root, version)` (path computation) | `SwtpmInstance::spawn(&spec)` (subprocess + state dir creation) |
| `qemu` | `build_argv(persona, paths, stick, swtpm)` | `Invocation::new()` (resolves OVMF, copies VARS, calls `build_argv`) |
| `serial` | `SerialBuffer::push` (in-memory append + cap eviction) | `SerialCapture::spawn(cmd, log_path)` (process + reader thread) |
| `coverage_grid` | `compute_grid(personas, registry, cfg)` (calls scenario.run) | n/a — orchestrator only |
| `doctor` | (PATH lookup + file exists checks; minimal I/O) | `run(&firmware_root)` |

Why: makes every module unit-testable without having to mock subprocess / filesystem state. Tests that need a fake binary use `spawn_with_binary("sleep", ...)` — same shape, different binary.

### 2. Skip is first-class

`ScenarioResult::Skip { reason }` is a peer of `Pass` and `Fail`, not a degraded `Fail`. This matters because:

- A scenario handed a persona it doesn't apply to (e.g., qemu-boots-ovmf with a TPM persona) returns `Skip`, not `Fail`. The coverage-grid renders it as SKIP, not the noisier FAIL/ERROR.
- A scenario whose prerequisites aren't met (no qemu on PATH, no signed stick provisioned) returns `Skip` with the specific missing dep as the reason. CI greps `SKIP:` and treats as N/A, never lying about coverage we don't have.
- A scenario that crashed the runner (bad persona input, I/O failure) returns `ScenarioError` (Err), which the grid renders as ERROR — that's distinct from a test failure.

Three-bucket reporting (Pass / Skip / Fail / runner-Error) is what lets the harness be honest about coverage as the persona × scenario matrix grows.

## Trust boundary diagram

```
   YAML                   Rust process              QEMU (spawned subprocess)
  (Tier 2)                  (Tier 1)                       (Tier 1)
                                                  
┌──────────┐  serde   ┌──────────────┐  Command  ┌─────────────────┐
│ persona  ├─────────▶│  Persona     ├──────────▶│  qemu-system-   │
│  *.yaml  │ +5 guards│  + sub-types │  ::args() │  x86_64         │
└──────────┘          └──────────────┘  (no sh)  └─────────────────┘
                              │                          │
                              │ NUL rejection            │ stdout
                              │ comma-escape             │
                              │ path-boundary            ▼
                              │                  ┌─────────────────┐
                              ▼                  │ SerialCapture   │
                      ┌───────────────┐          │ + log file      │
                      │ Invocation::  │          │ + bounded buf   │
                      │ build()       │          └─────────────────┘
                      │  → Command    │                  │
                      └───────────────┘                  │ wait_for_line
                                                         │
                                                  ┌──────▼─────┐
                                                  │  Scenario  │  asserts
                                                  │  ::run()   │  Pass/Fail
                                                  └────────────┘
```

Rules:

1. **No shell anywhere in the chain.** `Command::args()` passes argv as literals. Every persona DMI string passes through unmodified. The 60k random-input fuzz in `tests/fuzz_invocation.rs` exercises this contract.
2. **NUL rejection at the smbios boundary.** Argv elements containing NUL panic in `Command::args()` on Unix; we reject upfront with a typed error.
3. **Path-boundary defense, twice.** `loader.rs` rejects `custom_keyring` outside `firmware_root` at parse time. `ovmf::resolve` repeats the check at the QEMU boundary, post-canonicalize, so a future refactor that bypasses the loader can't escape.
4. **OVMF_VARS sandbox.** `qemu::Invocation` copies the VARS template into `work_dir/OVMF_VARS.fd`, then re-canonicalizes and verifies the result is still under `work_root` — symlink swap-in defense (E2.7).

## Invocation lifecycle

A typical scenario run:

```
1. Persona loaded:        loader::load_all()                (5 guards)
2. swtpm spawned:         SwtpmInstance::spawn(&spec)       (drop-guard)
3. OVMF paths resolved:   ovmf::resolve(variant, ...)       (path-boundary)
4. VARS copied per-run:   Invocation::new(...)              (vars sandbox)
5. argv composed:         qemu::build_argv(...)             (no shell)
6. QEMU spawned:          SerialCapture::spawn(cmd, log)    (reader thread)
7. Landmarks awaited:     SerialHandle::wait_for_line(...)  (polling)
8. Result returned:       Scenario::run() → ScenarioResult  (Pass/Fail/Skip)
9. Cleanup on drop:       SerialHandle::drop → SIGKILL + reap
                          SwtpmInstance::drop → SIGKILL + reap
```

Steps 2-9 happen inside one scenario invocation. Steps 1 + 6-9 are timed by the coverage-grid emitter — the per-cell `duration_ms` you see in `coverage-grid --format json`.

## Why this shape

Three constraints drove the architecture:

1. **CI must run end-to-end on Ubuntu without a signed stick.** That gave us the `qemu-boots-ovmf` smoke scenario (boots OVMF over an empty stick, asserts `BdsDxe`) — proves the whole pipeline every PR. Real signed-stick scenarios still skip on CI but their CODE is exercised.
2. **Personas are vendor data, not test logic.** Per the source-citation policy, every persona traces to a verified hardware-report or vendor spec. Adding personas is a YAML edit, not Rust. Adding scenarios is Rust + a registry registration.
3. **Coverage matrix has to be honest.** `Skip { reason }` is first-class so the grid never claims coverage we don't have. Reviewers click the per-PR `coverage-grid` artifact and see exactly which combinations were exercised vs skipped vs missed.

## See also

- [persona-authoring.md](persona-authoring.md) — schema reference + vendor DMI conventions
- [scenario-authoring.md](scenario-authoring.md) — Scenario trait contract + composition pattern
- [research/prior-art.md](research/prior-art.md) — adjacent tools (chipsec, fwts, LAVA, ...) and what we don't overlap
- [research/recent-projects.md](research/recent-projects.md) — 2025/2026 delta-scan + roadmap implications
- [research/arxiv-papers.md](research/arxiv-papers.md) — verified academic prior art
- [../CONTRIBUTING.md](../CONTRIBUTING.md) — quickstart + PR flow
