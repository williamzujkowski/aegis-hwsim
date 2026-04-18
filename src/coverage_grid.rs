//! Coverage-grid emitter.
//!
//! Iterates the persona library × scenario registry and produces a
//! grid of results, one cell per combination. Two output formats:
//!
//! - **`OutputFormat::Json`** — `schema_version=1` envelope (matches
//!   the `aegis-hwsim list-personas --json` family convention).
//!   Suitable for downstream tooling.
//! - **`OutputFormat::Markdown`** — human-readable table (rows =
//!   personas, columns = scenarios, cells = PASS/FAIL/SKIP).
//!
//! The runner can operate in two modes:
//!
//! - **Live**: actually invokes each scenario. Slow on a runner with
//!   real QEMU + signed sticks; useful for nightly CI.
//! - **Dry-run**: every cell is recorded as `Skip { reason:
//!   "dry-run" }` without invoking the scenario. Fast CI artifact —
//!   shows the matrix shape + the prerequisites each scenario flags
//!   as missing.
//!
//! No I/O on the file system beyond what scenarios themselves do.

use crate::persona::Persona;
use crate::scenario::{Registry, Scenario, ScenarioContext, ScenarioError, ScenarioResult};
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// One cell of the grid: result of running `scenario` against `persona`.
#[derive(Debug, Clone)]
pub struct GridCell {
    /// Persona id (e.g. `lenovo-thinkpad-x1-carbon-gen11`).
    pub persona_id: String,
    /// Scenario name (e.g. `signed-boot-ubuntu`).
    pub scenario_name: &'static str,
    /// Either the typed result, or the runner-error message (Err
    /// gets surfaced as a synthetic Fail cell so the grid stays
    /// rectangular).
    pub outcome: CellOutcome,
    /// Wall-clock duration of the cell's run. Zero when `dry-run`.
    pub duration: Duration,
}

/// Cell-level outcome. `RunnerError` is distinct from
/// `Result(Fail{..})` because a runner error is a defect-to-fix
/// (missing binary, bad stick path), not a test failure.
#[derive(Debug, Clone)]
pub enum CellOutcome {
    /// Scenario completed and returned a typed result.
    Result(ScenarioResult),
    /// Scenario runner errored — render in the grid as a synthetic
    /// FAIL with a "runner error: …" reason.
    RunnerError(String),
}

impl CellOutcome {
    /// One of `PASS`, `FAIL`, `SKIP`, or `ERROR` (synthetic).
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Result(r) => r.label(),
            Self::RunnerError(_) => "ERROR",
        }
    }
    /// One-line operator-facing reason (or empty for `Pass`).
    #[must_use]
    pub fn reason(&self) -> &str {
        match self {
            Self::Result(r) => r.reason(),
            Self::RunnerError(msg) => msg,
        }
    }
}

/// Output format selected via the CLI flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// `schema_version=1` JSON envelope.
    Json,
    /// Human-readable Markdown table.
    Markdown,
}

/// Configuration for [`compute_grid`].
#[derive(Debug, Clone)]
pub struct GridConfig {
    /// Per-cell working dir parent. Each cell gets a subdirectory
    /// `<work_root>/<persona-id>__<scenario-name>/`.
    pub work_root: PathBuf,
    /// Firmware-root passed into every scenario context.
    pub firmware_root: PathBuf,
    /// Stick path passed into every scenario context. Most scenarios
    /// will Skip on a non-existent path (which is the point under
    /// dry-run).
    pub stick: PathBuf,
    /// `true` → record every cell as `Skip { reason: "dry-run" }`
    /// without invoking the scenario.
    pub dry_run: bool,
}

/// Compute the grid: one cell per (persona, scenario) combination.
/// Personas iterated in the order [`crate::loader::load_all`] returns
/// (sorted by id); scenarios iterated in registration order.
#[must_use]
pub fn compute_grid(personas: &[Persona], registry: &Registry, cfg: &GridConfig) -> Vec<GridCell> {
    let mut cells = Vec::with_capacity(personas.len() * registry.len());
    for persona in personas {
        for (scenario_name, _) in registry.iter() {
            // `find` is guaranteed Some here because we just iterated
            // the same registry; if a future refactor breaks that
            // invariant, fall through with a synthetic ERROR cell
            // rather than panicking.
            let Some(scenario) = registry.find(scenario_name) else {
                cells.push(GridCell {
                    persona_id: persona.id.clone(),
                    scenario_name,
                    outcome: CellOutcome::RunnerError(
                        "internal: registry iter/find disagreement".to_string(),
                    ),
                    duration: Duration::ZERO,
                });
                continue;
            };
            let cell = run_one_cell(persona, scenario, cfg);
            cells.push(cell);
        }
    }
    cells
}

fn run_one_cell(persona: &Persona, scenario: &dyn Scenario, cfg: &GridConfig) -> GridCell {
    let cell_work_dir = cfg
        .work_root
        .join(format!("{}__{}", persona.id, scenario.name()));

    if cfg.dry_run {
        return GridCell {
            persona_id: persona.id.clone(),
            scenario_name: scenario.name(),
            outcome: CellOutcome::Result(ScenarioResult::Skip {
                reason: "dry-run".to_string(),
            }),
            duration: Duration::ZERO,
        };
    }

    let ctx = ScenarioContext {
        persona: persona.clone(),
        stick: cfg.stick.clone(),
        work_dir: cell_work_dir,
        firmware_root: cfg.firmware_root.clone(),
    };

    let start = Instant::now();
    let outcome = match scenario.run(&ctx) {
        Ok(r) => CellOutcome::Result(r),
        Err(e) => CellOutcome::RunnerError(format_runner_error(&e)),
    };
    let duration = start.elapsed();

    GridCell {
        persona_id: persona.id.clone(),
        scenario_name: scenario.name(),
        outcome,
        duration,
    }
}

fn format_runner_error(e: &ScenarioError) -> String {
    format!("runner error: {e}")
}

/// Render a grid in the requested format. Markdown is operator-facing
/// (sticky column = persona id, columns = scenario names); JSON is the
/// `schema_version=1` envelope.
#[must_use]
pub fn render(cells: &[GridCell], registry: &Registry, format: OutputFormat) -> String {
    match format {
        OutputFormat::Json => render_json(cells),
        OutputFormat::Markdown => render_markdown(cells, registry),
    }
}

fn render_json(cells: &[GridCell]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(cells.len() * 200);
    out.push_str("{\n");
    out.push_str("  \"schema_version\": 1,\n");
    out.push_str("  \"tool\": \"aegis-hwsim\",\n");
    let _ = writeln!(
        out,
        "  \"tool_version\": \"{}\",",
        env!("CARGO_PKG_VERSION")
    );
    out.push_str("  \"cells\": [\n");
    let last = cells.len().saturating_sub(1);
    for (i, c) in cells.iter().enumerate() {
        let comma = if i == last { "" } else { "," };
        out.push_str("    {\n");
        let _ = writeln!(
            out,
            "      \"persona_id\": \"{}\",",
            json_escape(&c.persona_id)
        );
        let _ = writeln!(
            out,
            "      \"scenario_name\": \"{}\",",
            json_escape(c.scenario_name)
        );
        let _ = writeln!(out, "      \"result\": \"{}\",", c.outcome.label());
        let _ = writeln!(
            out,
            "      \"reason\": \"{}\",",
            json_escape(c.outcome.reason())
        );
        let _ = writeln!(out, "      \"duration_ms\": {}", c.duration.as_millis());
        let _ = writeln!(out, "    }}{comma}");
    }
    out.push_str("  ]\n");
    out.push_str("}\n");
    out
}

fn render_markdown(cells: &[GridCell], registry: &Registry) -> String {
    use std::fmt::Write as _;
    let scenarios: Vec<&'static str> = registry.iter().map(|(n, _)| n).collect();
    let mut personas: Vec<String> = cells.iter().map(|c| c.persona_id.clone()).collect();
    personas.sort();
    personas.dedup();

    let mut out = String::with_capacity(cells.len() * 80);
    out.push_str("# aegis-hwsim coverage grid\n\n");
    let _ = writeln!(
        out,
        "{} persona(s) × {} scenario(s) = {} cell(s).\n",
        personas.len(),
        scenarios.len(),
        cells.len()
    );
    // Header row.
    out.push_str("| persona |");
    for s in &scenarios {
        let _ = write!(out, " {s} |");
    }
    out.push('\n');
    // Separator.
    out.push_str("|---|");
    for _ in &scenarios {
        out.push_str("---|");
    }
    out.push('\n');
    // Data rows.
    for p in &personas {
        let _ = write!(out, "| {p} |");
        for s in &scenarios {
            let cell = cells
                .iter()
                .find(|c| c.persona_id == *p && c.scenario_name == *s);
            let label = cell.map_or("?", |c| c.outcome.label());
            let _ = write!(out, " {label} |");
        }
        out.push('\n');
    }
    out.push('\n');
    // Reasons section — gives the operator the SKIP/FAIL details
    // without bloating the table.
    out.push_str("## Cell details\n\n");
    for c in cells {
        let r = c.outcome.reason();
        if r.is_empty() {
            continue;
        }
        let _ = writeln!(
            out,
            "- `{}` × `{}` — **{}**: {}",
            c.persona_id,
            c.scenario_name,
            c.outcome.label(),
            r
        );
    }
    out
}

/// Minimal JSON string escape — covers `"`, `\`, control chars, newline,
/// tab. Matches the existing pattern in `aegis-hwsim list-personas
/// --json` so the family parses uniformly.
fn json_escape(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn fake_persona(id: &str) -> Persona {
        let yaml = format!(
            "
schema_version: 1
id: {id}
vendor: QEMU
display_name: {id}
source:
  kind: vendor_docs
  ref_: test
dmi:
  sys_vendor: QEMU
  product_name: Standard PC
  bios_vendor: EDK II
  bios_version: stable
  bios_date: 01/01/2024
secure_boot:
  ovmf_variant: ms_enrolled
tpm:
  version: none
"
        );
        serde_yaml::from_str(&yaml).unwrap()
    }

    /// A minimal scenario for grid tests — always returns the result
    /// it was constructed with.
    struct CannedScenario {
        name: &'static str,
        result: ScenarioResult,
    }
    impl Scenario for CannedScenario {
        fn name(&self) -> &'static str {
            self.name
        }
        fn description(&self) -> &'static str {
            "test"
        }
        fn run(&self, _ctx: &ScenarioContext) -> Result<ScenarioResult, ScenarioError> {
            Ok(self.result.clone())
        }
    }

    fn fake_cfg() -> GridConfig {
        GridConfig {
            work_root: tempfile::tempdir().unwrap().path().to_path_buf(),
            firmware_root: PathBuf::from("/usr/share/OVMF"),
            stick: PathBuf::from("/no/such/stick"),
            dry_run: false,
        }
    }

    #[test]
    fn dry_run_skips_every_cell_without_invoking_scenarios() {
        let mut r = Registry::empty();
        // If the scenario actually ran, this would Pass — but dry-run
        // should preempt and emit Skip.
        r.register(Box::new(CannedScenario {
            name: "x",
            result: ScenarioResult::Pass,
        }));
        let p = vec![fake_persona("a"), fake_persona("b")];
        let mut cfg = fake_cfg();
        cfg.dry_run = true;
        let cells = compute_grid(&p, &r, &cfg);
        assert_eq!(cells.len(), 2);
        for cell in &cells {
            assert_eq!(cell.outcome.label(), "SKIP");
            assert_eq!(cell.outcome.reason(), "dry-run");
            assert_eq!(cell.duration, Duration::ZERO);
        }
    }

    #[test]
    fn live_grid_runs_each_combination() {
        let mut r = Registry::empty();
        r.register(Box::new(CannedScenario {
            name: "alpha",
            result: ScenarioResult::Pass,
        }));
        r.register(Box::new(CannedScenario {
            name: "beta",
            result: ScenarioResult::Fail {
                reason: "test-fail".into(),
            },
        }));
        let p = vec![fake_persona("p1"), fake_persona("p2")];
        let cells = compute_grid(&p, &r, &fake_cfg());
        // 2 personas × 2 scenarios = 4 cells.
        assert_eq!(cells.len(), 4);
        // Two PASS, two FAIL — order: (p1,alpha) PASS, (p1,beta) FAIL,
        // (p2,alpha) PASS, (p2,beta) FAIL.
        assert_eq!(cells[0].outcome.label(), "PASS");
        assert_eq!(cells[1].outcome.label(), "FAIL");
        assert_eq!(cells[1].outcome.reason(), "test-fail");
        assert_eq!(cells[2].outcome.label(), "PASS");
        assert_eq!(cells[3].outcome.label(), "FAIL");
    }

    #[test]
    fn render_json_emits_schema_version_envelope() {
        let cells = vec![GridCell {
            persona_id: "p1".into(),
            scenario_name: "scenario-x",
            outcome: CellOutcome::Result(ScenarioResult::Pass),
            duration: Duration::from_millis(1234),
        }];
        let json = render_json(&cells);
        assert!(json.contains("\"schema_version\": 1"));
        assert!(json.contains("\"tool\": \"aegis-hwsim\""));
        assert!(json.contains("\"persona_id\": \"p1\""));
        assert!(json.contains("\"scenario_name\": \"scenario-x\""));
        assert!(json.contains("\"result\": \"PASS\""));
        assert!(json.contains("\"duration_ms\": 1234"));
    }

    #[test]
    fn render_markdown_includes_table_and_reasons_section() {
        let mut r = Registry::empty();
        r.register(Box::new(CannedScenario {
            name: "smoke",
            result: ScenarioResult::Skip {
                reason: "missing dep".into(),
            },
        }));
        let cells = vec![GridCell {
            persona_id: "alpha".into(),
            scenario_name: "smoke",
            outcome: CellOutcome::Result(ScenarioResult::Skip {
                reason: "missing dep".into(),
            }),
            duration: Duration::from_millis(5),
        }];
        let md = render_markdown(&cells, &r);
        assert!(md.contains("# aegis-hwsim coverage grid"));
        assert!(md.contains("| persona |"));
        assert!(md.contains("| smoke |"));
        assert!(md.contains("| alpha |"));
        assert!(md.contains("SKIP"));
        assert!(md.contains("missing dep"));
    }

    #[test]
    fn runner_error_renders_as_synthetic_error_cell() {
        struct ErroringScenario;
        impl Scenario for ErroringScenario {
            fn name(&self) -> &'static str {
                "broken"
            }
            fn description(&self) -> &'static str {
                "broken"
            }
            fn run(&self, _ctx: &ScenarioContext) -> Result<ScenarioResult, ScenarioError> {
                Err(ScenarioError::UnsupportedPersona {
                    scenario: "broken",
                    persona: "any".into(),
                    reason: "test".into(),
                })
            }
        }
        let mut r = Registry::empty();
        r.register(Box::new(ErroringScenario));
        let cells = compute_grid(&[fake_persona("p")], &r, &fake_cfg());
        assert_eq!(cells.len(), 1);
        assert_eq!(cells[0].outcome.label(), "ERROR");
        assert!(cells[0].outcome.reason().contains("runner error"));
    }
}
