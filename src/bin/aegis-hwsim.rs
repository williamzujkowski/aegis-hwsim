//! `aegis-hwsim` CLI. Hand-rolled argv parser (no clap, matching
//! the aegis-boot family convention) dispatching seven subcommands:
//! `validate`, `list-personas`, `gen-schema`, `run`, `list-scenarios`,
//! `coverage-grid`, `doctor`.

#![forbid(unsafe_code)]

use aegis_hwsim::loader::{load_all, LoadError, LoadOptions};
use aegis_hwsim::persona::{Persona, SourceKind};
use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

/// Look up the value following `--flag` in an argv slice. Returns
/// `None` when the flag is absent or the flag is the final argv
/// token (no value to consume). Exact-equality match on the flag
/// name — `--firmware-root-extra` does NOT match `--firmware-root`.
///
/// `--flag=value` form is intentionally unsupported; the CLI uses
/// space-separated values throughout, matching the aegis-boot family
/// convention. If the operator writes `--flag=value`, the whole
/// `--flag=value` token won't equal `--flag` and the helper returns
/// `None` (the caller then falls back to default or errors).
fn flag_value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

/// Look up `--flag <PATH>` returning a `PathBuf` or the supplied default.
/// Convenience wrapper around `flag_value` for the common path-flag pattern.
fn flag_path_or(args: &[String], flag: &str, default: &str) -> PathBuf {
    flag_value(args, flag).map_or_else(|| PathBuf::from(default), PathBuf::from)
}

/// Resolve the current working directory or print a clear error and
/// exit. The CLI relies on cwd to find `personas/` and `firmware/` (see
/// `LoadOptions::default_at`); falling back to "." silently — as the
/// previous `unwrap_or_else(|_| PathBuf::from("."))` did — would let
/// the harness silently target the wrong filesystem location.
fn cwd_or_exit() -> Result<PathBuf, ExitCode> {
    env::current_dir().map_err(|e| {
        eprintln!("aegis-hwsim: cannot read current working directory: {e}");
        ExitCode::from(1)
    })
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("list-personas") => run_list(&args[1..]),
        Some("validate") => run_validate(&args[1..]),
        Some("gen-schema") => run_gen_schema(&args[1..]),
        Some("run") => run_scenario(&args[1..]),
        Some("list-scenarios") => run_list_scenarios(&args[1..]),
        Some("coverage-grid") => run_coverage_grid(&args[1..]),
        Some("doctor") => run_doctor(&args[1..]),
        Some("-h" | "--help" | "help") | None => {
            print_help();
            ExitCode::SUCCESS
        }
        Some("--version" | "version") => {
            // Match aegis-boot --version --json (PR #205): scriptable
            // consumers can parse without regex on the human string.
            if args.iter().any(|a| a == "--json") {
                println!("{{");
                println!("  \"schema_version\": 1,");
                println!("  \"tool\": \"aegis-hwsim\",");
                println!("  \"version\": \"{}\"", env!("CARGO_PKG_VERSION"));
                println!("}}");
            } else {
                println!("aegis-hwsim v{}", env!("CARGO_PKG_VERSION"));
            }
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("aegis-hwsim: unknown subcommand '{other}'");
            eprintln!("run 'aegis-hwsim --help' for usage");
            ExitCode::from(2)
        }
    }
}

fn print_help() {
    println!("aegis-hwsim — hardware-persona matrix harness for aegis-boot");
    println!();
    println!("USAGE:");
    println!("  aegis-hwsim list-personas [--json]  List YAML fixtures under personas/");
    println!("  aegis-hwsim validate [--quiet]      Validate all personas against the schema");
    println!("  aegis-hwsim gen-schema [--check]    Emit persona JSONSchema to stdout");
    println!("  aegis-hwsim list-scenarios          List registered test scenarios");
    println!("  aegis-hwsim run <persona> <scenario> <stick.img> [--firmware-root DIR]");
    println!("                                      Run a scenario against a persona+stick");
    println!("  aegis-hwsim coverage-grid [--format json|markdown] [--dry-run]");
    println!("                                      Emit persona × scenario grid");
    println!("  aegis-hwsim doctor [--firmware-root DIR]");
    println!("                                      Check host has qemu/swtpm/ovmf installed");
    println!("  aegis-hwsim --version               Print version");
    println!("  aegis-hwsim --help                  This message");
    println!();
    println!("All paths resolve against the current working directory. Run from the");
    println!("repo root (or the directory containing personas/ and firmware/).");
}

/// Shared helper — resolves the cwd-relative `LoadOptions` and calls into
/// the loader. Returns the personas on success or prints the error to
/// stderr and returns the appropriate `ExitCode`.
fn load_or_report() -> Result<Vec<Persona>, ExitCode> {
    let cwd = cwd_or_exit()?;
    let opts = LoadOptions::default_at(&cwd);
    match load_all(&opts) {
        Ok(personas) => Ok(personas),
        Err(e) => {
            report_load_error(&e);
            Err(ExitCode::from(1))
        }
    }
}

/// `aegis-hwsim validate` — load every persona, print a status line per
/// file, exit 0 if all pass or 1 on any failure. `--quiet` suppresses
/// the per-persona "OK" lines and prints only failures.
fn run_validate(args: &[String]) -> ExitCode {
    if matches!(args.first().map(String::as_str), Some("--help" | "-h")) {
        println!("aegis-hwsim validate — check every persona YAML against the schema");
        println!();
        println!("USAGE:");
        println!("  aegis-hwsim validate            # Print OK/FAIL per persona");
        println!("  aegis-hwsim validate --quiet    # Print only FAIL lines");
        return ExitCode::SUCCESS;
    }
    let quiet = args.iter().any(|a| a == "--quiet");
    match load_or_report() {
        Ok(personas) => {
            if !quiet {
                for p in &personas {
                    println!("  [OK]   {} ({})", p.id, p.display_name);
                }
                println!();
                println!("{} persona(s) valid.", personas.len());
            }
            ExitCode::SUCCESS
        }
        Err(code) => code,
    }
}

/// `aegis-hwsim list-personas` — inventory the persona library.
/// Default output is a fixed-width human-readable table. `--json`
/// emits a `schema_version=1` envelope matching `aegis-boot`'s JSON
/// convention so downstream tooling can parse with one library.
fn run_list(args: &[String]) -> ExitCode {
    if matches!(args.first().map(String::as_str), Some("--help" | "-h")) {
        println!("aegis-hwsim list-personas — inventory YAML fixtures under personas/");
        println!();
        println!("USAGE:");
        println!("  aegis-hwsim list-personas         # Human-readable table");
        println!("  aegis-hwsim list-personas --json  # schema_version=1 JSON envelope");
        return ExitCode::SUCCESS;
    }
    let json_mode = args.iter().any(|a| a == "--json");
    match load_or_report() {
        Ok(personas) => {
            if json_mode {
                print_list_json(&personas);
            } else {
                print_list_table(&personas);
            }
            ExitCode::SUCCESS
        }
        Err(code) => code,
    }
}

fn print_list_table(personas: &[Persona]) {
    println!(
        "{:<34} {:<10} {:<15} {:<14} DISPLAY NAME",
        "ID", "SOURCE", "OVMF", "TPM",
    );
    for p in personas {
        println!(
            "{:<34} {:<10} {:<15} {:<14} {}",
            truncate(&p.id, 33),
            source_kind_label(p.source.kind),
            ovmf_variant_label(p.secure_boot.ovmf_variant),
            tpm_version_label(p.tpm.version),
            p.display_name,
        );
    }
    println!();
    println!("{} persona(s).", personas.len());
}

fn print_list_json(personas: &[Persona]) {
    println!("{{");
    println!("  \"schema_version\": 1,");
    println!("  \"tool\": \"aegis-hwsim\",");
    println!("  \"tool_version\": \"{}\",", env!("CARGO_PKG_VERSION"));
    println!("  \"count\": {},", personas.len());
    println!("  \"personas\": [");
    let last = personas.len().saturating_sub(1);
    for (i, p) in personas.iter().enumerate() {
        let comma = if i == last { "" } else { "," };
        println!("    {{");
        println!("      \"id\": \"{}\",", json_escape(&p.id));
        println!("      \"vendor\": \"{}\",", json_escape(&p.vendor));
        println!(
            "      \"display_name\": \"{}\",",
            json_escape(&p.display_name)
        );
        println!(
            "      \"source_kind\": \"{}\",",
            source_kind_label(p.source.kind)
        );
        println!(
            "      \"ovmf_variant\": \"{}\",",
            ovmf_variant_label(p.secure_boot.ovmf_variant)
        );
        println!(
            "      \"tpm_version\": \"{}\"",
            tpm_version_label(p.tpm.version)
        );
        println!("    }}{comma}");
    }
    println!("  ]");
    println!("}}");
}

fn source_kind_label(k: SourceKind) -> &'static str {
    match k {
        SourceKind::CommunityReport => "community",
        SourceKind::LvfsCatalog => "lvfs",
        SourceKind::VendorDocs => "vendor",
    }
}

fn ovmf_variant_label(v: aegis_hwsim::persona::OvmfVariant) -> &'static str {
    use aegis_hwsim::persona::OvmfVariant as V;
    match v {
        V::MsEnrolled => "ms-enrolled",
        V::CustomPk => "custom-pk",
        V::SetupMode => "setup-mode",
        V::Disabled => "disabled",
    }
}

fn tpm_version_label(v: aegis_hwsim::persona::TpmVersion) -> &'static str {
    use aegis_hwsim::persona::TpmVersion as V;
    match v {
        V::None => "none",
        V::Tpm12 => "1.2",
        V::Tpm20 => "2.0",
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('\u{2026}');
    out
}

/// Minimal JSON string escaper — covers `"`, `\`, control chars, newline,
/// tab. Not a general-purpose JSON library; we keep the output format
/// deterministic + dependency-light (matches aegis-boot's
/// `doctor::json_escape` shape so the family parses uniformly).
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

/// `aegis-hwsim gen-schema` — emit the persona `JSONSchema` to stdout.
/// With `--check <path>`, compare the generated schema against the file at
/// `<path>` and exit 1 if they differ (CI drift-gate pattern).
fn run_gen_schema(args: &[String]) -> ExitCode {
    if matches!(args.first().map(String::as_str), Some("--help" | "-h")) {
        println!("aegis-hwsim gen-schema — emit the persona JSONSchema");
        println!();
        println!("USAGE:");
        println!("  aegis-hwsim gen-schema              # Print schema to stdout");
        println!("  aegis-hwsim gen-schema --check PATH # Exit 1 if PATH differs from generated");
        return ExitCode::SUCCESS;
    }
    let schema = schemars::schema_for!(aegis_hwsim::persona::Persona);
    let Ok(rendered) = serde_json::to_string_pretty(&schema) else {
        eprintln!("aegis-hwsim: failed to serialize schema");
        return ExitCode::from(1);
    };
    let rendered = format!("{rendered}\n");
    if let Some(idx) = args.iter().position(|a| a == "--check") {
        let Some(path) = args.get(idx + 1) else {
            eprintln!("aegis-hwsim gen-schema --check: missing PATH argument");
            return ExitCode::from(2);
        };
        match std::fs::read_to_string(path) {
            Ok(committed) if committed == rendered => ExitCode::SUCCESS,
            Ok(_) => {
                eprintln!(
                    "aegis-hwsim: {path} is out of date. Run 'aegis-hwsim gen-schema > {path}' \
                     and commit the result."
                );
                ExitCode::from(1)
            }
            Err(e) => {
                eprintln!("aegis-hwsim: cannot read {path}: {e}");
                ExitCode::from(1)
            }
        }
    } else {
        print!("{rendered}");
        ExitCode::SUCCESS
    }
}

/// `aegis-hwsim doctor` — host environment check. Returns exit 0 on
/// PASS or WARN, 1 on FAIL. Operators run this before filing a bug
/// report so they (and we) know the host has every prerequisite.
fn run_doctor(args: &[String]) -> ExitCode {
    if matches!(args.first().map(String::as_str), Some("--help" | "-h")) {
        println!("aegis-hwsim doctor — check host has qemu/swtpm/ovmf installed");
        println!();
        println!("USAGE:");
        println!("  aegis-hwsim doctor [--firmware-root DIR] [--json]");
        println!();
        println!("  --firmware-root DIR  Override OVMF dir (default: /usr/share/OVMF)");
        println!("  --json               schema_version=1 envelope (matches family convention)");
        return ExitCode::SUCCESS;
    }
    let firmware_root = flag_path_or(args, "--firmware-root", "/usr/share/OVMF");
    let json_mode = args.iter().any(|a| a == "--json");
    let report = aegis_hwsim::doctor::run(&firmware_root);
    if json_mode {
        print!("{}", report.render_json());
    } else {
        print!("{}", report.render());
    }
    if report.has_failures() {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// `aegis-hwsim coverage-grid` — iterate personas × scenarios and emit
/// the grid in the requested format. With `--dry-run`, every cell
/// records `Skip { reason: "dry-run" }` without invoking the
/// scenario; useful for fast CI artifacts.
fn run_coverage_grid(args: &[String]) -> ExitCode {
    if matches!(args.first().map(String::as_str), Some("--help" | "-h")) {
        println!("aegis-hwsim coverage-grid — emit persona × scenario matrix");
        println!();
        println!("USAGE:");
        println!(
            "  aegis-hwsim coverage-grid [--format json|markdown] [--dry-run] \\\n\
             \x20             [--stick PATH] [--firmware-root DIR]"
        );
        println!();
        println!("  --format markdown      Human-readable table (default)");
        println!("  --format json          schema_version=1 envelope");
        println!("  --dry-run              Skip every cell with reason='dry-run'");
        println!("  --stick PATH           Stick image to use for stick-needing scenarios.");
        println!("                         Falls back to AEGIS_HWSIM_STICK env var.");
        println!("  --firmware-root DIR    Override OVMF dir (default: /usr/share/OVMF)");
        return ExitCode::SUCCESS;
    }
    // Tight `--format VALUE` match: must be exactly "json" or
    // "markdown". Default (no flag) is markdown. The previous
    // `args.iter().any(|a| a == "json")` would silently default to
    // markdown for any unknown value — which masks operator typos.
    let format = match flag_value(args, "--format") {
        None | Some("markdown") => aegis_hwsim::coverage_grid::OutputFormat::Markdown,
        Some("json") => aegis_hwsim::coverage_grid::OutputFormat::Json,
        Some(other) => {
            eprintln!(
                "aegis-hwsim coverage-grid: --format must be 'json' or 'markdown', got {other:?}"
            );
            return ExitCode::from(2);
        }
    };
    let dry_run = args.iter().any(|a| a == "--dry-run");

    let stick = flag_value(args, "--stick")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("AEGIS_HWSIM_STICK").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("/no/stick/configured"));

    let firmware_root = flag_path_or(args, "--firmware-root", "/usr/share/OVMF");

    let personas = match load_or_report() {
        Ok(p) => p,
        Err(code) => return code,
    };
    let registry = aegis_hwsim::scenario::Registry::default_set();

    // Work dirs under /tmp rather than cwd: the Unix socket path
    // (Linux limit 108 chars) caps how deep we can nest. cwd-based
    // paths overflow on long persona+scenario combinations
    // (lenovo-thinkpad-x1-carbon-gen11__signed-boot-ubuntu →
    // 121-char swtpm.sock path → "UnioIO socket is too long" + cell
    // FAIL). /tmp/ahwsim-cov keeps the prefix to ~17 chars.
    let cfg = aegis_hwsim::coverage_grid::GridConfig {
        work_root: PathBuf::from("/tmp/ahwsim-cov"),
        firmware_root,
        stick,
        dry_run,
    };
    let cells = aegis_hwsim::coverage_grid::compute_grid(&personas, &registry, &cfg);
    print!(
        "{}",
        aegis_hwsim::coverage_grid::render(&cells, &registry, format)
    );
    ExitCode::SUCCESS
}

/// `aegis-hwsim list-scenarios` — print the registered scenario names
/// + descriptions. Read-only, no I/O beyond the registry init.
fn run_list_scenarios(args: &[String]) -> ExitCode {
    if matches!(args.first().map(String::as_str), Some("--help" | "-h")) {
        println!("aegis-hwsim list-scenarios — show registered test scenarios");
        println!();
        println!("USAGE: aegis-hwsim list-scenarios [--json]");
        println!();
        println!("  --json    schema_version=1 envelope (matches family convention)");
        return ExitCode::SUCCESS;
    }
    let json_mode = args.iter().any(|a| a == "--json");
    let registry = aegis_hwsim::scenario::Registry::default_set();
    if json_mode {
        print_scenarios_json(&registry);
    } else {
        print_scenarios_table(&registry);
    }
    ExitCode::SUCCESS
}

fn print_scenarios_table(registry: &aegis_hwsim::scenario::Registry) {
    if registry.is_empty() {
        println!("(no scenarios registered)");
        return;
    }
    println!("{:<28} DESCRIPTION", "NAME");
    for (name, desc) in registry.iter() {
        println!("{name:<28} {desc}");
    }
    println!();
    println!("{} scenario(s).", registry.len());
}

fn print_scenarios_json(registry: &aegis_hwsim::scenario::Registry) {
    println!("{{");
    println!("  \"schema_version\": 1,");
    println!("  \"tool\": \"aegis-hwsim\",");
    println!("  \"tool_version\": \"{}\",", env!("CARGO_PKG_VERSION"));
    println!("  \"count\": {},", registry.len());
    println!("  \"scenarios\": [");
    let entries: Vec<_> = registry.iter().collect();
    let last = entries.len().saturating_sub(1);
    for (i, (name, desc)) in entries.iter().enumerate() {
        let comma = if i == last { "" } else { "," };
        println!("    {{");
        println!("      \"name\": \"{}\",", json_escape(name));
        println!("      \"description\": \"{}\"", json_escape(desc));
        println!("    }}{comma}");
    }
    println!("  ]");
    println!("}}");
}

/// Parsed argv for `run_scenario`. Owned by the caller; lifetimes
/// follow the input slice.
struct RunArgs<'a> {
    persona_id: &'a str,
    scenario_name: &'a str,
    stick: PathBuf,
    firmware_root: Option<PathBuf>,
    work_dir: Option<PathBuf>,
}

/// Tiny argv parser for `run`. Returns the parsed inputs or a typed
/// exit code (2 = usage error). Extracted from `run_scenario` to keep
/// the runner under the 100-line clippy lint.
fn parse_run_args(args: &[String]) -> Result<RunArgs<'_>, u8> {
    let mut positional: Vec<&str> = Vec::new();
    let mut firmware_root: Option<PathBuf> = None;
    let mut work_dir: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        match a.as_str() {
            "--firmware-root" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    eprintln!("aegis-hwsim run: --firmware-root requires a path");
                    return Err(2);
                };
                firmware_root = Some(PathBuf::from(v));
            }
            "--work-dir" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    eprintln!("aegis-hwsim run: --work-dir requires a path");
                    return Err(2);
                };
                work_dir = Some(PathBuf::from(v));
            }
            arg if arg.starts_with("--") => {
                eprintln!("aegis-hwsim run: unknown option '{arg}'");
                return Err(2);
            }
            other => positional.push(other),
        }
        i += 1;
    }
    if positional.len() != 3 {
        eprintln!(
            "aegis-hwsim run: expected 3 positional args, got {}",
            positional.len()
        );
        eprintln!("Usage: aegis-hwsim run <persona-id> <scenario-name> <stick.img>");
        return Err(2);
    }
    Ok(RunArgs {
        persona_id: positional[0],
        scenario_name: positional[1],
        stick: PathBuf::from(positional[2]),
        firmware_root,
        work_dir,
    })
}

/// `aegis-hwsim run <persona> <scenario> <stick> [--firmware-root DIR]`
/// — load the persona library, look up the scenario by name, validate
/// inputs, run, and print a one-line PASS/FAIL/SKIP verdict.
///
/// Exit codes: 0 = Pass, 1 = Fail (asserted) or runner error, 2 = usage,
/// 77 = Skip (sysexits-style `EX_NOPERM` repurposed as "skipped").
fn run_scenario(args: &[String]) -> ExitCode {
    if args.is_empty() || matches!(args.first().map(String::as_str), Some("--help" | "-h")) {
        println!("aegis-hwsim run — execute a scenario against a persona + stick");
        println!();
        println!("USAGE:");
        println!("  aegis-hwsim run <persona-id> <scenario-name> <stick.img> \\");
        println!("    [--firmware-root DIR] [--work-dir DIR]");
        println!();
        println!("  --firmware-root DIR  Override OVMF dir (default: /usr/share/OVMF)");
        println!("  --work-dir DIR       Per-run work dir (default: ./work/<run-id>)");
        return ExitCode::SUCCESS;
    }

    let parsed = match parse_run_args(args) {
        Ok(p) => p,
        Err(code) => return ExitCode::from(code),
    };
    let RunArgs {
        persona_id,
        scenario_name,
        stick,
        firmware_root,
        work_dir,
    } = parsed;

    let personas = match load_or_report() {
        Ok(p) => p,
        Err(code) => return code,
    };
    let Some(persona) = personas.into_iter().find(|p| p.id == persona_id) else {
        eprintln!("aegis-hwsim run: persona '{persona_id}' not found");
        eprintln!("Run 'aegis-hwsim list-personas' to see available ids.");
        return ExitCode::from(1);
    };

    let registry = aegis_hwsim::scenario::Registry::default_set();
    let Some(scenario) = registry.find(scenario_name) else {
        eprintln!("aegis-hwsim run: scenario '{scenario_name}' not found");
        eprintln!("Run 'aegis-hwsim list-scenarios' to see available names.");
        return ExitCode::from(1);
    };

    let firmware_root = firmware_root.unwrap_or_else(|| PathBuf::from("/usr/share/OVMF"));
    let work_dir = match work_dir {
        Some(p) => p,
        None => match cwd_or_exit() {
            Ok(cwd) => cwd
                .join("work")
                .join(format!("{persona_id}-{scenario_name}")),
            Err(code) => return code,
        },
    };

    let ctx = aegis_hwsim::scenario::ScenarioContext {
        persona,
        stick,
        work_dir,
        firmware_root,
    };

    match scenario.run(&ctx) {
        Ok(result) => {
            let label = result.label();
            let reason = result.reason();
            if reason.is_empty() {
                println!("{label}: {scenario_name} on {persona_id}");
            } else {
                println!("{label}: {scenario_name} on {persona_id}");
                println!("  {reason}");
            }
            match result {
                aegis_hwsim::scenario::ScenarioResult::Pass => ExitCode::SUCCESS,
                aegis_hwsim::scenario::ScenarioResult::Fail { .. } => ExitCode::from(1),
                aegis_hwsim::scenario::ScenarioResult::Skip { .. } => ExitCode::from(77),
            }
        }
        Err(e) => {
            eprintln!("aegis-hwsim run: scenario runner error: {e}");
            ExitCode::from(1)
        }
    }
}

/// Pretty-print a `LoadError` to stderr with operator-actionable context.
/// All variants already carry the offending file path via Display; we
/// just add a `aegis-hwsim:` prefix so it composes with shell piping.
fn report_load_error(e: &LoadError) {
    eprintln!("aegis-hwsim: {e}");
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn flag_value_returns_value_following_flag() {
        let args = argv(&["--firmware-root", "/opt/ovmf", "--quiet"]);
        assert_eq!(flag_value(&args, "--firmware-root"), Some("/opt/ovmf"));
    }

    #[test]
    fn flag_value_returns_none_when_flag_absent() {
        let args = argv(&["--quiet", "--json"]);
        assert_eq!(flag_value(&args, "--firmware-root"), None);
    }

    #[test]
    fn flag_value_returns_none_when_flag_is_last_token() {
        // No value to consume after the trailing `--firmware-root`.
        let args = argv(&["--quiet", "--firmware-root"]);
        assert_eq!(flag_value(&args, "--firmware-root"), None);
    }

    #[test]
    fn flag_value_does_not_match_substring_or_eq_form() {
        // `--firmware-root-extra` and `--firmware-root=/opt/ovmf` must
        // NOT match `--firmware-root`. The previous bug class was a
        // substring/contains match that allowed `--format json-extra`
        // to silently route into JSON mode.
        let args = argv(&[
            "--firmware-root-extra",
            "/wrong",
            "--firmware-root=/equals-form",
        ]);
        assert_eq!(flag_value(&args, "--firmware-root"), None);
    }

    #[test]
    fn flag_path_or_returns_value_when_present() {
        let args = argv(&["--firmware-root", "/opt/ovmf"]);
        assert_eq!(
            flag_path_or(&args, "--firmware-root", "/usr/share/OVMF"),
            PathBuf::from("/opt/ovmf")
        );
    }

    #[test]
    fn flag_path_or_returns_default_when_flag_absent() {
        let args = argv(&["--quiet"]);
        assert_eq!(
            flag_path_or(&args, "--firmware-root", "/usr/share/OVMF"),
            PathBuf::from("/usr/share/OVMF")
        );
    }

    #[test]
    fn flag_value_picks_first_occurrence_when_repeated() {
        // CLI doesn't define repeat semantics, but the contract should
        // be deterministic. Document via test: first wins.
        let args = argv(&["--firmware-root", "/first", "--firmware-root", "/second"]);
        assert_eq!(flag_value(&args, "--firmware-root"), Some("/first"));
    }
}
