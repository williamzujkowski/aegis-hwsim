//! `aegis-hwsim` CLI. Two subcommands wired today (`validate`,
//! `list-personas`); `run` still exits 3 pending E3.

#![forbid(unsafe_code)]

use aegis_hwsim::loader::{load_all, LoadError, LoadOptions};
use aegis_hwsim::persona::{Persona, SourceKind};
use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("list-personas") => run_list(&args[1..]),
        Some("validate") => run_validate(&args[1..]),
        Some("gen-schema") => run_gen_schema(&args[1..]),
        Some("run") => run_scenario(&args[1..]),
        Some("list-scenarios") => run_list_scenarios(&args[1..]),
        Some("-h" | "--help" | "help") | None => {
            print_help();
            ExitCode::SUCCESS
        }
        Some("--version" | "version") => {
            println!("aegis-hwsim v{}", env!("CARGO_PKG_VERSION"));
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
    println!("  aegis-hwsim --version               Print version");
    println!("  aegis-hwsim --help                  This message");
    println!();
    println!("All paths resolve against the current working directory. Run from the");
    println!("repo root (or the directory containing personas/ and firmware/).");
}

/// Shared helper — resolves the cwd-relative `LoadOptions` and calls into
/// the loader. Returns the personas on success or prints the error to
/// stderr and returns the appropriate exit code.
fn load_or_report() -> Result<Vec<Persona>, u8> {
    let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let opts = LoadOptions::default_at(&cwd);
    match load_all(&opts) {
        Ok(personas) => Ok(personas),
        Err(e) => {
            report_load_error(&e);
            Err(1)
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
        Err(code) => ExitCode::from(code),
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
        Err(code) => ExitCode::from(code),
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

/// `aegis-hwsim list-scenarios` — print the registered scenario names
/// + descriptions. Read-only, no I/O beyond the registry init.
fn run_list_scenarios(args: &[String]) -> ExitCode {
    if matches!(args.first().map(String::as_str), Some("--help" | "-h")) {
        println!("aegis-hwsim list-scenarios — show registered test scenarios");
        println!();
        println!("USAGE: aegis-hwsim list-scenarios");
        return ExitCode::SUCCESS;
    }
    let registry = aegis_hwsim::scenario::Registry::default_set();
    if registry.is_empty() {
        println!("(no scenarios registered)");
        return ExitCode::SUCCESS;
    }
    println!("{:<28} DESCRIPTION", "NAME");
    for (name, desc) in registry.iter() {
        println!("{name:<28} {desc}");
    }
    println!();
    println!("{} scenario(s).", registry.len());
    ExitCode::SUCCESS
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
        Err(code) => return ExitCode::from(code),
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
    let work_dir = work_dir.unwrap_or_else(|| {
        let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        cwd.join("work")
            .join(format!("{persona_id}-{scenario_name}"))
    });

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
