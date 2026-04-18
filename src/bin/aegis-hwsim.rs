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
        Some("run") => {
            eprintln!("aegis-hwsim: run — not implemented yet");
            eprintln!("  Usage: aegis-hwsim run <persona> <scenario> <aegis-boot-stick.img>");
            eprintln!("  Track: https://github.com/williamzujkowski/aegis-hwsim/issues/3");
            ExitCode::from(3)
        }
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
    println!("  aegis-hwsim run <persona> <scenario> <stick>");
    println!("                                      (not yet implemented — tracks #3)");
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

/// Pretty-print a `LoadError` to stderr with operator-actionable context.
/// All variants already carry the offending file path via Display; we
/// just add a `aegis-hwsim:` prefix so it composes with shell piping.
fn report_load_error(e: &LoadError) {
    eprintln!("aegis-hwsim: {e}");
}
