//! Round-trip test: `schemas/persona.schema.json` must match what
//! `schemars::schema_for!(Persona)` currently produces. If a field is
//! added/renamed and the committed schema isn't regenerated, this test
//! fails locally before CI does. Regenerate via:
//!
//!     cargo run -q --bin aegis-hwsim -- gen-schema > schemas/persona.schema.json

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::PathBuf;

#[test]
fn committed_schema_matches_source() {
    let schema = schemars::schema_for!(aegis_hwsim::persona::Persona);
    let rendered = serde_json::to_string_pretty(&schema).unwrap();
    let rendered = format!("{rendered}\n");

    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("schemas");
    path.push("persona.schema.json");
    let committed = fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "could not read {}: {e}. Did you run `cargo run --bin aegis-hwsim -- gen-schema`?",
            path.display()
        )
    });
    assert_eq!(
        committed,
        rendered,
        "schemas/persona.schema.json is out of date. \
         Regenerate with: cargo run -q --bin aegis-hwsim -- gen-schema > schemas/persona.schema.json"
    );
}
