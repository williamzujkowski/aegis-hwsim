//! `load_all()` — scan `personas/*.yaml`, parse them into `Persona` structs,
//! and enforce the schema-level drift + safety guards that can't live in
//! serde alone.
//!
//! Guards implemented here (aegis-hwsim#8):
//!
//! * **Parse** — YAML syntax and serde structural validation (missing
//!   fields, wrong types). Comes from `serde_yaml`; we wrap the error.
//! * **`IdMismatch`** — `persona.id` must equal the filename stem (without
//!   `.yaml`). Catches the common rename-one-forget-the-other bug.
//! * **Placeholder** — no `TEST_ONLY_NOT_FOR_PRODUCTION` token may appear
//!   in any string field of a persona under `personas/`. Test fixtures
//!   that deliberately include the token live under `tests/fixtures/`,
//!   not the production persona directory.
//! * **`QuirkTag`** — each `quirks[].tag` must match
//!   `^[a-z0-9][a-z0-9-]*[a-z0-9]$` so tags stay grep-friendly across
//!   personas.
//! * **`CustomKeyringInRoot`** — when present, `custom_keyring` must resolve
//!   under `$AEGIS_HWSIM_ROOT/firmware/`. Canonicalization guards against
//!   `../../../etc/passwd` style traversal (aegis-boot#226 security
//!   constraint #2).

use crate::persona::Persona;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Exact token flagged by the `Placeholder` guard. Keeping it here as a
/// single `const` so it's grep-able and can't drift between guards.
const PLACEHOLDER_TOKEN: &str = "TEST_ONLY_NOT_FOR_PRODUCTION";

/// Fatal errors from `load_all`. Every variant carries the offending
/// file path so pretty-printers can produce actionable output.
#[derive(Debug, Error)]
pub enum LoadError {
    /// Failed to read the YAML file from disk.
    #[error("read {path:?}: {source}")]
    Read {
        /// Path that failed to read.
        path: PathBuf,
        /// Underlying filesystem error.
        #[source]
        source: std::io::Error,
    },

    /// YAML parse or serde schema mismatch.
    #[error("parse {path:?}: {source}")]
    Parse {
        /// Path that failed to parse.
        path: PathBuf,
        /// Underlying parser error.
        #[source]
        source: serde_yaml::Error,
    },

    /// `persona.id` doesn't match the filename stem.
    #[error("{path:?}: id '{yaml_id}' does not match filename stem '{filename_stem}'")]
    IdMismatch {
        /// Path with the mismatch.
        path: PathBuf,
        /// The `id:` field value from the YAML.
        yaml_id: String,
        /// The filename's stem (without `.yaml`).
        filename_stem: String,
    },

    /// A production-persona field contains the `TEST_ONLY_NOT_FOR_PRODUCTION`
    /// token. Test fixtures belong under `tests/fixtures/`, never
    /// `personas/`.
    #[error("{path:?}: field {field:?} contains placeholder token; production personas must not carry test markers")]
    Placeholder {
        /// Path that contains the placeholder.
        path: PathBuf,
        /// Human-readable field name (e.g. `"source.ref_"`).
        field: String,
    },

    /// Quirk tag doesn't satisfy `^[a-z0-9][a-z0-9-]*[a-z0-9]$`.
    #[error("{path:?}: quirk tag '{tag}' does not match ^[a-z0-9][a-z0-9-]*[a-z0-9]$")]
    QuirkTag {
        /// Path that contains the bad quirk tag.
        path: PathBuf,
        /// The offending tag string.
        tag: String,
    },

    /// `custom_keyring` doesn't resolve under the configured firmware root.
    #[error("{path:?}: custom_keyring {keyring:?} is not under {root:?}")]
    CustomKeyringOutsideRoot {
        /// Path of the persona YAML with the bad reference.
        path: PathBuf,
        /// The keyring path that escaped the root.
        keyring: PathBuf,
        /// The configured firmware root (`$AEGIS_HWSIM_ROOT/firmware/`).
        root: PathBuf,
    },
}

/// Options for `load_all`. Split from args so callers can extend without
/// breaking the signature.
#[derive(Debug, Clone)]
pub struct LoadOptions {
    /// The `personas/` directory to scan.
    pub personas_dir: PathBuf,
    /// Root under which `custom_keyring` paths must resolve.
    /// `$AEGIS_HWSIM_ROOT/firmware/` in production; tests set a temp dir.
    pub firmware_root: PathBuf,
}

impl LoadOptions {
    /// Default options rooted at the current working directory. Used by
    /// the CLI when the operator runs `aegis-hwsim` from the repo root.
    #[must_use]
    pub fn default_at(repo_root: &Path) -> Self {
        Self {
            personas_dir: repo_root.join("personas"),
            firmware_root: repo_root.join("firmware"),
        }
    }
}

/// Load every persona under `opts.personas_dir`, enforcing the schema
/// + drift + safety guards documented at the module level.
///
/// Returns personas sorted by `id` for deterministic output across runs.
///
/// # Errors
///
/// Any single persona that fails a guard causes the whole call to fail
/// with that persona's error. Fail-fast is deliberate — a partially
/// loaded persona set would silently exclude the one the operator is
/// trying to debug.
pub fn load_all(opts: &LoadOptions) -> Result<Vec<Persona>, LoadError> {
    let mut personas = Vec::new();
    let read_dir = std::fs::read_dir(&opts.personas_dir).map_err(|source| LoadError::Read {
        path: opts.personas_dir.clone(),
        source,
    })?;

    let mut yaml_paths: Vec<PathBuf> = Vec::new();
    for entry in read_dir {
        let entry = entry.map_err(|source| LoadError::Read {
            path: opts.personas_dir.clone(),
            source,
        })?;
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "yaml") {
            yaml_paths.push(path);
        }
    }
    // Deterministic order — id-sorted below, but filesystem order is
    // unspecified, so parse-sort once to make error messages reproducible.
    yaml_paths.sort();

    for path in yaml_paths {
        let persona = load_one(&path, opts)?;
        personas.push(persona);
    }

    personas.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(personas)
}

/// Load + validate a single persona YAML. Pulled out so the per-file
/// error paths don't have to inline all five guard checks.
fn load_one(path: &Path, opts: &LoadOptions) -> Result<Persona, LoadError> {
    let body = std::fs::read_to_string(path).map_err(|source| LoadError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let persona: Persona = serde_yaml::from_str(&body).map_err(|source| LoadError::Parse {
        path: path.to_path_buf(),
        source,
    })?;

    // Guard 1: filename stem must match persona.id.
    let filename_stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or_default();
    if persona.id != filename_stem {
        return Err(LoadError::IdMismatch {
            path: path.to_path_buf(),
            yaml_id: persona.id.clone(),
            filename_stem: filename_stem.to_string(),
        });
    }

    // Guard 2: no TEST_ONLY_NOT_FOR_PRODUCTION token in production personas.
    check_placeholder(&persona, path)?;

    // Guard 3: quirk tag regex.
    for quirk in &persona.quirks {
        if !quirk_tag_is_valid(&quirk.tag) {
            return Err(LoadError::QuirkTag {
                path: path.to_path_buf(),
                tag: quirk.tag.clone(),
            });
        }
    }

    // Guard 4: custom_keyring path-traversal.
    if let Some(keyring) = &persona.secure_boot.custom_keyring {
        check_custom_keyring(path, keyring, &opts.firmware_root)?;
    }

    Ok(persona)
}

/// Depth-limited string-field scan for the placeholder token. We check
/// the fields we care about explicitly rather than reflecting over
/// everything — keeps the error messages concrete.
fn check_placeholder(persona: &Persona, path: &Path) -> Result<(), LoadError> {
    let fields: &[(&str, &str)] = &[
        ("id", &persona.id),
        ("vendor", &persona.vendor),
        ("display_name", &persona.display_name),
        ("source.ref_", &persona.source.ref_),
        ("dmi.sys_vendor", &persona.dmi.sys_vendor),
        ("dmi.product_name", &persona.dmi.product_name),
        ("dmi.bios_vendor", &persona.dmi.bios_vendor),
        ("dmi.bios_version", &persona.dmi.bios_version),
        ("dmi.bios_date", &persona.dmi.bios_date),
    ];
    for (name, value) in fields {
        if value.contains(PLACEHOLDER_TOKEN) {
            return Err(LoadError::Placeholder {
                path: path.to_path_buf(),
                field: (*name).to_string(),
            });
        }
    }
    // Also check optional fields.
    for (name, value) in [
        (
            "dmi.product_version",
            persona.dmi.product_version.as_deref(),
        ),
        ("dmi.board_name", persona.dmi.board_name.as_deref()),
        ("source.captured_at", persona.source.captured_at.as_deref()),
        ("tpm.manufacturer", persona.tpm.manufacturer.as_deref()),
        (
            "tpm.firmware_version",
            persona.tpm.firmware_version.as_deref(),
        ),
    ] {
        if let Some(v) = value {
            if v.contains(PLACEHOLDER_TOKEN) {
                return Err(LoadError::Placeholder {
                    path: path.to_path_buf(),
                    field: name.to_string(),
                });
            }
        }
    }
    // Quirk descriptions too.
    for quirk in &persona.quirks {
        if quirk.description.contains(PLACEHOLDER_TOKEN) {
            return Err(LoadError::Placeholder {
                path: path.to_path_buf(),
                field: format!("quirks[{}].description", quirk.tag),
            });
        }
    }
    Ok(())
}

/// Grep-friendly tag regex check. Implemented by hand so we don't add a
/// regex dep for a 3-rule pattern.
fn quirk_tag_is_valid(tag: &str) -> bool {
    let bytes = tag.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    // First + last must be alphanumeric lowercase or digit.
    let is_edge_char = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    if !is_edge_char(bytes[0]) || !is_edge_char(bytes[bytes.len() - 1]) {
        return false;
    }
    // Middle chars add hyphen. Skip the loop entirely for tags of length
    // 1 or 2 — the edge checks already covered both positions.
    if bytes.len() > 2 {
        for &b in &bytes[1..bytes.len() - 1] {
            if !(b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
                return false;
            }
        }
    }
    true
}

/// Canonicalize `keyring` and verify it stays under `root`. Canonicalize
/// both sides so symlinks don't punch through the guard. If either side
/// can't be canonicalized (keyring doesn't exist yet, root missing), we
/// reject — a nonexistent keyring reference is just as dangerous as a
/// traversing one.
fn check_custom_keyring(path: &Path, keyring: &Path, root: &Path) -> Result<(), LoadError> {
    let canon_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    // Relative `custom_keyring` resolves against firmware_root — that's
    // the contract documented in firmware/test-keyring/README.md and in
    // docs/persona-authoring.md. Absolute paths stay as-is so the
    // existing /etc/passwd-traversal negative test continues to fire.
    let resolved = if keyring.is_absolute() {
        keyring.to_path_buf()
    } else {
        canon_root.join(keyring)
    };
    let canon_keyring = resolved.canonicalize().unwrap_or_else(|_| resolved.clone());
    if !canon_keyring.starts_with(&canon_root) {
        return Err(LoadError::CustomKeyringOutsideRoot {
            path: path.to_path_buf(),
            keyring: keyring.to_path_buf(),
            root: canon_root,
        });
    }
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use std::fs;

    fn write(tmp: &Path, name: &str, body: &str) -> PathBuf {
        let p = tmp.join(name);
        fs::write(&p, body).unwrap();
        p
    }

    fn minimal_yaml(id: &str) -> String {
        format!(
            r#"
schema_version: 1
id: {id}
vendor: QEMU
display_name: "Generic"
source:
  kind: vendor_docs
  ref_: "https://example.test/docs"
dmi:
  sys_vendor: QEMU
  product_name: "Standard PC"
  bios_vendor: EDK II
  bios_version: "edk2-stable"
  bios_date: 01/01/2024
secure_boot:
  ovmf_variant: ms_enrolled
tpm:
  version: "2.0"
"#
        )
    }

    fn tmp_opts() -> (tempfile::TempDir, LoadOptions) {
        let tmp = tempfile::tempdir().unwrap();
        let personas = tmp.path().join("personas");
        let firmware = tmp.path().join("firmware");
        fs::create_dir_all(&personas).unwrap();
        fs::create_dir_all(&firmware).unwrap();
        let opts = LoadOptions {
            personas_dir: personas,
            firmware_root: firmware,
        };
        (tmp, opts)
    }

    #[test]
    fn load_all_accepts_minimal_valid_persona() {
        let (_tmp, opts) = tmp_opts();
        write(&opts.personas_dir, "ok.yaml", &minimal_yaml("ok"));
        let loaded = load_all(&opts).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, "ok");
    }

    #[test]
    fn load_all_returns_personas_sorted_by_id() {
        let (_tmp, opts) = tmp_opts();
        write(&opts.personas_dir, "z.yaml", &minimal_yaml("z"));
        write(&opts.personas_dir, "a.yaml", &minimal_yaml("a"));
        write(&opts.personas_dir, "m.yaml", &minimal_yaml("m"));
        let loaded = load_all(&opts).unwrap();
        let ids: Vec<_> = loaded.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, vec!["a", "m", "z"]);
    }

    #[test]
    fn load_all_rejects_parse_error() {
        let (_tmp, opts) = tmp_opts();
        write(&opts.personas_dir, "bad.yaml", "not: [ valid");
        let err = load_all(&opts).unwrap_err();
        assert!(matches!(err, LoadError::Parse { .. }));
    }

    #[test]
    fn load_all_rejects_id_mismatch() {
        let (_tmp, opts) = tmp_opts();
        write(&opts.personas_dir, "drift.yaml", &minimal_yaml("other"));
        let err = load_all(&opts).unwrap_err();
        match err {
            LoadError::IdMismatch {
                yaml_id,
                filename_stem,
                ..
            } => {
                assert_eq!(yaml_id, "other");
                assert_eq!(filename_stem, "drift");
            }
            other => panic!("expected IdMismatch, got {other:?}"),
        }
    }

    #[test]
    fn load_all_rejects_placeholder_token_in_display_name() {
        let (_tmp, opts) = tmp_opts();
        let body = minimal_yaml("tagged").replace(
            "display_name: \"Generic\"",
            "display_name: \"TEST_ONLY_NOT_FOR_PRODUCTION\"",
        );
        write(&opts.personas_dir, "tagged.yaml", &body);
        let err = load_all(&opts).unwrap_err();
        match err {
            LoadError::Placeholder { field, .. } => assert_eq!(field, "display_name"),
            other => panic!("expected Placeholder, got {other:?}"),
        }
    }

    #[test]
    fn quirk_tag_regex_accepts_valid_tags() {
        assert!(quirk_tag_is_valid("fast-boot-default-on"));
        assert!(quirk_tag_is_valid("a"));
        assert!(quirk_tag_is_valid("a1"));
        assert!(quirk_tag_is_valid("abc-123"));
        assert!(quirk_tag_is_valid("0-x"));
    }

    #[test]
    fn quirk_tag_regex_rejects_invalid_tags() {
        assert!(!quirk_tag_is_valid(""));
        assert!(!quirk_tag_is_valid("-leading"));
        assert!(!quirk_tag_is_valid("trailing-"));
        assert!(!quirk_tag_is_valid("UPPER"));
        assert!(!quirk_tag_is_valid("has_underscore"));
        assert!(!quirk_tag_is_valid("has space"));
    }

    #[test]
    fn load_all_rejects_quirk_tag_with_uppercase() {
        let (_tmp, opts) = tmp_opts();
        let mut body = minimal_yaml("qt");
        body.push_str("quirks:\n  - tag: BAD_TAG\n    description: nope\n");
        write(&opts.personas_dir, "qt.yaml", &body);
        let err = load_all(&opts).unwrap_err();
        match err {
            LoadError::QuirkTag { tag, .. } => assert_eq!(tag, "BAD_TAG"),
            other => panic!("expected QuirkTag, got {other:?}"),
        }
    }

    #[test]
    fn custom_keyring_outside_root_is_rejected() {
        let (_tmp, opts) = tmp_opts();
        // Place the keyring OUTSIDE the firmware root.
        let escape_path = opts.personas_dir.parent().unwrap().join("escape-keyring");
        fs::write(&escape_path, b"").unwrap();
        let mut body = minimal_yaml("escape");
        body = body.replace(
            "secure_boot:\n  ovmf_variant: ms_enrolled\n",
            &format!(
                "secure_boot:\n  ovmf_variant: custom_pk\n  custom_keyring: {}\n",
                escape_path.display()
            ),
        );
        write(&opts.personas_dir, "escape.yaml", &body);
        let err = load_all(&opts).unwrap_err();
        assert!(
            matches!(err, LoadError::CustomKeyringOutsideRoot { .. }),
            "expected CustomKeyringOutsideRoot, got {err:?}"
        );
    }

    #[test]
    fn custom_keyring_inside_root_is_accepted() {
        let (_tmp, opts) = tmp_opts();
        // Place the keyring INSIDE the firmware root.
        let keyring = opts.firmware_root.join("test-keyring");
        fs::write(&keyring, b"").unwrap();
        let mut body = minimal_yaml("ok");
        body = body.replace(
            "secure_boot:\n  ovmf_variant: ms_enrolled\n",
            &format!(
                "secure_boot:\n  ovmf_variant: custom_pk\n  custom_keyring: {}\n",
                keyring.display()
            ),
        );
        write(&opts.personas_dir, "ok.yaml", &body);
        let loaded = load_all(&opts).unwrap();
        assert_eq!(loaded.len(), 1);
    }

    /// Relative `custom_keyring` paths resolve against `firmware_root`.
    /// This is the contract documented in `firmware/test-keyring/README.md`
    /// and exercised by `personas/qemu-custom-pk-sb.yaml`.
    #[test]
    fn custom_keyring_relative_path_resolves_against_firmware_root() {
        let (_tmp, opts) = tmp_opts();
        // Create the keyring under firmware_root/sub/keyring.fd, then
        // reference it via the RELATIVE path "sub/keyring.fd" from the
        // persona YAML.
        let sub = opts.firmware_root.join("sub");
        fs::create_dir_all(&sub).unwrap();
        let keyring_abs = sub.join("keyring.fd");
        fs::write(&keyring_abs, b"placeholder").unwrap();

        let mut body = minimal_yaml("relpath");
        body = body.replace(
            "secure_boot:\n  ovmf_variant: ms_enrolled\n",
            "secure_boot:\n  ovmf_variant: custom_pk\n  custom_keyring: sub/keyring.fd\n",
        );
        write(&opts.personas_dir, "relpath.yaml", &body);
        let loaded = load_all(&opts).unwrap();
        assert_eq!(loaded.len(), 1);
    }

    /// Relative `custom_keyring` with `..` traversal must still be rejected
    /// — the post-canonicalize `starts_with` check catches it even after
    /// the join with `firmware_root`.
    #[test]
    fn custom_keyring_relative_path_with_traversal_is_rejected() {
        let (_tmp, opts) = tmp_opts();
        // Create a target file *outside* firmware_root.
        let escape = opts.firmware_root.parent().unwrap().join("escape.fd");
        fs::write(&escape, b"outside").unwrap();
        // Reference via relative `../escape.fd` — joins to
        // firmware_root/../escape.fd = the file above. Canonicalize
        // resolves to the absolute outside-root path; starts_with fails.
        let mut body = minimal_yaml("traversal");
        body = body.replace(
            "secure_boot:\n  ovmf_variant: ms_enrolled\n",
            "secure_boot:\n  ovmf_variant: custom_pk\n  custom_keyring: ../escape.fd\n",
        );
        write(&opts.personas_dir, "traversal.yaml", &body);
        let err = load_all(&opts).unwrap_err();
        assert!(
            matches!(err, LoadError::CustomKeyringOutsideRoot { .. }),
            "got {err:?}"
        );
    }
}
