//! Test-keyring generator for E5 (custom-PK + setup-mode flows).
//!
//! Produces a self-contained PK/KEK/db Secure-Boot keyring under
//! `<out>/`. Every certificate carries `TEST_ONLY_NOT_FOR_PRODUCTION`
//! in its CN so:
//!
//! * The pre-publish audit (`scripts/audit-no-test-keys.sh`) refuses to
//!   ship any artifact carrying the marker (CLAUDE.md security
//!   constraint #4 + aegis-boot#226).
//! * Operators can grep an OVMF VARS dump and instantly tell whether a
//!   running VM is on hwsim's test keyring vs. real Secure Boot.
//!
//! ## Pipeline
//!
//! 1. `openssl req -new -x509 -newkey rsa:2048 -nodes -days N -subj
//!    "/CN=TEST_ONLY_NOT_FOR_PRODUCTION aegis-hwsim <ROLE>" \
//!    -keyout <ROLE>.key -out <ROLE>.crt`
//!    → 3 certs (PK, KEK, db) and their private keys.
//! 2. `cert-to-efi-sig-list -g <GUID> <ROLE>.crt <ROLE>.esl`
//!    → UEFI signature list, one cert per ESL.
//! 3. `sign-efi-sig-list -k PK.key -c PK.crt <VAR> <ROLE>.esl <ROLE>.auth`
//!    → time-stamped, PK-signed update payload that OVMF will accept
//!      via `SetVariable`. PK is self-signed (UEFI rule).
//!
//! Step 4 — actually loading these into an `OVMF_VARS` file — is
//! deferred to a follow-up PR (E5.1d). It needs `virt-fw-vars` (from
//! python3-virt-firmware) or an OVMF first-boot enrollment script,
//! both of which expand the host-tooling surface beyond what this PR
//! scopes to.
//!
//! ## Tooling
//!
//! All three external tools (`openssl`, `cert-to-efi-sig-list`,
//! `sign-efi-sig-list`) are probed by `aegis-hwsim doctor` (see
//! `src/doctor.rs`). When invoked from the CLI, this module skips
//! gracefully with exit code 77 if any tool is missing — same
//! pattern as the QEMU/swtpm scenarios.
//!
//! ## Output layout
//!
//! ```text
//! <out>/
//!   PK.key      PK.crt      PK.esl      PK.auth
//!   KEK.key     KEK.crt     KEK.esl     KEK.auth
//!   db.key      db.crt      db.esl      db.auth
//!   GUID        # owner GUID used for the ESL files
//!   README.md   # operator-facing notes about the keyring
//! ```

use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Command;

use thiserror::Error;

/// Test-keyring marker baked into every CN. Must stay in sync with
/// `loader::PLACEHOLDER_TOKEN` and the audit script.
pub const TEST_ONLY_MARKER: &str = "TEST_ONLY_NOT_FOR_PRODUCTION";

/// Default cert validity in days. 10 years — long enough that test
/// runs don't fail on cert expiry; short enough that a leaked key
/// becomes useless within a decade. Tests can override.
pub const DEFAULT_VALIDITY_DAYS: u32 = 3650;

/// One of the three Secure Boot variables that gets a cert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Platform Key — the root of trust. Self-signed.
    Pk,
    /// Key Exchange Key — signs the db updates. Signed by PK.
    Kek,
    /// Allowed-signature database — signs EFI binaries (kernel, shim,
    /// grub). Signed by KEK.
    Db,
}

impl Role {
    /// Filename stem (no extension) used for all artifacts of a role.
    #[must_use]
    pub fn stem(self) -> &'static str {
        match self {
            Self::Pk => "PK",
            Self::Kek => "KEK",
            Self::Db => "db",
        }
    }

    /// Subject CN for openssl. The marker is the leading token so the
    /// audit's `grep --fixed-strings` always wins.
    #[must_use]
    pub fn subject_cn(self) -> String {
        format!("/CN={TEST_ONLY_MARKER} aegis-hwsim {}", self.stem())
    }

    /// UEFI variable name passed to `sign-efi-sig-list`.
    #[must_use]
    pub fn uefi_var_name(self) -> &'static str {
        match self {
            Self::Pk => "PK",
            Self::Kek => "KEK",
            Self::Db => "db",
        }
    }

    /// Iteration order: PK, KEK, db. Each role's `.auth` is signed by
    /// the previous role's `.key`, so order matters.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[Self::Pk, Self::Kek, Self::Db]
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.stem())
    }
}

/// Knobs for [`generate`]. Constructed via `Default::default()` for
/// the production path; tests inject smaller validity windows for speed.
#[derive(Debug, Clone)]
pub struct GenerateOptions {
    /// Output directory. Created if missing.
    pub out_dir: PathBuf,
    /// Owner GUID for the ESL entries. Defaults to a constant
    /// `aegis-hwsim` test GUID — operators can grep OVMF VARS for it.
    pub owner_guid: String,
    /// Cert validity in days.
    pub validity_days: u32,
    /// Fixed timestamp passed to `sign-efi-sig-list`. Reproducible
    /// builds use a constant; tests do too. None → tool's default
    /// (current UTC time).
    pub timestamp: Option<String>,
}

impl Default for GenerateOptions {
    fn default() -> Self {
        Self {
            out_dir: PathBuf::from("firmware/test-keyring/generated"),
            // RFC 4122 v4-shaped, but content is stable. The leading
            // `aeae...` makes the GUID grep-able in OVMF VARS dumps:
            // `xxd OVMF_VARS.fd | grep -i aeae`.
            owner_guid: "aeaeaeae-aeae-4aea-aeae-aeaeaeaeaeae".to_string(),
            validity_days: DEFAULT_VALIDITY_DAYS,
            timestamp: Some("2024-01-01 00:00:00".to_string()),
        }
    }
}

/// Errors from [`generate`].
#[derive(Debug, Error)]
pub enum GenerateError {
    /// A required tool isn't on PATH. Caller should map to skip
    /// (exit 77) rather than fail.
    #[error("required tool '{tool}' not on PATH ({hint})")]
    MissingTool {
        /// Binary name.
        tool: &'static str,
        /// Operator-facing hint, e.g. install command.
        hint: &'static str,
    },

    /// Failed to create or write into the output directory.
    #[error("output directory {path:?}: {source}")]
    OutputDir {
        /// The output directory.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// A subprocess returned non-zero or didn't spawn.
    #[error("{tool} {args:?} failed: {detail}")]
    Subprocess {
        /// Tool name.
        tool: &'static str,
        /// Arguments passed.
        args: Vec<String>,
        /// stderr or spawn error rendered as a single string.
        detail: String,
    },
}

/// Generate the full PK/KEK/db keyring under `opts.out_dir`. Returns
/// the canonical path to each role's artifacts.
///
/// Idempotent: if files already exist they're overwritten. Caller is
/// responsible for tearing down previous output if reproducibility
/// matters.
///
/// # Errors
///
/// Returns [`GenerateError::MissingTool`] for any of the three external
/// dependencies; [`GenerateError::OutputDir`] for I/O on the output
/// directory; [`GenerateError::Subprocess`] for a tool exiting non-zero.
pub fn generate(opts: &GenerateOptions) -> Result<KeyringPaths, GenerateError> {
    require_tool("openssl", "Debian: apt install openssl")?;
    require_tool("cert-to-efi-sig-list", "Debian: apt install efitools")?;
    require_tool("sign-efi-sig-list", "Debian: apt install efitools")?;

    std::fs::create_dir_all(&opts.out_dir).map_err(|source| GenerateError::OutputDir {
        path: opts.out_dir.clone(),
        source,
    })?;

    // Step 1: certs. Each role gets a self-contained PEM key + cert.
    for role in Role::all() {
        gen_cert(*role, opts)?;
    }

    // Step 2: ESL. Convert each PEM cert to a UEFI signature list.
    for role in Role::all() {
        cert_to_esl(*role, opts)?;
    }

    // Step 3: AUTH. Wrap each ESL in an authenticated update payload.
    // PK signs its own AUTH (UEFI rule: PK is self-managed); KEK is
    // signed by PK; db is signed by KEK. So the signing key is the
    // PREVIOUS role's, except for PK itself.
    sign_esl(Role::Pk, Role::Pk, opts)?;
    sign_esl(Role::Kek, Role::Pk, opts)?;
    sign_esl(Role::Db, Role::Kek, opts)?;

    // Drop a GUID file so `virt-fw-vars` (or a successor tool) can
    // pick up the owner identity without re-deriving it.
    let guid_path = opts.out_dir.join("GUID");
    std::fs::write(&guid_path, opts.owner_guid.as_bytes()).map_err(|source| {
        GenerateError::OutputDir {
            path: guid_path.clone(),
            source,
        }
    })?;

    write_readme(opts)?;

    Ok(KeyringPaths::new(&opts.out_dir))
}

/// Resolved paths to each role's artifacts. Returned by [`generate`]
/// so callers don't have to re-derive paths.
#[derive(Debug, Clone)]
pub struct KeyringPaths {
    /// PK private key (PEM).
    pub pk_key: PathBuf,
    /// PK certificate (PEM).
    pub pk_crt: PathBuf,
    /// PK signature list.
    pub pk_esl: PathBuf,
    /// PK self-signed auth update.
    pub pk_auth: PathBuf,
    /// KEK private key (PEM).
    pub kek_key: PathBuf,
    /// KEK certificate (PEM).
    pub kek_crt: PathBuf,
    /// KEK signature list.
    pub kek_esl: PathBuf,
    /// KEK auth update (signed by PK).
    pub kek_auth: PathBuf,
    /// db private key (PEM).
    pub db_key: PathBuf,
    /// db certificate (PEM).
    pub db_crt: PathBuf,
    /// db signature list.
    pub db_esl: PathBuf,
    /// db auth update (signed by KEK).
    pub db_auth: PathBuf,
    /// Owner GUID file.
    pub guid: PathBuf,
}

impl KeyringPaths {
    fn new(dir: &Path) -> Self {
        let p = |stem: &str, ext: &str| dir.join(format!("{stem}.{ext}"));
        Self {
            pk_key: p("PK", "key"),
            pk_crt: p("PK", "crt"),
            pk_esl: p("PK", "esl"),
            pk_auth: p("PK", "auth"),
            kek_key: p("KEK", "key"),
            kek_crt: p("KEK", "crt"),
            kek_esl: p("KEK", "esl"),
            kek_auth: p("KEK", "auth"),
            db_key: p("db", "key"),
            db_crt: p("db", "crt"),
            db_esl: p("db", "esl"),
            db_auth: p("db", "auth"),
            guid: dir.join("GUID"),
        }
    }
}

fn gen_cert(role: Role, opts: &GenerateOptions) -> Result<(), GenerateError> {
    let key = opts.out_dir.join(format!("{}.key", role.stem()));
    let crt = opts.out_dir.join(format!("{}.crt", role.stem()));
    let subj = role.subject_cn();
    let days = opts.validity_days.to_string();
    let args: Vec<String> = vec![
        "req".into(),
        "-new".into(),
        "-x509".into(),
        "-newkey".into(),
        "rsa:2048".into(),
        "-nodes".into(),
        "-days".into(),
        days,
        "-subj".into(),
        subj,
        "-keyout".into(),
        key.display().to_string(),
        "-out".into(),
        crt.display().to_string(),
    ];
    run("openssl", &args)
}

fn cert_to_esl(role: Role, opts: &GenerateOptions) -> Result<(), GenerateError> {
    let crt = opts.out_dir.join(format!("{}.crt", role.stem()));
    let esl = opts.out_dir.join(format!("{}.esl", role.stem()));
    let args: Vec<String> = vec![
        "-g".into(),
        opts.owner_guid.clone(),
        crt.display().to_string(),
        esl.display().to_string(),
    ];
    run("cert-to-efi-sig-list", &args)
}

fn sign_esl(role: Role, signer: Role, opts: &GenerateOptions) -> Result<(), GenerateError> {
    let esl = opts.out_dir.join(format!("{}.esl", role.stem()));
    let auth = opts.out_dir.join(format!("{}.auth", role.stem()));
    let signer_key = opts.out_dir.join(format!("{}.key", signer.stem()));
    let signer_crt = opts.out_dir.join(format!("{}.crt", signer.stem()));
    let mut args: Vec<String> = vec![
        "-c".into(),
        signer_crt.display().to_string(),
        "-k".into(),
        signer_key.display().to_string(),
    ];
    if let Some(ts) = &opts.timestamp {
        args.push("-t".into());
        args.push(ts.clone());
    }
    args.extend([
        role.uefi_var_name().to_string(),
        esl.display().to_string(),
        auth.display().to_string(),
    ]);
    run("sign-efi-sig-list", &args)
}

fn run(tool: &'static str, args: &[String]) -> Result<(), GenerateError> {
    let output = Command::new(tool)
        .args(args)
        .output()
        .map_err(|e| GenerateError::Subprocess {
            tool,
            args: args.to_vec(),
            detail: format!("spawn failed: {e}"),
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(GenerateError::Subprocess {
            tool,
            args: args.to_vec(),
            detail: format!("exit {}: {}", output.status, stderr.trim()),
        });
    }
    Ok(())
}

fn require_tool(tool: &'static str, hint: &'static str) -> Result<(), GenerateError> {
    if which_on_path(tool).is_some() {
        Ok(())
    } else {
        Err(GenerateError::MissingTool { tool, hint })
    }
}

/// Same shape as `doctor::which_on_path` but kept private here to
/// avoid pulling the public doctor surface into this module's API.
fn which_on_path(binary: &str) -> Option<PathBuf> {
    let path = std::env::var("PATH").ok()?;
    for dir in path.split(':') {
        let candidate = PathBuf::from(dir).join(binary);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn write_readme(opts: &GenerateOptions) -> Result<(), GenerateError> {
    let readme_path = opts.out_dir.join("README.md");
    let body = format!(
        "# Generated test keyring\n\
        \n\
        **DO NOT SHIP.** Every cert here carries `{TEST_ONLY_MARKER}` in\n\
        its CN. The release-gate audit (`scripts/audit-no-test-keys.sh`)\n\
        refuses to publish any artifact carrying the marker, and\n\
        Cargo.toml's `exclude` keeps `firmware/test-keyring/**` out of\n\
        the cargo package by default.\n\
        \n\
        Generated by `aegis-hwsim gen-test-keyring`.\n\
        \n\
        ## Files\n\
        \n\
        | Stem | Role | Signs | Notes |\n\
        |------|------|-------|-------|\n\
        | `PK`  | Platform Key                  | itself (UEFI rule) | self-signed root of trust |\n\
        | `KEK` | Key Exchange Key              | db updates         | signed by PK |\n\
        | `db`  | Authorized signature database | EFI binaries (shim/grub/kernel) | signed by KEK |\n\
        \n\
        Each stem has 4 artifacts: `<stem>.key` (private key, PEM),\n\
        `<stem>.crt` (X.509 cert, PEM), `<stem>.esl` (UEFI signature\n\
        list), `<stem>.auth` (signed update payload OVMF accepts via\n\
        `SetVariable`).\n\
        \n\
        ## Owner GUID\n\
        \n\
        `{guid}` — grep an OVMF VARS dump for `aeae` to confirm a VM\n\
        is running on this keyring rather than real Microsoft enrollment.\n\
        \n\
        ## Loading into OVMF_VARS\n\
        \n\
        Deferred to E5.1d. The intended path is `virt-fw-vars`\n\
        (python3-virt-firmware): `virt-fw-vars --set-pk PK.auth\n\
        --set-kek KEK.auth --add-db db.auth -i template.fd -o\n\
        custom-pk.fd`.\n",
        guid = opts.owner_guid,
    );
    std::fs::write(&readme_path, body).map_err(|source| GenerateError::OutputDir {
        path: readme_path,
        source,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn role_subject_cn_carries_marker_at_start() {
        for role in Role::all() {
            let cn = role.subject_cn();
            // "/CN=<MARKER> ..." — split off the "/CN=" header and
            // confirm the marker is the first token.
            let after_eq = cn.strip_prefix("/CN=").expect("CN prefix");
            assert!(
                after_eq.starts_with(TEST_ONLY_MARKER),
                "role {role} CN must start with marker; got {cn:?}"
            );
        }
    }

    #[test]
    fn role_uefi_var_name_matches_uefi_spec() {
        // UEFI 2.10 §32.4.3: PK, KEK, db (lowercase) are the spec
        // names. Misnaming would route SetVariable to the wrong slot
        // — silently fatal in OVMF.
        assert_eq!(Role::Pk.uefi_var_name(), "PK");
        assert_eq!(Role::Kek.uefi_var_name(), "KEK");
        assert_eq!(Role::Db.uefi_var_name(), "db");
    }

    #[test]
    fn role_all_iterates_in_dependency_order() {
        // PK must come first (signs itself), then KEK (signed by PK),
        // then db (signed by KEK). The generator's auth-signing step
        // depends on this ordering — flipping it would try to sign
        // KEK before PK exists.
        let order: Vec<Role> = Role::all().to_vec();
        assert_eq!(order, vec![Role::Pk, Role::Kek, Role::Db]);
    }

    #[test]
    fn keyring_paths_layout_uses_role_stems() {
        let dir = PathBuf::from("/tmp/somewhere");
        let paths = KeyringPaths::new(&dir);
        assert_eq!(paths.pk_key, dir.join("PK.key"));
        assert_eq!(paths.kek_crt, dir.join("KEK.crt"));
        assert_eq!(paths.db_auth, dir.join("db.auth"));
        assert_eq!(paths.guid, dir.join("GUID"));
    }

    /// `MissingTool` is the path the CLI maps to skip (exit 77).
    /// We don't test it via env-mutation — `std::env::set_var` is
    /// `unsafe` under newer toolchains and the crate's `forbid(unsafe_code)`
    /// rejects unsafe blocks even in tests. Instead, assert the
    /// variant's Display output carries the fields the CLI surfaces
    /// (tool name + install hint). A future refactor that drops
    /// either field breaks this test before it reaches the operator.
    #[test]
    fn missing_tool_error_carries_tool_and_hint() {
        let e = GenerateError::MissingTool {
            tool: "openssl",
            hint: "Debian: apt install openssl",
        };
        let rendered = format!("{e}");
        assert!(rendered.contains("openssl"), "got {rendered:?}");
        assert!(rendered.contains("apt install openssl"), "got {rendered:?}");
    }

    /// Full end-to-end: generate the keyring, then assert each
    /// artifact exists and the cert CN contains the marker.
    /// Skips when the host is missing any of the three tools — the
    /// E5 doctor probes are the operator-facing surface; this test
    /// is silent self-skip so CI without efitools doesn't FAIL.
    #[test]
    fn generate_produces_full_keyring_with_marker_cn() {
        if which_on_path("openssl").is_none()
            || which_on_path("cert-to-efi-sig-list").is_none()
            || which_on_path("sign-efi-sig-list").is_none()
        {
            eprintln!("skipping: openssl + efitools required");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let opts = GenerateOptions {
            out_dir: tmp.path().to_path_buf(),
            // 30 days — minimal; we don't assert validity in the
            // test, but openssl insists on a positive integer.
            validity_days: 30,
            ..Default::default()
        };
        let paths = generate(&opts).expect("generate must succeed when tools present");

        for f in [
            &paths.pk_key,
            &paths.pk_crt,
            &paths.pk_esl,
            &paths.pk_auth,
            &paths.kek_key,
            &paths.kek_crt,
            &paths.kek_esl,
            &paths.kek_auth,
            &paths.db_key,
            &paths.db_crt,
            &paths.db_esl,
            &paths.db_auth,
            &paths.guid,
        ] {
            assert!(f.is_file(), "missing generated file: {}", f.display());
        }

        // The PK cert must carry the marker in its subject. We check
        // via openssl x509 -text rather than a binary grep so the
        // assertion is robust against ASN.1 encoding choices.
        let out = Command::new("openssl")
            .args([
                "x509",
                "-in",
                &paths.pk_crt.display().to_string(),
                "-noout",
                "-subject",
            ])
            .output()
            .expect("openssl x509 -subject must run");
        let subject = String::from_utf8_lossy(&out.stdout);
        assert!(
            subject.contains(TEST_ONLY_MARKER),
            "PK cert subject {subject:?} must contain {TEST_ONLY_MARKER}"
        );
    }
}
