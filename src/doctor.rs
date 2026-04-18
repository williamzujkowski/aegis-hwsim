//! Host-environment check.
//!
//! `aegis-hwsim doctor` inspects the host for the binaries + firmware
//! files the harness needs (qemu-system-x86_64, swtpm, OVMF
//! {CODE,VARS}_4M.{secboot.,}.{ms.,}fd) and reports per-check
//! verdicts (`OK` / `WARN` / `FAIL`). Mirrors the
//! [aegis-boot doctor](https://github.com/williamzujkowski/aegis-boot)
//! shape so operators get the same diagnostic UX across the family.
//!
//! Pure logic + path/PATH lookups; no subprocess spawning beyond
//! version probes (and even those use `--version`/`-v`, never shells).
//!
//! Why an aegis-hwsim doctor: when a scenario `Skip`s with reason
//! "qemu-system-x86_64 not on PATH", the operator gets ONE skip
//! reason at a time. Doctor surfaces them all in one pass so the
//! operator can fix everything in one apt-install.

use std::path::{Path, PathBuf};

/// Per-check outcome. Mirrors aegis-boot's `Verdict` for cross-family
/// readability — operators familiar with `aegis-boot doctor` see the
/// same labels here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Check passed; no action needed.
    Pass,
    /// Check found a degraded-but-usable state (e.g. swtpm missing,
    /// only no-TPM scenarios will run).
    Warn,
    /// Check failed; the harness can't run at all without the
    /// referenced fix.
    Fail,
}

impl Verdict {
    /// Single-character status for the table prefix.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
        }
    }
}

/// One row of the doctor report.
#[derive(Debug, Clone)]
pub struct Check {
    /// Verdict.
    pub verdict: Verdict,
    /// Subject of the check (e.g. `qemu-system-x86_64`).
    pub subject: String,
    /// One-line operator-facing message. For `Pass`, what was found;
    /// for `Warn`/`Fail`, the action to take.
    pub message: String,
}

/// Output of [`run`]. Aggregates per-check rows + a single
/// [`Self::next_action`] pointer.
#[derive(Debug, Clone)]
pub struct Report {
    /// Ordered checks.
    pub checks: Vec<Check>,
}

impl Report {
    /// Whether any check has FAIL severity.
    #[must_use]
    pub fn has_failures(&self) -> bool {
        self.checks.iter().any(|c| c.verdict == Verdict::Fail)
    }

    /// Whether any check has WARN severity.
    #[must_use]
    pub fn has_warnings(&self) -> bool {
        self.checks.iter().any(|c| c.verdict == Verdict::Warn)
    }

    /// Single operator-facing next-action string. Picks the
    /// highest-severity actionable check; falls back to a celebratory
    /// "ready" message when everything passes.
    #[must_use]
    pub fn next_action(&self) -> String {
        if let Some(c) = self.checks.iter().find(|c| c.verdict == Verdict::Fail) {
            return format!("FIX: {} — {}", c.subject, c.message);
        }
        if let Some(c) = self.checks.iter().find(|c| c.verdict == Verdict::Warn) {
            return format!("CONSIDER: {} — {}", c.subject, c.message);
        }
        "ALL CHECKS PASS — harness is ready for any registered scenario".to_string()
    }

    /// Pretty-print the report to a String. Operator-facing format
    /// matches the aegis-boot family; columns: VERDICT, SUBJECT,
    /// MESSAGE.
    #[must_use]
    pub fn render(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::with_capacity(self.checks.len() * 80);
        let _ = writeln!(out, "{:<6} {:<30} MESSAGE", "STATUS", "SUBJECT");
        for c in &self.checks {
            let _ = writeln!(
                out,
                "{:<6} {:<30} {}",
                c.verdict.label(),
                c.subject,
                c.message
            );
        }
        let _ = writeln!(out);
        let _ = writeln!(out, "NEXT ACTION: {}", self.next_action());
        out
    }
}

/// Run the doctor checks against `firmware_root`. Returns a [`Report`]
/// the caller renders + uses to set its exit code (FAIL → 1, WARN →
/// 0, ALL PASS → 0).
#[must_use]
pub fn run(firmware_root: &Path) -> Report {
    let mut checks = Vec::with_capacity(8);

    // Required binaries.
    checks.push(check_binary(
        "qemu-system-x86_64",
        Verdict::Fail,
        "Debian: apt install qemu-system-x86. Required for every scenario.",
    ));
    checks.push(check_binary(
        "swtpm",
        Verdict::Warn,
        "Debian: apt install swtpm. Only no-TPM scenarios (qemu-boots-ovmf) \
         can run without it; persona-driven TPM scenarios will Skip.",
    ));

    // OVMF firmware files.
    checks.push(check_firmware_file(
        firmware_root,
        "OVMF_CODE_4M.secboot.fd",
        Verdict::Fail,
        "Debian: apt install ovmf. Required for any Secure-Boot scenario.",
    ));
    checks.push(check_firmware_file(
        firmware_root,
        "OVMF_VARS_4M.ms.fd",
        Verdict::Fail,
        "Debian: apt install ovmf (provides the MS-enrolled VARS template).",
    ));
    checks.push(check_firmware_file(
        firmware_root,
        "OVMF_CODE_4M.fd",
        Verdict::Warn,
        "Optional: needed only by personas with ovmf_variant=disabled.",
    ));
    checks.push(check_firmware_file(
        firmware_root,
        "OVMF_VARS_4M.fd",
        Verdict::Warn,
        "Optional: needed by personas with ovmf_variant=setup_mode or =disabled.",
    ));

    // Persona library presence.
    checks.push(check_personas_dir(Path::new("personas")));

    Report { checks }
}

fn check_binary(name: &str, severity_on_miss: Verdict, fix: &str) -> Check {
    if let Some(path) = which_on_path(name) {
        Check {
            verdict: Verdict::Pass,
            subject: name.to_string(),
            message: format!("found at {}", path.display()),
        }
    } else {
        Check {
            verdict: severity_on_miss,
            subject: name.to_string(),
            message: format!("not on PATH. {fix}"),
        }
    }
}

fn check_firmware_file(root: &Path, filename: &str, severity_on_miss: Verdict, fix: &str) -> Check {
    let path = root.join(filename);
    if path.is_file() {
        Check {
            verdict: Verdict::Pass,
            subject: filename.to_string(),
            message: format!("found at {}", path.display()),
        }
    } else {
        Check {
            verdict: severity_on_miss,
            subject: filename.to_string(),
            message: format!("missing under {}. {fix}", root.display()),
        }
    }
}

fn check_personas_dir(personas_dir: &Path) -> Check {
    if !personas_dir.is_dir() {
        return Check {
            verdict: Verdict::Fail,
            subject: "personas/".into(),
            message: format!(
                "directory not found at {}. Run from the aegis-hwsim repo root.",
                personas_dir.display()
            ),
        };
    }
    let count = std::fs::read_dir(personas_dir)
        .map(|iter| {
            iter.flatten()
                .filter(|e| {
                    e.path()
                        .extension()
                        .and_then(|s| s.to_str())
                        .is_some_and(|s| s == "yaml")
                })
                .count()
        })
        .unwrap_or(0);
    if count == 0 {
        return Check {
            verdict: Verdict::Fail,
            subject: "personas/".into(),
            message: format!(
                "no .yaml files under {}. Persona library is empty.",
                personas_dir.display()
            ),
        };
    }
    Check {
        verdict: Verdict::Pass,
        subject: "personas/".into(),
        message: format!("{count} persona file(s) present"),
    }
}

/// PATH lookup matching the scenarios' `binary_on_path` helper,
/// returning the resolved path (not just bool) so we can include it
/// in the Pass message.
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn fake_firmware_root() -> (TempDir, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        for name in [
            "OVMF_CODE_4M.secboot.fd",
            "OVMF_CODE_4M.fd",
            "OVMF_VARS_4M.ms.fd",
            "OVMF_VARS_4M.fd",
        ] {
            std::fs::write(root.join(name), b"fake").unwrap();
        }
        (tmp, root)
    }

    #[test]
    fn next_action_picks_first_failure() {
        let r = Report {
            checks: vec![
                Check {
                    verdict: Verdict::Pass,
                    subject: "a".into(),
                    message: "ok".into(),
                },
                Check {
                    verdict: Verdict::Fail,
                    subject: "missing-binary".into(),
                    message: "install via apt".into(),
                },
                Check {
                    verdict: Verdict::Warn,
                    subject: "should-not-be-picked".into(),
                    message: "warn".into(),
                },
            ],
        };
        assert!(r.has_failures());
        assert!(r.next_action().contains("missing-binary"));
        assert!(r.next_action().starts_with("FIX:"));
    }

    #[test]
    fn next_action_picks_warning_when_no_failures() {
        let r = Report {
            checks: vec![
                Check {
                    verdict: Verdict::Pass,
                    subject: "a".into(),
                    message: "ok".into(),
                },
                Check {
                    verdict: Verdict::Warn,
                    subject: "swtpm".into(),
                    message: "install for TPM scenarios".into(),
                },
            ],
        };
        assert!(!r.has_failures());
        assert!(r.has_warnings());
        let action = r.next_action();
        assert!(action.starts_with("CONSIDER:"));
        assert!(action.contains("swtpm"));
    }

    #[test]
    fn next_action_celebrates_when_all_pass() {
        let r = Report {
            checks: vec![Check {
                verdict: Verdict::Pass,
                subject: "everything".into(),
                message: "ok".into(),
            }],
        };
        assert!(!r.has_failures());
        assert!(!r.has_warnings());
        assert!(r.next_action().starts_with("ALL CHECKS PASS"));
    }

    #[test]
    fn check_firmware_file_returns_pass_when_present() {
        let (_tmp, root) = fake_firmware_root();
        let c = check_firmware_file(
            &root,
            "OVMF_CODE_4M.secboot.fd",
            Verdict::Fail,
            "install ovmf",
        );
        assert_eq!(c.verdict, Verdict::Pass);
        assert!(c.message.contains("found at"));
    }

    #[test]
    fn check_firmware_file_returns_severity_when_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let c = check_firmware_file(tmp.path(), "OVMF_CODE_4M.secboot.fd", Verdict::Fail, "fix");
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.message.contains("missing"));
    }

    #[test]
    fn check_binary_returns_pass_for_sh() {
        // /bin/sh is on PATH on every CI runner.
        let c = check_binary("sh", Verdict::Fail, "fix");
        assert_eq!(c.verdict, Verdict::Pass);
    }

    #[test]
    fn check_binary_returns_severity_for_missing() {
        let c = check_binary("definitely-not-a-binary-xyz-doctor", Verdict::Warn, "fix");
        assert_eq!(c.verdict, Verdict::Warn);
        assert!(c.message.contains("not on PATH"));
    }

    #[test]
    fn check_personas_dir_returns_fail_for_missing_dir() {
        let c = check_personas_dir(Path::new("/no/such/personas-dir-xyz"));
        assert_eq!(c.verdict, Verdict::Fail);
    }

    #[test]
    fn render_includes_status_subject_message_and_next_action() {
        let (_tmp, root) = fake_firmware_root();
        let r = run(&root);
        let s = r.render();
        assert!(s.contains("STATUS"));
        assert!(s.contains("SUBJECT"));
        assert!(s.contains("MESSAGE"));
        assert!(s.contains("NEXT ACTION:"));
    }
}
