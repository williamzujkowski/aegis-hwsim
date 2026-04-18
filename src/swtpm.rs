//! swtpm lifecycle management.
//!
//! A [`SwtpmInstance`] represents a per-run swtpm process with isolated
//! state + socket. The intended lifecycle:
//!
//! ```text
//! let spec = SwtpmSpec::derive("run-42", &work_root, TpmVersion::Tpm20);
//! let swtpm = SwtpmInstance::spawn(&spec)?;
//! // pass swtpm.socket_path() to QEMU's -chardev socket arg
//! // ...run QEMU...
//! drop(swtpm); // SIGKILLs swtpm on scope exit
//! ```
//!
//! Isolation: each run has its own `<work_root>/<run_id>/swtpm.sock`
//! and `<work_root>/<run_id>/tpm-state/` directory. No cross-run PCR
//! contamination possible.
//!
//! TPM version `None` on a persona → no `SwtpmInstance` is created; the
//! caller gets back a [`SwtpmInstance::NoTpm`] variant and the
//! Invocation builder (E2.4) skips the chardev wiring.
//!
//! Testability: path derivation is factored into a pure
//! [`SwtpmSpec::derive`] function. The subprocess-spawning path accepts
//! a `binary` override so tests can point at a fake swtpm (e.g. the
//! `sleep` command) without needing the real swtpm installed.

use crate::persona::TpmVersion;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use thiserror::Error;

/// Resolved per-run file layout for a swtpm invocation. Pure; no I/O.
/// Construct via [`SwtpmSpec::derive`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwtpmSpec {
    /// Version to emulate. `None` variant means no swtpm will be spawned.
    pub version: TpmVersion,
    /// Per-run state directory under `work_root/<run_id>/tpm-state/`.
    pub state_dir: PathBuf,
    /// Per-run UNIX socket path under `work_root/<run_id>/swtpm.sock`.
    pub socket: PathBuf,
}

impl SwtpmSpec {
    /// Derive the per-run file layout. Pure — no directories are
    /// created, no processes are spawned.
    #[must_use]
    pub fn derive(run_id: &str, work_root: &Path, version: TpmVersion) -> Self {
        let run_dir = work_root.join(run_id);
        Self {
            version,
            state_dir: run_dir.join("tpm-state"),
            socket: run_dir.join("swtpm.sock"),
        }
    }
}

/// Either a live swtpm process + its spec, or the `NoTpm` sentinel when
/// the persona opted out of TPM emulation.
///
/// The `Drop` impl on the `Live` variant sends SIGKILL via
/// [`std::process::Child::kill`] — swtpm has no persistent state worth
/// flushing beyond the per-run state dir (which the harness usually
/// discards after the scenario).
#[derive(Debug)]
pub enum SwtpmInstance {
    /// Persona requested no TPM. No child was spawned. `spec.version`
    /// will be `TpmVersion::None`.
    NoTpm {
        /// The resolved spec (with `version = TpmVersion::None`).
        spec: SwtpmSpec,
    },
    /// swtpm process is running and bound to `spec.socket`.
    Live {
        /// The resolved spec for this run.
        spec: SwtpmSpec,
        /// Handle to the child process. Kept private to force callers
        /// through the typed accessors + drop-guard.
        child: Child,
    },
}

impl SwtpmInstance {
    /// Spawn swtpm for `spec`. On `TpmVersion::None`, skip the subprocess
    /// and return the `NoTpm` variant (no I/O). Otherwise:
    /// create the state dir, invoke `swtpm socket --tpm2 --tpmstate dir=<state> --ctrl type=unixio,path=<sock>`
    /// (swtpm 1.2 variant drops `--tpm2`), return a `Live` handle.
    ///
    /// # Errors
    ///
    /// - [`SwtpmError::WorkDirInaccessible`] when the state dir can't
    ///   be created.
    /// - [`SwtpmError::SpawnFailed`] when the binary can't be launched.
    pub fn spawn(spec: &SwtpmSpec) -> Result<Self, SwtpmError> {
        Self::spawn_with_binary(spec, "swtpm")
    }

    /// Testing-friendly version of [`Self::spawn`] that lets the caller
    /// override the binary path — pass `"sleep"` (or a shell script) to
    /// exercise the lifecycle without needing real swtpm installed.
    ///
    /// # Errors
    ///
    /// Same as [`Self::spawn`].
    pub fn spawn_with_binary(spec: &SwtpmSpec, binary: &str) -> Result<Self, SwtpmError> {
        if matches!(spec.version, TpmVersion::None) {
            return Ok(Self::NoTpm { spec: spec.clone() });
        }
        fs::create_dir_all(&spec.state_dir).map_err(|e| SwtpmError::WorkDirInaccessible {
            path: spec.state_dir.clone(),
            kind: format!("{:?}", e.kind()),
        })?;

        let mut cmd = Command::new(binary);
        if binary == "swtpm" {
            cmd.arg("socket");
            if matches!(spec.version, TpmVersion::Tpm20) {
                cmd.arg("--tpm2");
            }
            cmd.args([
                "--tpmstate",
                &format!("dir={}", spec.state_dir.display()),
                "--ctrl",
                &format!("type=unixio,path={}", spec.socket.display()),
                "--log",
                "level=0",
            ]);
        } else {
            // Test stub: pass a single arg that keeps the process alive
            // long enough for the lifecycle test to observe it.
            cmd.arg("30");
        }

        let child = cmd.spawn().map_err(|e| SwtpmError::SpawnFailed {
            binary: binary.to_string(),
            kind: format!("{:?}", e.kind()),
        })?;

        Ok(Self::Live {
            spec: spec.clone(),
            child,
        })
    }

    /// The UNIX socket QEMU's `-chardev socket` arg should bind to.
    /// Returns `None` when this instance is `NoTpm` (caller must skip
    /// the chardev wiring).
    #[must_use]
    pub fn socket_path(&self) -> Option<&Path> {
        match self {
            Self::NoTpm { .. } => None,
            Self::Live { spec, .. } => Some(&spec.socket),
        }
    }

    /// The spec this instance was built from.
    #[must_use]
    pub fn spec(&self) -> &SwtpmSpec {
        match self {
            Self::NoTpm { spec } | Self::Live { spec, .. } => spec,
        }
    }

    /// `true` when the TPM was skipped (persona's `tpm.version == "none"`).
    #[must_use]
    pub fn is_no_tpm(&self) -> bool {
        matches!(self, Self::NoTpm { .. })
    }
}

impl Drop for SwtpmInstance {
    fn drop(&mut self) {
        if let Self::Live { child, .. } = self {
            // SIGKILL via Child::kill — swtpm's per-run state dir is
            // ephemeral; no graceful-shutdown value. Ignore errors:
            // the child may already be dead and we can't meaningfully
            // recover from a kill failure at drop time.
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Failure modes for swtpm lifecycle.
#[derive(Debug, Error)]
pub enum SwtpmError {
    /// The state dir under `work_root/<run_id>/tpm-state/` couldn't be
    /// created (permissions, disk full, parent missing, etc.).
    #[error("swtpm state dir {path} inaccessible: {kind}")]
    WorkDirInaccessible {
        /// The state dir path we tried to create.
        path: PathBuf,
        /// Rendered `io::ErrorKind`.
        kind: String,
    },

    /// The binary couldn't be launched — most commonly a
    /// `NotFound` if swtpm isn't installed on the host.
    #[error("failed to spawn {binary}: {kind}. Is swtpm installed? Debian: `apt install swtpm`")]
    SpawnFailed {
        /// Binary name that failed.
        binary: String,
        /// Rendered `io::ErrorKind`.
        kind: String,
    },
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn derive_socket_path_is_under_work_root() {
        let root = PathBuf::from("/tmp/hwsim-work");
        let spec = SwtpmSpec::derive("run-42", &root, TpmVersion::Tpm20);
        assert_eq!(spec.socket, root.join("run-42").join("swtpm.sock"));
        assert_eq!(spec.state_dir, root.join("run-42").join("tpm-state"));
    }

    #[test]
    fn derive_preserves_tpm_version() {
        let root = PathBuf::from("/tmp/x");
        assert_eq!(
            SwtpmSpec::derive("r", &root, TpmVersion::None).version,
            TpmVersion::None,
        );
        assert_eq!(
            SwtpmSpec::derive("r", &root, TpmVersion::Tpm12).version,
            TpmVersion::Tpm12,
        );
        assert_eq!(
            SwtpmSpec::derive("r", &root, TpmVersion::Tpm20).version,
            TpmVersion::Tpm20,
        );
    }

    #[test]
    fn spawn_with_tpm_none_returns_no_tpm_without_io() {
        let tmp = tempfile::tempdir().unwrap();
        let spec = SwtpmSpec::derive("run-none", tmp.path(), TpmVersion::None);
        let inst = SwtpmInstance::spawn(&spec).unwrap();
        assert!(inst.is_no_tpm());
        assert!(inst.socket_path().is_none());
        // State dir was NOT created — NoTpm short-circuits before fs::create_dir_all.
        assert!(
            !spec.state_dir.exists(),
            "NoTpm must not create the state dir: {:?}",
            spec.state_dir
        );
    }

    #[test]
    fn spawn_with_fake_binary_creates_state_dir_and_returns_live() {
        let tmp = tempfile::tempdir().unwrap();
        let spec = SwtpmSpec::derive("run-live", tmp.path(), TpmVersion::Tpm20);
        // `sleep 30` plays the role of a long-running swtpm.
        let inst = SwtpmInstance::spawn_with_binary(&spec, "sleep").unwrap();
        assert!(!inst.is_no_tpm());
        assert!(spec.state_dir.exists(), "state dir should be created");
        assert_eq!(inst.socket_path(), Some(spec.socket.as_path()));
        drop(inst); // drop-guard should SIGKILL the sleep process
    }

    #[test]
    fn spawn_failure_yields_named_error() {
        let tmp = tempfile::tempdir().unwrap();
        let spec = SwtpmSpec::derive("run-fail", tmp.path(), TpmVersion::Tpm20);
        let err =
            SwtpmInstance::spawn_with_binary(&spec, "/definitely/not/a/binary-xyz123").unwrap_err();
        assert!(
            matches!(err, SwtpmError::SpawnFailed { .. }),
            "expected SpawnFailed, got {err:?}"
        );
    }

    #[test]
    fn work_dir_inaccessible_when_parent_is_a_file() {
        let tmp = tempfile::tempdir().unwrap();
        // Put a regular FILE where the per-run dir would go. Now
        // `<file>/tpm-state/` can't be created — parent isn't a dir.
        let blocker = tmp.path().join("blocked");
        fs::write(&blocker, b"not-a-dir").unwrap();
        let spec = SwtpmSpec {
            version: TpmVersion::Tpm20,
            state_dir: blocker.join("tpm-state"),
            socket: blocker.join("swtpm.sock"),
        };
        let err = SwtpmInstance::spawn_with_binary(&spec, "sleep").unwrap_err();
        assert!(
            matches!(err, SwtpmError::WorkDirInaccessible { .. }),
            "expected WorkDirInaccessible, got {err:?}"
        );
    }

    #[test]
    fn drop_guard_terminates_child() {
        use std::time::Duration;
        let tmp = tempfile::tempdir().unwrap();
        let spec = SwtpmSpec::derive("run-drop", tmp.path(), TpmVersion::Tpm20);
        let inst = SwtpmInstance::spawn_with_binary(&spec, "sleep").unwrap();
        // Capture the PID before dropping.
        let pid = match &inst {
            SwtpmInstance::Live { child, .. } => child.id(),
            SwtpmInstance::NoTpm { .. } => panic!("should be live"),
        };
        drop(inst);
        // Give the OS a moment to reap. `kill -0 PID` should now fail.
        std::thread::sleep(Duration::from_millis(100));
        let alive = std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        assert!(!alive, "drop-guard should have killed PID {pid}");
    }
}
