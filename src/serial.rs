//! QEMU serial capture.
//!
//! Spawns a QEMU [`std::process::Command`] with `stdout` piped through
//! a reader thread that tees each chunk to (a) a log file under the
//! per-run working dir and (b) a bounded in-memory buffer the caller
//! can poll via [`SerialHandle::wait_for_line`] / snapshot via
//! [`SerialHandle::buffer_snapshot`].
//!
//! Scenarios (E3+) consume this via:
//!
//! ```no_run
//! # use std::process::Command;
//! # use std::time::Duration;
//! # use aegis_hwsim::serial::SerialCapture;
//! # use std::path::Path;
//! # let cmd: Command = todo!();
//! # let log_path: &Path = Path::new("/tmp/serial.log");
//! let mut handle = SerialCapture::spawn(cmd, log_path, None).unwrap();
//! handle.wait_for_line("shim: loading grub", Duration::from_secs(60));
//! let full = handle.buffer_snapshot();
//! // ...
//! drop(handle); // sends SIGKILL + joins the reader thread
//! ```
//!
//! Bounded buffer: default 10 MiB. When the guest produces more than
//! that, the oldest bytes are evicted and a sentinel
//! `[--- BUFFER OVERFLOW, N bytes elided ---]` is written in their
//! place so a runaway guest can't OOM the runner.
//!
//! No tokio: std threads + `Arc<Mutex>` + polling. Scenario tests don't
//! need microsecond-precision waits.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use thiserror::Error;

/// Default in-memory buffer cap. 10 MiB is plenty for a boot-chain
/// serial log (a full Linux boot emits ~200 KB).
pub const DEFAULT_BUFFER_CAP_BYTES: usize = 10 * 1024 * 1024;

/// How often [`SerialHandle::wait_for_line`] polls the shared buffer.
/// 50ms is a balance: short enough that assertions feel live, long
/// enough that the polling overhead is invisible.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Shared state between the reader thread and the handle. `Mutex` keeps
/// it dead simple — this is a test harness, not a throughput system.
#[derive(Debug)]
struct SerialBuffer {
    /// In-memory text (may have been truncated if overflow fired).
    text: String,
    /// Total bytes evicted by overflow. Nonzero → the user-facing
    /// buffer was capped.
    overflow_bytes: usize,
    /// Set by the reader thread on EOF / error.
    closed: bool,
    /// Per-instance cap. Kept here so tests can verify overflow with a
    /// tiny cap.
    cap_bytes: usize,
}

impl SerialBuffer {
    fn push(&mut self, chunk: &[u8]) {
        // Append as UTF-8, falling back to lossy conversion for
        // non-UTF-8 bytes (QEMU serial is usually ASCII but may emit
        // raw bytes during boot).
        self.text.push_str(&String::from_utf8_lossy(chunk));
        // Enforce cap: if we went over, drop from the front and
        // replace with a sentinel so readers see that bytes were lost.
        if self.text.len() > self.cap_bytes {
            let excess = self.text.len() - self.cap_bytes;
            self.overflow_bytes += excess;
            let marker = format!(
                "\n[--- BUFFER OVERFLOW, {} bytes elided ---]\n",
                self.overflow_bytes
            );
            // Keep the tail, prepend the marker. Use char_indices to
            // slice at a UTF-8 boundary.
            let start_byte = char_start_at_or_after(&self.text, excess);
            let tail = self.text.split_off(start_byte);
            self.text = marker;
            self.text.push_str(&tail);
        }
    }
}

/// Find the first char boundary at or after `byte_offset`. Safe slice
/// point for `String::split_off`. If `byte_offset >= len` returns `len`.
fn char_start_at_or_after(s: &str, byte_offset: usize) -> usize {
    if byte_offset >= s.len() {
        return s.len();
    }
    let mut i = byte_offset;
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

/// Handle to a running captured subprocess.
///
/// Drops: sends SIGKILL via [`Child::kill`], reaps, and joins the
/// reader thread. No poisoned-mutex handling — if the reader thread
/// panics, we surface it via [`SerialError`] from accessor methods.
#[derive(Debug)]
pub struct SerialHandle {
    child: Child,
    shared: Arc<Mutex<SerialBuffer>>,
    reader: Option<JoinHandle<()>>,
    log_path: PathBuf,
}

impl SerialHandle {
    /// Wait until a line containing `pattern` appears in the buffer, or
    /// `timeout` elapses. Returns the matching line (without trailing
    /// newline) on success, `None` on timeout or child exit.
    ///
    /// The match is a substring search on complete lines; partial lines
    /// at the tail are not matched until they're terminated (avoids
    /// spurious matches on ANSI-escape-mid-line torn reads).
    #[must_use]
    pub fn wait_for_line(&self, pattern: &str, timeout: Duration) -> Option<String> {
        let deadline = Instant::now() + timeout;
        loop {
            {
                let Ok(buf) = self.shared.lock() else {
                    return None; // poisoned → reader panicked, give up
                };
                for line in buf.text.lines() {
                    if line.contains(pattern) {
                        return Some(line.to_string());
                    }
                }
                if buf.closed {
                    return None;
                }
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    /// Current buffer snapshot. Safe to call mid-run; returns a clone
    /// of whatever's been captured so far.
    #[must_use]
    pub fn buffer_snapshot(&self) -> String {
        self.shared.lock().map_or_else(
            |_| String::from("<buffer mutex poisoned>"),
            |b| b.text.clone(),
        )
    }

    /// How many bytes have been evicted by overflow.
    #[must_use]
    pub fn overflow_bytes(&self) -> usize {
        self.shared.lock().map_or(0, |b| b.overflow_bytes)
    }

    /// Path to the per-run log file this capture is teeing into.
    #[must_use]
    pub fn log_path(&self) -> &Path {
        &self.log_path
    }

    /// SIGKILL the child and wait for exit. The reader thread closes
    /// on EOF and is joined by [`Self::drop`].
    ///
    /// # Errors
    ///
    /// Propagates the `io::Error` from `Child::kill` / `Child::wait`.
    pub fn kill(&mut self) -> Result<ExitStatus, std::io::Error> {
        self.child.kill()?;
        self.child.wait()
    }
}

impl Drop for SerialHandle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(h) = self.reader.take() {
            let _ = h.join();
        }
    }
}

/// Spawning the capture. No shared state with [`SerialHandle`] itself;
/// this is a free function factored into a struct just for namespacing.
pub struct SerialCapture;

impl SerialCapture {
    /// Spawn `cmd` with `stdout` + `stderr` piped into the reader thread.
    ///
    /// `log_path` is created (truncated) and each chunk written to it in
    /// parallel with the in-memory buffer. `cap_bytes = None` → use
    /// [`DEFAULT_BUFFER_CAP_BYTES`].
    ///
    /// # Errors
    ///
    /// - [`SerialError::SpawnFailed`] — child couldn't start.
    /// - [`SerialError::LogFileInaccessible`] — log couldn't be opened.
    pub fn spawn(
        mut cmd: Command,
        log_path: &Path,
        cap_bytes: Option<usize>,
    ) -> Result<SerialHandle, SerialError> {
        // Make sure the log dir exists; if it doesn't, the OpenOptions
        // below will fail with a clearer error than "spawn failed".
        if let Some(parent) = log_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| SerialError::LogFileInaccessible {
                path: log_path.to_path_buf(),
                kind: format!("{:?}", e.kind()),
            })?;
        }
        let log_file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(log_path)
            .map_err(|e| SerialError::LogFileInaccessible {
                path: log_path.to_path_buf(),
                kind: format!("{:?}", e.kind()),
            })?;

        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = cmd.spawn().map_err(|e| SerialError::SpawnFailed {
            kind: format!("{:?}", e.kind()),
        })?;

        let stdout = child.stdout.take().ok_or(SerialError::StdoutUnavailable)?;
        // stderr merged into the same buffer — QEMU writes diagnostics
        // to stderr and the caller shouldn't care which stream a line
        // came from.
        let stderr = child.stderr.take();

        let shared = Arc::new(Mutex::new(SerialBuffer {
            text: String::new(),
            overflow_bytes: 0,
            closed: false,
            cap_bytes: cap_bytes.unwrap_or(DEFAULT_BUFFER_CAP_BYTES),
        }));
        let shared_for_thread = Arc::clone(&shared);
        let reader = std::thread::spawn(move || {
            run_reader(stdout, stderr, log_file, &shared_for_thread);
        });

        Ok(SerialHandle {
            child,
            shared,
            reader: Some(reader),
            log_path: log_path.to_path_buf(),
        })
    }
}

/// Reader thread body. Tees stdout (and stderr, when captured) into
/// the shared buffer and the log file. Sets `closed=true` on EOF so
/// pollers break their loop.
fn run_reader(
    mut stdout: impl Read + Send + 'static,
    stderr: Option<impl Read + Send + 'static>,
    log_file: File,
    shared: &Arc<Mutex<SerialBuffer>>,
) {
    // Share the log writer across both drain threads. Mutex serializes
    // line-level interleaving; the rare stderr fan-out is tolerable.
    let log = Arc::new(Mutex::new(log_file));

    if let Some(stderr) = stderr {
        let shared2 = Arc::clone(shared);
        let log2 = Arc::clone(&log);
        let _ = std::thread::Builder::new()
            .name("serial-stderr".into())
            .spawn(move || drain_into(stderr, &shared2, &log2));
    }
    drain_into(&mut stdout, shared, &log);

    if let Ok(mut f) = log.lock() {
        let _ = f.flush();
    }
    if let Ok(mut buf) = shared.lock() {
        buf.closed = true;
    }
}

fn drain_into(mut src: impl Read, shared: &Arc<Mutex<SerialBuffer>>, log: &Arc<Mutex<File>>) {
    let mut chunk = [0_u8; 4096];
    loop {
        match src.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let data = &chunk[..n];
                if let Ok(mut buf) = shared.lock() {
                    buf.push(data);
                }
                if let Ok(mut f) = log.lock() {
                    let _ = f.write_all(data);
                }
            }
        }
    }
}

/// Failure modes for [`SerialCapture::spawn`].
#[derive(Debug, Error)]
pub enum SerialError {
    /// The child process couldn't be launched.
    #[error("failed to spawn child: {kind}")]
    SpawnFailed {
        /// Rendered `io::ErrorKind`.
        kind: String,
    },

    /// The log file couldn't be opened/created.
    #[error("log file {path} inaccessible: {kind}")]
    LogFileInaccessible {
        /// Path we tried to open.
        path: PathBuf,
        /// Rendered `io::ErrorKind`.
        kind: String,
    },

    /// The child refused to give us its stdout (should never happen
    /// since we just set `Stdio::piped`, but we surface it as a named
    /// error rather than panicking).
    #[error("child stdout unexpectedly unavailable after spawn")]
    StdoutUnavailable,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::fs;
    use std::process::Command;

    fn echo_cmd(msg: &str) -> Command {
        // Portable echo via /bin/sh — present everywhere CI cares about.
        let mut c = Command::new("/bin/sh");
        c.arg("-c");
        c.arg(format!("printf '{msg}'"));
        c
    }

    fn sleep_cmd(secs: u64) -> Command {
        let mut c = Command::new("sleep");
        c.arg(secs.to_string());
        c
    }

    fn slow_echo_cmd(msg: &str, delay_ms: u64) -> Command {
        // Emit `msg`, then sleep. The sleep keeps the child alive so
        // wait_for_line exercises the polling path before the reader
        // closes the buffer.
        let mut c = Command::new("/bin/sh");
        c.arg("-c");
        let secs = delay_ms / 1000;
        let ms = delay_ms % 1000;
        c.arg(format!("printf '{msg}'; sleep {secs}.{ms:03}"));
        c
    }

    #[test]
    fn captures_stdout_into_buffer_and_log() {
        let tmp = tempfile::tempdir().unwrap();
        let log = tmp.path().join("serial.log");
        let handle = SerialCapture::spawn(echo_cmd("hello world\\n"), &log, None).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let buf = handle.buffer_snapshot();
        assert!(buf.contains("hello world"), "got: {buf:?}");
        drop(handle);
        // Log file exists + is non-empty. Reader flushes on drop, but we
        // gave it 100 ms above.
        let meta = fs::metadata(&log).unwrap();
        assert!(meta.len() > 0, "log file should be non-empty after drop");
    }

    #[test]
    fn wait_for_line_returns_match_when_present() {
        let tmp = tempfile::tempdir().unwrap();
        let log = tmp.path().join("serial.log");
        let handle = SerialCapture::spawn(
            slow_echo_cmd("boot ok: shim reached grub\\n", 500),
            &log,
            None,
        )
        .unwrap();
        let line = handle.wait_for_line("shim reached grub", Duration::from_secs(3));
        assert!(line.is_some(), "expected match within 3s");
        assert!(line.unwrap().contains("shim reached grub"));
    }

    #[test]
    fn wait_for_line_times_out_when_pattern_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let log = tmp.path().join("serial.log");
        let handle = SerialCapture::spawn(slow_echo_cmd("only noise\\n", 500), &log, None).unwrap();
        let start = Instant::now();
        let line = handle.wait_for_line("this-never-appears", Duration::from_millis(200));
        assert!(line.is_none());
        // Shouldn't block indefinitely past the timeout (plus some slack).
        assert!(start.elapsed() < Duration::from_millis(1000));
    }

    #[test]
    fn wait_for_line_returns_none_when_child_exits_without_match() {
        let tmp = tempfile::tempdir().unwrap();
        let log = tmp.path().join("serial.log");
        let handle = SerialCapture::spawn(echo_cmd("early exit\\n"), &log, None).unwrap();
        // Child will exit quickly; wait_for_line should return None when
        // buf.closed is set.
        let line = handle.wait_for_line("not-in-output", Duration::from_secs(2));
        assert!(
            line.is_none(),
            "child exited without match; wait_for_line must return None"
        );
    }

    #[test]
    fn overflow_cap_evicts_old_bytes_and_inserts_sentinel() {
        let tmp = tempfile::tempdir().unwrap();
        let log = tmp.path().join("serial.log");
        // Emit 8 KiB; cap at 2 KiB → overflow must fire.
        let big: String = "A".repeat(8 * 1024);
        let handle = SerialCapture::spawn(echo_cmd(&big), &log, Some(2 * 1024)).unwrap();
        std::thread::sleep(Duration::from_millis(200));
        let snap = handle.buffer_snapshot();
        assert!(
            snap.contains("BUFFER OVERFLOW"),
            "overflow sentinel missing from snapshot: {snap}"
        );
        assert!(
            handle.overflow_bytes() > 0,
            "overflow_bytes should be nonzero after cap exceeded"
        );
        assert!(
            snap.len() < 8 * 1024,
            "snapshot should be smaller than raw output after eviction"
        );
    }

    #[test]
    fn log_file_inaccessible_when_parent_is_a_file() {
        let tmp = tempfile::tempdir().unwrap();
        let blocker = tmp.path().join("blocker");
        fs::write(&blocker, b"not a dir").unwrap();
        let log = blocker.join("serial.log");
        let err = SerialCapture::spawn(echo_cmd("x\\n"), &log, None).unwrap_err();
        assert!(
            matches!(err, SerialError::LogFileInaccessible { .. }),
            "expected LogFileInaccessible, got {err:?}"
        );
    }

    #[test]
    fn spawn_failure_yields_named_error() {
        let tmp = tempfile::tempdir().unwrap();
        let log = tmp.path().join("serial.log");
        let cmd = Command::new("/definitely/not/a/binary-xyz-serial-9932");
        let err = SerialCapture::spawn(cmd, &log, None).unwrap_err();
        assert!(
            matches!(err, SerialError::SpawnFailed { .. }),
            "expected SpawnFailed, got {err:?}"
        );
    }

    #[test]
    fn drop_kills_long_running_child() {
        let tmp = tempfile::tempdir().unwrap();
        let log = tmp.path().join("serial.log");
        let handle = SerialCapture::spawn(sleep_cmd(30), &log, None).unwrap();
        let pid = handle.child.id();
        drop(handle);
        std::thread::sleep(Duration::from_millis(100));
        let alive = Command::new("kill")
            .args(["-0", &pid.to_string()])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        assert!(!alive, "sleep pid {pid} should be dead after drop");
    }
}
