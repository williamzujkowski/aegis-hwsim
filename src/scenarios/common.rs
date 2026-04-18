//! Helpers shared across scenario implementations. Kept tiny — only
//! lift code here when at least three scenarios need it (DRY by
//! extraction-when-it's-actually-duplicated, not pre-emptively).

use std::path::Path;

/// PATH lookup — splits the `PATH` env var on `:`, joins each entry
/// with `binary`, and checks for an executable file. Used by every
/// scenario's skip-gate to detect missing `qemu-system-x86_64` /
/// `swtpm` cleanly.
///
/// Returns `false` when `PATH` is unset or no match is found. Does
/// not check the executable bit — `is_file()` is enough on every
/// platform aegis-hwsim targets (Linux + future macOS); a non-exec
/// binary on `PATH` is a vanishingly rare misconfig that scenarios
/// would catch via `Command::spawn()` anyway.
#[must_use]
pub fn binary_on_path(binary: &str) -> bool {
    let Ok(path) = std::env::var("PATH") else {
        return false;
    };
    for dir in path.split(':') {
        let candidate = Path::new(dir).join(binary);
        if candidate.is_file() {
            return true;
        }
    }
    false
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn finds_existing_binary() {
        // sh is on PATH on every CI/dev machine we care about.
        assert!(binary_on_path("sh"));
    }

    #[test]
    fn misses_nonexistent_binary() {
        assert!(!binary_on_path("definitely-not-a-binary-xyz-common-12345"));
    }
}
