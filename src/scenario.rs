//! Scenario trait — the contract every test scenario implements.
//!
//! A scenario takes a [`ScenarioContext`] (persona + stick + work
//! root + firmware root) and returns a [`ScenarioResult`] indicating
//! whether the persona's signed-chain flow worked, failed in a
//! diagnosable way, or had to be skipped (missing prerequisites,
//! environment not provisioned, etc.).
//!
//! Scenarios MUST NOT panic. Every code path returns `Result`. A
//! scenario that crashes the runner is a defect to fix, not a test
//! failure to report.
//!
//! Registry: scenarios are dispatched by name from
//! [`Registry::default_set`] which the CLI's `run` subcommand
//! consults. Adding a new scenario means: implement [`Scenario`],
//! return it from `default_set`, file an issue. No central enum to
//! update.

use crate::persona::Persona;
use std::path::PathBuf;
use thiserror::Error;

/// Outcome of a scenario run. The runner prints one of these per
/// invocation; CI greps for `PASS:` lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScenarioResult {
    /// Every assertion held — signed-chain verification path completed.
    Pass,
    /// At least one assertion didn't hold. `reason` is operator-facing.
    Fail {
        /// Why the scenario failed, in plain English. Will be printed
        /// after the `FAIL:` line.
        reason: String,
    },
    /// Prerequisites weren't met — the run could not be attempted.
    /// CI treats this as neither pass nor fail; it's an honest "not
    /// applicable" signal so green CI doesn't claim coverage we don't
    /// actually have.
    Skip {
        /// Why the scenario was skipped (e.g. "stick fixture not
        /// provisioned", "qemu-system-x86_64 not on PATH").
        reason: String,
    },
}

impl ScenarioResult {
    /// Convenience for CI greps + exit-code mapping.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail { .. } => "FAIL",
            Self::Skip { .. } => "SKIP",
        }
    }

    /// One-line operator-facing reason (or empty for `Pass`).
    #[must_use]
    pub fn reason(&self) -> &str {
        match self {
            Self::Pass => "",
            Self::Fail { reason } | Self::Skip { reason } => reason,
        }
    }
}

/// Inputs every scenario gets. The runner constructs this once per
/// invocation; scenarios borrow it immutably so a malicious scenario
/// can't redirect another scenario's stick or work dir.
#[derive(Debug, Clone)]
pub struct ScenarioContext {
    /// The validated persona under test.
    pub persona: Persona,
    /// Absolute path to the aegis-boot stick image to flash + boot.
    pub stick: PathBuf,
    /// Per-run working directory. Scenarios write logs + per-run state
    /// (`OVMF_VARS` copy, swtpm state, serial.log) under here.
    pub work_dir: PathBuf,
    /// Firmware root (typically `/usr/share/OVMF/`).
    pub firmware_root: PathBuf,
}

/// Failure modes for a scenario *runner* — distinct from
/// [`ScenarioResult::Fail`]. A `ScenarioError` means the runner itself
/// couldn't get far enough to attempt the assertion (bad input, I/O
/// error, missing binary). The CLI surfaces these as a non-zero exit.
#[derive(Debug, Error)]
pub enum ScenarioError {
    /// The persona referenced a feature this scenario doesn't support
    /// (e.g. a TPM 1.2 persona handed to a scenario that requires 2.0).
    #[error("scenario {scenario} cannot run against persona {persona}: {reason}")]
    UnsupportedPersona {
        /// Scenario name.
        scenario: &'static str,
        /// Persona id.
        persona: String,
        /// Why the combination is unsupported.
        reason: String,
    },

    /// QEMU/swtpm/OVMF wiring failure — propagates the underlying
    /// [`crate::qemu::InvocationError`].
    #[error(transparent)]
    Invocation(#[from] crate::qemu::InvocationError),

    /// swtpm couldn't be spawned (binary missing, work dir bad).
    #[error(transparent)]
    Swtpm(#[from] crate::swtpm::SwtpmError),

    /// Serial capture couldn't be set up.
    #[error(transparent)]
    Serial(#[from] crate::serial::SerialError),

    /// A non-recoverable I/O failure during the scenario (e.g. work
    /// dir creation, file copy).
    #[error("scenario I/O error: {kind}: {context}")]
    Io {
        /// Rendered `io::ErrorKind`.
        kind: String,
        /// What the runner was trying to do when it failed.
        context: String,
    },
}

/// The contract every scenario implements.
pub trait Scenario {
    /// Stable kebab-case name. Used by the CLI registry; must NOT
    /// change once published or operator-side scripts will break.
    fn name(&self) -> &'static str;

    /// One-line human-facing description, printed by `aegis-hwsim
    /// list-scenarios` (when that ships).
    fn description(&self) -> &'static str;

    /// Run the scenario. The implementation is responsible for:
    /// - Spawning swtpm + QEMU via the [`crate::qemu`] + [`crate::swtpm`] modules
    /// - Asserting boot-chain landmarks via [`crate::serial::SerialHandle::wait_for_line`]
    /// - Returning a [`ScenarioResult`] (never panicking)
    ///
    /// # Errors
    ///
    /// See [`ScenarioError`] variants — runner-level failures only.
    /// Test-failures are [`ScenarioResult::Fail`].
    fn run(&self, ctx: &ScenarioContext) -> Result<ScenarioResult, ScenarioError>;
}

/// Scenario lookup by name. The registry holds a closed set of
/// scenarios known at build time; `aegis-hwsim run <name>` consults
/// it.
pub struct Registry {
    scenarios: Vec<Box<dyn Scenario + Send + Sync>>,
}

impl Default for Registry {
    fn default() -> Self {
        Self::default_set()
    }
}

impl Registry {
    /// Empty registry — for tests that want to inject a single
    /// scenario without the default set.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            scenarios: Vec::new(),
        }
    }

    /// The default registry shipping in this build. As scenarios
    /// land, add them here.
    #[must_use]
    pub fn default_set() -> Self {
        let mut r = Self::empty();
        r.register(Box::new(crate::scenarios::SignedBootUbuntu));
        r
    }

    /// Register a scenario. Used by `default_set` and by tests.
    pub fn register(&mut self, s: Box<dyn Scenario + Send + Sync>) {
        self.scenarios.push(s);
    }

    /// Look up a scenario by name. Returns `None` if no scenario with
    /// that name is registered.
    #[must_use]
    pub fn find(&self, name: &str) -> Option<&(dyn Scenario + Send + Sync)> {
        self.scenarios
            .iter()
            .find(|s| s.name() == name)
            .map(std::convert::AsRef::as_ref)
    }

    /// Iterate over registered (name, description) pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&'static str, &'static str)> + '_ {
        self.scenarios.iter().map(|s| (s.name(), s.description()))
    }

    /// Number of registered scenarios.
    #[must_use]
    pub fn len(&self) -> usize {
        self.scenarios.len()
    }

    /// True when no scenarios are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.scenarios.is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// A noop scenario that returns whatever result it was constructed
    /// with. Lets us exercise the trait + registry without needing
    /// QEMU.
    struct NoopScenario {
        name: &'static str,
        result: ScenarioResult,
    }

    impl Scenario for NoopScenario {
        fn name(&self) -> &'static str {
            self.name
        }
        fn description(&self) -> &'static str {
            "noop"
        }
        fn run(&self, _ctx: &ScenarioContext) -> Result<ScenarioResult, ScenarioError> {
            Ok(self.result.clone())
        }
    }

    fn fake_ctx() -> ScenarioContext {
        ScenarioContext {
            persona: serde_yaml::from_str(
                r#"
schema_version: 1
id: fake
vendor: QEMU
display_name: Fake
source:
  kind: vendor_docs
  ref_: fake
dmi:
  sys_vendor: QEMU
  product_name: Standard PC
  bios_vendor: EDK II
  bios_version: stable
  bios_date: 01/01/2024
secure_boot:
  ovmf_variant: ms_enrolled
tpm:
  version: "2.0"
"#,
            )
            .unwrap(),
            stick: PathBuf::from("/fake/stick.img"),
            work_dir: PathBuf::from("/fake/work"),
            firmware_root: PathBuf::from("/fake/fw"),
        }
    }

    #[test]
    fn scenario_result_labels_match_expected_strings() {
        assert_eq!(ScenarioResult::Pass.label(), "PASS");
        assert_eq!(ScenarioResult::Fail { reason: "x".into() }.label(), "FAIL");
        assert_eq!(ScenarioResult::Skip { reason: "y".into() }.label(), "SKIP");
    }

    #[test]
    fn scenario_result_reasons_extract_correctly() {
        assert_eq!(ScenarioResult::Pass.reason(), "");
        assert_eq!(
            ScenarioResult::Fail {
                reason: "hi".into()
            }
            .reason(),
            "hi"
        );
        assert_eq!(
            ScenarioResult::Skip {
                reason: "missing dep".into()
            }
            .reason(),
            "missing dep"
        );
    }

    #[test]
    fn registry_default_set_includes_signed_boot_ubuntu() {
        // Pin the shipped scenario set. As more scenarios land in
        // future epics (E5 MOK enrollment, E6 attestation, etc.),
        // extend this assertion; the goal is to catch a registry
        // regression that silently drops a published scenario name.
        let r = Registry::default_set();
        assert_eq!(r.len(), 1);
        assert!(r.find("signed-boot-ubuntu").is_some());
    }

    #[test]
    fn registry_find_returns_registered_scenario() {
        let mut r = Registry::empty();
        r.register(Box::new(NoopScenario {
            name: "test-noop",
            result: ScenarioResult::Pass,
        }));
        assert!(r.find("test-noop").is_some());
        assert!(r.find("nonexistent").is_none());
    }

    #[test]
    fn registry_find_returns_scenario_that_runs() {
        let mut r = Registry::empty();
        r.register(Box::new(NoopScenario {
            name: "test-pass",
            result: ScenarioResult::Pass,
        }));
        r.register(Box::new(NoopScenario {
            name: "test-fail",
            result: ScenarioResult::Fail {
                reason: "pretend the stick refused to boot".into(),
            },
        }));
        let pass = r.find("test-pass").unwrap();
        assert_eq!(pass.run(&fake_ctx()).unwrap(), ScenarioResult::Pass);

        let fail = r.find("test-fail").unwrap();
        match fail.run(&fake_ctx()).unwrap() {
            ScenarioResult::Fail { reason } => {
                assert!(reason.contains("refused to boot"));
            }
            other => panic!("expected Fail, got {other:?}"),
        }
    }

    #[test]
    fn registry_iter_yields_name_description_pairs() {
        let mut r = Registry::empty();
        r.register(Box::new(NoopScenario {
            name: "alpha",
            result: ScenarioResult::Pass,
        }));
        r.register(Box::new(NoopScenario {
            name: "beta",
            result: ScenarioResult::Pass,
        }));
        let pairs: Vec<_> = r.iter().collect();
        assert_eq!(pairs.len(), 2);
        assert!(pairs.contains(&("alpha", "noop")));
        assert!(pairs.contains(&("beta", "noop")));
    }
}
