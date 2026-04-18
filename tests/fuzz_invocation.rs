//! Property-based subprocess-safety fuzz for [`smbios_argv`] and the
//! [`Invocation`] boundary.
//!
//! The contract the whole QEMU-synthesis layer relies on:
//!
//!   For every possible persona string value, [`smbios_argv`] either
//!   (a) returns `Ok(argv)` where `argv` contains the input as a
//!   literal argv element (with QEMU's `,,` comma-escape applied), or
//!   (b) returns a named [`SmbiosError`] variant.
//!
//! No intermediate state, no silent corruption, no command-injection
//! path. This test generates thousands of adversarial inputs and
//! asserts the contract holds for each.
//!
//! No external PRNG dep — a tiny xorshift64 keeps the test hermetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use aegis_hwsim::persona::Dmi;
use aegis_hwsim::smbios::{smbios_argv, SmbiosError};

/// Fixed seed so the fuzzer is deterministic under CI. Change it only
/// if you want to explore a different input space and are prepared to
/// investigate failures.
const SEED: u64 = 0xDEAD_BEEF_CAFE_BABE;

/// Total inputs per target field. 10k × 4 fields = 40k invocations;
/// still under a second on a laptop since `smbios_argv` is pure.
const ITERS: usize = 10_000;

/// xorshift64* — good enough for test randomness, no crate dep.
struct Rng {
    state: u64,
}

impl Rng {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn range(&mut self, n: usize) -> usize {
        #[allow(clippy::cast_possible_truncation)]
        let v = self.next_u64() as usize;
        v % n
    }
}

/// The adversarial character palette. Every byte we want the fuzzer to
/// combine: shell metacharacters, QEMU-syntax separators, UTF-8 nasties,
/// long runs, and (rarely) NUL to exercise the rejection path.
///
/// We return `Vec<&'static str>` so multi-byte UTF-8 sequences are one
/// palette entry.
fn char_palette() -> Vec<&'static str> {
    vec![
        // Regular printable ASCII
        "A",
        "Z",
        "m",
        "0",
        "9",
        " ",
        "-",
        "_",
        ".",
        "(",
        ")",
        // Shell metacharacters — must pass through as literal argv since
        // Command::args (no shell).
        ";",
        "|",
        "&",
        "`",
        "$",
        "(",
        ")",
        "\\",
        "'",
        "\"",
        "*",
        "?",
        "#",
        "!",
        "~",
        // Dollar-paren substitution pattern (three chars concatenated).
        "$(",
        // QEMU option-string syntax (comma is the key-value separator;
        // `,,` is the literal escape).
        ",",
        ",,",
        "=",
        // Whitespace variants including tab + newline.
        "\t",
        "\n",
        "\r",
        // UTF-8 RTL override (U+202E) — visual-order attack.
        "\u{202e}",
        // Zero-width joiner (U+200D) — homograph attack material.
        "\u{200d}",
        // UTF-8 BOM (U+FEFF).
        "\u{feff}",
        // Long-byte UTF-8 sequences.
        "é",
        "漢",
        "🚀",
        // Pathy strings — meaningless here but exercise "/" handling.
        "/",
        "..",
        "../../etc/passwd",
        // NUL byte — the one character that MUST trigger
        // SmbiosError::NulByte rather than passing through.
        "\0",
    ]
}

/// Generate a random string of up to 32 palette entries. The entry count
/// distribution intentionally favors small strings (most DMI fields are
/// 8-32 chars in real life) but occasionally ventures long to exercise
/// allocator paths.
fn random_input(rng: &mut Rng, palette: &[&'static str]) -> String {
    let len = (rng.range(32)).max(1);
    let mut out = String::with_capacity(len * 4);
    for _ in 0..len {
        out.push_str(palette[rng.range(palette.len())]);
    }
    out
}

/// Mutate a fresh DMI, plug `value` into the named field, return it.
fn dmi_with_field(field: &str, value: &str) -> Dmi {
    let mut d = Dmi {
        sys_vendor: "QEMU".into(),
        product_name: "Standard PC".into(),
        product_version: None,
        bios_vendor: "EDK II".into(),
        bios_version: "edk2-stable".into(),
        bios_date: "01/01/2024".into(),
        board_name: None,
        chassis_type: None,
    };
    match field {
        "sys_vendor" => d.sys_vendor = value.to_string(),
        "product_name" => d.product_name = value.to_string(),
        "bios_vendor" => d.bios_vendor = value.to_string(),
        "bios_version" => d.bios_version = value.to_string(),
        "bios_date" => d.bios_date = value.to_string(),
        "product_version" => d.product_version = Some(value.to_string()),
        "board_name" => d.board_name = Some(value.to_string()),
        _ => panic!("unknown field {field}"),
    }
    d
}

/// For a field + value, assert the fuzz contract:
/// - If the value contains NUL, `smbios_argv` MUST return the matching
///   `SmbiosError::NulByte { field }`.
/// - Otherwise, `smbios_argv` MUST return Ok, and the argv MUST contain
///   the value with QEMU's `,,` comma-escape applied as a literal.
fn assert_contract(field_label: &str, value: &str, field_key: &str) {
    let dmi = dmi_with_field(field_label, value);
    let result = smbios_argv(&dmi);

    let has_nul = value.contains('\0');
    match result {
        Ok(argv) => {
            assert!(
                !has_nul,
                "NUL in {field_label} value {value:?} should have been rejected but got argv"
            );
            // The escaped form of the value must appear verbatim inside
            // at least one argv element.
            let needle = value.replace(',', ",,");
            let found = argv.iter().any(|a| a.contains(&needle));
            assert!(
                found,
                "escaped value {needle:?} not found in argv for {field_label}={value:?}: \
                 argv={argv:?}"
            );
        }
        Err(SmbiosError::NulByte { field: got_field }) => {
            assert!(
                has_nul,
                "non-NUL input was rejected as NulByte for {field_label}={value:?}"
            );
            assert_eq!(
                got_field, field_key,
                "NulByte reported wrong field: expected {field_key}, got {got_field}"
            );
        }
    }
}

#[test]
fn fuzz_sys_vendor_preserves_argv_contract() {
    let mut rng = Rng::new(SEED);
    let palette = char_palette();
    for _ in 0..ITERS {
        let v = random_input(&mut rng, &palette);
        assert_contract("sys_vendor", &v, "sys_vendor");
    }
}

#[test]
fn fuzz_product_name_preserves_argv_contract() {
    let mut rng = Rng::new(SEED.wrapping_add(1));
    let palette = char_palette();
    for _ in 0..ITERS {
        let v = random_input(&mut rng, &palette);
        assert_contract("product_name", &v, "product_name");
    }
}

#[test]
fn fuzz_bios_vendor_preserves_argv_contract() {
    let mut rng = Rng::new(SEED.wrapping_add(2));
    let palette = char_palette();
    for _ in 0..ITERS {
        let v = random_input(&mut rng, &palette);
        assert_contract("bios_vendor", &v, "bios_vendor");
    }
}

#[test]
fn fuzz_bios_version_preserves_argv_contract() {
    let mut rng = Rng::new(SEED.wrapping_add(3));
    let palette = char_palette();
    for _ in 0..ITERS {
        let v = random_input(&mut rng, &palette);
        assert_contract("bios_version", &v, "bios_version");
    }
}

#[test]
fn fuzz_product_version_optional_field_contract() {
    let mut rng = Rng::new(SEED.wrapping_add(4));
    let palette = char_palette();
    for _ in 0..ITERS {
        let v = random_input(&mut rng, &palette);
        assert_contract("product_version", &v, "product_version");
    }
}

#[test]
fn fuzz_board_name_optional_field_contract() {
    let mut rng = Rng::new(SEED.wrapping_add(5));
    let palette = char_palette();
    for _ in 0..ITERS {
        let v = random_input(&mut rng, &palette);
        assert_contract("board_name", &v, "board_name");
    }
}

/// Regression fixtures: specific crafted inputs that historically caught
/// design bugs or would catch a regression if argv handling changed.
#[test]
fn regression_dollar_paren_substitution_is_literal() {
    // If someone ever pipes argv through a shell, `$(whoami)` would
    // execute. Command::args doesn't; this assertion captures the
    // no-shell invariant.
    let dmi = dmi_with_field("product_name", "$(whoami)");
    let argv = smbios_argv(&dmi).unwrap();
    assert!(argv.iter().any(|a| a.contains("$(whoami)")));
}

#[test]
fn regression_rtl_override_passes_through_literal() {
    // U+202E can visually reorder characters, making a product name
    // look like something else in terminals. We pass it through unchanged
    // — the persona YAML is Tier 1 authoritative content; this is
    // *not* where we'd scrub it. Just assert no corruption.
    let dmi = dmi_with_field("product_name", "\u{202e}evilname");
    let argv = smbios_argv(&dmi).unwrap();
    assert!(argv.iter().any(|a| a.contains("\u{202e}evilname")));
}

#[test]
fn regression_repeated_commas_escape_correctly() {
    let dmi = dmi_with_field("product_name", "a,b,c,d");
    let argv = smbios_argv(&dmi).unwrap();
    // Each `,` → `,,`; verify the whole chain not a partial.
    let t1 = argv
        .iter()
        .find(|a| a.starts_with("type=1,"))
        .expect("type=1");
    assert!(t1.contains("product=a,,b,,c,,d"));
}

#[test]
fn regression_nul_in_optional_field_still_names_the_field() {
    let dmi = dmi_with_field("board_name", "x\0y");
    let err = smbios_argv(&dmi).unwrap_err();
    match err {
        SmbiosError::NulByte { field } => assert_eq!(field, "board_name"),
    }
}
