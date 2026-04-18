//! `Dmi → -smbios` argv synthesis.
//!
//! Turns a validated [`crate::persona::Dmi`] into the argv tokens QEMU's
//! `-smbios` option expects — one `(-smbios, "type=N,k=v,...")` pair per
//! populated SMBIOS type. Values are escaped for QEMU's option-string
//! syntax (`,,` = literal `,`).
//!
//! Pure function — no I/O, no process spawning. The caller splices the
//! returned tokens into a [`std::process::Command`] via
//! [`std::process::Command::args`]; there is no shell in the chain, so
//! shell metacharacters in a persona string are passed through as
//! literal argv, never interpreted.
//!
//! NUL bytes (`\0`) in any field are rejected upfront with a named
//! [`SmbiosError::NulByte`] — `Command::args()` panics on NUL-containing
//! argv elements on Unix, so we'd rather surface a typed error at the
//! persona-parse boundary than discover the issue at spawn time.

use crate::persona::Dmi;
use thiserror::Error;

/// Synthesis failure. One variant per refusable-at-boundary condition.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SmbiosError {
    /// A DMI field carried a NUL byte. Persona YAML shouldn't produce
    /// this (YAML doesn't allow `\0` in scalar strings), but we reject
    /// explicitly since `Command::args()` panics on NUL argv.
    #[error("DMI field '{field}' contains NUL byte; QEMU argv cannot encode it")]
    NulByte {
        /// Name of the offending persona field.
        field: &'static str,
    },
}

/// Build the full `-smbios` argv for a persona's DMI block.
///
/// Emits, in order:
/// - `type=0` (BIOS) — vendor, version, date
/// - `type=1` (System) — manufacturer, product, version (if set)
/// - `type=2` (Board) — manufacturer, product (only if `board_name` set)
/// - `type=3` (Chassis) — type (only if `chassis_type` set)
///
/// # Errors
///
/// Returns [`SmbiosError::NulByte`] if any DMI field contains a NUL byte.
pub fn smbios_argv(dmi: &Dmi) -> Result<Vec<String>, SmbiosError> {
    check_nul("sys_vendor", &dmi.sys_vendor)?;
    check_nul("product_name", &dmi.product_name)?;
    check_nul("bios_vendor", &dmi.bios_vendor)?;
    check_nul("bios_version", &dmi.bios_version)?;
    check_nul("bios_date", &dmi.bios_date)?;
    if let Some(pv) = dmi.product_version.as_deref() {
        check_nul("product_version", pv)?;
    }
    if let Some(bn) = dmi.board_name.as_deref() {
        check_nul("board_name", bn)?;
    }

    let mut argv = Vec::with_capacity(8);

    // type=0 — BIOS Information
    argv.push("-smbios".to_string());
    argv.push(format!(
        "type=0,vendor={},version={},date={}",
        qemu_escape(&dmi.bios_vendor),
        qemu_escape(&dmi.bios_version),
        qemu_escape(&dmi.bios_date),
    ));

    // type=1 — System Information
    let mut type1 = format!(
        "type=1,manufacturer={},product={}",
        qemu_escape(&dmi.sys_vendor),
        qemu_escape(&dmi.product_name),
    );
    if let Some(pv) = dmi.product_version.as_deref() {
        type1.push_str(",version=");
        type1.push_str(&qemu_escape(pv));
    }
    argv.push("-smbios".to_string());
    argv.push(type1);

    // type=2 — Baseboard (only when board_name is populated; some vendors
    // leave this unset and we'd rather emit fewer args than lie).
    if let Some(bn) = dmi.board_name.as_deref() {
        argv.push("-smbios".to_string());
        argv.push(format!(
            "type=2,manufacturer={},product={}",
            qemu_escape(&dmi.sys_vendor),
            qemu_escape(bn),
        ));
    }

    // type=3 — System Enclosure. We DON'T emit one even when
    // `dmi.chassis_type` is set: QEMU's `-smbios type=3` accepts
    // manufacturer/version/serial/asset/sku but does NOT expose the
    // chassis-type code (3=desktop, 10=notebook, etc.) as a
    // settable field. Emitting `type=3,type={ct}` is parsed by QEMU
    // as "switch to SMBIOS type {ct}" and rejected for unknown types
    // (real-world failure: 2026-04-18 against the Framework persona,
    // QEMU said `Don't know how to build fields for SMBIOS type 10`).
    //
    // The persona's chassis_type field is preserved as informational
    // metadata that future readers can use; we just don't pass it to
    // QEMU. If/when QEMU exposes the field, switch this back on.
    let _ = &dmi.chassis_type;

    Ok(argv)
}

fn check_nul(field: &'static str, value: &str) -> Result<(), SmbiosError> {
    if value.contains('\0') {
        Err(SmbiosError::NulByte { field })
    } else {
        Ok(())
    }
}

/// Escape a value for QEMU option-string syntax. QEMU treats `,` as the
/// key-value separator; `,,` is the sole escape sequence for a literal
/// comma. Nothing else (backslash, quote, equals) is special inside a
/// value slot.
fn qemu_escape(s: &str) -> String {
    if s.contains(',') {
        s.replace(',', ",,")
    } else {
        s.to_string()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn minimal_dmi() -> Dmi {
        Dmi {
            sys_vendor: "LENOVO".into(),
            product_name: "21HM".into(),
            product_version: None,
            bios_vendor: "LENOVO".into(),
            bios_version: "N3VET18W".into(),
            bios_date: "03/15/2024".into(),
            board_name: None,
            chassis_type: None,
        }
    }

    #[test]
    fn emits_type0_and_type1_for_minimal_dmi() {
        let argv = smbios_argv(&minimal_dmi()).unwrap();
        assert_eq!(argv.len(), 4, "minimal DMI: 2 -smbios pairs = 4 argv");
        assert_eq!(argv[0], "-smbios");
        assert_eq!(
            argv[1],
            "type=0,vendor=LENOVO,version=N3VET18W,date=03/15/2024"
        );
        assert_eq!(argv[2], "-smbios");
        assert_eq!(argv[3], "type=1,manufacturer=LENOVO,product=21HM");
    }

    #[test]
    fn emits_type2_when_board_name_set() {
        let mut d = minimal_dmi();
        d.board_name = Some("21HMCTO1WW".into());
        let argv = smbios_argv(&d).unwrap();
        assert!(argv.iter().any(|a| a.starts_with("type=2,")));
        let t2 = argv
            .iter()
            .find(|a| a.starts_with("type=2,"))
            .expect("type=2");
        assert_eq!(t2, "type=2,manufacturer=LENOVO,product=21HMCTO1WW");
    }

    #[test]
    fn skips_type2_when_board_name_unset() {
        let argv = smbios_argv(&minimal_dmi()).unwrap();
        assert!(!argv.iter().any(|a| a.starts_with("type=2,")));
    }

    #[test]
    fn does_not_emit_type3_even_when_chassis_type_set() {
        // QEMU's `-smbios type=3` doesn't accept a chassis-type code
        // field; emitting `type=3,type=N` is parsed as "switch SMBIOS
        // type to N" and rejected. We deliberately drop it. The
        // persona's chassis_type stays as informational metadata.
        let mut d = minimal_dmi();
        d.chassis_type = Some(10); // notebook
        let argv = smbios_argv(&d).unwrap();
        assert!(
            !argv.iter().any(|a| a.starts_with("type=3")),
            "must not emit `-smbios type=3`; got {argv:?}"
        );
    }

    #[test]
    fn emits_product_version_when_set() {
        let mut d = minimal_dmi();
        d.product_version = Some("ThinkPad X1 Carbon Gen 11".into());
        let argv = smbios_argv(&d).unwrap();
        let t1 = argv
            .iter()
            .find(|a| a.starts_with("type=1,"))
            .expect("type=1");
        assert!(t1.contains("version=ThinkPad X1 Carbon Gen 11"));
    }

    #[test]
    fn escapes_comma_in_value() {
        let mut d = minimal_dmi();
        d.product_name = "Standard PC (Q35 + ICH9, 2009)".into();
        let argv = smbios_argv(&d).unwrap();
        let t1 = argv
            .iter()
            .find(|a| a.starts_with("type=1,"))
            .expect("type=1");
        // The comma inside the value is doubled — QEMU's literal-comma escape.
        assert!(t1.contains("product=Standard PC (Q35 + ICH9,, 2009)"));
    }

    #[test]
    fn rejects_nul_byte_in_any_field() {
        let mut d = minimal_dmi();
        d.product_name = "foo\0bar".into();
        let err = smbios_argv(&d).unwrap_err();
        assert_eq!(
            err,
            SmbiosError::NulByte {
                field: "product_name"
            }
        );
    }

    #[test]
    fn rejects_nul_byte_in_optional_field() {
        let mut d = minimal_dmi();
        d.board_name = Some("evil\0name".into());
        let err = smbios_argv(&d).unwrap_err();
        assert_eq!(
            err,
            SmbiosError::NulByte {
                field: "board_name"
            }
        );
    }

    #[test]
    fn shell_metacharacters_pass_through_as_literal_argv() {
        // No shell is invoked by the caller (Command::args, not sh -c), so
        // these characters survive as literal argv elements. If a future
        // refactor pipes argv through a shell, this test still passes —
        // QEMU's escape rules handle commas, everything else is literal —
        // but the caller contract would break elsewhere.
        let mut d = minimal_dmi();
        d.product_name = "a;b|c&d`e$(f)g\\h".into();
        let argv = smbios_argv(&d).unwrap();
        let t1 = argv
            .iter()
            .find(|a| a.starts_with("type=1,"))
            .expect("type=1");
        assert!(t1.contains("product=a;b|c&d`e$(f)g\\h"));
    }
}
