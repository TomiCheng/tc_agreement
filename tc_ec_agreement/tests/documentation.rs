//! Every public function, every method a type implements, and every helper on
//! a secret path documents its timing.

/// Declaration prefixes whose doc comments must state their timing.
const DECLARATIONS: &[&str] = &[
    "pub fn ",
    "pub(crate) fn ",
    "fn init(",
    "fn agreement_size(",
    "fn calculate_agreement(",
    "fn default(",
    "fn fmt(",
    "fn agreement_x",
    "fn reduce",
];

fn missing_timing_docs(source: &str) -> (usize, Vec<String>) {
    let mut docs = String::new();
    let mut attribute_depth = 0_i32;
    let mut checked = 0;
    let mut missing = Vec::new();
    for line in source.lines().map(str::trim) {
        // Helpers inside test modules are not part of the contract.
        if line == "#[cfg(test)]" {
            break;
        }
        if let Some(comment) = line.strip_prefix("///") {
            // Lines join with a space, so that a classification may wrap.
            docs.push_str(comment.trim());
            docs.push(' ');
            continue;
        }
        if line.starts_with("#[") || attribute_depth > 0 {
            attribute_depth += line.chars().filter(|&c| c == '[').count() as i32;
            attribute_depth -= line.chars().filter(|&c| c == ']').count() as i32;
            continue;
        }
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        if DECLARATIONS.iter().any(|prefix| line.starts_with(prefix)) {
            checked += 1;
            let docs = docs.to_ascii_lowercase();
            if docs.contains("constant time") == docs.contains("variable time") {
                missing.push(line.to_owned());
            }
        }
        docs.clear();
    }
    (checked, missing)
}

#[test]
fn the_scanner_requires_exactly_one_timing_classification_on_each_declaration() {
    let fixture = "\
/// Constant time.
pub fn documented() {}
pub fn undocumented() {}
/// VARIABLE TIME.
#[inline]
fn init() {}
/// Constant time and variable time.
fn default() {}
/// Wrapped, constant
/// time.
fn fmt() {}
fn helper() {}
#[cfg(test)]
mod tests {
    fn init() {}
}
";
    let (checked, missing) = missing_timing_docs(fixture);
    assert_eq!(checked, 5);
    assert_eq!(missing, ["pub fn undocumented() {}", "fn default() {}"]);
}

#[test]
fn every_public_api_and_secret_path_has_an_unambiguous_timing_doc() {
    for (name, source, minimum) in [
        (
            "ecdh/basic_agreement.rs",
            include_str!("../src/ecdh/basic_agreement.rs"),
            6,
        ),
        (
            "ecdh/cofactor_agreement.rs",
            include_str!("../src/ecdh/cofactor_agreement.rs"),
            5,
        ),
        ("ecdh/error.rs", include_str!("../src/ecdh/error.rs"), 1),
        (
            "mqv/basic_agreement.rs",
            include_str!("../src/mqv/basic_agreement.rs"),
            7,
        ),
        ("mqv/params.rs", include_str!("../src/mqv/params.rs"), 8),
        ("mqv/error.rs", include_str!("../src/mqv/error.rs"), 1),
        (
            "vko/agreement.rs",
            include_str!("../src/vko/agreement.rs"),
            4,
        ),
        ("vko/params.rs", include_str!("../src/vko/params.rs"), 3),
        ("vko/error.rs", include_str!("../src/vko/error.rs"), 1),
    ] {
        let (checked, missing) = missing_timing_docs(source);
        assert!(
            checked >= minimum,
            "only {checked} declarations scanned in {name}"
        );
        assert!(
            missing.is_empty(),
            "missing timing docs in {name}: {missing:?}"
        );
    }
}
