//! Every public function, every method a type implements, and every helper on
//! a secret path documents its timing.

/// Declaration prefixes whose doc comments must state their timing.
const DECLARATIONS: &[&str] = &[
    "pub fn ",
    "pub(crate) fn ",
    "fn fmt(",
    "fn client_secret",
    "fn zero(",
    "fn padded_length(",
    "fn pad(",
    "fn pad_bytes(",
    "fn finish",
    "fn from_ng(",
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
fn fmt() {}
/// Constant time and variable time.
fn zero() {}
/// Wrapped, constant
/// time.
fn finish() {}
fn helper() {}
#[cfg(test)]
mod tests {
    fn fmt() {}
}
";
    let (checked, missing) = missing_timing_docs(fixture);
    assert_eq!(checked, 5);
    assert_eq!(missing, ["pub fn undocumented() {}", "fn zero() {}"]);
}

#[test]
fn every_public_api_and_secret_path_has_an_unambiguous_timing_doc() {
    for (name, source, minimum) in [
        ("client.rs", include_str!("../src/client.rs"), 9),
        ("server.rs", include_str!("../src/server.rs"), 8),
        (
            "verifier_generator.rs",
            include_str!("../src/verifier_generator.rs"),
            3,
        ),
        ("utilities.rs", include_str!("../src/utilities.rs"), 16),
        ("group.rs", include_str!("../src/group.rs"), 4),
        ("error.rs", include_str!("../src/error.rs"), 1),
        (
            "standard_groups.rs",
            include_str!("../src/standard_groups.rs"),
            8,
        ),
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
