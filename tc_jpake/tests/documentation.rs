//! Every function documents its timing: the helpers sit on the path of the
//! password and the private values, so all of them are checked, private ones
//! included. Trait
//! declarations, which end in `;`, make no promise of their own.

/// Whether `line` declares a function, whatever its visibility.
fn declares_function(line: &str) -> bool {
    let line = line
        .strip_prefix("pub(crate) ")
        .or_else(|| line.strip_prefix("pub(super) "))
        .or_else(|| line.strip_prefix("pub "))
        .unwrap_or(line);
    let line = line.strip_prefix("const ").unwrap_or(line);
    line.starts_with("fn ")
}

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
        if declares_function(line) && !line.ends_with(';') {
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
fn the_scanner_requires_exactly_one_timing_classification_on_each_function() {
    let fixture = "/// Constant time.
pub fn documented() {}
pub fn undocumented() {}
/// VARIABLE TIME.
#[inline]
pub(super) const fn id() {}
/// Constant time and variable time.
fn helper() {}
/// Wrapped, constant
/// time.
pub(crate) fn wrapped() {}
fn declared(&self) -> u32;
let value = fnord;
#[cfg(test)]
mod tests {
    fn helper() {}
}
";
    let (checked, missing) = missing_timing_docs(fixture);
    assert_eq!(checked, 5);
    assert_eq!(missing, ["pub fn undocumented() {}", "fn helper() {}"]);
}

#[test]
fn every_function_has_an_unambiguous_timing_doc() {
    for (name, source, minimum) in [
        ("error.rs", include_str!("../src/error.rs"), 1),
        ("group.rs", include_str!("../src/group.rs"), 6),
        ("params.rs", include_str!("../src/params.rs"), 6),
        ("participant.rs", include_str!("../src/participant.rs"), 14),
        ("payloads.rs", include_str!("../src/payloads.rs"), 16),
        (
            "standard_groups.rs",
            include_str!("../src/standard_groups.rs"),
            5,
        ),
        ("utilities.rs", include_str!("../src/utilities.rs"), 21),
    ] {
        let (checked, missing) = missing_timing_docs(source);
        assert!(
            checked >= minimum,
            "only {checked} functions scanned in {name}"
        );
        assert!(
            missing.is_empty(),
            "missing timing docs in {name}: {missing:?}"
        );
    }
}
