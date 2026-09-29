//! Every public type and method, and every padding method a scheme implements,
//! documents its timing.

/// Declaration prefixes whose doc comments must state their timing.
const DECLARATIONS: &[&str] = &[
    "pub struct ",
    "pub fn ",
    "pub const fn ",
    "fn add_padding(",
    "fn pad_count(",
    "fn fmt(",
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
            docs.push_str(comment);
            docs.push('\n');
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
pub struct Documented;
pub struct Undocumented;
/// VARIABLE TIME.
#[inline]
pub fn accepted() {}
/// Constant time and variable time.
fn add_padding() {}
fn pad_count() {}
/// Constant time.
fn fmt() {}
impl Trait for Type {
    fn drop() {}
}
#[cfg(test)]
mod tests {
    fn pad_count() {}
}
";
    let (checked, missing) = missing_timing_docs(fixture);
    assert_eq!(checked, 6);
    assert_eq!(
        missing,
        [
            "pub struct Undocumented;",
            "fn add_padding() {}",
            "fn pad_count() {}",
        ]
    );
}

#[test]
fn every_public_api_and_padding_method_has_an_unambiguous_timing_doc() {
    for (name, source) in [
        ("iso10126.rs", include_str!("../src/iso10126.rs")),
        ("iso7816.rs", include_str!("../src/iso7816.rs")),
        ("padding_error.rs", include_str!("../src/padding_error.rs")),
        ("pkcs7.rs", include_str!("../src/pkcs7.rs")),
        ("tbc.rs", include_str!("../src/tbc.rs")),
        ("traits.rs", include_str!("../src/traits.rs")),
        ("x923.rs", include_str!("../src/x923.rs")),
        ("zero.rs", include_str!("../src/zero.rs")),
    ] {
        let (checked, missing) = missing_timing_docs(source);
        assert!(checked > 0, "no declarations scanned in {name}");
        assert!(
            missing.is_empty(),
            "missing timing docs in {name}: {missing:?}"
        );
    }
}
