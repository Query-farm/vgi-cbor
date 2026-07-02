//! Shared helpers for the per-object discovery/description metadata that the
//! `vgi-lint` strict profile expects on every function and table:
//! `vgi.title`, `vgi.doc_llm`, `vgi.doc_md`, and `vgi.keywords`.

/// Encode comma-separated keywords as the JSON array of strings `vgi.keywords`
/// requires (VGI138).
pub fn keywords_json(keywords: &str) -> String {
    let items: Vec<String> = keywords
        .split(',')
        .map(str::trim)
        .filter(|k| !k.is_empty())
        .map(|k| {
            let escaped = k.replace('\\', "\\\\").replace('"', "\\\"");
            format!("\"{escaped}\"")
        })
        .collect();
    format!("[{}]", items.join(","))
}

/// Build the standard per-object discovery tags: title / doc_llm / doc_md /
/// keywords plus the `vgi.category` that places the object in its schema's
/// `vgi.categories` navigation registry (VGI409/VGI411).
pub fn object_tags(
    title: &str,
    description_llm: &str,
    description_md: &str,
    keywords: &str,
    category: &str,
) -> Vec<(String, String)> {
    vec![
        ("vgi.title".to_string(), title.to_string()),
        ("vgi.doc_llm".to_string(), description_llm.to_string()),
        ("vgi.doc_md".to_string(), description_md.to_string()),
        ("vgi.keywords".to_string(), keywords_json(keywords)),
        ("vgi.category".to_string(), category.to_string()),
    ]
}
