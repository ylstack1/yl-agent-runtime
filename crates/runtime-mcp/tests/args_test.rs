//! Argument normalization tests (TDD: written before the implementation).
//! `normalize_args` and `levenshtein` are `pub` in `crates/runtime-mcp/src/args.rs`.

use runtime_mcp::args::{levenshtein, normalize_args};
use serde_json::json;

fn obj(value: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
    value.as_object().expect("test fixture is a JSON object").clone()
}

fn err_text(result: std::result::Result<serde_json::Map<String, serde_json::Value>, rmcp::ErrorData>) -> String {
    match result {
        Ok(_) => panic!("expected an error, got Ok"),
        Err(e) => e.message.to_string(),
    }
}

#[test]
fn alias_file_maps_to_path() {
    let result = normalize_args("workspace.read", &obj(json!({"file": "a.txt"}))).unwrap();
    assert_eq!(result.get("path"), Some(&json!("a.txt")));
    assert!(!result.contains_key("file"));
}

#[test]
fn alias_old_new_map_to_old_text_new_text() {
    let result = normalize_args(
        "workspace.edit",
        &obj(json!({"path": "p.txt", "old": "a", "new": "b", "edits": []})),
    )
    .unwrap();
    assert_eq!(result.get("old_text"), Some(&json!("a")));
    assert_eq!(result.get("new_text"), Some(&json!("b")));
    assert!(!result.contains_key("old"));
    assert!(!result.contains_key("new"));
}

#[test]
fn canonical_wins_over_alias() {
    let result =
        normalize_args("workspace.read", &obj(json!({"path": "p.txt", "file": "q.txt"}))).unwrap();
    assert_eq!(result.get("path"), Some(&json!("p.txt")));
    assert!(!result.contains_key("file"));
}

#[test]
fn unknown_key_suggests_did_you_mean() {
    let msg = err_text(normalize_args("workspace.search", &obj(json!({"patern": "x"}))));
    assert!(msg.contains("Did you mean 'query'?"), "unexpected message: {msg}");
}

#[test]
fn unknown_key_lists_valid() {
    let msg = err_text(normalize_args("workspace.search", &obj(json!({"zzz": 1}))));
    assert!(msg.contains("Valid arguments:"), "unexpected message: {msg}");
}

#[test]
fn missing_required_lists_fields() {
    let msg = err_text(normalize_args("workspace.write", &obj(json!({"path": "x.txt"}))));
    assert!(msg.contains("Missing required argument(s): content"), "unexpected message: {msg}");
}

#[test]
fn levenshtein_distances() {
    assert_eq!(levenshtein("kitten", "sitting"), 3);
    assert_eq!(levenshtein("", "abc"), 3);
    assert_eq!(levenshtein("abc", "abc"), 0);
    assert_eq!(levenshtein("flaw", "lawn"), 2);
}
