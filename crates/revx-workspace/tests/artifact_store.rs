use revx_workspace::Workspace;
use std::fs;
use tempfile::tempdir;

#[test]
fn truncated_artifact_is_repaired_on_rewrite() {
    let dir = tempdir().expect("tempdir");
    let ws = Workspace::init(dir.path(), "test", None).expect("init");
    let value = serde_json::json!({ "blob": "x".repeat(4096) });
    let handle = ws
        .write_json_artifact("application/json", &value)
        .expect("write");
    let path = ws.root().join(&handle.relative_path);
    let original = fs::read(&path).expect("read");
    fs::write(&path, &original[..10]).expect("truncate");
    let again = ws
        .write_json_artifact("application/json", &value)
        .expect("rewrite");
    assert_eq!(again.hash_blake3, handle.hash_blake3);
    assert_eq!(fs::read(&path).expect("read"), original);
}

#[test]
fn artifact_preview_reads_bounded_window() {
    let dir = tempdir().expect("tempdir");
    let ws = Workspace::init(dir.path(), "test", None).expect("init");
    let value = serde_json::json!({ "blob": "abcdef0123456789".repeat(64 * 1024) });
    let handle = ws
        .write_json_artifact("application/json", &value)
        .expect("write");
    let bytes = fs::read(ws.root().join(&handle.relative_path)).expect("read");
    let response = ws
        .read_artifact_preview(Some(&handle.relative_path), None, 100, 64)
        .expect("preview");
    assert_eq!(response.total_size, bytes.len() as u64);
    assert_eq!(response.returned_size, 64);
    assert!(response.truncated);
    assert_eq!(response.artifact.hash_blake3, handle.hash_blake3);
    let expected: String = bytes[100..164].iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(response.preview_hex, expected);
    let tail = ws
        .read_artifact_preview(
            Some(&handle.relative_path),
            None,
            bytes.len() as u64 - 10,
            64,
        )
        .expect("tail preview");
    assert_eq!(tail.returned_size, 10);
    assert!(!tail.truncated);
}
