//! Fail-closed behavior for `yl mcp`: no workspace roots must refuse to start.

#[test]
fn mcp_without_roots_fails_closed() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_yl"))
        .args(["mcp"])
        .stdin(std::process::Stdio::null())
        .output()
        .expect("failed to spawn `yl mcp`");
    assert!(!out.status.success(), "expected a non-zero exit code");
    let msg = String::from_utf8_lossy(&out.stderr);
    assert!(
        msg.contains("No workspace roots configured"),
        "stderr: {msg}"
    );
}
