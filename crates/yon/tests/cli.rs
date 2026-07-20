#![forbid(unsafe_code)]

use std::fs;
use std::process::Command;
use tempfile::tempdir;
use yonder_net::Keypair;

#[test]
fn invalid_connection_code_is_rejected_without_echoing_the_secret() {
    let secret = "0000-0000-0000-000U";
    let output = Command::new(env!("CARGO_BIN_EXE_yon"))
        .args(["connect", secret])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("the connection code is invalid"));
    assert!(!stderr.contains(secret));
}

#[test]
fn configuration_failures_retain_a_safe_actionable_cause() {
    let directory = tempdir().unwrap();
    fs::write(
        directory.path().join("yon.toml"),
        "unsupported_setting = true\n",
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_yon"))
        .arg("host")
        .current_dir(directory.path())
        .env_remove("YON_RELAYS")
        .env_remove("YON_WSS_CA_DER")
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("failed to load endpoint configuration:"));
    assert!(stderr.contains("relays"));
}

#[test]
fn invalid_wss_ca_fails_closed_for_both_endpoint_roles() {
    let directory = tempdir().unwrap();
    let peer = Keypair::generate_ed25519().public().to_peer_id();
    fs::write(directory.path().join("invalid-ca.der"), [1_u8]).unwrap();
    fs::write(
        directory.path().join("yon.toml"),
        format!(
            "relays = ['/dns4/localhost/tcp/443/tls/ws/p2p/{peer}']\nwss_ca_der = 'invalid-ca.der'\n"
        ),
    )
    .unwrap();

    for arguments in [vec!["host"], vec!["connect", "0000-0000-0000-0000"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_yon"))
            .args(arguments)
            .current_dir(directory.path())
            .env_remove("YON_RELAYS")
            .env_remove("YON_WSS_CA_DER")
            .output()
            .unwrap();

        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("failed to configure WSS TLS"));
        assert!(stderr.contains("invalid peer certificate"));
    }
}
