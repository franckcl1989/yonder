#![forbid(unsafe_code)]

use std::fs;
use std::process::Command;
use tempfile::tempdir;
use yonder_net::Keypair;

#[test]
fn invalid_connection_code_is_rejected_without_echoing_the_secret() {
    let directory = tempdir().unwrap();
    let peer = Keypair::generate_ed25519().public().to_peer_id();
    fs::write(
        directory.path().join("yon.toml"),
        format!("relays = ['/ip4/127.0.0.1/tcp/1/p2p/{peer}']\n"),
    )
    .unwrap();
    let secret = "0000-0000-0000-000U";
    let output = Command::new(env!("CARGO_BIN_EXE_yon"))
        .args(["connect", secret])
        .current_dir(directory.path())
        .env_remove("YON_RELAYS")
        .env_remove("YON_WSS_CA")
        .env_remove("YON_WSS_CA_DER")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(stderr, "error: connection code is invalid or expired\n");
    for forbidden in [secret, "OPAQUE", "PeerId", "locator"] {
        assert!(
            !stderr.contains(forbidden),
            "public error leaked {forbidden}"
        );
    }

    let log = directory.path().join("yon-debug.log");
    let logged = Command::new(env!("CARGO_BIN_EXE_yon"))
        .args([
            "--log-level",
            "debug",
            "--log-file",
            log.to_str().unwrap(),
            "connect",
            secret,
        ])
        .current_dir(directory.path())
        .env_remove("YON_RELAYS")
        .env_remove("YON_WSS_CA")
        .env_remove("YON_WSS_CA_DER")
        .output()
        .unwrap();
    assert_eq!(logged.status.code(), Some(2));
    assert!(logged.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&logged.stderr),
        "error: connection code is invalid or expired\n"
    );
    let diagnostics = fs::read_to_string(log).unwrap();
    assert!(diagnostics.contains("connection code input was rejected"));
    assert!(!diagnostics.contains(secret));
}

#[test]
fn config_check_and_sources_are_script_friendly() {
    let directory = tempdir().unwrap();
    let peer = Keypair::generate_ed25519().public().to_peer_id();
    fs::write(
        directory.path().join("yon.toml"),
        format!("relays = ['/ip4/127.0.0.1/tcp/1/p2p/{peer}']\n"),
    )
    .unwrap();

    let check = Command::new(env!("CARGO_BIN_EXE_yon"))
        .args(["config", "check"])
        .current_dir(directory.path())
        .env_remove("YON_RELAYS")
        .env_remove("YON_WSS_CA")
        .env_remove("YON_WSS_CA_DER")
        .output()
        .unwrap();
    assert!(check.status.success());
    assert_eq!(check.stdout, b"Configuration is valid.\n");
    assert!(check.stderr.is_empty());

    let sources = Command::new(env!("CARGO_BIN_EXE_yon"))
        .args(["config", "sources"])
        .current_dir(directory.path())
        .env_remove("YON_RELAYS")
        .env_remove("YON_WSS_CA")
        .env_remove("YON_WSS_CA_DER")
        .output()
        .unwrap();
    assert!(sources.status.success());
    assert!(sources.stderr.is_empty());
    let sources = String::from_utf8(sources.stdout).unwrap();
    assert!(sources.contains("Configuration precedence (lowest to highest):"));
    assert!(sources.contains(&directory.path().join("yon.toml").display().to_string()));
    assert!(sources.contains("Environment variables: YON_* (values hidden)"));
    assert!(!sources.contains(&peer.to_string()));
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
        .env_remove("YON_WSS_CA")
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
            .env_remove("YON_WSS_CA")
            .env_remove("YON_WSS_CA_DER")
            .output()
            .unwrap();

        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("failed to configure WSS TLS"));
        assert!(
            stderr.contains("invalid peer certificate"),
            "unexpected WSS diagnostic: {stderr}"
        );
    }
}
