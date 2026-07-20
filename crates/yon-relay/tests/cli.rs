#![forbid(unsafe_code)]

use std::io::{BufRead as _, BufReader, Read as _};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::tempdir;
use yonder_net::EndpointRelayAddress;

const START_TIMEOUT: Duration = Duration::from_secs(10);

#[test]
fn identity_cli_supports_every_log_level_and_refuses_overwrite() {
    let directory = tempdir().unwrap();
    for level in ["off", "error", "warn", "info", "debug", "trace"] {
        let path = directory.path().join(format!("relay-{level}.identity"));
        let output = Command::new(env!("CARGO_BIN_EXE_yon-relay"))
            .args(["--log-level", level, "identity", "init", "--output"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut product_lines = stdout.lines();
        assert!(
            product_lines
                .next()
                .is_some_and(|line| line.starts_with("Relay PeerId: "))
        );
        assert_eq!(product_lines.next(), None);
        assert!(path.is_file());

        let duplicate = Command::new(env!("CARGO_BIN_EXE_yon-relay"))
            .args(["identity", "init", "--output"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(!duplicate.status.success());
        assert!(duplicate.stdout.is_empty());
        assert!(String::from_utf8_lossy(&duplicate.stderr).contains("already exists"));
    }
}

#[test]
fn serve_cli_starts_the_real_relay_and_prints_its_canonical_address() {
    let directory = tempdir().unwrap();
    let port = available_port();
    let identity = directory.path().join("relay.identity");
    let initialized = Command::new(env!("CARGO_BIN_EXE_yon-relay"))
        .args(["identity", "init", "--output"])
        .arg(&identity)
        .output()
        .unwrap();
    assert!(initialized.status.success());
    let initialized_stdout = String::from_utf8_lossy(&initialized.stdout);
    let peer = initialized_stdout
        .lines()
        .find_map(|line| line.strip_prefix("Relay PeerId: "))
        .expect("identity command prints its PeerId")
        .to_owned();
    std::fs::write(
        directory.path().join("yon-relay.toml"),
        format!(
            "identity = \"relay.identity\"\n\
             listen = [\"/ip4/0.0.0.0/tcp/{port}\"]\n\
             external = [\"/ip4/127.0.0.1/tcp/{port}\"]\n"
        ),
    )
    .unwrap();

    let mut relay = Command::new(env!("CARGO_BIN_EXE_yon-relay"))
        .args(["--log-level", "trace", "serve"])
        .current_dir(directory.path())
        .env_remove("YON_RELAY_IDENTITY")
        .env_remove("YON_RELAY_LISTEN")
        .env_remove("YON_RELAY_EXTERNAL")
        .env_remove("YON_RELAY_WSS_CERTIFICATE_DER")
        .env_remove("YON_RELAY_WSS_PRIVATE_KEY_DER")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = relay.stdout.take().expect("relay stdout was piped");
    let mut stderr = relay.stderr.take().expect("relay stderr was piped");
    let diagnostic_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).map(|_| bytes)
    });
    let (line_tx, line_rx) = mpsc::channel();
    let reader = thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if line_tx.send(line).is_err() {
                break;
            }
        }
    });

    let outcome = (|| -> Result<Vec<String>, String> {
        let deadline = Instant::now() + START_TIMEOUT;
        let mut printed_peer = false;
        let mut printed_address = false;
        let mut product_lines = Vec::new();
        while !(printed_peer && printed_address) {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let line = line_rx
                .recv_timeout(remaining)
                .map_err(|error| format!("relay start output timed out: {error}"))?
                .map_err(|error| format!("relay start output failed: {error}"))?;
            printed_peer |= line == format!("Relay PeerId: {peer}");
            printed_address |=
                line.starts_with("/ip4/127.0.0.1/tcp/") && line.ends_with(&format!("/p2p/{peer}"));
            product_lines.push(line);
        }
        match relay.try_wait().map_err(|error| error.to_string())? {
            None => Ok(product_lines),
            Some(status) => Err(format!("relay exited during startup: {status}")),
        }
    })();

    let _ = relay.kill();
    relay.wait().unwrap();
    reader.join().unwrap();
    let diagnostic_bytes = diagnostic_reader.join().unwrap().unwrap();
    assert!(!diagnostic_bytes.is_empty());
    let mut product_lines = outcome.unwrap();
    product_lines.extend(line_rx.try_iter().map(Result::unwrap));
    assert!(product_lines.iter().all(|line| {
        line == &format!("Relay PeerId: {peer}") || line.parse::<EndpointRelayAddress>().is_ok()
    }));
    assert!(!product_lines.iter().any(|line| line.contains("0.0.0.0")));
}

fn available_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
