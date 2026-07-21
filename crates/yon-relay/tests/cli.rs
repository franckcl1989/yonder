#![forbid(unsafe_code)]

use std::io::{BufRead as _, BufReader, Read as _};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::{TempDir, tempdir};
use yonder_net::EndpointRelayAddress;

const START_TIMEOUT: Duration = Duration::from_secs(10);

#[test]
fn identity_cli_supports_every_log_level_and_refuses_overwrite() {
    let directory = test_directory();
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
fn readonly_identity_and_configuration_diagnostics_are_actionable() {
    let directory = test_directory();
    let identity = directory.path().join("relay.identity");
    let initialized = Command::new(env!("CARGO_BIN_EXE_yon-relay"))
        .args(["identity", "init", "--output"])
        .arg(&identity)
        .output()
        .unwrap();
    assert!(initialized.status.success());

    let shown = Command::new(env!("CARGO_BIN_EXE_yon-relay"))
        .args(["identity", "show", "--input"])
        .arg(&identity)
        .output()
        .unwrap();
    assert!(shown.status.success());
    assert_eq!(shown.stdout, initialized.stdout);
    assert!(shown.stderr.is_empty());

    let occupied = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = occupied.local_addr().unwrap().port();
    std::fs::write(
        directory.path().join("yon-relay.toml"),
        format!(
            "identity = \"relay.identity\"\n\
             listen = [\"/ip4/127.0.0.1/tcp/{port}\"]\n\
             external = [\"/ip4/203.0.113.1/tcp/{port}\"]\n"
        ),
    )
    .unwrap();
    let checked = relay_command(directory.path())
        .args(["config", "check"])
        .output()
        .unwrap();
    assert!(checked.status.success());
    assert_eq!(checked.stdout, b"Relay configuration is valid.\n");
    assert!(checked.stderr.is_empty());

    std::fs::write(
        directory.path().join("yon-relay.toml"),
        format!(
            "identity = \"relay.identity\"\n\
             listen = [\"/ip4/127.0.0.1/tcp/{port}\", \"/ip4/127.0.0.1/tcp/{port}\"]\n\
             external = [\"/ip4/203.0.113.1/tcp/{port}\"]\n"
        ),
    )
    .unwrap();
    let rejected = relay_command(directory.path())
        .args(["config", "check"])
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("duplicate endpoint"));

    let help = Command::new(env!("CARGO_BIN_EXE_yon-relay"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(help.status.success());
    let help = String::from_utf8_lossy(&help.stdout);
    assert!(help.contains("config"));
    assert!(help.contains("identity"));
    assert!(help.contains("serve"));
}

#[test]
fn serve_cli_starts_the_real_relay_and_prints_its_canonical_address() {
    let directory = test_directory();
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

fn relay_command(directory: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_yon-relay"));
    command
        .current_dir(directory)
        .env_remove("YON_RELAY_IDENTITY")
        .env_remove("YON_RELAY_LISTEN")
        .env_remove("YON_RELAY_EXTERNAL")
        .env_remove("YON_RELAY_WSS_CERTIFICATE_DER")
        .env_remove("YON_RELAY_WSS_PRIVATE_KEY_DER");
    command
}

fn test_directory() -> TempDir {
    let directory = tempdir().unwrap();
    secure_test_directory(directory.path());
    directory
}

#[cfg(not(windows))]
fn secure_test_directory(_path: &std::path::Path) {}

#[cfg(windows)]
fn secure_test_directory(path: &std::path::Path) {
    const SCRIPT: &str = r#"
$ErrorActionPreference='Stop'
$path=$env:YONDER_TEST_DIRECTORY
$current=[Security.Principal.WindowsIdentity]::GetCurrent().User
$system=New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
$administrators=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
$acl=New-Object Security.AccessControl.DirectorySecurity
$acl.SetOwner($current)
$acl.SetAccessRuleProtection($true,$false)
$rights=[Security.AccessControl.FileSystemRights]::FullControl
$inherit=[Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
$propagate=[Security.AccessControl.PropagationFlags]::None
$allow=[Security.AccessControl.AccessControlType]::Allow
foreach($sid in @($current,$system,$administrators)){$rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,$rights,$inherit,$propagate,$allow);[void]$acl.AddAccessRule($rule)}
[IO.Directory]::SetAccessControl($path,$acl)
exit 0
"#;
    let executable = std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap())
        .join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let status = Command::new(executable)
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            SCRIPT,
        ])
        .env("YONDER_TEST_DIRECTORY", path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
}
