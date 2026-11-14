//! CLI first-run initialization without a VPN connection or existing keys.
use std::process::Command;

#[tokio::test]
async fn control_panel_remains_available_after_vpn_startup_failure() {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let directory = tempfile::tempdir().unwrap();
    let binary = directory.path().join(
        std::path::Path::new(env!("CARGO_BIN_EXE_rvpn"))
            .file_name()
            .unwrap(),
    );
    std::fs::copy(env!("CARGO_BIN_EXE_rvpn"), &binary).unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let config = directory.path().join("client.toml");
    std::fs::write(directory.path().join("invalid.key"), "invalid identity").unwrap();
    std::fs::write(&config, format!("identity_key_file = './invalid.key'\ndata_dir = './data'\n[logging]\nfile_enabled = false\n[dashboard]\nenabled = true\nlisten_address = '{address}'\n")).unwrap();
    struct Process(std::process::Child);
    impl Drop for Process {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut child = Process(
        Command::new(binary)
            .args(["-c", config.to_str().unwrap()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "Client exited before configuration could be repaired"
            );
            let mut request = format!("ws://{address}/ws").into_client_request().unwrap();
            request
                .headers_mut()
                .insert("origin", format!("http://{address}").parse().unwrap());
            if let Ok((mut ws, _)) = tokio_tungstenite::connect_async(request).await {
                loop {
                    let event: serde_json::Value =
                        serde_json::from_str(ws.next().await.unwrap().unwrap().to_text().unwrap())
                            .unwrap();
                    if event["type"] == "stats" && event["data"]["runtime_error"].is_string() {
                        assert!(event["data"]["runtime_error"]
                            .as_str()
                            .unwrap()
                            .contains("identity"));
                        return;
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
}

#[test]
fn client_honors_configured_log_directory_and_disable_switch() {
    for enabled in [true, false] {
        let directory = tempfile::tempdir().unwrap();
        let binary = directory.path().join(
            std::path::Path::new(env!("CARGO_BIN_EXE_rvpn"))
                .file_name()
                .unwrap(),
        );
        std::fs::copy(env!("CARGO_BIN_EXE_rvpn"), &binary).unwrap();
        let config_dir = directory.path().join("config");
        std::fs::create_dir(&config_dir).unwrap();
        std::fs::write(config_dir.join("invalid.key"), "invalid identity").unwrap();
        let config = config_dir.join("client.toml");
        std::fs::write(&config, format!(
            "identity_key_file = './invalid.key'\ndata_dir = './data'\n[logging]\nfile_enabled = {enabled}\ndirectory = './logs'\n"
        )).unwrap();
        let output = Command::new(&binary)
            .args(["-c", config.to_str().unwrap()])
            .current_dir(std::env::temp_dir())
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("Client terminated:"));
        let log_dir = config_dir.join("logs");
        if enabled {
            let logs: String = std::fs::read_dir(&log_dir)
                .unwrap()
                .map(|entry| std::fs::read_to_string(entry.unwrap().path()).unwrap())
                .collect();
            assert!(logs.contains("Client terminated:"));
        } else {
            assert!(!log_dir.exists());
        }
        assert!(!directory.path().join("logs").exists());
    }
}

#[test]
fn client_creates_identity_but_never_invents_server_bundle() {
    let dir = tempfile::tempdir().unwrap();
    // Run a private copy from a different working directory: default logs must
    // follow the executable, not the shell or configuration directory.
    let binary = dir.path().join(
        std::path::Path::new(env!("CARGO_BIN_EXE_rvpn"))
            .file_name()
            .unwrap(),
    );
    std::fs::copy(env!("CARGO_BIN_EXE_rvpn"), &binary).unwrap();
    let config = dir.path().join("client.toml");
    std::fs::write(&config, "identity_key_file = './keys/identity.key'\nprekey_bundle = './missing-server-bundle.json'\ndata_dir = './data'\n").unwrap();
    let key_path = dir.path().join("keys/identity.key");
    let mut previous = None;
    for run in 0..2 {
        let output = Command::new(&binary)
            .current_dir(std::env::temp_dir())
            .args(["-c", config.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "Missing server bundle should stop startup"
        );
        let logs = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(logs.contains("client cannot generate it"), "{logs}");
        assert!(logs.contains("Client public identity (Ed25519, base64)"));
        assert!(logs.contains("Client identity fingerprint: ik:1:"));
        assert!(logs.contains(if run == 0 {
            "Client identity key generated:"
        } else {
            "Client identity key loaded:"
        }));
        let key = std::fs::read_to_string(&key_path).unwrap();
        let file_logs: String = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "log"))
            .map(|path| std::fs::read_to_string(path).unwrap())
            .collect();
        assert!(file_logs.contains("Client terminated:"));
        assert!(file_logs.contains("client cannot generate it"));
        assert_eq!(file_logs.matches("Client terminated:").count(), run + 1);
        assert!(!file_logs.contains(key.lines().nth(2).unwrap()));
        assert!(
            !logs.contains(key.lines().nth(2).unwrap()),
            "Private key leaked into logs"
        );
        if let Some(before) = &previous {
            assert_eq!(&key, before);
        }
        previous = Some(key);
        assert!(!dir.path().join("missing-server-bundle.json").exists());
    }
}
