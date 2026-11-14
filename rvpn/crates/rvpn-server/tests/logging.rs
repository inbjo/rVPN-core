//! Verify file logging through real server startup without opening any sockets.
use std::{fs, path::Path, process::Command};

#[test]
fn server_logs_startup_failures_and_honors_file_settings() {
    for mode in ["default", "custom", "disabled", "unwritable"] {
        let directory = tempfile::tempdir().unwrap();
        let binary = directory.path().join(
            Path::new(env!("CARGO_BIN_EXE_rvpn-server"))
                .file_name()
                .unwrap(),
        );
        fs::copy(env!("CARGO_BIN_EXE_rvpn-server"), &binary).unwrap();
        let config_dir = directory.path().join("config");
        fs::create_dir(&config_dir).unwrap();
        fs::write(config_dir.join("invalid.key"), "invalid identity").unwrap();
        let settings = match mode {
            "custom" => "[server.logging]\ndirectory = './logs'\nmax_files = 3\n",
            "disabled" => "[server.logging]\nfile_enabled = false\n",
            "unwritable" => "[server.logging]\ndirectory = './invalid.key'\n",
            _ => "",
        };
        let config = config_dir.join("server.toml");
        fs::write(
            &config,
            format!("[server]\nidentity_key_file = './invalid.key'\n{settings}"),
        )
        .unwrap();
        let output = Command::new(&binary)
            .args(["-c", config.to_str().unwrap()])
            .current_dir(std::env::temp_dir())
            .output()
            .unwrap();
        assert!(!output.status.success());
        let console = String::from_utf8_lossy(&output.stdout);
        assert!(console.contains("Server terminated:"), "{console}");
        if mode == "unwritable" {
            assert!(console.contains("File logging unavailable"), "{console}");
        }
        let log_dir = if mode == "custom" {
            config_dir.join("logs")
        } else {
            directory.path().to_owned()
        };
        let logs: Vec<_> = fs::read_dir(&log_dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "log"))
            .collect();
        if matches!(mode, "disabled" | "unwritable") {
            assert!(logs.is_empty());
        } else {
            assert_eq!(logs.len(), 1);
            assert!(logs[0]
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("rvpn-server."));
            let log = fs::read_to_string(&logs[0]).unwrap();
            assert!(log.contains("Server terminated:"));
            assert!(log.contains("Failed to load"), "{log}");
            assert!(!log.contains('\u{1b}'));
        }
    }
}
