//! CLI first-run initialization without a VPN connection or existing keys.
use std::process::Command;

#[test]
fn client_creates_identity_but_never_invents_server_bundle() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("client.toml");
    std::fs::write(&config, "identity_key_file = './keys/identity.key'\nprekey_bundle = './missing-server-bundle.json'\ndata_dir = './data'\n").unwrap();
    let key_path = dir.path().join("keys/identity.key");
    let mut previous = None;
    for run in 0..2 {
        let output = Command::new(env!("CARGO_BIN_EXE_rvpn"))
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
