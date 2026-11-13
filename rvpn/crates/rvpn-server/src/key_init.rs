//! Initialize persistent server identity and its matching X3DH bundle.

use std::path::Path;

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use rvpn_core::crypto::key_files::{ensure_identity, replace_public_file, write_new_file};
use rvpn_core::crypto::{X3DHPublicBundle, X3DHResponder};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::config::ServerConfig;

#[derive(Serialize, Deserialize)]
struct PrivatePrekey {
    signed_prekey_private: String,
    #[serde(default)]
    public_bundle: Option<X3DHPublicBundle>,
}

fn exists(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => {
            Err(error).with_context(|| format!("Failed to inspect key file: {}", path.display()))
        }
    }
}

/// Generate missing private material, then publish a matching public bundle.
/// Malformed existing files still fail instead of being silently replaced.
pub fn initialize(config: &mut ServerConfig, config_directory: &Path) -> Result<()> {
    let bundle_path = config
        .prekey_bundle_file
        .get_or_insert_with(|| config_directory.join("prekey-bundle.json"))
        .clone();
    let private_path = bundle_path.with_extension("private.json");
    anyhow::ensure!(
        bundle_path != private_path
            && config.identity_key_file != bundle_path
            && config.identity_key_file != private_path,
        "Identity, public bundle, and private prekey paths must be distinct"
    );
    let has_bundle = exists(&bundle_path)?;
    let has_private = exists(&private_path)?;
    let has_identity = exists(&config.identity_key_file)?;
    let existing: Option<X3DHPublicBundle> = if has_bundle {
        Some(
            serde_json::from_slice(&std::fs::read(&bundle_path)?).with_context(|| {
                format!("Invalid public prekey bundle: {}", bundle_path.display())
            })?,
        )
    } else {
        None
    };
    let private: Option<PrivatePrekey> = if has_private {
        Some(
            serde_json::from_slice(&std::fs::read(&private_path)?)
                .with_context(|| format!("Invalid private prekey: {}", private_path.display()))?,
        )
    } else {
        None
    };
    // Parse all existing material before creating anything new.
    let private_key = private
        .as_ref()
        .map(|private| -> Result<[u8; 32]> {
            BASE64
                .decode(&private.signed_prekey_private)
                .context("Invalid base64 in server private prekey")?
                .try_into()
                .map_err(|_| {
                    anyhow::anyhow!(
                        "Server private prekey must be 32 bytes: {}",
                        private_path.display()
                    )
                })
        })
        .transpose()?;
    let identity = ensure_identity(&config.identity_key_file, "Server")?;
    let responder = match private_key {
        Some(key) => {
            info!("Loaded server private prekey: {}", private_path.display());
            X3DHResponder::from_identity_with_bundle(identity, key)
        }
        None => X3DHResponder::from_identity(identity),
    };
    let mut exported = responder.get_public_bundle();
    let previous = existing
        .as_ref()
        .or_else(|| private.as_ref().and_then(|p| p.public_bundle.as_ref()));
    // Retain valid identity-rotation metadata when only the signed prekey changes.
    if let Some(previous) = previous {
        if previous.identity_key == exported.identity_key {
            exported.identity_key_version = previous.identity_key_version;
            exported.rotation_signature = previous.rotation_signature;
        }
    }
    if !has_identity && (has_bundle || has_private) {
        warn!("Server identity was regenerated because its file was missing. Previously pinned clients must verify the new fingerprint and update their server bundle");
    }
    let matches = existing.as_ref().is_some_and(|bundle| {
        bundle.identity_key == exported.identity_key
            && bundle.identity_x25519_key == exported.identity_x25519_key
            && bundle.signed_prekey == exported.signed_prekey
            && bundle.one_time_prekey == exported.one_time_prekey
            && bundle.prekey_signature == exported.prekey_signature
    });
    anyhow::ensure!(
        !has_bundle || matches || !has_identity || !has_private,
        "Existing server identity, public bundle, and private prekey do not match: {}",
        bundle_path.display()
    );
    if !has_private {
        let private = PrivatePrekey {
            signed_prekey_private: BASE64.encode(responder.get_signed_prekey_private()),
            public_bundle: Some(exported.clone()),
        };
        write_new_file(&private_path, &serde_json::to_vec_pretty(&private)?, true)?;
        info!(
            "Generated server private prekey: {} (server-only)",
            private_path.display()
        );
    }
    if !has_bundle {
        write_new_file(&bundle_path, &serde_json::to_vec_pretty(&exported)?, false)?;
        info!(
            "Generated server public prekey bundle: {}",
            bundle_path.display()
        );
    } else if matches {
        info!(
            "Loaded matching server public bundle: {}",
            bundle_path.display()
        );
    } else {
        replace_public_file(&bundle_path, &serde_json::to_vec_pretty(&exported)?)?;
        warn!("Regenerated public bundle {} to match newly generated missing key material; update client copies", bundle_path.display());
    }
    info!(
        "Server bundle identity version: {}",
        exported.identity_key_version
    );
    info!(
        "Server signed prekey (public, base64): {}",
        BASE64.encode(exported.signed_prekey)
    );
    info!("Distribute public bundle {} to clients; identity and private prekey files stay on the server", bundle_path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(directory: &Path) -> ServerConfig {
        ServerConfig {
            identity_key_file: directory.join("identity.key"),
            ..ServerConfig::default()
        }
    }

    #[test]
    fn first_run_creates_matching_files_and_restarts_preserve_them() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = config(dir.path());
        initialize(&mut config, dir.path()).unwrap();
        let paths = [
            config.identity_key_file.clone(),
            config.prekey_bundle_file.clone().unwrap(),
            dir.path().join("prekey-bundle.private.json"),
        ];
        let before: Vec<_> = paths.iter().map(|p| std::fs::read(p).unwrap()).collect();
        initialize(&mut config, dir.path()).unwrap();
        for (path, bytes) in paths.iter().zip(before) {
            assert_eq!(std::fs::read(path).unwrap(), bytes);
        }
    }

    #[test]
    fn missing_public_bundle_is_rebuilt_from_existing_private_prekey() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = config(dir.path());
        initialize(&mut config, dir.path()).unwrap();
        let public = config.prekey_bundle_file.as_ref().unwrap();
        let before: X3DHPublicBundle =
            serde_json::from_slice(&std::fs::read(public).unwrap()).unwrap();
        std::fs::remove_file(public).unwrap();
        initialize(&mut config, dir.path()).unwrap();
        let after: X3DHPublicBundle =
            serde_json::from_slice(&std::fs::read(config.prekey_bundle_file.unwrap()).unwrap())
                .unwrap();
        assert_eq!(before.signed_prekey, after.signed_prekey);
        assert_eq!(before.identity_key, after.identity_key);
    }

    #[test]
    fn rebuilding_public_bundle_preserves_stored_identity_rotation_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = config(dir.path());
        initialize(&mut config, dir.path()).unwrap();
        let private_path = dir.path().join("prekey-bundle.private.json");
        let mut private: PrivatePrekey =
            serde_json::from_slice(&std::fs::read(&private_path).unwrap()).unwrap();
        let bundle = private.public_bundle.as_mut().unwrap();
        let previous = rvpn_core::crypto::IdentityKey::generate();
        bundle.identity_key_version = 2;
        let message = rvpn_core::identity_pin::rotation_signature_message(&bundle.identity_key, 2);
        bundle.rotation_signature = Some(previous.sign(&message));
        let expected_signature = bundle.rotation_signature;
        std::fs::write(&private_path, serde_json::to_vec(&private).unwrap()).unwrap();
        std::fs::remove_file(dir.path().join("prekey-bundle.json")).unwrap();
        initialize(&mut config, dir.path()).unwrap();
        let restored: X3DHPublicBundle =
            serde_json::from_slice(&std::fs::read(dir.path().join("prekey-bundle.json")).unwrap())
                .unwrap();
        assert_eq!(restored.identity_key_version, 2);
        assert_eq!(restored.rotation_signature, expected_signature);
    }

    #[test]
    fn missing_private_prekey_and_identity_are_generated_with_matching_public_bundle() {
        for missing in ["identity.key", "prekey-bundle.private.json"] {
            let dir = tempfile::tempdir().unwrap();
            let mut config = config(dir.path());
            initialize(&mut config, dir.path()).unwrap();
            let before: X3DHPublicBundle = serde_json::from_slice(
                &std::fs::read(dir.path().join("prekey-bundle.json")).unwrap(),
            )
            .unwrap();
            std::fs::remove_file(dir.path().join(missing)).unwrap();
            initialize(&mut config, dir.path()).unwrap();
            assert!(dir.path().join(missing).is_file());
            let after: X3DHPublicBundle = serde_json::from_slice(
                &std::fs::read(dir.path().join("prekey-bundle.json")).unwrap(),
            )
            .unwrap();
            if missing == "identity.key" {
                assert_ne!(before.identity_key, after.identity_key);
                assert_eq!(before.signed_prekey, after.signed_prekey);
            } else {
                assert_eq!(before.identity_key, after.identity_key);
                assert_ne!(before.signed_prekey, after.signed_prekey);
            }
            initialize(&mut config, dir.path()).unwrap();
        }
    }

    #[test]
    fn corrupt_or_mismatched_material_is_rejected_without_overwrite() {
        for file in [
            "identity.key",
            "prekey-bundle.json",
            "prekey-bundle.private.json",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let mut config = config(dir.path());
            initialize(&mut config, dir.path()).unwrap();
            let path = dir.path().join(file);
            std::fs::write(&path, "corrupt").unwrap();
            assert!(initialize(&mut config, dir.path()).is_err());
            assert_eq!(std::fs::read_to_string(path).unwrap(), "corrupt");
        }
        let dir = tempfile::tempdir().unwrap();
        let mut config = config(dir.path());
        initialize(&mut config, dir.path()).unwrap();
        rvpn_core::crypto::IdentityKey::generate()
            .save(&config.identity_key_file)
            .unwrap();
        let before = std::fs::read(&config.identity_key_file).unwrap();
        assert!(initialize(&mut config, dir.path()).is_err());
        assert_eq!(std::fs::read(&config.identity_key_file).unwrap(), before);
    }
}
