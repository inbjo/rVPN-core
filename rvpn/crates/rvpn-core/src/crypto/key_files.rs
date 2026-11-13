//! First-run identity creation and atomic, non-overwriting key publication.

use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use tracing::info;

use super::IdentityKey;

/// Publish a fully written file atomically. Existing files are never replaced.
pub fn write_new_file(path: &Path, content: &[u8], private: bool) -> Result<()> {
    write_file(path, content, private, false)
}

/// Atomically replace a derived public bundle after regenerating missing keys.
pub fn replace_public_file(path: &Path, content: &[u8]) -> Result<()> {
    write_file(path, content, false, true)
}

fn write_file(path: &Path, content: &[u8], private: bool, replace: bool) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)
        .with_context(|| format!("Failed to create key directory: {}", parent.display()))?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.as_file()
            .set_permissions(std::fs::Permissions::from_mode(if private {
                0o600
            } else {
                0o644
            }))?;
    }
    #[cfg(not(unix))]
    let _ = private;
    file.write_all(content)?;
    file.as_file().sync_all()?;
    let result = if replace {
        file.persist(path)
    } else {
        file.persist_noclobber(path)
    };
    result
        .map_err(|error| error.error)
        .with_context(|| format!("Failed to publish key file: {}", path.display()))?;
    Ok(())
}

/// Load an existing identity, or securely create it on the first run.
/// Unreadable, malformed, and dangling-symlink files are errors, not rotations.
pub fn ensure_identity(path: &Path, role: &str) -> Result<IdentityKey> {
    let created = match std::fs::symlink_metadata(path) {
        Ok(_) => false,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            info!(
                "{} identity key is missing; generating Ed25519 key at {}",
                role,
                path.display()
            );
            let identity = IdentityKey::generate();
            let data = zeroize::Zeroizing::new(format!(
                "R-VPN-IDENTITY-v1\n{}\n{}\n",
                BASE64.encode(identity.verifying_key.to_bytes()),
                BASE64.encode(identity.signing_key.to_bytes())
            ));
            match write_new_file(path, data.as_bytes(), true) {
                Ok(()) => true,
                Err(error)
                    if error
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|e| e.kind() == std::io::ErrorKind::AlreadyExists) =>
                {
                    false
                }
                Err(error) => return Err(error),
            }
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("Failed to inspect identity key: {}", path.display()))
        }
    };
    let identity = IdentityKey::load(path)
        .with_context(|| format!("Failed to load {} identity key: {}", role, path.display()))?;
    info!(
        "{} identity key {}: {}",
        role,
        if created { "generated" } else { "loaded" },
        path.display()
    );
    info!(
        "{} public identity (Ed25519, base64): {}",
        role,
        BASE64.encode(identity.verifying_key.to_bytes())
    );
    info!(
        "{} identity fingerprint: {}",
        role,
        crate::identity_pin::encode_identity_pin(identity.verifying_key.as_bytes())?
    );
    Ok(identity)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_identity_is_created_once_and_existing_bytes_are_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/identity.key");
        let first = ensure_identity(&path, "Test").unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let second = ensure_identity(&path, "Test").unwrap();
        assert_eq!(first.verifying_key, second.verifying_key);
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn corrupt_and_existing_files_are_not_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.key");
        std::fs::write(&path, "corrupt").unwrap();
        assert!(ensure_identity(&path, "Test").is_err());
        assert!(write_new_file(&path, b"replacement", true).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "corrupt");
    }

    #[test]
    fn concurrent_initialization_publishes_only_one_complete_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.key");
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let path = path.clone();
                std::thread::spawn(move || {
                    ensure_identity(&path, "Test")
                        .unwrap()
                        .verifying_key
                        .to_bytes()
                })
            })
            .collect();
        let expected = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>();
        assert!(expected.iter().all(|key| key == &expected[0]));
    }
}
