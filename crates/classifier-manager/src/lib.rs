use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const COMPONENT: &str = "classifierd";
pub const AMD64_PLATFORM: &str = "linux-musl-x86_64";
pub const ARM64_PLATFORM: &str = "linux-musl-aarch64";
/// The canonical platform identifier for this manager's compiled architecture.
#[cfg(target_arch = "x86_64")]
pub const PLATFORM: &str = AMD64_PLATFORM;
#[cfg(target_arch = "aarch64")]
pub const PLATFORM: &str = ARM64_PLATFORM;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub const PLATFORM: &str = "unsupported";
pub const IPC_PROTOCOL_VERSION: u32 = netqmon_classifier_client::PROTOCOL_VERSION;
pub const MAX_BINARY_BYTES: u64 = 64 * 1024 * 1024;
pub const TEST_KEY_ID: &str = "test-classifier-component";
pub const TEST_PUBLIC_KEY_HEX: &str =
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const INSTALLED_MANIFEST: &str = "manifest.json";

#[must_use]
pub fn platform_for_arch(arch: &str) -> Option<&'static str> {
    match arch {
        "amd64" | "x86_64" => Some(AMD64_PLATFORM),
        "arm64" | "aarch64" => Some(ARM64_PLATFORM),
        _ => None,
    }
}

/// Returns the canonical component platform for the manager's compiled CPU.
///
/// # Errors
/// Returns an error when the manager is compiled for an unsupported CPU
/// architecture.
pub fn current_platform() -> Result<&'static str, String> {
    platform_for_arch(std::env::consts::ARCH).ok_or_else(|| {
        format!(
            "unsupported classifierd host architecture: {}",
            std::env::consts::ARCH
        )
    })
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ComponentManifest {
    pub format: String,
    pub format_version: u32,
    pub component: String,
    pub version: String,
    pub channel: String,
    pub platform: String,
    pub minimum_netqmon_version: String,
    pub ipc_protocol_version: u32,
    pub sha256: String,
    pub size_bytes: u64,
    pub download_url: String,
    pub signature: ManifestSignature,
}

/// Returns whether an installed manifest already contains the same release
/// content as the manifest advertised by Cloud.
///
/// Version alone is not sufficient here: Cloud may republish a corrected
/// binary under the same component version during a beta release.
#[must_use]
pub fn same_release_content(installed: &ComponentManifest, advertised: &ComponentManifest) -> bool {
    installed.version == advertised.version
        && installed.channel == advertised.channel
        && installed.sha256 == advertised.sha256
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ManifestSignature {
    pub algorithm: String,
    pub key_id: String,
    pub key_version: u32,
    pub value: String,
}

#[derive(Serialize)]
struct SignedManifest<'a> {
    format: &'a str,
    format_version: u32,
    component: &'a str,
    version: &'a str,
    channel: &'a str,
    platform: &'a str,
    minimum_netqmon_version: &'a str,
    ipc_protocol_version: u32,
    sha256: &'a str,
    size_bytes: u64,
}

/// Serializes the canonical signed portion of a component manifest.
///
/// # Errors
/// Returns an error if canonical JSON serialization fails.
pub fn signing_payload(manifest: &ComponentManifest) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&SignedManifest {
        format: &manifest.format,
        format_version: manifest.format_version,
        component: &manifest.component,
        version: &manifest.version,
        channel: &manifest.channel,
        platform: &manifest.platform,
        minimum_netqmon_version: &manifest.minimum_netqmon_version,
        ipc_protocol_version: manifest.ipc_protocol_version,
        sha256: &manifest.sha256,
        size_bytes: manifest.size_bytes,
    })
    .map_err(|error| error.to_string())
}

/// Validates compatibility and the pinned Ed25519 signature.
///
/// # Errors
/// Returns an error for an incompatible, malformed, or untrusted manifest.
pub fn verify_manifest(
    manifest: &ComponentManifest,
    current_netqmon: &Version,
    trusted_key_id: &str,
    trusted_key_version: u32,
    trusted_public_key_hex: &str,
) -> Result<(), String> {
    if manifest.format != "netqmon-component" || manifest.format_version != 1 {
        return Err("unsupported component manifest format".into());
    }
    if manifest.component != COMPONENT || manifest.platform != current_platform()? {
        return Err("component manifest target does not match this manager".into());
    }
    if manifest.ipc_protocol_version != IPC_PROTOCOL_VERSION {
        return Err("classifier IPC protocol is incompatible".into());
    }
    if manifest.size_bytes == 0 || manifest.size_bytes > MAX_BINARY_BYTES {
        return Err("classifier component size is outside the accepted range".into());
    }
    let minimum = Version::parse(&manifest.minimum_netqmon_version)
        .map_err(|error| format!("invalid minimum NetQMon version: {error}"))?;
    Version::parse(&manifest.version)
        .map_err(|error| format!("invalid classifier version: {error}"))?;
    if current_netqmon < &minimum {
        return Err(format!("classifier requires NetQMon >= {minimum}"));
    }
    if manifest.signature.algorithm != "ed25519"
        || manifest.signature.key_id != trusted_key_id
        || manifest.signature.key_version != trusted_key_version
    {
        return Err("component manifest is not signed by a trusted key".into());
    }
    let bytes = hex::decode(trusted_public_key_hex)
        .map_err(|error| format!("invalid trusted public key: {error}"))?;
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "trusted Ed25519 public key must contain 32 bytes".to_owned())?;
    let key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|error| format!("invalid trusted public key: {error}"))?;
    let signature_bytes = BASE64
        .decode(&manifest.signature.value)
        .map_err(|error| format!("invalid component signature encoding: {error}"))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|error| format!("invalid component signature: {error}"))?;
    key.verify(&signing_payload(manifest)?, &signature)
        .map_err(|error| format!("component manifest signature verification failed: {error}"))
}

/// Validates downloaded bytes against the signed size and digest.
///
/// # Errors
/// Returns an error when the size or SHA-256 digest differs.
pub fn verify_binary(manifest: &ComponentManifest, bytes: &[u8]) -> Result<(), String> {
    if u64::try_from(bytes.len()).ok() != Some(manifest.size_bytes) {
        return Err("downloaded classifier size does not match manifest".into());
    }
    let actual = hex::encode(Sha256::digest(bytes));
    if actual != manifest.sha256 {
        return Err("downloaded classifier SHA-256 does not match manifest".into());
    }
    Ok(())
}

/// Atomically installs verified component bytes into the release directory.
///
/// # Errors
/// Returns an error if verification or filesystem installation fails.
pub fn install_binary(
    root: &Path,
    manifest: &ComponentManifest,
    bytes: &[u8],
) -> Result<PathBuf, String> {
    verify_binary(manifest, bytes)?;
    let version = Version::parse(&manifest.version).map_err(|error| error.to_string())?;
    let releases = root.join("releases");
    let staging = root.join("staging");
    fs::create_dir_all(&releases).map_err(display)?;
    fs::create_dir_all(&staging).map_err(display)?;
    fs::set_permissions(root, fs::Permissions::from_mode(0o700)).map_err(display)?;
    let target_dir = releases.join(version.to_string());
    let target = target_dir.join("netqmon-classifierd");
    if target_dir.exists() {
        let existing = fs::read(&target).map_err(display)?;
        verify_binary(manifest, &existing)?;
        let installed: ComponentManifest = serde_json::from_slice(
            &fs::read(target_dir.join(INSTALLED_MANIFEST)).map_err(display)?,
        )
        .map_err(display)?;
        if signing_payload(&installed)? != signing_payload(manifest)?
            || installed.signature.value != manifest.signature.value
        {
            return Err("installed release manifest differs from downloaded manifest".into());
        }
        return Ok(target);
    }
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(display)?
        .as_nanos();
    let temporary_dir = staging.join(format!("{}-{}-{nonce}", version, std::process::id()));
    fs::create_dir(&temporary_dir).map_err(display)?;
    let temporary = temporary_dir.join("netqmon-classifierd");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o700)
        .open(&temporary)
        .map_err(display)?;
    file.write_all(bytes).map_err(display)?;
    file.sync_all().map_err(display)?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o755)).map_err(display)?;
    let manifest_path = temporary_dir.join(INSTALLED_MANIFEST);
    let mut manifest_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&manifest_path)
        .map_err(display)?;
    manifest_file
        .write_all(&serde_json::to_vec(manifest).map_err(display)?)
        .map_err(display)?;
    manifest_file.sync_all().map_err(display)?;
    File::open(&temporary_dir)
        .and_then(|file| file.sync_all())
        .map_err(display)?;
    fs::rename(&temporary_dir, &target_dir).map_err(display)?;
    File::open(&releases)
        .and_then(|file| file.sync_all())
        .map_err(display)?;
    Ok(target)
}

/// Loads and verifies an installed release before it is executed.
///
/// # Errors
/// Returns an error if the metadata, trust signature, compatibility, size, or digest is invalid.
pub fn verify_installed_binary(
    binary: &Path,
    current_netqmon: &Version,
    trusted_key_id: &str,
    trusted_key_version: u32,
    trusted_public_key_hex: &str,
) -> Result<ComponentManifest, String> {
    let release = binary
        .parent()
        .ok_or_else(|| "installed classifier has no release directory".to_owned())?;
    let manifest: ComponentManifest =
        serde_json::from_slice(&fs::read(release.join(INSTALLED_MANIFEST)).map_err(display)?)
            .map_err(display)?;
    verify_manifest(
        &manifest,
        current_netqmon,
        trusted_key_id,
        trusted_key_version,
        trusted_public_key_hex,
    )?;
    let metadata = fs::metadata(binary).map_err(display)?;
    if metadata.len() != manifest.size_bytes || metadata.len() > MAX_BINARY_BYTES {
        return Err("installed classifier size does not match manifest".into());
    }
    verify_binary(&manifest, &fs::read(binary).map_err(display)?)?;
    Ok(manifest)
}

/// Atomically promotes a binary while retaining the prior target for rollback.
///
/// # Errors
/// Returns an error if either symlink cannot be replaced safely.
pub fn switch_current(root: &Path, binary: &Path) -> Result<(), String> {
    let current = root.join("current");
    let previous = root.join("previous");
    if let Ok(existing) = fs::read_link(&current) {
        replace_symlink(&previous, &existing)?;
    }
    replace_symlink(&current, binary)
}

#[must_use]
pub fn current_binary(root: &Path) -> Option<PathBuf> {
    let target = fs::read_link(root.join("current")).ok()?;
    target.is_file().then_some(target)
}

#[must_use]
pub fn previous_binary(root: &Path) -> Option<PathBuf> {
    let target = fs::read_link(root.join("previous")).ok()?;
    target.is_file().then_some(target)
}

/// Removes obsolete managed releases, preserving only current and previous.
///
/// Directories whose names are not semantic versions are left untouched.
///
/// # Errors
/// Returns an error if a stale managed release cannot be removed.
pub fn prune_releases(root: &Path) -> Result<(), String> {
    let releases = root.join("releases");
    let current = current_binary(root).and_then(|path| path.parent().map(Path::to_path_buf));
    let previous = previous_binary(root).and_then(|path| path.parent().map(Path::to_path_buf));
    let entries = match fs::read_dir(&releases) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.to_string()),
    };
    for entry in entries {
        let entry = entry.map_err(display)?;
        let path = entry.path();
        if !entry.file_type().map_err(display)?.is_dir()
            || current.as_ref() == Some(&path)
            || previous.as_ref() == Some(&path)
        {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if Version::parse(&name).is_ok() {
            fs::remove_dir_all(path).map_err(display)?;
        }
    }
    Ok(())
}

/// Reads a component body without permitting unbounded allocation.
///
/// # Errors
/// Returns an error for invalid declared sizes, oversized bodies, or I/O failures.
pub fn read_bounded(mut response: impl Read, expected: u64) -> Result<Vec<u8>, String> {
    if expected == 0 || expected > MAX_BINARY_BYTES {
        return Err("component download size is outside the accepted range".into());
    }
    let mut bytes = Vec::with_capacity(usize::try_from(expected).map_err(display)?);
    response
        .by_ref()
        .take(MAX_BINARY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(display)?;
    if u64::try_from(bytes.len()).map_err(display)? > MAX_BINARY_BYTES {
        return Err("component download exceeded maximum size".into());
    }
    Ok(bytes)
}

fn replace_symlink(path: &Path, target: &Path) -> Result<(), String> {
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    match fs::remove_file(&temporary) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.to_string()),
    }
    symlink(target, &temporary).map_err(display)?;
    fs::rename(temporary, path).map_err(display)
}

fn display(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn manifest(bytes: &[u8]) -> ComponentManifest {
        let mut value = ComponentManifest {
            format: "netqmon-component".into(),
            format_version: 1,
            component: COMPONENT.into(),
            version: "1.2.3".into(),
            channel: "stable".into(),
            platform: PLATFORM.into(),
            minimum_netqmon_version: "0.1.0".into(),
            ipc_protocol_version: IPC_PROTOCOL_VERSION,
            sha256: hex::encode(Sha256::digest(bytes)),
            size_bytes: bytes.len() as u64,
            download_url: "/download".into(),
            signature: ManifestSignature {
                algorithm: "ed25519".into(),
                key_id: TEST_KEY_ID.into(),
                key_version: 1,
                value: String::new(),
            },
        };
        // RFC 8032 test key. It is intentionally public test material.
        let seed: [u8; 32] =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap()
                .try_into()
                .unwrap();
        value.signature.value = BASE64.encode(
            SigningKey::from_bytes(&seed)
                .sign(&signing_payload(&value).unwrap())
                .to_bytes(),
        );
        value
    }

    #[test]
    fn verifies_signed_manifest_and_binary() {
        let bytes = b"classifier";
        let mut value = manifest(bytes);
        verify_manifest(
            &value,
            &Version::new(0, 1, 0),
            TEST_KEY_ID,
            1,
            TEST_PUBLIC_KEY_HEX,
        )
        .unwrap();
        verify_binary(&value, bytes).unwrap();
        value.sha256 = "00".repeat(32);
        assert!(verify_binary(&value, bytes).is_err());
    }

    #[test]
    fn detects_same_version_binary_replacement_by_checksum() {
        let installed = manifest(b"old-binary");
        let same_content = manifest(b"old-binary");
        let corrected_content = manifest(b"corrected-binary");

        assert!(same_release_content(&installed, &same_content));
        assert!(!same_release_content(&installed, &corrected_content));
    }

    #[test]
    fn maps_common_architecture_aliases_to_component_platforms() {
        assert_eq!(platform_for_arch("amd64"), Some(AMD64_PLATFORM));
        assert_eq!(platform_for_arch("x86_64"), Some(AMD64_PLATFORM));
        assert_eq!(platform_for_arch("arm64"), Some(ARM64_PLATFORM));
        assert_eq!(platform_for_arch("aarch64"), Some(ARM64_PLATFORM));
        assert_eq!(platform_for_arch("armv7"), None);
    }

    #[test]
    fn rejects_tampering() {
        let mut value = manifest(b"classifier");
        value.version = "1.2.4".into();
        assert!(
            verify_manifest(
                &value,
                &Version::new(0, 1, 0),
                TEST_KEY_ID,
                1,
                TEST_PUBLIC_KEY_HEX
            )
            .is_err()
        );
        assert!(verify_binary(&manifest(b"classifier"), b"tampered").is_err());
    }

    #[test]
    fn installs_and_switches_atomically() {
        let root = tempfile::tempdir().unwrap();
        let value = manifest(b"first");
        let first = install_binary(root.path(), &value, b"first").unwrap();
        switch_current(root.path(), &first).unwrap();
        assert_eq!(current_binary(root.path()), Some(first.clone()));
        verify_installed_binary(
            &first,
            &Version::new(0, 1, 0),
            TEST_KEY_ID,
            1,
            TEST_PUBLIC_KEY_HEX,
        )
        .unwrap();
    }

    #[test]
    fn rejects_tampered_installed_binary_and_prunes_stale_releases() {
        let root = tempfile::tempdir().unwrap();
        let first_manifest = manifest(b"first");
        let first = install_binary(root.path(), &first_manifest, b"first").unwrap();
        switch_current(root.path(), &first).unwrap();

        let mut second_manifest = manifest(b"second");
        second_manifest.version = "1.2.4".into();
        let seed: [u8; 32] =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap()
                .try_into()
                .unwrap();
        second_manifest.signature.value = BASE64.encode(
            SigningKey::from_bytes(&seed)
                .sign(&signing_payload(&second_manifest).unwrap())
                .to_bytes(),
        );
        let second = install_binary(root.path(), &second_manifest, b"second").unwrap();
        switch_current(root.path(), &second).unwrap();

        let stale = root.path().join("releases/1.2.2");
        fs::create_dir_all(&stale).unwrap();
        let unmanaged = root.path().join("releases/notes");
        fs::create_dir_all(&unmanaged).unwrap();
        prune_releases(root.path()).unwrap();
        assert!(!stale.exists());
        assert!(unmanaged.exists());
        assert!(first.exists());
        assert!(second.exists());

        fs::write(&second, b"tampered").unwrap();
        assert!(
            verify_installed_binary(
                &second,
                &Version::new(0, 1, 0),
                TEST_KEY_ID,
                1,
                TEST_PUBLIC_KEY_HEX,
            )
            .is_err()
        );
    }

    #[test]
    fn empty_root_initial_install_and_promotion() {
        let root = tempfile::tempdir().unwrap();
        assert_eq!(current_binary(root.path()), None);
        assert_eq!(previous_binary(root.path()), None);

        let manifest = manifest(b"v1-bytes");
        let installed = install_binary(root.path(), &manifest, b"v1-bytes").unwrap();
        assert!(installed.exists());
        assert_eq!(current_binary(root.path()), None);

        switch_current(root.path(), &installed).unwrap();
        assert_eq!(current_binary(root.path()), Some(installed.clone()));
        assert_eq!(previous_binary(root.path()), None);

        let verified = verify_installed_binary(
            &installed,
            &Version::new(0, 1, 0),
            TEST_KEY_ID,
            1,
            TEST_PUBLIC_KEY_HEX,
        )
        .unwrap();
        assert_eq!(verified.version, "1.2.3");
    }

    #[test]
    fn upgrade_and_rollback_flow() {
        let root = tempfile::tempdir().unwrap();
        let m1 = manifest(b"v1");
        let bin1 = install_binary(root.path(), &m1, b"v1").unwrap();
        switch_current(root.path(), &bin1).unwrap();
        assert_eq!(current_binary(root.path()), Some(bin1.clone()));

        // Upgrade to v2
        let mut m2 = manifest(b"v2");
        m2.version = "1.2.4".into();
        let seed: [u8; 32] =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap()
                .try_into()
                .unwrap();
        m2.signature.value = BASE64.encode(
            SigningKey::from_bytes(&seed)
                .sign(&signing_payload(&m2).unwrap())
                .to_bytes(),
        );
        let bin2 = install_binary(root.path(), &m2, b"v2").unwrap();
        switch_current(root.path(), &bin2).unwrap();

        assert_eq!(current_binary(root.path()), Some(bin2.clone()));
        assert_eq!(previous_binary(root.path()), Some(bin1.clone()));

        // Rollback: switch back to previous
        let prev = previous_binary(root.path()).unwrap();
        switch_current(root.path(), &prev).unwrap();
        assert_eq!(current_binary(root.path()), Some(bin1.clone()));
        assert_eq!(previous_binary(root.path()), Some(bin2.clone()));
    }

    #[test]
    fn rejects_invalid_manifest_scenarios() {
        let mut bad_ipc = manifest(b"content");
        bad_ipc.ipc_protocol_version = 999;
        assert!(
            verify_manifest(
                &bad_ipc,
                &Version::new(0, 1, 0),
                TEST_KEY_ID,
                1,
                TEST_PUBLIC_KEY_HEX
            )
            .is_err()
        );

        let mut oversized = manifest(b"content");
        oversized.size_bytes = MAX_BINARY_BYTES + 1;
        assert!(
            verify_manifest(
                &oversized,
                &Version::new(0, 1, 0),
                TEST_KEY_ID,
                1,
                TEST_PUBLIC_KEY_HEX
            )
            .is_err()
        );

        let mut wrong_key = manifest(b"content");
        assert!(
            verify_manifest(
                &wrong_key,
                &Version::new(0, 1, 0),
                "untrusted-key",
                1,
                TEST_PUBLIC_KEY_HEX
            )
            .is_err()
        );

        wrong_key.signature.key_version = 2;
        assert!(
            verify_manifest(
                &wrong_key,
                &Version::new(0, 1, 0),
                TEST_KEY_ID,
                1,
                TEST_PUBLIC_KEY_HEX
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_legacy_installation_without_manifest() {
        let root = tempfile::tempdir().unwrap();
        let legacy_dir = root.path().join("releases/1.0.0");
        fs::create_dir_all(&legacy_dir).unwrap();
        let legacy_bin = legacy_dir.join("netqmon-classifierd");
        fs::write(&legacy_bin, b"legacy-binary").unwrap();

        let err = verify_installed_binary(
            &legacy_bin,
            &Version::new(0, 1, 0),
            TEST_KEY_ID,
            1,
            TEST_PUBLIC_KEY_HEX,
        );
        assert!(
            err.is_err(),
            "legacy release without manifest must be rejected"
        );
    }
}
