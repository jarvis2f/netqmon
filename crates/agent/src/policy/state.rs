use std::fs::{self, OpenOptions};
use std::io::{Read as _, Write as _};
use std::net::IpAddr;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use netqmon_protocol::policy::PolicyWireFrame;
use serde::{Deserialize, Serialize};

use super::mark::MarkRule;
use super::shaper::ShapingState;

const MAX_POLICY_STATE_BYTES: usize = 2 * 1024 * 1024;
const MAX_BLOCKED_ADDRESSES_PER_FAMILY: usize = 16_384;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PolicyState {
    pub schema_version: u32,
    pub gateway_id: String,
    pub controller_epoch: String,
    pub config_revision: u64,
    pub bundle_generation: u64,
    pub checksum: String,
    #[serde(default)]
    pub topology_fingerprint: String,
    pub snapshot: PolicyWireFrame,
    pub blocked_clients_v4: Vec<IpAddr>,
    pub blocked_clients_v6: Vec<IpAddr>,
    #[serde(default)]
    pub shaping_state: Option<ShapingState>,
    #[serde(default)]
    pub shaping_marks: Vec<MarkRule>,
}

impl PolicyState {
    pub(crate) fn from_snapshot(
        snapshot: PolicyWireFrame,
        topology_fingerprint: String,
        blocked_clients_v4: Vec<IpAddr>,
        blocked_clients_v6: Vec<IpAddr>,
        shaping_state: Option<ShapingState>,
        shaping_marks: Vec<MarkRule>,
    ) -> Result<Self, String> {
        snapshot.validate()?;
        let Some((gateway_id, controller_epoch, config_revision, bundle_generation, checksum)) =
            snapshot.snapshot_identity()
        else {
            return Err("expected a complete policy snapshot".to_owned());
        };
        Ok(Self {
            schema_version: 1,
            gateway_id: gateway_id.to_owned(),
            controller_epoch: controller_epoch.to_owned(),
            config_revision,
            bundle_generation,
            checksum: checksum.to_owned(),
            topology_fingerprint,
            snapshot,
            blocked_clients_v4,
            blocked_clients_v6,
            shaping_state,
            shaping_marks,
        })
    }

    pub(crate) fn validate(&self, expected_gateway: &str) -> Result<(), String> {
        if self.schema_version != 1 {
            return Err("unsupported local policy state schema".to_owned());
        }
        if !self.topology_fingerprint.is_empty()
            && (self.topology_fingerprint.len() != 64
                || !self
                    .topology_fingerprint
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()))
        {
            return Err("local policy state has an invalid topology fingerprint".to_owned());
        }
        if self.gateway_id != expected_gateway {
            return Err("local policy state belongs to a different gateway".to_owned());
        }
        self.snapshot.validate()?;
        let Some((gateway, epoch, revision, generation, checksum)) =
            self.snapshot.snapshot_identity()
        else {
            return Err("local policy state does not contain a snapshot".to_owned());
        };
        if gateway != self.gateway_id
            || epoch != self.controller_epoch
            || revision != self.config_revision
            || generation != self.bundle_generation
            || checksum != self.checksum
        {
            return Err("local policy state identity does not match its snapshot".to_owned());
        }
        if self
            .blocked_clients_v4
            .iter()
            .any(|address| !address.is_ipv4())
            || self
                .blocked_clients_v6
                .iter()
                .any(|address| !address.is_ipv6())
        {
            return Err("local policy state contains an invalid address family".to_owned());
        }
        if self.blocked_clients_v4.len() > MAX_BLOCKED_ADDRESSES_PER_FAMILY
            || self.blocked_clients_v6.len() > MAX_BLOCKED_ADDRESSES_PER_FAMILY
        {
            return Err("local policy state exceeds the blocked-address limit".to_owned());
        }
        if let Some(shaping) = &self.shaping_state {
            shaping.validate()?;
        }
        if self.shaping_marks.len() > 512 {
            return Err("local policy state has too many traffic-shaping marks".to_owned());
        }
        Ok(())
    }
}

pub(crate) fn load(path: &Path, expected_gateway: &str) -> Result<Option<PolicyState>, String> {
    let state = load_any(path)?;
    if let Some(state) = &state {
        state.validate(expected_gateway)?;
    }
    Ok(state)
}

pub(crate) fn load_any(path: &Path) -> Result<Option<PolicyState>, String> {
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("read local policy state: {error}")),
    };
    let mut contents = Vec::new();
    file.take((MAX_POLICY_STATE_BYTES + 1) as u64)
        .read_to_end(&mut contents)
        .map_err(|error| format!("read local policy state: {error}"))?;
    if contents.len() > MAX_POLICY_STATE_BYTES {
        return Err("local policy state exceeds the size limit".to_owned());
    }
    let value: PolicyState = serde_json::from_slice(&contents)
        .map_err(|error| format!("decode local policy state: {error}"))?;
    value.validate(&value.gateway_id)?;
    Ok(Some(value))
}

pub(crate) fn persist(path: &Path, value: &PolicyState) -> Result<(), String> {
    value
        .validate(&value.gateway_id)
        .map_err(|error| format!("refuse to persist invalid policy state: {error}"))?;
    let identity = value
        .snapshot
        .snapshot_identity()
        .ok_or_else(|| "refuse to persist a non-snapshot frame".to_owned())?;
    if identity.0 != value.gateway_id
        || identity.1 != value.controller_epoch
        || identity.2 != value.config_revision
        || identity.3 != value.bundle_generation
        || identity.4 != value.checksum
    {
        return Err("refuse to persist mismatched snapshot identity".to_owned());
    }
    let bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    if bytes.len() > MAX_POLICY_STATE_BYTES {
        return Err("refuse to persist policy state above the size limit".to_owned());
    }
    atomic_write(path, &bytes)
}

pub(crate) fn write_disabled_marker(path: &Path) -> Result<(), String> {
    atomic_write(path, b"netqmon emergency policy disable\n")
}

pub(crate) fn remove_disabled_marker(path: &Path) -> Result<(), String> {
    match fs::remove_file(path) {
        Ok(()) => sync_parent(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("remove emergency policy marker: {error}")),
    }
}

pub(crate) fn quarantine_gateway_mismatch(path: &Path) -> Result<(), String> {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis());
    let target = path.with_extension(format!("gateway-mismatch-{suffix}"));
    fs::rename(path, &target)
        .map_err(|error| format!("quarantine policy state for a different gateway: {error}"))?;
    sync_parent(path)
}

fn atomic_write(path: &Path, contents: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "policy state path has no parent directory".to_owned())?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("create policy state directory: {error}"))?;
    let temporary = path.with_extension(format!("tmp.{}", std::process::id()));
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|error| format!("create temporary policy state: {error}"))?;
    file.write_all(contents)
        .map_err(|error| format!("write temporary policy state: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("sync temporary policy state: {error}"))?;
    fs::rename(&temporary, path).map_err(|error| format!("install policy state: {error}"))?;
    sync_parent(path)
}

fn sync_parent(path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "policy state path has no parent directory".to_owned())?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("sync policy state directory: {error}"))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use netqmon_protocol::policy::PolicyWireFrame;
    use tempfile::tempdir;

    use super::*;

    fn snapshot() -> PolicyWireFrame {
        PolicyWireFrame::snapshot(
            "gw-state".to_owned(),
            "00000000-0000-4000-8000-000000000001".to_owned(),
            4,
            2,
            1_800_000_000_000,
            1_802_592_000_000,
            Vec::new(),
            Vec::new(),
        )
        .unwrap()
    }

    #[test]
    fn state_round_trips_and_rejects_gateway_or_checksum_mismatch() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("policy-state.json");
        let state = PolicyState::from_snapshot(
            snapshot(),
            String::new(),
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20))],
            Vec::new(),
            None,
            Vec::new(),
        )
        .unwrap();
        persist(&path, &state).unwrap();
        assert_eq!(load(&path, "gw-state").unwrap(), Some(state.clone()));
        assert!(load(&path, "another-gateway").is_err());

        let mut corrupt = state;
        corrupt.checksum.push('0');
        assert!(corrupt.validate("gw-state").is_err());
    }

    #[test]
    fn oversized_policy_state_file_is_rejected_before_deserialization() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("policy-state.json");
        fs::write(&path, vec![b' '; MAX_POLICY_STATE_BYTES + 1]).unwrap();
        assert!(load_any(&path).unwrap_err().contains("size limit"));
    }

    #[cfg(unix)]
    #[test]
    fn state_file_is_private_and_atomic_marker_can_be_removed() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempdir().unwrap();
        let state_path = directory.path().join("policy-state.json");
        let marker_path = directory.path().join("policies-disabled");
        let state = PolicyState::from_snapshot(
            snapshot(),
            String::new(),
            Vec::new(),
            Vec::new(),
            None,
            Vec::new(),
        )
        .unwrap();
        persist(&state_path, &state).unwrap();
        assert_eq!(
            fs::metadata(&state_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        write_disabled_marker(&marker_path).unwrap();
        assert!(marker_path.exists());
        remove_disabled_marker(&marker_path).unwrap();
        assert!(!marker_path.exists());
    }
}
