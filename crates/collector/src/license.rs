use std::{
    env,
    fmt::Write as _,
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use chrono::{DateTime, Utc};
use netqmon_classifier_client::{
    AllowedRule, ClassifierEntitlement, ClassifierIdentity, EntitlementLease,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::classifier::ClassifierHandle;

const DEFAULT_CLOUD_API_URL: &str = "https://netqmon.com";
const DEFAULT_IDENTITY_PATH: &str = "/data/license.json";
const CHECK_INTERVAL: Duration = Duration::from_secs(15 * 60);
const OFFLINE_GRACE_SECONDS: i64 = 24 * 60 * 60;

#[derive(Clone, Debug, Serialize)]
#[allow(clippy::struct_field_names)]
pub(crate) struct LicenseStatus {
    pub installation_id: Uuid,
    pub activated: bool,
    pub edition: String,
    pub license_status: String,
    pub rule_version: Option<String>,
    pub lease_valid_until: Option<i64>,
    pub last_success_at: Option<i64>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PersistedIdentity {
    installation_id: Uuid,
    installation_credential: Option<String>,
    last_success_at: Option<i64>,
    edition: String,
    license_status: String,
    lease_valid_until: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct ActivateResponse {
    installation_id: Uuid,
    installation_credential: String,
}

#[derive(Clone, Debug, Deserialize)]
struct CloudAllowedRule {
    artifact_id: Uuid,
    rule_version: String,
}

#[derive(Clone, Debug, Deserialize)]
struct CheckResponse {
    edition: String,
    license_status: String,
    lease_valid_until: DateTime<Utc>,
    #[allow(dead_code)]
    check_after_seconds: i64,
    allowed_rule: Option<CloudAllowedRule>,
    #[serde(default)]
    sealed_rule_key: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CloudErrorEnvelope {
    error: CloudErrorBody,
}

#[derive(Debug, Deserialize)]
struct CloudErrorBody {
    code: String,
    message: String,
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    details: Option<serde_json::Value>,
}

#[derive(Serialize)]
struct VersionReport<'a> {
    netqmon_version: &'a str,
    classifier_version: &'a str,
    current_rule_version: Option<&'a str>,
    current_edition: &'a str,
    capabilities: &'a [&'a str],
    #[serde(skip_serializing_if = "Option::is_none")]
    classifier_public_key: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    classifier_key_id: Option<&'a str>,
}

#[derive(Serialize)]
struct ActivateRequest<'a> {
    license_key: &'a str,
    installation_id: Uuid,
    netqmon_version: &'a str,
    classifier_version: &'a str,
    current_rule_version: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    classifier_public_key: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    classifier_key_id: Option<&'a str>,
}

pub(crate) struct LicenseCoordinator {
    client: reqwest::Client,
    cloud_api_url: String,
    identity_path: PathBuf,
    classifier: ClassifierHandle,
    identity: Mutex<Option<PersistedIdentity>>,
    last_error: Mutex<Option<String>>,
    operation: tokio::sync::Mutex<()>,
}

impl LicenseCoordinator {
    pub(crate) fn from_env(classifier: ClassifierHandle) -> Self {
        let identity_path = env::var_os("NETQMON_LICENSE_STATE_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                if cfg!(test) {
                    std::env::temp_dir()
                        .join(format!("netqmon-test-license-{}.json", Uuid::new_v4()))
                } else {
                    let default_path = PathBuf::from(DEFAULT_IDENTITY_PATH);
                    if default_path.exists() {
                        default_path
                    } else if let Some(parent) = default_path.parent() {
                        if parent.exists() || fs::create_dir_all(parent).is_ok() {
                            default_path
                        } else {
                            std::env::temp_dir().join("netqmon-license.json")
                        }
                    } else {
                        default_path
                    }
                }
            });
        Self::new(
            classifier,
            env::var("NETQMON_CLOUD_API_URL")
                .unwrap_or_else(|_| DEFAULT_CLOUD_API_URL.into())
                .trim_end_matches('/')
                .to_owned(),
            identity_path,
        )
    }

    fn new(classifier: ClassifierHandle, cloud_api_url: String, identity_path: PathBuf) -> Self {
        Self {
            client: reqwest::Client::new(),
            cloud_api_url,
            identity_path,
            classifier,
            identity: Mutex::new(None),
            last_error: Mutex::new(None),
            operation: tokio::sync::Mutex::new(()),
        }
    }

    pub(crate) fn ensure_identity(&self) -> Result<(), String> {
        if self
            .identity
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
        {
            return Ok(());
        }
        let identity = if self.identity_path.exists() {
            fs::set_permissions(&self.identity_path, fs::Permissions::from_mode(0o600))
                .map_err(display)?;
            serde_json::from_slice(&fs::read(&self.identity_path).map_err(display)?)
                .map_err(display)?
        } else {
            let identity = PersistedIdentity {
                installation_id: Uuid::new_v4(),
                installation_credential: None,
                last_success_at: None,
                edition: "community".into(),
                license_status: "unlicensed".into(),
                lease_valid_until: None,
            };
            self.persist(&identity)?;
            identity
        };
        *self.identity.lock().unwrap_or_else(PoisonError::into_inner) = Some(identity);
        Ok(())
    }

    pub(crate) fn status(&self) -> Result<LicenseStatus, String> {
        self.ensure_identity()?;
        let identity = self.identity.lock().unwrap_or_else(PoisonError::into_inner);
        let identity = identity.as_ref().expect("identity initialized");
        let classifier = self.classifier.entitlement_status().ok();
        Ok(LicenseStatus {
            installation_id: identity.installation_id,
            activated: identity.installation_credential.is_some(),
            edition: classifier
                .as_ref()
                .map_or_else(|| identity.edition.clone(), |v| v.edition.clone()),
            license_status: classifier.as_ref().map_or_else(
                || identity.license_status.clone(),
                |v| v.license_status.clone(),
            ),
            rule_version: classifier.and_then(|value| value.rule_version),
            lease_valid_until: identity.lease_valid_until,
            last_success_at: identity.last_success_at,
            last_error: self
                .last_error
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone(),
        })
    }

    fn classifier_identity(&self) -> Option<ClassifierIdentity> {
        self.classifier.identity().ok().filter(|id| {
            !id.public_key.trim().is_empty()
                && id.key_id != "unknown"
                && !id.key_id.trim().is_empty()
        })
    }

    pub(crate) async fn activate(&self, license_key: &str) -> Result<LicenseStatus, String> {
        let _operation = self.operation.lock().await;
        self.ensure_identity()?;
        let snapshot = self.snapshot()?;
        let classifier_version = self.classifier.classifier_version()?;
        let rule_version = self.classifier.rule_version().ok();
        let classifier_identity = self.classifier_identity();
        let response = self
            .client
            .post(format!("{}/api/v1/licenses/activate", self.cloud_api_url))
            .json(&ActivateRequest {
                license_key,
                installation_id: snapshot.installation_id,
                netqmon_version: env!("CARGO_PKG_VERSION"),
                classifier_version: &classifier_version,
                current_rule_version: rule_version.as_deref(),
                classifier_public_key: classifier_identity
                    .as_ref()
                    .map(|id| id.public_key.as_str()),
                classifier_key_id: classifier_identity.as_ref().map(|id| id.key_id.as_str()),
            })
            .send()
            .await
            .map_err(display)?;
        if !response.status().is_success() {
            return self.fail(cloud_response_message(response, "activation").await);
        }
        let activated: ActivateResponse = response.json().await.map_err(display)?;
        if activated.installation_id != snapshot.installation_id {
            return Err("Cloud returned a different installation id".into());
        }
        if activated.installation_credential.is_empty() {
            return Err("Cloud returned an empty installation credential".into());
        }
        let mut identity = snapshot;
        identity.installation_credential = Some(activated.installation_credential);
        self.save_identity(identity)?;
        self.check_inner().await
    }

    pub(crate) async fn check(&self) -> Result<LicenseStatus, String> {
        let _operation = self.operation.lock().await;
        self.check_inner().await
    }

    #[allow(clippy::too_many_lines)]
    async fn check_inner(&self) -> Result<LicenseStatus, String> {
        self.ensure_identity()?;
        let snapshot = self.snapshot()?;
        let credential = snapshot
            .installation_credential
            .clone()
            .ok_or_else(|| "No license has been activated".to_owned())?;
        let classifier_version = self.classifier.classifier_version()?;
        let rule_version = self.classifier.rule_version().ok();
        let classifier_identity = self.classifier_identity();
        let current = self
            .classifier
            .entitlement_status()
            .unwrap_or(ClassifierEntitlement {
                edition: snapshot.edition.clone(),
                license_status: snapshot.license_status.clone(),
                lease_valid_until: snapshot.lease_valid_until,
                rule_version: rule_version.clone(),
            });
        let report = VersionReport {
            netqmon_version: env!("CARGO_PKG_VERSION"),
            classifier_version: &classifier_version,
            current_rule_version: rule_version.as_deref(),
            current_edition: &current.edition,
            capabilities: &[
                "rule_bundle_v1",
                "rule_ir_v1",
                "rule_ir_v2",
                "domain",
                "cidr",
                "classifier_domains_v1",
                "classifier_cidrs_v1",
                "classifier_protocol_evidence_v1",
                "classifier_favicon_sha256_v1",
                "device_fingerprints_v1",
                "auxiliary_datasets_v1",
            ],
            classifier_public_key: classifier_identity
                .as_ref()
                .map(|id| id.public_key.as_str()),
            classifier_key_id: classifier_identity.as_ref().map(|id| id.key_id.as_str()),
        };
        let result = self
            .client
            .post(format!("{}/api/v1/installations/check", self.cloud_api_url))
            .bearer_auth(&credential)
            .json(&report)
            .send()
            .await;
        let response = match result {
            Ok(response) if response.status().is_success() => {
                response.json::<CheckResponse>().await.map_err(display)?
            }
            Ok(response)
                if response.status().as_u16() == 401 || response.status().as_u16() == 403 =>
            {
                let status = response.status();
                let message = cloud_response_message(response, "device check").await;
                self.apply_community(cloud_local_status(status, &message))?;
                return self.fail(format!(
                    "Cloud rejected device credential ({status}): {message}"
                ));
            }
            Ok(response) => {
                let message = cloud_response_message(response, "device check").await;
                return self.transport_failure(message, &snapshot);
            }
            Err(error) => return self.transport_failure(error.to_string(), &snapshot),
        };
        let no_compatible_rule = response.edition == "pro" && response.allowed_rule.is_none();
        let lease = EntitlementLease {
            edition: response.edition.clone(),
            license_status: response.license_status.clone(),
            lease_valid_until: response.lease_valid_until.timestamp(),
            allowed_rule: response.allowed_rule.map(|rule| AllowedRule {
                artifact_id: rule.artifact_id.to_string(),
                rule_version: rule.rule_version,
                edition: response.edition.clone(),
            }),
            cloud_api_url: self.cloud_api_url.clone(),
            installation_credential: Some(credential),
            sealed_rule_key: response.sealed_rule_key,
        };
        self.classifier.apply_entitlement(lease)?;
        let mut identity = snapshot;
        identity.last_success_at = Some(now());
        identity.edition = response.edition;
        identity.license_status = response.license_status;
        identity.lease_valid_until = Some(response.lease_valid_until.timestamp());
        self.save_identity(identity)?;
        let rule_error = if no_compatible_rule {
            Some(
                "Pro license is active, but Cloud has no compatible Pro rule package for this installation."
                    .to_owned(),
            )
        } else {
            None
        };
        *self
            .last_error
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = rule_error;
        self.status()
    }

    fn transport_failure(
        &self,
        error: String,
        identity: &PersistedIdentity,
    ) -> Result<LicenseStatus, String> {
        if identity
            .last_success_at
            .is_none_or(|value| now() - value > OFFLINE_GRACE_SECONDS)
        {
            self.apply_community("offline_grace_expired")?;
        }
        self.fail(error)
    }

    fn fail(&self, error: String) -> Result<LicenseStatus, String> {
        *self
            .last_error
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(error.clone());
        Err(error)
    }

    fn apply_community(&self, status: &str) -> Result<(), String> {
        self.classifier
            .apply_entitlement(EntitlementLease {
                edition: "community".into(),
                license_status: status.into(),
                lease_valid_until: now(),
                allowed_rule: None,
                cloud_api_url: self.cloud_api_url.clone(),
                installation_credential: None,
                sealed_rule_key: None,
            })
            .map(|_| ())
    }

    fn snapshot(&self) -> Result<PersistedIdentity, String> {
        self.identity
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .ok_or_else(|| "license identity is not initialized".into())
    }

    fn save_identity(&self, identity: PersistedIdentity) -> Result<(), String> {
        self.persist(&identity)?;
        *self.identity.lock().unwrap_or_else(PoisonError::into_inner) = Some(identity);
        Ok(())
    }

    fn persist(&self, identity: &PersistedIdentity) -> Result<(), String> {
        let parent = self
            .identity_path
            .parent()
            .unwrap_or_else(|| Path::new("."));
        if let Err(err) = fs::create_dir_all(parent) {
            // If default path is not writable (e.g. non-root /var/lib/netqmon), fallback to temp dir
            if self.identity_path == Path::new(DEFAULT_IDENTITY_PATH) {
                let fallback = std::env::temp_dir().join("netqmon-license.json");
                tracing::warn!(
                    path = %self.identity_path.display(),
                    fallback = %fallback.display(),
                    error = %err,
                    "default license path not writable; falling back to temporary directory"
                );
                return Self::persist_to_path(&fallback, identity);
            }
            return Err(display(err));
        }
        Self::persist_to_path(&self.identity_path, identity)
    }

    fn persist_to_path(target_path: &Path, identity: &PersistedIdentity) -> Result<(), String> {
        let temporary = target_path.with_extension(format!("tmp-{}", Uuid::new_v4()));
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(display)?;
        file.write_all(&serde_json::to_vec(identity).map_err(display)?)
            .map_err(display)?;
        file.sync_all().map_err(display)?;
        fs::rename(&temporary, target_path).map_err(display)?;
        fs::set_permissions(target_path, fs::Permissions::from_mode(0o600)).map_err(display)
    }
}

pub(crate) fn spawn(coordinator: Arc<LicenseCoordinator>) {
    tokio::spawn(async move {
        let mut wait = CHECK_INTERVAL;
        let mut failure_delay = Duration::from_secs(15);
        loop {
            tokio::time::sleep(wait).await;
            if coordinator.status().is_ok_and(|status| !status.activated) {
                wait = CHECK_INTERVAL;
                continue;
            }
            match coordinator.check().await {
                Ok(_) => {
                    wait = CHECK_INTERVAL;
                    failure_delay = Duration::from_secs(15);
                }
                Err(error) => {
                    tracing::warn!(%error, "license check failed");
                    let jitter = Duration::from_secs(
                        u64::try_from(now().rem_euclid(7)).unwrap_or_default() + 1,
                    );
                    wait = failure_delay + jitter;
                    failure_delay = failure_delay.saturating_mul(2).min(CHECK_INTERVAL);
                }
            }
        }
    });
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|value| i64::try_from(value.as_secs()).ok())
        .unwrap_or(i64::MAX)
}

async fn cloud_response_message(response: reqwest::Response, operation: &str) -> String {
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if let Ok(envelope) = serde_json::from_str::<CloudErrorEnvelope>(&body) {
        let error = envelope.error;
        let mut message = format!(
            "Cloud {operation} failed (HTTP {status}, code={}): {}",
            error.code, error.message
        );
        if let Some(category) = error.category {
            let _ = write!(message, " [category={category}]");
        }
        if let Some(action) = error.action {
            let _ = write!(message, " Action: {action}.");
        }
        if let Some(details) = error.details {
            let details = serde_json::to_string(&details).unwrap_or_else(|_| "{}".to_owned());
            let _ = write!(message, " Details: {details}");
        }
        message
    } else {
        let body = body.trim();
        let body = truncate_body(body, 1024);
        if body.is_empty() {
            format!("Cloud {operation} failed (HTTP {status})")
        } else {
            format!("Cloud {operation} failed (HTTP {status}): {body}")
        }
    }
}

fn cloud_local_status(status: reqwest::StatusCode, message: &str) -> &'static str {
    let lower = message.to_ascii_lowercase();
    if lower.contains("license_expired") || lower.contains("license expired") {
        "expired"
    } else if lower.contains("license_revoked") || lower.contains("license revoked") {
        "revoked"
    } else if lower.contains("account_disabled") || lower.contains("account disabled") {
        "disabled"
    } else if status == reqwest::StatusCode::UNAUTHORIZED {
        "credential_invalid"
    } else {
        "access_denied"
    }
}

fn truncate_body(body: &str, max_len: usize) -> &str {
    if body.len() <= max_len {
        return body;
    }
    let end = body
        .char_indices()
        .find_map(|(index, character)| (index + character.len_utf8() > max_len).then_some(index))
        .unwrap_or(max_len);
    &body[..end]
}

fn display(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn installation_identity_is_stable_and_private() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("license.json");
        let coordinator = LicenseCoordinator::new(
            ClassifierHandle::test_default(),
            "http://127.0.0.1:1".into(),
            path.clone(),
        );
        coordinator.ensure_identity().unwrap();
        let first = coordinator.status().unwrap().installation_id;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let reloaded = LicenseCoordinator::new(
            ClassifierHandle::test_default(),
            "http://127.0.0.1:1".into(),
            path,
        );
        assert_eq!(reloaded.status().unwrap().installation_id, first);
    }

    #[tokio::test]
    async fn check_and_activate_report_classifier_identity_and_forward_sealed_rule_key() {
        use axum::{Json, Router, routing::post};

        let app = Router::new()
            .route(
                "/api/v1/licenses/activate",
                post(|Json(body): Json<serde_json::Value>| async move {
                    assert_eq!(body["license_key"], "test-key");
                    assert_eq!(body["classifier_public_key"], "00".repeat(32));
                    assert_eq!(body["classifier_key_id"], "test-key-id");
                    Json(serde_json::json!({
                        "installation_id": body["installation_id"],
                        "installation_credential": "test-credential"
                    }))
                }),
            )
            .route(
                "/api/v1/installations/check",
                post(|Json(body): Json<serde_json::Value>| async move {
                    assert_eq!(body["classifier_public_key"], "00".repeat(32));
                    assert_eq!(body["classifier_key_id"], "test-key-id");
                    assert_eq!(
                        body["capabilities"],
                        serde_json::json!([
                            "rule_bundle_v1",
                            "rule_ir_v1",
                            "rule_ir_v2",
                            "domain",
                            "cidr",
                            "classifier_domains_v1",
                            "classifier_cidrs_v1",
                            "classifier_protocol_evidence_v1",
                            "classifier_favicon_sha256_v1",
                            "device_fingerprints_v1",
                            "auxiliary_datasets_v1",
                        ])
                    );
                    Json(serde_json::json!({
                        "edition": "pro",
                        "license_status": "active",
                        "lease_valid_until": "2099-01-01T00:00:00Z",
                        "check_after_seconds": 3600,
                        "allowed_rule": {
                            "artifact_id": "00000000-0000-0000-0000-000000000001",
                            "rule_version": "1.0.0"
                        },
                        "sealed_rule_key": "sealed-key-sample"
                    }))
                }),
            );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("license.json");
        let coordinator = LicenseCoordinator::new(
            ClassifierHandle::test_default(),
            format!("http://127.0.0.1:{port}"),
            path.clone(),
        );

        let status = coordinator.activate("test-key").await.unwrap();
        assert!(status.activated);
        assert_eq!(status.edition, "pro");
        assert_eq!(status.license_status, "active");

        // Verify License Key is NEVER persisted to disk, only device credential
        let saved_json = fs::read_to_string(&path).unwrap();
        assert!(
            !saved_json.contains("test-key"),
            "license.json must never contain the raw license key"
        );
        assert!(
            saved_json.contains("test-credential"),
            "license.json must contain the installation credential"
        );
    }

    #[tokio::test]
    async fn check_immediate_downgrade_on_revocation_401_403() {
        use axum::{Json, Router, routing::post};
        use std::sync::atomic::{AtomicU16, Ordering};

        let status_code = Arc::new(AtomicU16::new(200));
        let status_code_clone = Arc::clone(&status_code);

        let app = Router::new()
            .route(
                "/api/v1/licenses/activate",
                post(|Json(body): Json<serde_json::Value>| async move {
                    Json(serde_json::json!({
                        "installation_id": body["installation_id"],
                        "installation_credential": "active-credential"
                    }))
                }),
            )
            .route(
                "/api/v1/installations/check",
                post(move || {
                    let code = status_code_clone.load(Ordering::SeqCst);
                    async move {
                        if code == 200 {
                            (
                                axum::http::StatusCode::OK,
                                Json(serde_json::json!({
                                    "edition": "pro",
                                    "license_status": "active",
                                    "lease_valid_until": "2099-01-01T00:00:00Z",
                                    "check_after_seconds": 900,
                                    "allowed_rule": {
                                        "artifact_id": "00000000-0000-0000-0000-000000000001",
                                        "rule_version": "1.0.0"
                                    }
                                })),
                            )
                        } else if code == 403 {
                            (
                                axum::http::StatusCode::FORBIDDEN,
                                Json(serde_json::json!({
                                    "error": {
                                        "code": "license_revoked",
                                        "category": "license",
                                        "message": "The Pro license has been revoked.",
                                        "action": "contact_support"
                                    }
                                })),
                            )
                        } else {
                            (
                                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                                Json(serde_json::json!({ "error": "server_error" })),
                            )
                        }
                    }
                }),
            );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("license.json");
        let coordinator = LicenseCoordinator::new(
            ClassifierHandle::test_default(),
            format!("http://127.0.0.1:{port}"),
            path,
        );

        // 1. Activate Pro successfully
        let status = coordinator.activate("valid-key").await.unwrap();
        assert_eq!(status.edition, "pro");
        assert_eq!(status.license_status, "active");

        // 2. Cloud now returns 403 (revoked / disabled)
        status_code.store(403, Ordering::SeqCst);
        let check_result = coordinator.check().await;
        assert!(check_result.is_err());
        assert!(
            check_result
                .unwrap_err()
                .contains("rejected device credential (403")
        );
        let error = coordinator.status().unwrap().last_error.unwrap();
        assert!(error.contains("license_revoked"));
        assert!(error.contains("contact_support"));

        // 3. Status must immediately downgrade to Community with revoked status
        let current_status = coordinator.status().unwrap();
        assert_eq!(current_status.edition, "community");
        assert_eq!(current_status.license_status, "revoked");
    }

    #[tokio::test]
    async fn check_transport_failure_and_offline_grace_period() {
        use axum::{Json, Router, routing::post};

        let app = Router::new()
            .route(
                "/api/v1/licenses/activate",
                post(|Json(body): Json<serde_json::Value>| async move {
                    Json(serde_json::json!({
                        "installation_id": body["installation_id"],
                        "installation_credential": "active-credential"
                    }))
                }),
            )
            .route(
                "/api/v1/installations/check",
                post(|| async {
                    (
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({ "error": "gateway timeout" })),
                    )
                }),
            );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("license.json");
        let classifier = ClassifierHandle::test_default();

        // Seed an existing Pro identity whose last success was 1 hour ago (< 24h grace)
        let now_ts = now();
        let initial_identity = PersistedIdentity {
            installation_id: Uuid::new_v4(),
            installation_credential: Some("test-cred".into()),
            last_success_at: Some(now_ts - 3600),
            edition: "pro".into(),
            license_status: "active".into(),
            lease_valid_until: Some(now_ts + 86400),
        };
        fs::write(&path, serde_json::to_vec(&initial_identity).unwrap()).unwrap();
        // Also prime the classifier mock state with Pro
        classifier
            .apply_entitlement(EntitlementLease {
                edition: "pro".into(),
                license_status: "active".into(),
                lease_valid_until: now_ts + 86400,
                allowed_rule: None,
                cloud_api_url: "http://127.0.0.1:1".into(),
                installation_credential: Some("test-cred".into()),
                sealed_rule_key: None,
            })
            .unwrap();

        let coordinator = LicenseCoordinator::new(
            classifier.clone(),
            format!("http://127.0.0.1:{port}"),
            path.clone(),
        );

        // Check fails due to 500 error, but < 24h grace retains Pro lease
        let err = coordinator.check().await.unwrap_err();
        assert!(err.contains("Cloud check failed (500"));
        let status = coordinator.status().unwrap();
        assert_eq!(status.edition, "pro");
        assert_eq!(status.license_status, "active");

        // Now set last_success_at to 25 hours ago (> 24h grace)
        let mut expired_identity = initial_identity;
        expired_identity.last_success_at = Some(now_ts - 25 * 3600);
        coordinator.save_identity(expired_identity).unwrap();

        // Check fails again, now triggering Community downgrade
        let err = coordinator.check().await.unwrap_err();
        assert!(err.contains("Cloud check failed (500"));
        let status = coordinator.status().unwrap();
        assert_eq!(status.edition, "community");
        assert_eq!(status.license_status, "offline_grace_expired");
    }

    #[tokio::test]
    async fn concurrent_operations_are_serialized() {
        use axum::{Json, Router, routing::post};

        let app = Router::new().route(
            "/api/v1/installations/check",
            post(|| async {
                tokio::time::sleep(Duration::from_millis(10)).await;
                Json(serde_json::json!({
                    "edition": "pro",
                    "license_status": "active",
                    "lease_valid_until": "2099-01-01T00:00:00Z",
                    "check_after_seconds": 900,
                    "allowed_rule": {
                        "artifact_id": "00000000-0000-0000-0000-000000000001",
                        "rule_version": "1.0.0"
                    }
                }))
            }),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("license.json");
        let initial_identity = PersistedIdentity {
            installation_id: Uuid::new_v4(),
            installation_credential: Some("test-cred".into()),
            last_success_at: Some(now()),
            edition: "pro".into(),
            license_status: "active".into(),
            lease_valid_until: Some(now() + 3600),
        };
        fs::write(&path, serde_json::to_vec(&initial_identity).unwrap()).unwrap();

        let coordinator = Arc::new(LicenseCoordinator::new(
            ClassifierHandle::test_default(),
            format!("http://127.0.0.1:{port}"),
            path,
        ));

        // Spawn 10 concurrent check tasks
        let mut handles = Vec::new();
        for _ in 0..10 {
            let coord = Arc::clone(&coordinator);
            handles.push(tokio::spawn(async move { coord.check().await }));
        }

        for handle in handles {
            let res = handle.await.unwrap();
            assert!(res.is_ok());
            assert_eq!(res.unwrap().edition, "pro");
        }
    }
}
