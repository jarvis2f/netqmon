use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use netqmon_classifier_client::{ClassifierClient, ClassifierClientConfig};
use netqmon_classifier_manager::{
    ComponentManifest, IPC_PROTOCOL_VERSION, MAX_BINARY_BYTES, TEST_KEY_ID, TEST_PUBLIC_KEY_HEX,
    current_binary, current_platform, install_binary, previous_binary, prune_releases,
    same_release_content, switch_current, verify_installed_binary, verify_manifest,
};
use nix::{
    sys::signal::{Signal, kill},
    unistd::Pid,
};
use semver::Version;
use serde::Serialize;
use tokio::process::{Child, Command};

const DEFAULT_COMPONENT_ROOT: &str = "/data/components/classifierd";
const DEFAULT_SOCKET: &str = "/run/netqmon/classifierd.sock";
const DEFAULT_UPDATE_SECONDS: u64 = 6 * 60 * 60;
const MAX_UPGRADE_CRASHES: u32 = 3;
const UPGRADE_STABILIZATION_SECONDS: u64 = 60;

#[derive(Clone)]
struct Config {
    api_url: String,
    channel: String,
    root: PathBuf,
    socket: PathBuf,
    interval: Duration,
    trusted_key_id: String,
    trusted_key_version: u32,
    trusted_public_key: String,
}

#[derive(Serialize)]
struct Status<'a> {
    state: &'a str,
    current_version: Option<&'a str>,
    candidate_version: Option<&'a str>,
    last_checked_at: i64,
    last_error: Option<&'a str>,
}

#[tokio::main]
#[allow(clippy::too_many_lines)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    if env::var("NETQMON_CLASSIFIER_MANAGED")
        .is_ok_and(|value| matches!(value.as_str(), "0" | "false" | "no"))
    {
        tracing::info!("managed classifier is disabled");
        std::future::pending::<()>().await;
    }
    let config = Config::from_env()?;
    fs::create_dir_all(&config.root)?;
    if config.trusted_public_key == TEST_PUBLIC_KEY_HEX {
        tracing::warn!("classifier component manager is using the development TEST trust key");
    }

    let current_netqmon = Version::parse(env!("CARGO_PKG_VERSION"))?;
    let mut active_path =
        trusted_installed_binary(&config, current_binary(&config.root), &current_netqmon);
    if active_path.is_none() {
        active_path =
            trusted_installed_binary(&config, previous_binary(&config.root), &current_netqmon);
    }
    let mut child = None;
    if let Some(path) = active_path.as_deref() {
        if let Some(version) = installed_version(path) {
            if let Ok(mut started) = spawn_classifier(path, &config).await {
                match wait_ready(&mut started, &config, &version).await {
                    Ok(()) => child = Some(started),
                    Err(error) => {
                        tracing::warn!(%error, "installed classifier did not become ready");
                        stop_running_child(started).await;
                    }
                }
            }
        }
    }
    let mut restart_retry = Duration::from_secs(1);
    let mut update_retry = Duration::from_secs(1);
    let mut restart_not_before = tokio::time::Instant::now();
    let mut guarded_upgrade: Option<PathBuf> = None;
    let mut upgrade_started_at: Option<tokio::time::Instant> = None;
    let mut upgrade_crashes = 0_u32;
    let mut next_update = tokio::time::Instant::now();
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    write_runtime_status(
        if child.is_some() {
            "ready"
        } else {
            "unavailable"
        },
        active_path
            .as_deref()
            .and_then(installed_version)
            .as_deref(),
        None,
        0,
        None,
    )?;

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                stop_child(&mut child).await;
                return Ok(());
            }
            _ = terminate.recv() => {
                stop_child(&mut child).await;
                return Ok(());
            }
            _ = ticker.tick() => {
                if let Some(running) = child.as_mut() {
                    if let Some(status) = running.try_wait()? {
                        tracing::warn!(%status, "classifierd exited; scheduling restart");
                        child = None;
                        if guarded_upgrade.as_ref() == active_path.as_ref() {
                            upgrade_crashes += 1;
                        }
                        if upgrade_crashes >= MAX_UPGRADE_CRASHES {
                            if let Some(previous) = trusted_installed_binary(
                                &config,
                                previous_binary(&config.root),
                                &current_netqmon,
                            ) {
                                tracing::error!("upgraded classifier repeatedly crashed; rolling back");
                                switch_current(&config.root, &previous)?;
                                active_path = Some(previous);
                                guarded_upgrade = None;
                                upgrade_started_at = None;
                                upgrade_crashes = 0;
                                restart_retry = Duration::from_secs(1);
                            }
                        }
                        restart_not_before = tokio::time::Instant::now() + restart_retry;
                        restart_retry = restart_retry.saturating_mul(2).min(Duration::from_secs(30));
                        write_runtime_status(
                            "degraded",
                            active_path.as_deref().and_then(installed_version).as_deref(),
                            guarded_upgrade.as_deref().and_then(installed_version).as_deref(),
                            now(),
                            Some("classifierd exited unexpectedly"),
                        )?;
                    }
                }
                if guarded_upgrade.is_some()
                    && upgrade_started_at.is_some_and(|started| {
                        started.elapsed() >= Duration::from_secs(UPGRADE_STABILIZATION_SECONDS)
                    })
                {
                    guarded_upgrade = None;
                    upgrade_started_at = None;
                    upgrade_crashes = 0;
                }
                if child.is_none() && tokio::time::Instant::now() >= restart_not_before {
                    if let Some(path) = active_path.as_deref() {
                        match spawn_classifier(path, &config).await {
                            Ok(mut started) => {
                                let version = installed_version(path)
                                    .ok_or("installed classifier path has no version")?;
                                match wait_ready(&mut started, &config, &version).await {
                                    Ok(()) => {
                                        child = Some(started);
                                        restart_retry = Duration::from_secs(1);
                                        write_runtime_status("ready", Some(&version), None, now(), None)?;
                                    }
                                    Err(error) => {
                                        stop_running_child(started).await;
                                        restart_not_before = tokio::time::Instant::now() + restart_retry;
                                        restart_retry = restart_retry.saturating_mul(2).min(Duration::from_secs(30));
                                        write_runtime_status("degraded", Some(&version), None, now(), Some(&error))?;
                                    }
                                }
                            }
                            Err(error) => {
                                tracing::warn!(%error, "failed to restart classifierd");
                                restart_not_before = tokio::time::Instant::now() + restart_retry;
                                restart_retry = restart_retry.saturating_mul(2).min(Duration::from_secs(30));
                            }
                        }
                    }
                }
                if tokio::time::Instant::now() >= next_update {
                    match update(&config, active_path.as_deref()).await {
                        Ok(Some((path, version))) => {
                            write_runtime_status(
                                "activating",
                                active_path.as_deref().and_then(installed_version).as_deref(),
                                Some(&version),
                                now(),
                                None,
                            )?;
                            stop_child(&mut child).await;
                            switch_current(&config.root, &path)?;
                            active_path = Some(path.clone());
                            match spawn_classifier(&path, &config).await {
                                Ok(mut started) => {
                                    match wait_ready(&mut started, &config, &version).await {
                                        Ok(()) => {
                                            child = Some(started);
                                            restart_retry = Duration::from_secs(1);
                                            update_retry = Duration::from_secs(1);
                                            guarded_upgrade = Some(path);
                                            upgrade_started_at = Some(tokio::time::Instant::now());
                                            upgrade_crashes = 0;
                                            prune_releases(&config.root)?;
                                            write_runtime_status("ready", Some(&version), None, now(), None)?;
                                        }
                                        Err(error) => {
                                            stop_running_child(started).await;
                                            rollback(&config, &current_netqmon, &mut active_path, &mut child).await;
                                            write_runtime_status("degraded", active_path.as_deref().and_then(installed_version).as_deref(), Some(&version), now(), Some(&error))?;
                                        }
                                    }
                                }
                                Err(error) => {
                                    tracing::error!(%error, "new classifier failed after activation; rolling back");
                                    rollback(&config, &current_netqmon, &mut active_path, &mut child).await;
                                    write_runtime_status("degraded", active_path.as_deref().and_then(installed_version).as_deref(), Some(&version), now(), Some(&error))?;
                                }
                            }
                        }
                        Ok(None) => {
                            update_retry = Duration::from_secs(1);
                            write_runtime_status(
                                if child.is_some() { "ready" } else { "degraded" },
                                active_path.as_deref().and_then(installed_version).as_deref(),
                                None,
                                now(),
                                None,
                            )?;
                        }
                        Err(error) => {
                            tracing::warn!(%error, "classifier component update check failed");
                            write_runtime_status(
                                if child.is_some() { "ready" } else { "degraded" },
                                active_path.as_deref().and_then(installed_version).as_deref(),
                                None,
                                now(),
                                Some(&error),
                            )?;
                            update_retry = update_retry.saturating_mul(2).min(Duration::from_secs(30));
                        }
                    }
                    next_update = tokio::time::Instant::now() + if active_path.is_some() { config.interval } else { update_retry };
                }
            }
        }
    }
}

impl Config {
    fn from_env() -> Result<Self, String> {
        let api_url = env::var("NETQMON_COMPONENT_API_URL")
            .or_else(|_| env::var("NETQMON_CLOUD_API_URL"))
            .unwrap_or_else(|_| "https://netqmon.com".into())
            .trim_end_matches('/')
            .to_owned();
        let interval = env::var("NETQMON_CLASSIFIER_UPDATE_INTERVAL_SECONDS")
            .ok()
            .map(|value| value.parse::<u64>())
            .transpose()
            .map_err(|error| error.to_string())?
            .unwrap_or(DEFAULT_UPDATE_SECONDS);
        let trusted_key_version = env::var("NETQMON_CLASSIFIER_COMPONENT_KEY_VERSION")
            .ok()
            .map(|value| value.parse::<u32>())
            .transpose()
            .map_err(|error| error.to_string())?
            .unwrap_or(1);
        Ok(Self {
            api_url,
            channel: env::var("NETQMON_CLASSIFIER_UPDATE_CHANNEL")
                .unwrap_or_else(|_| "stable".into()),
            root: env::var_os("NETQMON_CLASSIFIER_COMPONENT_DIR")
                .map_or_else(|| PathBuf::from(DEFAULT_COMPONENT_ROOT), PathBuf::from),
            socket: env::var_os("NETQMON_CLASSIFIER_SOCKET")
                .map_or_else(|| PathBuf::from(DEFAULT_SOCKET), PathBuf::from),
            interval: Duration::from_secs(interval.max(60)),
            trusted_key_id: env::var("NETQMON_CLASSIFIER_COMPONENT_KEY_ID")
                .unwrap_or_else(|_| TEST_KEY_ID.into()),
            trusted_key_version,
            trusted_public_key: option_env!("NETQMON_CLASSIFIER_COMPONENT_PUBLIC_KEY_HEX")
                .unwrap_or(TEST_PUBLIC_KEY_HEX)
                .to_owned(),
        })
    }
}

async fn update(
    config: &Config,
    current: Option<&Path>,
) -> Result<Option<(PathBuf, String)>, String> {
    let netqmon = Version::parse(env!("CARGO_PKG_VERSION")).map_err(|error| error.to_string())?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(display)?;
    let url = format!(
        "{}/api/v1/components/classifierd/releases/latest",
        config.api_url
    );
    let response = client
        .get(url)
        .query(&[
            ("channel", config.channel.as_str()),
            ("netqmon_version", env!("CARGO_PKG_VERSION")),
            ("platform", current_platform()?),
            ("ipc_protocol_version", &IPC_PROTOCOL_VERSION.to_string()),
        ])
        .send()
        .await
        .map_err(display)?
        .error_for_status()
        .map_err(display)?;
    let manifest: ComponentManifest = response.json().await.map_err(display)?;
    verify_manifest(
        &manifest,
        &netqmon,
        &config.trusted_key_id,
        config.trusted_key_version,
        &config.trusted_public_key,
    )?;
    let installed_manifest = current.and_then(|path| {
        verify_installed_binary(
            path,
            &netqmon,
            &config.trusted_key_id,
            config.trusted_key_version,
            &config.trusted_public_key,
        )
        .ok()
    });
    if installed_manifest
        .as_ref()
        .is_some_and(|installed| same_release_content(installed, &manifest))
    {
        return Ok(None);
    }
    let download_url = if manifest.download_url.starts_with("https://")
        || manifest.download_url.starts_with("http://")
    {
        manifest.download_url.clone()
    } else {
        format!("{}{}", config.api_url, manifest.download_url)
    };
    let mut response = client
        .get(download_url)
        .send()
        .await
        .map_err(display)?
        .error_for_status()
        .map_err(display)?;
    if response
        .content_length()
        .is_some_and(|length| length != manifest.size_bytes || length > MAX_BINARY_BYTES)
    {
        return Err("classifier download Content-Length does not match manifest".into());
    }
    let mut bytes = Vec::with_capacity(usize::try_from(manifest.size_bytes).map_err(display)?);
    while let Some(chunk) = response.chunk().await.map_err(display)? {
        let next = bytes
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| "classifier download size overflow".to_owned())?;
        if u64::try_from(next).map_err(display)? > manifest.size_bytes
            || u64::try_from(next).map_err(display)? > MAX_BINARY_BYTES
        {
            return Err("classifier download exceeded signed size limit".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    if u64::try_from(bytes.len()).map_err(display)? != manifest.size_bytes {
        return Err("classifier download ended before signed size was received".into());
    }
    let path = install_binary(&config.root, &manifest, &bytes)?;
    preflight(&path, config, &manifest.version).await?;
    Ok(Some((path, manifest.version)))
}

async fn preflight(path: &Path, config: &Config, expected: &str) -> Result<(), String> {
    let socket = config.root.join("candidate.sock");
    let cache = config.root.join("candidate-rules.nqrp");
    let _ = fs::remove_file(&socket);
    let mut child = classifier_command(path, &socket, &cache, config)
        .spawn()
        .map_err(display)?;
    let result = wait_ready_at(&mut child, &socket, expected).await;
    stop_running_child(child).await;
    let _ = fs::remove_file(socket);
    result
}

#[allow(clippy::unused_async)]
async fn spawn_classifier(path: &Path, config: &Config) -> Result<Child, String> {
    if let Some(parent) = config.socket.parent() {
        fs::create_dir_all(parent).map_err(display)?;
    }
    let cache = config.root.join("rules/active-rules.nqrp");
    if let Some(parent) = cache.parent() {
        fs::create_dir_all(parent).map_err(display)?;
    }
    match fs::remove_file(&config.socket) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.to_string()),
    }
    classifier_command(path, &config.socket, &cache, config)
        .spawn()
        .map_err(display)
}

fn classifier_command(path: &Path, socket: &Path, cache: &Path, config: &Config) -> Command {
    let mut command = Command::new(path);
    let identity_path = config.root.join("identity/classifier_identity.key");
    command
        .args([
            "--socket",
            &socket.to_string_lossy(),
            "--cloud-api-url",
            &config.api_url,
            "--rule-cache",
            &cache.to_string_lossy(),
            "--identity-path",
            &identity_path.to_string_lossy(),
            "--channel",
            &config.channel,
            "--netqmon-version",
            env!("CARGO_PKG_VERSION"),
            "--environment",
            "production",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    command
}

async fn stop_child(child: &mut Option<Child>) {
    if let Some(value) = child.take() {
        stop_running_child(value).await;
    }
}

async fn stop_running_child(mut child: Child) {
    if let Some(id) = child.id().and_then(|id| i32::try_from(id).ok()) {
        let _ = kill(Pid::from_raw(id), Signal::SIGTERM);
    }
    if tokio::time::timeout(Duration::from_secs(10), child.wait())
        .await
        .is_err()
    {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
}

async fn wait_ready(child: &mut Child, config: &Config, expected: &str) -> Result<(), String> {
    wait_ready_at(child, &config.socket, expected).await
}

async fn wait_ready_at(child: &mut Child, socket: &Path, expected: &str) -> Result<(), String> {
    let client = ClassifierClient::new(ClassifierClientConfig {
        socket_path: socket.to_path_buf(),
        connect_timeout: Duration::from_millis(250),
        read_timeout: Duration::from_secs(2),
        write_timeout: Duration::from_secs(2),
        ..Default::default()
    })
    .map_err(display)?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait().map_err(display)? {
            return Err(format!("classifier exited before readiness with {status}"));
        }
        if let Ok(version) = client.classifier_version() {
            if version.version != expected {
                return Err(format!(
                    "classifier reported version {}, expected {expected}",
                    version.version
                ));
            }
            if client.health().is_ok() && client.rule_version().is_ok() {
                return Ok(());
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err("classifier did not become ready".into());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

fn trusted_installed_binary(
    config: &Config,
    binary: Option<PathBuf>,
    current_netqmon: &Version,
) -> Option<PathBuf> {
    let binary = binary?;
    match verify_installed_binary(
        &binary,
        current_netqmon,
        &config.trusted_key_id,
        config.trusted_key_version,
        &config.trusted_public_key,
    ) {
        Ok(_) => Some(binary),
        Err(error) => {
            tracing::error!(path = %binary.display(), %error, "refusing unverified installed classifier");
            None
        }
    }
}

async fn rollback(
    config: &Config,
    current_netqmon: &Version,
    active_path: &mut Option<PathBuf>,
    child: &mut Option<Child>,
) {
    let Some(previous) =
        trusted_installed_binary(config, previous_binary(&config.root), current_netqmon)
    else {
        *active_path = None;
        *child = None;
        return;
    };
    if let Err(error) = switch_current(&config.root, &previous) {
        tracing::error!(%error, "failed to restore previous classifier symlink");
        *active_path = None;
        *child = None;
        return;
    }
    *active_path = Some(previous.clone());
    *child = spawn_classifier(&previous, config).await.ok();
}

fn installed_version(path: &Path) -> Option<String> {
    path.parent()?.file_name()?.to_str().map(str::to_owned)
}

fn write_runtime_status(
    state: &str,
    current_version: Option<&str>,
    candidate_version: Option<&str>,
    last_checked_at: i64,
    last_error: Option<&str>,
) -> Result<(), String> {
    let runtime = Path::new("/run/netqmon");
    fs::create_dir_all(runtime).map_err(display)?;
    let temporary = runtime.join(format!(
        "classifier-manager-status.{}.tmp",
        std::process::id()
    ));
    let status = Status {
        state,
        current_version,
        candidate_version,
        last_checked_at,
        last_error,
    };
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&temporary)
        .map_err(display)?;
    file.write_all(&serde_json::to_vec(&status).map_err(display)?)
        .map_err(display)?;
    file.sync_all().map_err(display)?;
    fs::rename(temporary, runtime.join("classifier-manager-status.json")).map_err(display)?;
    std::fs::File::open(runtime)
        .and_then(|dir| dir.sync_all())
        .map_err(display)?;
    Ok(())
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|v| i64::try_from(v.as_secs()).ok())
        .unwrap_or(i64::MAX)
}
fn display(error: impl std::fmt::Display) -> String {
    error.to_string()
}
