use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use netqmon_geo::{GeoDatabaseMetadata, inspect_database, validate_mmdb_bytes};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};

pub const DEFAULT_CITY_SOURCE: &str =
    "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-City.mmdb";
pub const DEFAULT_ASN_SOURCE: &str =
    "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-ASN.mmdb";
pub const GEOLITE_ATTRIBUTION: &str =
    "GeoLite2 data created by MaxMind / P3TERX mirror (https://github.com/P3TERX/GeoLite.mmdb)";
pub const CITY_FILENAME: &str = "GeoLite2-City.mmdb";
pub const ASN_FILENAME: &str = "GeoLite2-ASN.mmdb";

// Backward compatibility aliases
#[allow(dead_code)]
pub const DEFAULT_COUNTRY_SOURCE: &str = DEFAULT_CITY_SOURCE;
#[allow(dead_code)]
pub const COUNTRY_FILENAME: &str = CITY_FILENAME;
#[allow(dead_code)]
pub const DB_IP_ATTRIBUTION: &str = GEOLITE_ATTRIBUTION;

const HTTP_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GeoDatabaseItem {
    pub filename: String,
    pub installed: bool,
    pub database_type: Option<String>,
    pub build_epoch: Option<u64>,
    pub build_date: Option<String>,
    pub file_size_bytes: u64,
    pub last_modified_unix_s: Option<u64>,
    pub record_count: Option<u32>,
    pub source_url: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GeoStatusResponse {
    pub enabled: bool,
    pub directory: String,
    pub databases: Vec<GeoDatabaseItem>,
    pub attribution: String,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GeoUpdateResult {
    pub success: bool,
    pub message: String,
    pub updated_files: Vec<String>,
    pub status: GeoStatusResponse,
}

/// Returns the current Geo status and database inventory for `directory`.
pub fn get_geo_status(directory: &Path, enabled: bool) -> GeoStatusResponse {
    let city_source = std::env::var("NETQMON_GEO_CITY_URL")
        .or_else(|_| std::env::var("NETQMON_GEO_COUNTRY_URL"))
        .unwrap_or_else(|_| DEFAULT_CITY_SOURCE.to_owned());
    let asn_source =
        std::env::var("NETQMON_GEO_ASN_URL").unwrap_or_else(|_| DEFAULT_ASN_SOURCE.to_owned());

    let city_path = directory.join(CITY_FILENAME);
    let asn_path = directory.join(ASN_FILENAME);

    let city_meta = inspect_database(&city_path);
    let asn_meta = inspect_database(&asn_path);

    let mut databases = Vec::new();

    databases.push(build_item(CITY_FILENAME, &city_source, city_meta.as_ref()));
    databases.push(build_item(ASN_FILENAME, &asn_source, asn_meta.as_ref()));

    // Also scan directory for any other *.mmdb files that are not the two standard ones
    if let Ok(entries) = fs::read_dir(directory) {
        let mut others = entries
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                p.extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("mmdb"))
                    && p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n != CITY_FILENAME && n != ASN_FILENAME)
            })
            .collect::<Vec<_>>();
        others.sort();
        for other_path in others {
            if let Some(filename) = other_path.file_name().and_then(|n| n.to_str()) {
                let meta = inspect_database(&other_path);
                databases.push(build_item(filename, "custom", meta.as_ref()));
            }
        }
    }

    GeoStatusResponse {
        enabled,
        directory: directory.display().to_string(),
        databases,
        attribution: GEOLITE_ATTRIBUTION.to_owned(),
    }
}

fn build_item(
    filename: &str,
    source_url: &str,
    meta: Option<&GeoDatabaseMetadata>,
) -> GeoDatabaseItem {
    if let Some(meta) = meta {
        let build_date = meta.build_epoch.and_then(format_epoch);
        GeoDatabaseItem {
            filename: filename.to_owned(),
            installed: true,
            database_type: meta.database_type.clone(),
            build_epoch: meta.build_epoch,
            build_date,
            file_size_bytes: meta.file_size_bytes,
            last_modified_unix_s: meta.last_modified_unix_s,
            record_count: meta.record_count,
            source_url: source_url.to_owned(),
        }
    } else {
        GeoDatabaseItem {
            filename: filename.to_owned(),
            installed: false,
            database_type: None,
            build_epoch: None,
            build_date: None,
            file_size_bytes: 0,
            last_modified_unix_s: None,
            record_count: None,
            source_url: source_url.to_owned(),
        }
    }
}

fn format_epoch(epoch: u64) -> Option<String> {
    use std::time::{Duration, UNIX_EPOCH};
    let system_time = UNIX_EPOCH.checked_add(Duration::from_secs(epoch))?;
    let datetime: ChronoFreeFormat = system_time.into();
    Some(format!(
        "{:04}-{:02}-{:02}",
        datetime.year, datetime.month, datetime.day
    ))
}

struct ChronoFreeFormat {
    year: i32,
    month: u32,
    day: u32,
}

impl From<std::time::SystemTime> for ChronoFreeFormat {
    fn from(time: std::time::SystemTime) -> Self {
        let secs = time
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let days = i64::try_from(secs / 86_400).unwrap_or(i64::MAX);
        let (y, m, d) = days_to_date(days);
        Self {
            year: y,
            month: m,
            day: d,
        }
    }
}

// Convert days since UNIX epoch (1970-01-01) to (year, month, day)
fn days_to_date(days_since_epoch: i64) -> (i32, u32, u32) {
    let days = days_since_epoch + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let doe = u32::try_from(days - era * 146_097).unwrap_or(0);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = i64::from(yoe) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (
        i32::try_from(y).unwrap_or(if y.is_negative() { i32::MIN } else { i32::MAX }),
        m,
        d,
    )
}

#[allow(dead_code)]
/// Downloads and updates both GeoLite2-City and GeoLite2-ASN databases into `directory`.
pub fn update_geo_databases(directory: &Path) -> Result<(PathBuf, Vec<String>), String> {
    let city_source = std::env::var("NETQMON_GEO_CITY_URL")
        .or_else(|_| std::env::var("NETQMON_GEO_COUNTRY_URL"))
        .unwrap_or_else(|_| DEFAULT_CITY_SOURCE.to_owned());
    let asn_source =
        std::env::var("NETQMON_GEO_ASN_URL").unwrap_or_else(|_| DEFAULT_ASN_SOURCE.to_owned());
    update_geo_databases_with_urls(directory, &city_source, &asn_source)
}

/// Downloads and updates both databases using explicit sources.
pub fn update_geo_databases_with_urls(
    directory: &Path,
    city_source: &str,
    asn_source: &str,
) -> Result<(PathBuf, Vec<String>), String> {
    let target_dir: PathBuf = match fs::create_dir_all(directory) {
        Ok(()) => directory.to_path_buf(),
        Err(e)
            if e.raw_os_error() == Some(30)
                || e.kind() == std::io::ErrorKind::PermissionDenied
                || e.kind() == std::io::ErrorKind::ReadOnlyFilesystem =>
        {
            let fallback = if Path::new("target").is_dir() {
                PathBuf::from("target/geo")
            } else {
                std::env::temp_dir().join("netqmon-geo")
            };
            tracing::warn!(
                original = %directory.display(),
                fallback = %fallback.display(),
                error = %e,
                "configured geo directory is read-only or permission denied; falling back to writable directory"
            );
            fs::create_dir_all(&fallback).map_err(|err| {
                format!(
                    "cannot create directory {} ({e}) and fallback {} failed: {err}",
                    directory.display(),
                    fallback.display()
                )
            })?;
            fallback
        }
        Err(e) => {
            return Err(format!(
                "cannot create directory {}: {e}",
                directory.display()
            ));
        }
    };

    let client = Client::builder()
        .timeout(HTTP_TIMEOUT)
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))?;

    let mut updated = Vec::new();

    // 1. Download and update City DB
    tracing::info!(source = %city_source, "updating GeoLite2-City database");
    download_and_install_db(&client, city_source, &target_dir, CITY_FILENAME, "city")?;
    updated.push(CITY_FILENAME.to_owned());

    // 2. Download and update ASN DB
    tracing::info!(source = %asn_source, "updating GeoLite2-ASN database");
    download_and_install_db(&client, asn_source, &target_dir, ASN_FILENAME, "asn")?;
    updated.push(ASN_FILENAME.to_owned());

    Ok((target_dir, updated))
}

fn download_and_install_db(
    client: &Client,
    source_url: &str,
    directory: &Path,
    target_filename: &str,
    kind: &str,
) -> Result<(), String> {
    // Resolve final download URL (either direct MMDB/GZ or scrapable page)
    let download_url = resolve_download_url(client, source_url, kind);
    tracing::info!(download_url = %download_url, "resolved download URL");

    let response = client
        .get(&download_url)
        .header("Referer", "https://db-ip.com/")
        .header(
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        )
        .send()
        .map_err(|e| format!("HTTP request to {download_url} failed: {e}"))?
        .error_for_status()
        .map_err(|e| format!("HTTP error from {download_url}: {e}"))?;

    let raw_bytes = response
        .bytes()
        .map_err(|e| format!("failed reading bytes from {download_url}: {e}"))?;

    let decompressed = if is_gzip(&raw_bytes) {
        decompress_gzip(&raw_bytes)?
    } else {
        raw_bytes.to_vec()
    };

    // Verify MMDB integrity
    validate_mmdb_bytes(&decompressed)
        .map_err(|e| format!("downloaded data is not a valid MMDB database: {e}"))?;

    // Atomic write
    let temp_path = directory.join(format!(".netqmon-{target_filename}.tmp"));
    let target_path = directory.join(target_filename);

    let mut file = fs::File::create(&temp_path)
        .map_err(|e| format!("failed to create temp file {}: {e}", temp_path.display()))?;
    file.write_all(&decompressed)
        .map_err(|e| format!("failed to write to temp file: {e}"))?;
    file.sync_all()
        .map_err(|e| format!("failed to sync temp file: {e}"))?;
    drop(file);

    fs::rename(&temp_path, &target_path).map_err(|e| {
        let _ = fs::remove_file(&temp_path);
        format!("failed to replace {}: {e}", target_path.display())
    })?;

    tracing::info!(path = %target_path.display(), "successfully installed Geo database");
    Ok(())
}

fn is_gzip(bytes: &[u8]) -> bool {
    bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b
}

fn decompress_gzip(compressed: &[u8]) -> Result<Vec<u8>, String> {
    let mut child = Command::new("gzip")
        .arg("-dc")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .or_else(|_| {
            Command::new("gunzip")
                .arg("-c")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
        })
        .map_err(|e| format!("failed to execute gzip/gunzip command for decompression: {e}"))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(compressed)
            .map_err(|e| format!("failed to write to gzip stdin: {e}"))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| format!("failed waiting for gzip process: {e}"))?;

    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(format!("gzip decompression failed: {err}"));
    }

    Ok(output.stdout)
}

fn resolve_download_url(client: &Client, source_url: &str, kind: &str) -> String {
    // If it already points to a direct mmdb or gz, use directly
    if has_mmdb_extension(source_url) || source_url.to_ascii_lowercase().ends_with(".mmdb.gz") {
        return source_url.to_owned();
    }

    // Otherwise, try fetching HTML page and parse the link
    let fetch_result = client
        .get(source_url)
        .header(
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        )
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .and_then(reqwest::blocking::Response::text);

    match fetch_result {
        Ok(html) => {
            if let Some(found_url) = extract_mmdb_download_link(&html, kind) {
                return found_url;
            }
        }
        Err(e) => {
            let mirror = if kind == "city" || kind == "country" {
                DEFAULT_CITY_SOURCE
            } else {
                DEFAULT_ASN_SOURCE
            };
            tracing::warn!(
                source_url,
                mirror,
                error = %e,
                "fetching page failed (e.g. anti-bot protection); falling back to mirror"
            );
            return mirror.to_owned();
        }
    }

    let mirror = if kind == "city" || kind == "country" {
        DEFAULT_CITY_SOURCE
    } else {
        DEFAULT_ASN_SOURCE
    };
    mirror.to_owned()
}

fn extract_mmdb_download_link(html: &str, kind: &str) -> Option<String> {
    // Pattern looking for https://download.db-ip.com/free/dbip-{kind}-lite-YYYY-MM.mmdb.gz
    let pattern = format!("dbip-{kind}-lite-");
    let mut search_idx = 0;
    while let Some(idx) = html[search_idx..].find(&pattern) {
        let abs_idx = search_idx + idx;
        // find starting quote of href
        let href_start = html[..abs_idx].rfind(['\'', '"'])?;
        let href_end = html[abs_idx..]
            .find(['\'', '"'])
            .map(|offset| abs_idx + offset)?;
        let url_candidate = &html[href_start + 1..href_end];
        if url_candidate.to_ascii_lowercase().ends_with(".mmdb.gz")
            || has_mmdb_extension(url_candidate)
        {
            if url_candidate.starts_with("http") {
                return Some(url_candidate.to_owned());
            }
            if url_candidate.starts_with('/') {
                return Some(format!("https://db-ip.com{url_candidate}"));
            }
        }
        search_idx = abs_idx + pattern.len();
    }
    None
}

#[allow(dead_code)]
fn fallback_predicted_url(kind: &str) -> String {
    let now = std::time::SystemTime::now();
    let date: ChronoFreeFormat = now.into();
    format!(
        "https://download.db-ip.com/free/dbip-{kind}-lite-{:04}-{:02}.mmdb.gz",
        date.year, date.month
    )
}

fn has_mmdb_extension(url: &str) -> bool {
    Path::new(url)
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("mmdb"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_mmdb_download_link() {
        let sample_html = r#"
        <div class="card">
            <a href='https://download.db-ip.com/free/dbip-country-lite-2026-09.csv.gz'>CSV</a>
            <a href='https://download.db-ip.com/free/dbip-country-lite-2026-09.mmdb.gz' class='btn'>MMDB</a>
        </div>
        "#;
        let link = extract_mmdb_download_link(sample_html, "country");
        assert_eq!(
            link.as_deref(),
            Some("https://download.db-ip.com/free/dbip-country-lite-2026-09.mmdb.gz")
        );
    }

    #[test]
    fn test_days_to_date() {
        let epoch = 1_788_307_200; // approx 2026-09-02
        let days = epoch / 86_400;
        let (y, m, _d) = days_to_date(days);
        assert_eq!(y, 2026);
        assert_eq!(m, 9);
    }

    #[test]
    fn test_gzip_detection_and_decompression() {
        let original = b"testing maxmind mmdb dummy payload";
        let mut child = Command::new("gzip")
            .arg("-c")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("gzip must be available");
        child.stdin.as_mut().unwrap().write_all(original).unwrap();
        let output = child.wait_with_output().unwrap();
        let compressed = output.stdout;

        assert!(is_gzip(&compressed));
        let decompressed = decompress_gzip(&compressed).unwrap();
        assert_eq!(decompressed, original);
    }
}
