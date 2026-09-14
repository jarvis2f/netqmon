//! `GeoIP` and ASN enrichment abstractions for netqmon.

use std::error::Error;
use std::fmt;
use std::fs;
use std::net::IpAddr;
use std::path::Path;

use maxminddb::{Reader, geoip2};
use serde::Deserialize;

/// Default directory mounted by the Controller container for local databases.
pub const DEFAULT_GEO_DIRECTORY: &str = "/data/geo";

/// Destination intelligence returned by a [`GeoProvider`].
#[derive(Clone, Debug, Default, PartialEq)]
pub struct GeoRecord {
    pub country_code: Option<String>,
    pub country_name: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub asn: Option<u32>,
    pub organization: Option<String>,
}

impl GeoRecord {
    /// Returns true when the lookup did not yield any enrichment field.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

/// Metadata information about a local MMDB database file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeoDatabaseMetadata {
    pub filename: String,
    pub path: String,
    pub installed: bool,
    pub database_type: Option<String>,
    pub build_epoch: Option<u64>,
    pub file_size_bytes: u64,
    pub last_modified_unix_s: Option<u64>,
    pub record_count: Option<u32>,
}

/// Inspects a single mmdb file if it exists and extracts metadata.
#[must_use]
pub fn inspect_database(path: &Path) -> Option<GeoDatabaseMetadata> {
    let metadata = fs::metadata(path).ok()?;
    let filename = path.file_name()?.to_string_lossy().into_owned();
    let file_size_bytes = metadata.len();
    let last_modified_unix_s = metadata
        .modified()
        .ok()
        .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs());

    let (database_type, build_epoch, record_count) = match Reader::open_readfile(path) {
        Ok(reader) => {
            let meta = reader.metadata();
            (
                Some(meta.database_type.clone()),
                Some(meta.build_epoch),
                Some(meta.node_count),
            )
        }
        Err(_) => (None, None, None),
    };

    Some(GeoDatabaseMetadata {
        filename,
        path: path.to_string_lossy().into_owned(),
        installed: true,
        database_type,
        build_epoch,
        file_size_bytes,
        last_modified_unix_s,
        record_count,
    })
}

/// Validates that raw bytes represent a readable MMDB database.
///
/// # Errors
///
/// Returns [`GeoError`] when the byte slice cannot be parsed as an MMDB reader.
pub fn validate_mmdb_bytes(bytes: &[u8]) -> Result<(), GeoError> {
    Reader::from_source(bytes).map(|_| ()).map_err(geo_error)
}

/// A recoverable `GeoIP` lookup failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeoError(String);

impl GeoError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for GeoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for GeoError {}

/// Provides optional local destination intelligence without network access.
pub trait GeoProvider: Send + Sync {
    /// Looks up an IPv4 or IPv6 address using default English or fallback locale.
    ///
    /// `Ok(None)` means that the provider is disabled or has no record for the
    /// address. Callers should preserve traffic data in that case.
    ///
    /// # Errors
    ///
    /// Returns an error when an enabled provider cannot read or decode its
    /// local data source for this address.
    fn lookup(&self, ip: IpAddr) -> Result<Option<GeoRecord>, GeoError> {
        self.lookup_with_lang(ip, None)
    }

    /// Looks up an IPv4 or IPv6 address with an optional requested language tag (e.g. `zh-CN`, `en`).
    ///
    /// # Errors
    ///
    /// Returns an error when an enabled provider cannot read or decode its
    /// local data source for this address.
    fn lookup_with_lang(
        &self,
        ip: IpAddr,
        _lang: Option<&str>,
    ) -> Result<Option<GeoRecord>, GeoError> {
        self.lookup(ip)
    }

    /// Reports whether at least one backing data source is available.
    fn is_enabled(&self) -> bool;
}

/// Provider used when no local Geo database is installed.
#[derive(Clone, Copy, Debug, Default)]
pub struct DisabledGeoProvider;

impl GeoProvider for DisabledGeoProvider {
    fn lookup(&self, _ip: IpAddr) -> Result<Option<GeoRecord>, GeoError> {
        Ok(None)
    }

    fn lookup_with_lang(
        &self,
        _ip: IpAddr,
        _lang: Option<&str>,
    ) -> Result<Option<GeoRecord>, GeoError> {
        Ok(None)
    }

    fn is_enabled(&self) -> bool {
        false
    }
}

#[derive(Debug)]
enum DatabaseReader {
    City(Reader<Vec<u8>>),
    Country(Reader<Vec<u8>>),
    Asn(Reader<Vec<u8>>),
}

/// A local provider assembled from supported `*.mmdb` files in one directory.
#[derive(Debug, Default)]
pub struct LocalDbProvider {
    databases: Vec<DatabaseReader>,
}

/// Outcome of scanning a directory for local Geo databases.
#[derive(Debug, Default)]
pub struct LocalDbLoad {
    pub provider: LocalDbProvider,
    pub warnings: Vec<String>,
}

impl LocalDbProvider {
    /// Loads every supported `MaxMind` DB file in `directory`.
    ///
    /// A missing directory, an empty directory, corrupt files, and unsupported
    /// database types all leave the provider usable. Problems are returned as
    /// warnings so Controller startup is never blocked by optional enrichment.
    #[must_use]
    pub fn load(directory: &Path) -> LocalDbLoad {
        let mut load = LocalDbLoad::default();
        let entries = match fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return load,
            Err(error) => {
                load.warnings.push(format!(
                    "cannot read Geo database directory {}: {error}",
                    directory.display()
                ));
                return load;
            }
        };
        let mut paths = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("mmdb"))
            })
            .collect::<Vec<_>>();
        paths.sort();
        for path in paths {
            load.provider.add_database(&path, &mut load.warnings);
        }
        load
    }

    fn add_database(&mut self, path: &Path, warnings: &mut Vec<String>) {
        let reader = match Reader::open_readfile(path) {
            Ok(reader) => reader,
            Err(error) => {
                warnings.push(format!(
                    "cannot load Geo database {}: {error}",
                    path.display()
                ));
                return;
            }
        };
        let database_type = reader.metadata().database_type.as_str();
        let database_type_lower = database_type.to_ascii_lowercase();
        let database = if database_type_lower.contains("city") {
            DatabaseReader::City(reader)
        } else if database_type_lower.contains("country") {
            DatabaseReader::Country(reader)
        } else if database_type_lower.contains("asn") {
            DatabaseReader::Asn(reader)
        } else {
            warnings.push(format!(
                "unsupported Geo database type {database_type} in {}",
                path.display()
            ));
            return;
        };
        self.databases.push(database);
    }
}

#[derive(Debug, Deserialize)]
struct FlatCountry<'a> {
    country_code: Option<&'a str>,
    country_name: Option<&'a str>,
}

impl GeoProvider for LocalDbProvider {
    fn lookup(&self, ip: IpAddr) -> Result<Option<GeoRecord>, GeoError> {
        self.lookup_with_lang(ip, None)
    }

    fn lookup_with_lang(
        &self,
        ip: IpAddr,
        lang: Option<&str>,
    ) -> Result<Option<GeoRecord>, GeoError> {
        let mut record = GeoRecord::default();
        for database in &self.databases {
            match database {
                DatabaseReader::City(reader) => merge_city(&mut record, reader, ip, lang)?,
                DatabaseReader::Country(reader) => merge_country(&mut record, reader, ip, lang)?,
                DatabaseReader::Asn(reader) => merge_asn(&mut record, reader, ip)?,
            }
        }
        Ok((!record.is_empty()).then_some(record))
    }

    fn is_enabled(&self) -> bool {
        !self.databases.is_empty()
    }
}

/// Resolves localized string from `MaxMind` `Names` based on language preference.
#[must_use]
pub fn resolve_names<'a>(names: &'a geoip2::Names<'a>, lang: Option<&str>) -> Option<&'a str> {
    if let Some(l) = lang {
        let l_lower = l.to_ascii_lowercase();
        if l_lower.starts_with("zh") {
            if let Some(name) = names.simplified_chinese {
                return Some(name);
            }
        } else if l_lower.starts_with("de") {
            if let Some(name) = names.german {
                return Some(name);
            }
        } else if l_lower.starts_with("es") {
            if let Some(name) = names.spanish {
                return Some(name);
            }
        } else if l_lower.starts_with("fr") {
            if let Some(name) = names.french {
                return Some(name);
            }
        } else if l_lower.starts_with("ja") {
            if let Some(name) = names.japanese {
                return Some(name);
            }
        } else if l_lower.starts_with("pt") {
            if let Some(name) = names.brazilian_portuguese {
                return Some(name);
            }
        } else if l_lower.starts_with("ru") {
            if let Some(name) = names.russian {
                return Some(name);
            }
        } else if l_lower.starts_with("en") {
            if let Some(name) = names.english {
                return Some(name);
            }
        }
    }
    names
        .english
        .or(names.simplified_chinese)
        .or(names.german)
        .or(names.spanish)
        .or(names.french)
        .or(names.japanese)
        .or(names.brazilian_portuguese)
        .or(names.russian)
}

fn merge_city(
    target: &mut GeoRecord,
    reader: &Reader<Vec<u8>>,
    ip: IpAddr,
    lang: Option<&str>,
) -> Result<(), GeoError> {
    let lookup = reader.lookup(ip).map_err(geo_error)?;
    let Some(city) = lookup.decode::<geoip2::City<'_>>().map_err(geo_error)? else {
        return Ok(());
    };
    fill_country(
        target,
        city.country.iso_code,
        resolve_names(&city.country.names, lang),
    );
    target.region = target.region.take().or_else(|| {
        city.subdivisions
            .first()
            .and_then(|region| resolve_names(&region.names, lang).or(region.iso_code))
            .map(str::to_owned)
    });
    target.city = target
        .city
        .take()
        .or_else(|| resolve_names(&city.city.names, lang).map(str::to_owned));
    target.latitude = target.latitude.or(city.location.latitude);
    target.longitude = target.longitude.or(city.location.longitude);
    Ok(())
}

fn merge_country(
    target: &mut GeoRecord,
    reader: &Reader<Vec<u8>>,
    ip: IpAddr,
    lang: Option<&str>,
) -> Result<(), GeoError> {
    let lookup = reader.lookup(ip).map_err(geo_error)?;
    if let Ok(Some(flat)) = lookup.decode::<FlatCountry<'_>>() {
        if flat.country_code.is_some() || flat.country_name.is_some() {
            fill_country(target, flat.country_code, flat.country_name);
            return Ok(());
        }
    }
    let Some(country) = lookup.decode::<geoip2::Country<'_>>().map_err(geo_error)? else {
        return Ok(());
    };
    fill_country(
        target,
        country.country.iso_code,
        resolve_names(&country.country.names, lang),
    );
    Ok(())
}

fn merge_asn(target: &mut GeoRecord, reader: &Reader<Vec<u8>>, ip: IpAddr) -> Result<(), GeoError> {
    let lookup = reader.lookup(ip).map_err(geo_error)?;
    let Some(asn) = lookup.decode::<geoip2::Asn<'_>>().map_err(geo_error)? else {
        return Ok(());
    };
    target.asn = target.asn.or(asn.autonomous_system_number);
    target.organization = target.organization.take().or_else(|| {
        asn.autonomous_system_organization
            .filter(|s| !s.trim().is_empty())
            .map(str::to_owned)
    });
    Ok(())
}

fn fill_country(target: &mut GeoRecord, code: Option<&str>, name: Option<&str>) {
    target.country_code = target
        .country_code
        .take()
        .or_else(|| code.map(str::to_owned));
    target.country_name = target
        .country_name
        .take()
        .or_else(|| name.map(str::to_owned));
}

fn geo_error(error: impl fmt::Display) -> GeoError {
    GeoError::new(error.to_string())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{DisabledGeoProvider, GeoProvider, GeoRecord, LocalDbProvider};

    #[test]
    fn disabled_provider_is_an_explicit_non_error_state() {
        let provider = DisabledGeoProvider;
        assert!(!provider.is_enabled());
        assert_eq!(
            provider.lookup("2001:db8::1".parse().unwrap()).unwrap(),
            None
        );
    }

    #[test]
    fn empty_records_are_detectable() {
        assert!(GeoRecord::default().is_empty());
        assert!(
            !GeoRecord {
                country_code: Some("US".to_owned()),
                ..GeoRecord::default()
            }
            .is_empty()
        );
    }

    #[test]
    fn missing_directory_disables_enrichment_without_an_error() {
        let directory = tempfile::tempdir().unwrap();
        let load = LocalDbProvider::load(&directory.path().join("missing"));
        assert!(!load.provider.is_enabled());
        assert!(load.warnings.is_empty());
    }

    #[test]
    fn corrupt_databases_are_skipped_with_a_warning() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("broken.mmdb"), b"not an mmdb").unwrap();
        let load = LocalDbProvider::load(directory.path());
        assert!(!load.provider.is_enabled());
        assert_eq!(load.warnings.len(), 1);
        assert!(load.warnings[0].contains("broken.mmdb"));
    }

    #[test]
    fn resolve_names_prefers_requested_language_with_fallback() {
        use maxminddb::geoip2::Names;

        let names = Names {
            english: Some("United States"),
            simplified_chinese: Some("美国"),
            german: Some("Vereinigte Staaten"),
            spanish: Some("Estados Unidos"),
            french: Some("États-Unis"),
            japanese: Some("アメリカ合衆国"),
            brazilian_portuguese: Some("Estados Unidos"),
            russian: Some("США"),
        };

        // Exact & prefix match for Chinese
        assert_eq!(super::resolve_names(&names, Some("zh-CN")), Some("美国"));
        assert_eq!(super::resolve_names(&names, Some("zh")), Some("美国"));
        assert_eq!(super::resolve_names(&names, Some("ZH-CN")), Some("美国"));

        // English & German & other languages
        assert_eq!(
            super::resolve_names(&names, Some("en")),
            Some("United States")
        );
        assert_eq!(
            super::resolve_names(&names, Some("en-US")),
            Some("United States")
        );
        assert_eq!(
            super::resolve_names(&names, Some("de")),
            Some("Vereinigte Staaten")
        );
        assert_eq!(
            super::resolve_names(&names, Some("ja")),
            Some("アメリカ合衆国")
        );

        // Fallback when requested language not found
        assert_eq!(
            super::resolve_names(&names, Some("ko")),
            Some("United States")
        );
        assert_eq!(super::resolve_names(&names, None), Some("United States"));

        // Fallback when english is none
        let names_no_en = Names {
            english: None,
            simplified_chinese: Some("中国"),
            ..Names::default()
        };
        assert_eq!(super::resolve_names(&names_no_en, Some("en")), Some("中国"));
        assert_eq!(super::resolve_names(&names_no_en, None), Some("中国"));
    }

    #[test]
    fn local_db_provider_loads_country_and_asn_with_ipvall_types() {
        let dir = std::path::Path::new("../../target/geo");
        let has_city =
            dir.join("GeoLite2-City.mmdb").exists() || dir.join("Geo-Country.mmdb").exists();
        let has_asn = dir.join("GeoLite2-ASN.mmdb").exists() || dir.join("Geo-ASN.mmdb").exists();
        if has_city && has_asn {
            let load = LocalDbProvider::load(dir);
            assert!(
                load.warnings.is_empty(),
                "unexpected warnings: {:?}",
                load.warnings
            );
            assert!(load.provider.is_enabled());

            let record_8888 = load
                .provider
                .lookup("8.8.8.8".parse().unwrap())
                .unwrap()
                .unwrap();
            assert_eq!(record_8888.country_code.as_deref(), Some("US"));
            assert_eq!(record_8888.asn, Some(15169));

            let record_cn = load
                .provider
                .lookup_with_lang("223.5.5.5".parse().unwrap(), Some("zh-CN"))
                .unwrap()
                .unwrap();
            assert_eq!(record_cn.country_code.as_deref(), Some("CN"));
            assert!(record_cn.asn.is_some());
        }
    }
}
