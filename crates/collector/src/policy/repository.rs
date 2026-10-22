use std::fs::{self, OpenOptions};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use rusqlite::Connection;

pub(crate) struct PolicyRepository {
    connection: Mutex<Connection>,
}

impl PolicyRepository {
    pub(crate) fn open(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)
                .map_err(|error| format!("create policy database directory: {error}"))?;
        }
        if !path.exists() {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            drop(
                options
                    .open(path)
                    .map_err(|error| format!("create policy database file: {error}"))?,
            );
        }
        let connection =
            Connection::open(path).map_err(|error| format!("open policy database: {error}"))?;
        Self::configure(connection, Some(path))
    }

    pub(crate) fn open_in_memory() -> Result<Self, String> {
        let connection = Connection::open_in_memory()
            .map_err(|error| format!("open in-memory policy database: {error}"))?;
        Self::configure(connection, None)
    }

    fn configure(connection: Connection, path: Option<&Path>) -> Result<Self, String> {
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(|error| format!("configure policy database busy timeout: {error}"))?;
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .map_err(|error| format!("enable policy database foreign keys: {error}"))?;
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(|error| format!("enable policy database WAL: {error}"))?;
        connection
            .pragma_update(None, "synchronous", "NORMAL")
            .map_err(|error| format!("configure policy database durability: {error}"))?;
        migrate(&connection)?;
        #[cfg(unix)]
        if let Some(path) = path {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .map_err(|error| format!("restrict policy database file permissions: {error}"))?;
        }
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    pub(crate) fn lock(&self) -> Result<MutexGuard<'_, Connection>, String> {
        self.connection
            .lock()
            .map_err(|_| "policy database lock is unavailable".to_owned())
    }
}

fn migrate(connection: &Connection) -> Result<(), String> {
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS policy_schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at_ms INTEGER NOT NULL
            );",
        )
        .map_err(|error| format!("initialize policy migration ledger: {error}"))?;
    for (version, sql) in [(
        1,
        include_str!("../../../../migrations/policy/0001_initial.sql"),
    )] {
        let applied: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM policy_schema_migrations WHERE version = ?1)",
                [version],
                |row| row.get(0),
            )
            .map_err(|error| format!("read policy migration ledger: {error}"))?;
        if applied {
            continue;
        }
        let transaction = connection
            .unchecked_transaction()
            .map_err(|error| format!("begin policy database migration {version}: {error}"))?;
        transaction
            .execute_batch(sql)
            .map_err(|error| format!("apply policy database migration {version}: {error}"))?;
        transaction
            .execute(
                "INSERT INTO policy_schema_migrations(version, applied_at_ms) VALUES (?1, ?2)",
                rusqlite::params![
                    version,
                    i64::try_from(crate::unix_time_ms()).unwrap_or(i64::MAX)
                ],
            )
            .map_err(|error| format!("record policy database migration {version}: {error}"))?;
        transaction
            .commit()
            .map_err(|error| format!("commit policy database migration {version}: {error}"))?;
    }
    Ok(())
}
