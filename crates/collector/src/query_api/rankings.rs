//! Rankings use minute rollups without computing detail-only flow statistics.

use super::{Page, SqlValue, Value, icon_json, json, page_ok, storage_error, to_i64, to_u64};
use axum::response::Response;

pub(super) fn applications(
    inner: &crate::QueryContext<'_>,
    page: Page,
    window: Option<(i64, i64)>,
) -> Response {
    let result = (|| -> rusqlite::Result<(Vec<Value>, u64)> {
        let (filter, mut values) = match window {
            Some((from, to)) => (
                "WHERE timestamp >= ?1 AND timestamp < ?2",
                vec![SqlValue::Integer(from), SqlValue::Integer(to)],
            ),
            None => ("", Vec::new()),
        };
        let sql = format!(
            "SELECT application_id, category_id, SUM(upload_bytes), SUM(download_bytes),
                    SUM(packets), SUM(flow_count), MAX(timestamp), COUNT(*) OVER ()
             FROM traffic_application_minute {filter}
             GROUP BY application_id, category_id
             ORDER BY SUM(upload_bytes) + SUM(download_bytes) DESC, application_id
             LIMIT ? OFFSET ?"
        );
        let count_values = values.clone();
        values.push(SqlValue::Integer(i64::from(page.limit)));
        values.push(SqlValue::Integer(to_i64(page.offset)));
        let mut statement = inner.storage.connection().prepare(&sql)?;
        let totals = statement
            .query_map(rusqlite::params_from_iter(values), |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let total = if let Some(row) = totals.first() {
            to_u64(row.7)
        } else {
            let count_sql = format!(
                "SELECT COUNT(*) FROM (SELECT application_id, category_id FROM traffic_application_minute {filter} GROUP BY application_id, category_id)"
            );
            inner.storage.connection().query_row(
                &count_sql,
                rusqlite::params_from_iter(count_values),
                |row| row.get::<_, i64>(0).map(to_u64),
            )?
        };
        let items = totals
            .into_iter()
            .map(
                |(id, category, upload, download, packets, flows, last_seen, _)| {
                    let metadata = inner.classifier.application_metadata(&id);
                    json!({
                        "application_id": id,
                        "category_id": category,
                        "name": metadata.as_ref().map(|value| value.name.clone()),
                        "icon": icon_json(metadata),
                        "upload_bytes": upload,
                        "download_bytes": download,
                        "packets": packets,
                        "flow_count": flows,
                        "last_seen": last_seen,
                    })
                },
            )
            .collect();
        Ok((items, total))
    })();
    result.map_or_else(storage_error, |(items, total)| page_ok(items, page, total))
}
