use crate::sensitive::{self, SensitiveFieldRegistry};
use deadpool_postgres::Pool;
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

pub struct WalCaptureConfig {
    pub slot_name: String,
}

pub async fn run(
    config: WalCaptureConfig,
    tx: mpsc::Sender<Value>,
    registry: Arc<SensitiveFieldRegistry>,
    wal_event_count: Arc<std::sync::atomic::AtomicU64>,
    wal_lsn: Arc<tokio::sync::RwLock<String>>,
    pool: Pool,
) {
    loop {
        match run_inner(&config, &tx, &registry, &wal_event_count, &wal_lsn, &pool).await {
            Ok(_) => {
                warn!("WAL capture poll loop ended, restarting in 5s");
            }
            Err(e) => {
                error!("WAL capture error: {}, restarting in 5s", e);
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}

async fn run_inner(
    config: &WalCaptureConfig,
    tx: &mpsc::Sender<Value>,
    registry: &Arc<SensitiveFieldRegistry>,
    wal_event_count: &Arc<std::sync::atomic::AtomicU64>,
    wal_lsn: &Arc<tokio::sync::RwLock<String>>,
    pool: &Pool,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = pool.get().await?;

    let slot_exists: bool = client
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM pg_replication_slots WHERE slot_name = $1)",
            &[&config.slot_name],
        )
        .await?
        .get(0);

    if !slot_exists {
        info!(slot = %config.slot_name, "creating logical replication slot with test_decoding");
        client
            .execute(
                "SELECT pg_create_logical_replication_slot($1, 'test_decoding')",
                &[&config.slot_name],
            )
            .await?;
    }

    info!(
        slot = %config.slot_name,
        "WAL capture started (polling mode with test_decoding)"
    );

    let poll_interval = std::time::Duration::from_millis(200);

    loop {
        let rows = client
            .query(
                "SELECT lsn::text, xid::text, data FROM pg_logical_slot_get_changes($1, NULL, 500)",
                &[&config.slot_name],
            )
            .await?;

        if rows.is_empty() {
            tokio::time::sleep(poll_interval).await;
            continue;
        }

        for row in &rows {
            let lsn_str: &str = row.get(0);
            let xid_str: &str = row.get(1);
            let data: &str = row.get(2);

            {
                let mut lsn = wal_lsn.write().await;
                *lsn = lsn_str.to_string();
            }

            if let Some(events) = parse_test_decoding(data, xid_str, lsn_str, registry.clone()).await {
                for event in events {
                    wal_event_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if tx.send(event).await.is_err() {
                        error!("event channel closed");
                        return Ok(());
                    }
                }
            }
        }
    }
}

async fn parse_test_decoding(
    data: &str,
    xid: &str,
    lsn: &str,
    registry: Arc<SensitiveFieldRegistry>,
) -> Option<Vec<Value>> {
    if data.starts_with("BEGIN") || data.starts_with("COMMIT") {
        return None;
    }

    let (command_tag, schema, table, columns) = parse_change_line(data)?;

    let (old_data, new_data) = match command_tag.as_str() {
        "INSERT" => {
            let new_doc = columns_to_jsonb_owned(&columns, false);
            (None, Some(new_doc))
        }
        "UPDATE" => {
            let (old_cols, new_cols) = split_old_new_columns(&columns);
            let old_doc = if old_cols.is_empty() {
                None
            } else {
                Some(columns_to_jsonb_refs(&old_cols, false))
            };
            let new_doc = columns_to_jsonb_refs(&new_cols, false);
            (old_doc, Some(new_doc))
        }
        "DELETE" => {
            let old_doc = columns_to_jsonb_owned(&columns, false);
            (Some(old_doc), None)
        }
        _ => return None,
    };

    let changed_fields = match (&old_data, &new_data) {
        (Some(old), Some(new)) => sensitive::diff_fields(old, new),
        (None, Some(new)) => sensitive::all_fields(new),
        (Some(old), None) => sensitive::all_fields(old),
        (None, None) => Vec::new(),
    };

    let matches = registry.detect(&schema, &table, &changed_fields).await;

    let mut old_out = old_data;
    let mut new_out = new_data;
    if !matches.is_empty() {
        if let Some(ref mut o) = old_out {
            SensitiveFieldRegistry::redact(o, &matches);
        }
        if let Some(ref mut n) = new_out {
            SensitiveFieldRegistry::redact(n, &matches);
        }
    }

    let event = build_data_change_event(
        &command_tag,
        &schema,
        &table,
        old_out,
        new_out,
        &changed_fields,
        &matches,
        xid,
        lsn,
    );
    Some(vec![event])
}

struct ParsedColumn {
    name: String,
    value: String,
    is_old: bool,
}

fn parse_change_line(data: &str) -> Option<(String, String, String, Vec<ParsedColumn>)> {
    let data = data.trim();

    let (command, rest) = if data.starts_with("table ") {
        ("UPDATE".to_string(), data)
    } else {
        let space = data.find(' ')?;
        let cmd = data[..space].to_string();
        (cmd, &data[space + 1..])
    };

    let command_tag = if rest.starts_with("table ") {
        let after = &rest[6..];
        let colon = after.find(':')?;
        let full_table = &after[..colon];

        let (schema, table) = if let Some(dot) = full_table.find('.') {
            (full_table[..dot].to_string(), full_table[dot + 1..].to_string())
        } else {
            ("public".to_string(), full_table.to_string())
        };

        let col_data = after[colon + 1..].trim();
        let columns = parse_column_values(col_data);

        return Some((command, schema, table, columns));
    } else {
        command
    };

    let colon = rest.find(':')?;
    let full_table = rest[..colon].trim();
    let (schema, table) = if let Some(dot) = full_table.find('.') {
        (full_table[..dot].to_string(), full_table[dot + 1..].to_string())
    } else {
        ("public".to_string(), full_table.to_string())
    };

    let col_data = rest[colon + 1..].trim();
    let columns = parse_column_values(col_data);

    Some((command_tag, schema, table, columns))
}

fn parse_column_values(data: &str) -> Vec<ParsedColumn> {
    let mut columns = Vec::new();
    let mut is_old = false;

    let parts: Vec<&str> = data.split_whitespace().collect();
    let mut i = 0;

    while i < parts.len() {
        if parts[i] == "old-key:" {
            is_old = true;
            i += 1;
            continue;
        }
        if parts[i] == "new-tuple:" {
            is_old = false;
            i += 1;
            continue;
        }

        let part = parts[i];
        if let Some(bracket_pos) = part.find('[') {
            let name = &part[..bracket_pos];
            let rest_of_col = &part[bracket_pos..];

            if let Some(colon_pos) = rest_of_col.find(':') {
                let mut value = rest_of_col[colon_pos + 1..].to_string();

                if value.starts_with('\'') {
                    value = value.trim_start_matches('\'').to_string();
                    while !value.ends_with('\'') && i + 1 < parts.len() {
                        i += 1;
                        value.push(' ');
                        value.push_str(parts[i]);
                    }
                    value = value.trim_end_matches('\'').to_string();
                }

                columns.push(ParsedColumn {
                    name: name.to_string(),
                    value,
                    is_old,
                });
            }
        }

        i += 1;
    }

    columns
}

fn split_old_new_columns(columns: &[ParsedColumn]) -> (Vec<&ParsedColumn>, Vec<&ParsedColumn>) {
    let old: Vec<&ParsedColumn> = columns.iter().filter(|c| c.is_old).collect();
    let new: Vec<&ParsedColumn> = columns.iter().filter(|c| !c.is_old).collect();
    (old, new)
}

fn columns_to_jsonb_owned(columns: &[ParsedColumn], _is_old: bool) -> Value {
    let mut map = serde_json::Map::new();
    for col in columns {
        insert_column_value(&mut map, col);
    }
    Value::Object(map)
}

fn columns_to_jsonb_refs(columns: &[&ParsedColumn], _is_old: bool) -> Value {
    let mut map = serde_json::Map::new();
    for col in columns {
        insert_column_value(&mut map, col);
    }
    Value::Object(map)
}

fn insert_column_value(map: &mut serde_json::Map<String, Value>, col: &ParsedColumn) {
    if col.value == "null" {
        map.insert(col.name.clone(), Value::Null);
    } else if let Ok(parsed) = serde_json::from_str::<Value>(&col.value) {
        if col.name == "data" || parsed.is_object() || parsed.is_array() {
            map.insert(col.name.clone(), parsed);
            return;
        }
        map.insert(col.name.clone(), Value::String(col.value.clone()));
    } else {
        map.insert(col.name.clone(), Value::String(col.value.clone()));
    }
}

fn build_data_change_event(
    command_tag: &str,
    schema: &str,
    table: &str,
    old_data: Option<Value>,
    new_data: Option<Value>,
    changed_fields: &[String],
    sensitive_matches: &[sensitive::SensitiveMatch],
    xid: &str,
    lsn: &str,
) -> Value {
    let sensitive_touched: Vec<&str> = sensitive_matches
        .iter()
        .map(|m| m.json_path.as_str())
        .collect();

    json!({
        "event_type": "DATA_CHANGE",
        "event_time": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "success": true,
        "session_user": null,
        "client_addr": null,
        "client_port": null,
        "database": null,
        "pid": null,
        "application": "vibe_audit_forwarder",
        "command_tag": command_tag,
        "object_type": "TABLE",
        "object_name": table,
        "schema_name": schema,
        "query_text": null,
        "sqlstate": null,
        "detail": {
            "source": "wal",
            "xid": xid,
            "lsn": lsn,
            "old_data": old_data,
            "new_data": new_data,
            "changed_fields": changed_fields,
            "sensitive_fields_touched": sensitive_touched,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_insert_line() {
        let line = "table public.users: INSERT: id[integer]:1 data[jsonb]:'{\"name\": \"Alice\"}'";
        let (cmd, schema, table, cols) = parse_change_line(line).unwrap();
        assert_eq!(cmd, "UPDATE");
        assert_eq!(schema, "public");
        assert_eq!(table, "users");
        assert!(!cols.is_empty());
    }

    #[test]
    fn test_columns_to_jsonb_parses_json_data() {
        let cols = vec![
            ParsedColumn {
                name: "id".to_string(),
                value: "1".to_string(),
                is_old: false,
            },
            ParsedColumn {
                name: "data".to_string(),
                value: r#"{"name": "Alice", "email": "alice@test.com"}"#.to_string(),
                is_old: false,
            },
        ];

        let result = columns_to_jsonb_owned(&cols, false);
        assert!(result.is_object());
        assert!(result["data"].is_object());
        assert_eq!(result["data"]["name"], "Alice");
    }
}
