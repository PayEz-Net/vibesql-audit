use deadpool_postgres::{Config, Pool, Runtime};
use serde_json::Value;
use tokio_postgres::NoTls;
use tracing::{error, info};

pub struct BatchWriter {
    pool: Pool,
}

impl BatchWriter {
    pub fn pool(&self) -> &Pool {
        &self.pool
    }

    pub async fn new(db_url: &str) -> Self {
        let mut cfg = Config::new();
        cfg.url = Some(db_url.to_string());
        let pool = cfg
            .create_pool(Some(Runtime::Tokio1), NoTls)
            .expect("failed to create database pool");

        let writer = Self { pool };
        writer.ensure_partition().await;
        writer
    }

    pub async fn ensure_partition(&self) {
        match self.pool.get().await {
            Ok(client) => {
                match client
                    .execute("SELECT vibe_audit.ensure_partition(CURRENT_DATE)", &[])
                    .await
                {
                    Ok(_) => info!("partition ensured for current month"),
                    Err(e) => error!("failed to ensure partition: {}", e),
                }
            }
            Err(e) => error!("failed to get db connection for partition: {}", e),
        }
    }

    pub async fn write_batch(&self, events: &[Value]) {
        if events.is_empty() {
            return;
        }

        let client = match self.pool.get().await {
            Ok(c) => c,
            Err(e) => {
                error!("failed to get db connection: {}", e);
                return;
            }
        };

        let stmt = "INSERT INTO vibe_audit.events \
            (event_type, event_time, success, session_user, client_addr, client_port, \
             database, pid, application, command_tag, object_type, object_name, \
             schema_name, query_text, sqlstate, detail, prev_hash, event_hash) \
            VALUES ($1, $2::timestamptz, $3, $4, $5::inet, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16::jsonb, $17, $18)";

        let prepared = match client.prepare(stmt).await {
            Ok(s) => s,
            Err(e) => {
                error!("failed to prepare insert: {}", e);
                return;
            }
        };

        for event in events {
            let event_type = event["event_type"].as_str().unwrap_or("UNKNOWN");
            let event_time = event["event_time"].as_str().unwrap_or("1970-01-01T00:00:00Z");
            let success = event["success"].as_bool().unwrap_or(false);
            let session_user = str_or_null(&event["session_user"]);
            let client_addr = str_or_null(&event["client_addr"]);
            let client_port = event["client_port"].as_i64().map(|v| v as i32);
            let database = str_or_null(&event["database"]);
            let pid = event["pid"].as_i64().map(|v| v as i32);
            let application = str_or_null(&event["application"]);
            let command_tag = str_or_null(&event["command_tag"]);
            let object_type = str_or_null(&event["object_type"]);
            let object_name = str_or_null(&event["object_name"]);
            let schema_name = str_or_null(&event["schema_name"]);
            let query_text = str_or_null(&event["query_text"]);
            let sqlstate = str_or_null(&event["sqlstate"]);
            let detail = if event["detail"].is_null() {
                None
            } else {
                Some(event["detail"].to_string())
            };
            let prev_hash = str_or_null(&event["prev_hash"]);
            let event_hash = str_or_null(&event["event_hash"]);

            if let Err(e) = client
                .execute(
                    &prepared,
                    &[
                        &event_type,
                        &event_time,
                        &success,
                        &session_user,
                        &client_addr,
                        &client_port,
                        &database,
                        &pid,
                        &application,
                        &command_tag,
                        &object_type,
                        &object_name,
                        &schema_name,
                        &query_text,
                        &sqlstate,
                        &detail,
                        &prev_hash,
                        &event_hash,
                    ],
                )
                .await
            {
                error!("failed to insert audit event: {}", e);
            }
        }

        info!("wrote batch of {} events", events.len());
    }
}

fn str_or_null(v: &Value) -> Option<String> {
    v.as_str().map(|s| s.to_string())
}
