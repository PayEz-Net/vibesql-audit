use deadpool_postgres::{Config, Pool, Runtime};
use serde_json::Value;
use tokio_postgres::NoTls;
use tracing::{error, info, warn};

pub struct BatchWriter {
    pool: Pool,
    retry_queue: tokio::sync::Mutex<Vec<Value>>,
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

        let writer = Self {
            pool,
            retry_queue: tokio::sync::Mutex::new(Vec::new()),
        };
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

        let mut retries = {
            let mut q = self.retry_queue.lock().await;
            std::mem::take(&mut *q)
        };

        let all_events: Vec<&Value> = retries.iter().chain(events.iter()).collect();

        let client = match self.pool.get().await {
            Ok(c) => c,
            Err(e) => {
                error!("failed to get db connection: {}", e);
                self.enqueue_retries(events).await;
                return;
            }
        };

        let mut query = String::from(
            "INSERT INTO vibe_audit.events \
            (event_type, event_time, success, session_user, client_addr, client_port, \
             database, pid, application, command_tag, object_type, object_name, \
             schema_name, query_text, sqlstate, detail, prev_hash, event_hash) VALUES "
        );

        let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> = Vec::new();
        let mut param_idx = 1u32;

        for (i, event) in all_events.iter().enumerate() {
            if i > 0 {
                query.push_str(", ");
            }
            query.push_str(&format!(
                "(${}, ${}::timestamptz, ${}, ${}, ${}::inet, ${}, ${}, ${}, ${}, ${}, ${}, ${}, ${}, ${}, ${}, ${}::jsonb, ${}, ${})",
                param_idx, param_idx + 1, param_idx + 2, param_idx + 3,
                param_idx + 4, param_idx + 5, param_idx + 6, param_idx + 7,
                param_idx + 8, param_idx + 9, param_idx + 10, param_idx + 11,
                param_idx + 12, param_idx + 13, param_idx + 14, param_idx + 15,
                param_idx + 16, param_idx + 17
            ));
            param_idx += 18;

            let event_type = str_val(&event["event_type"]).unwrap_or_else(|| "UNKNOWN".to_string());
            let event_time = str_val(&event["event_time"]).unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string());
            let success = event["success"].as_bool().unwrap_or(false);
            let session_user = str_val(&event["session_user"]);
            let client_addr = str_val(&event["client_addr"]);
            let client_port = event["client_port"].as_i64().map(|v| v as i32);
            let database = str_val(&event["database"]);
            let pid = event["pid"].as_i64().map(|v| v as i32);
            let application = str_val(&event["application"]);
            let command_tag = str_val(&event["command_tag"]);
            let object_type = str_val(&event["object_type"]);
            let object_name = str_val(&event["object_name"]);
            let schema_name = str_val(&event["schema_name"]);
            let query_text = str_val(&event["query_text"]);
            let sqlstate = str_val(&event["sqlstate"]);
            let detail: Option<String> = if event["detail"].is_null() {
                None
            } else {
                Some(event["detail"].to_string())
            };
            let prev_hash = str_val(&event["prev_hash"]);
            let event_hash = str_val(&event["event_hash"]);

            params.push(Box::new(event_type));
            params.push(Box::new(event_time));
            params.push(Box::new(success));
            params.push(Box::new(session_user));
            params.push(Box::new(client_addr));
            params.push(Box::new(client_port));
            params.push(Box::new(database));
            params.push(Box::new(pid));
            params.push(Box::new(application));
            params.push(Box::new(command_tag));
            params.push(Box::new(object_type));
            params.push(Box::new(object_name));
            params.push(Box::new(schema_name));
            params.push(Box::new(query_text));
            params.push(Box::new(sqlstate));
            params.push(Box::new(detail));
            params.push(Box::new(prev_hash));
            params.push(Box::new(event_hash));
        }

        let param_refs: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
            params.iter().map(|p| p.as_ref() as &(dyn tokio_postgres::types::ToSql + Sync)).collect();

        match client.execute(&query as &str, &param_refs).await {
            Ok(_) => {
                let total = all_events.len();
                let retry_count = retries.len();
                if retry_count > 0 {
                    info!(total, retried = retry_count, "wrote batch with retries");
                } else {
                    info!(total, "wrote batch of events");
                }
                retries.clear();
            }
            Err(e) => {
                error!("batch insert failed: {}, queuing {} events for retry", e, all_events.len());
                let mut q = self.retry_queue.lock().await;
                let max_retry = 10_000;
                for event in retries.into_iter().chain(events.iter().cloned()) {
                    if q.len() >= max_retry {
                        warn!("retry queue full ({} events), dropping oldest", max_retry);
                        q.remove(0);
                    }
                    q.push(event);
                }
                if !q.is_empty() {
                    warn!(queued = q.len(), "events queued for retry");
                }
            }
        }
    }

    async fn enqueue_retries(&self, events: &[Value]) {
        let mut q = self.retry_queue.lock().await;
        let max_retry = 10_000;
        for event in events {
            if q.len() >= max_retry {
                warn!("retry queue full ({} events), dropping oldest", max_retry);
                q.remove(0);
            }
            q.push(event.clone());
        }
        if !events.is_empty() {
            warn!(queued = q.len(), "events queued for retry");
        }
    }
}

fn str_val(v: &Value) -> Option<String> {
    v.as_str().map(|s| s.to_string())
}
