use deadpool_postgres::Pool;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info};

pub struct SensitiveMatch {
    pub json_path: String,
    pub redact: bool,
}

pub struct SensitiveFieldRegistry {
    global_fields: Vec<String>,
    db_fields: Arc<RwLock<HashMap<String, Vec<DbSensitiveField>>>>,
    pool: Pool,
}

struct DbSensitiveField {
    json_path: String,
    redact_in_log: bool,
}

impl SensitiveFieldRegistry {
    pub fn new(pool: Pool, global_fields_csv: &str) -> Self {
        let global_fields: Vec<String> = global_fields_csv
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        if !global_fields.is_empty() {
            info!(count = global_fields.len(), "loaded global sensitive fields");
        }

        Self {
            global_fields,
            db_fields: Arc::new(RwLock::new(HashMap::new())),
            pool,
        }
    }

    pub async fn refresh_cache(&self) {
        let client = match self.pool.get().await {
            Ok(c) => c,
            Err(e) => {
                error!("failed to get db connection for sensitive fields: {}", e);
                return;
            }
        };

        let rows = match client
            .query(
                "SELECT schema_name, table_name, json_path, redact_in_log \
                 FROM vibe_audit.sensitive_fields",
                &[],
            )
            .await
        {
            Ok(r) => r,
            Err(e) => {
                error!("failed to query sensitive_fields: {}", e);
                return;
            }
        };

        let mut map: HashMap<String, Vec<DbSensitiveField>> = HashMap::new();
        for row in &rows {
            let schema: &str = row.get(0);
            let table: &str = row.get(1);
            let json_path: &str = row.get(2);
            let redact: bool = row.get(3);

            let key = format!("{}.{}", schema, table);
            map.entry(key).or_default().push(DbSensitiveField {
                json_path: json_path.to_string(),
                redact_in_log: redact,
            });
        }

        let count: usize = map.values().map(|v| v.len()).sum();
        info!(tables = map.len(), fields = count, "refreshed sensitive field cache");

        let mut cache = self.db_fields.write().await;
        *cache = map;
    }

    pub async fn detect(
        &self,
        schema: &str,
        table: &str,
        changed_fields: &[String],
    ) -> Vec<SensitiveMatch> {
        let mut matches = Vec::new();

        for field in changed_fields {
            let normalized = field.trim_start_matches("$.");
            if self.global_fields.iter().any(|g| g == normalized || g == field) {
                matches.push(SensitiveMatch {
                    json_path: field.clone(),
                    redact: true,
                });
            }
        }

        let key = format!("{}.{}", schema, table);
        let cache = self.db_fields.read().await;
        if let Some(db_fields) = cache.get(&key) {
            for field in changed_fields {
                let normalized = field.trim_start_matches("$.");
                for db_field in db_fields {
                    let db_normalized = db_field.json_path.trim_start_matches("$.");
                    if db_normalized == normalized || db_normalized == field {
                        if !matches.iter().any(|m| m.json_path == *field) {
                            matches.push(SensitiveMatch {
                                json_path: field.clone(),
                                redact: db_field.redact_in_log,
                            });
                        }
                    }
                }
            }
        }

        matches
    }

    pub fn redact(doc: &mut Value, matches: &[SensitiveMatch]) {
        if let Value::Object(map) = doc {
            for m in matches {
                if !m.redact {
                    continue;
                }
                let key = m.json_path.trim_start_matches("$.");
                if map.contains_key(key) {
                    map.insert(key.to_string(), Value::String("[REDACTED]".to_string()));
                }
            }
        }
    }
}

pub fn diff_fields(old: &Value, new: &Value) -> Vec<String> {
    let mut changed = Vec::new();

    match (old, new) {
        (Value::Object(old_map), Value::Object(new_map)) => {
            for (key, new_val) in new_map {
                match old_map.get(key) {
                    Some(old_val) if old_val == new_val => {}
                    _ => changed.push(key.clone()),
                }
            }
            for key in old_map.keys() {
                if !new_map.contains_key(key) {
                    changed.push(key.clone());
                }
            }
        }
        _ => {}
    }

    changed
}

pub fn all_fields(doc: &Value) -> Vec<String> {
    match doc {
        Value::Object(map) => map.keys().cloned().collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_diff_fields_detects_changes() {
        let old = json!({"name": "Alice", "email": "a@b.com", "role": "user"});
        let new = json!({"name": "Alice", "email": "a@c.com", "role": "admin"});

        let changed = diff_fields(&old, &new);
        assert!(changed.contains(&"email".to_string()));
        assert!(changed.contains(&"role".to_string()));
        assert!(!changed.contains(&"name".to_string()));
    }

    #[test]
    fn test_diff_fields_detects_added() {
        let old = json!({"name": "Alice"});
        let new = json!({"name": "Alice", "card_number": "4111111111111111"});

        let changed = diff_fields(&old, &new);
        assert!(changed.contains(&"card_number".to_string()));
        assert!(!changed.contains(&"name".to_string()));
    }

    #[test]
    fn test_diff_fields_detects_removed() {
        let old = json!({"name": "Alice", "ssn": "123-45-6789"});
        let new = json!({"name": "Alice"});

        let changed = diff_fields(&old, &new);
        assert!(changed.contains(&"ssn".to_string()));
    }

    #[test]
    fn test_all_fields() {
        let doc = json!({"a": 1, "b": 2, "c": 3});
        let fields = all_fields(&doc);
        assert_eq!(fields.len(), 3);
    }

    #[test]
    fn test_redact() {
        let mut doc = json!({"name": "Alice", "card_number": "4111111111111111", "cvv": "123"});
        let matches = vec![
            SensitiveMatch { json_path: "card_number".to_string(), redact: true },
            SensitiveMatch { json_path: "cvv".to_string(), redact: true },
        ];

        SensitiveFieldRegistry::redact(&mut doc, &matches);

        assert_eq!(doc["card_number"], "[REDACTED]");
        assert_eq!(doc["cvv"], "[REDACTED]");
        assert_eq!(doc["name"], "Alice");
    }

    #[test]
    fn test_redact_respects_flag() {
        let mut doc = json!({"card_number": "4111111111111111", "email": "a@b.com"});
        let matches = vec![
            SensitiveMatch { json_path: "card_number".to_string(), redact: true },
            SensitiveMatch { json_path: "email".to_string(), redact: false },
        ];

        SensitiveFieldRegistry::redact(&mut doc, &matches);

        assert_eq!(doc["card_number"], "[REDACTED]");
        assert_eq!(doc["email"], "a@b.com");
    }
}
