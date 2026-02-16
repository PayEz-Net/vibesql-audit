use serde_json::Value;
use sha2::{Digest, Sha256};

pub struct HashChain {
    prev_hash: String,
    chain_length: u64,
}

impl HashChain {
    pub fn new() -> Self {
        Self {
            prev_hash: String::new(),
            chain_length: 0,
        }
    }

    pub fn apply(&mut self, event: &mut Value) -> (String, String) {
        let payload = build_payload(event);

        let mut hasher = Sha256::new();
        hasher.update(self.prev_hash.as_bytes());
        hasher.update(payload.as_bytes());
        let event_hash = hex::encode(hasher.finalize());

        let prev = self.prev_hash.clone();

        event["prev_hash"] = Value::String(prev.clone());
        event["event_hash"] = Value::String(event_hash.clone());

        self.prev_hash = event_hash.clone();
        self.chain_length += 1;

        (prev, event_hash)
    }

    pub fn chain_length(&self) -> u64 {
        self.chain_length
    }
}

fn build_payload(event: &Value) -> String {
    let event_type = event["event_type"].as_str().unwrap_or("");
    let event_time = event["event_time"].as_str().unwrap_or("");
    let session_user = event["session_user"].as_str().unwrap_or("");
    let database = event["database"].as_str().unwrap_or("");
    let command_tag = event["command_tag"].as_str().unwrap_or("");
    let query_text = event["query_text"].as_str().unwrap_or("");

    format!(
        "{}|{}|{}|{}|{}|{}",
        event_type, event_time, session_user, database, command_tag, query_text
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_chain_produces_hashes() {
        let mut chain = HashChain::new();
        let mut event = json!({
            "event_type": "AUTH_SUCCESS",
            "event_time": "2026-01-01T00:00:00Z",
            "session_user": "admin",
            "database": "vibesql",
            "command_tag": "authentication",
            "query_text": null
        });

        chain.apply(&mut event);

        assert!(event["prev_hash"].is_string());
        assert!(event["event_hash"].is_string());
        assert_eq!(event["prev_hash"].as_str().unwrap(), "");
        assert_eq!(chain.chain_length(), 1);
    }

    #[test]
    fn test_chain_links() {
        let mut chain = HashChain::new();

        let mut e1 = json!({"event_type":"A","event_time":"t1","session_user":"u","database":"d","command_tag":"c","query_text":""});
        let mut e2 = json!({"event_type":"B","event_time":"t2","session_user":"u","database":"d","command_tag":"c","query_text":""});

        chain.apply(&mut e1);
        chain.apply(&mut e2);

        assert_eq!(
            e2["prev_hash"].as_str().unwrap(),
            e1["event_hash"].as_str().unwrap()
        );
        assert_eq!(chain.chain_length(), 2);
    }
}
