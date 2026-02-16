use flate2::write::GzEncoder;
use flate2::Compression;
use serde_json::{json, Value};
use std::io::Write;
use std::net::UdpSocket;
use tracing::{debug, error};

pub struct GelfForwarder {
    socket: UdpSocket,
    target: String,
    hostname: String,
}

impl GelfForwarder {
    pub fn new(host: &str, port: u16) -> Self {
        let socket = UdpSocket::bind("0.0.0.0:0").expect("failed to bind GELF UDP socket");
        socket
            .set_nonblocking(true)
            .expect("failed to set non-blocking");

        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        Self {
            socket,
            target: format!("{}:{}", host, port),
            hostname,
        }
    }

    pub fn send(&self, event: &Value) {
        let gelf = self.to_gelf(event);

        let json_bytes = match serde_json::to_vec(&gelf) {
            Ok(b) => b,
            Err(e) => {
                error!("failed to serialize GELF: {}", e);
                return;
            }
        };

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        if encoder.write_all(&json_bytes).is_err() {
            error!("failed to compress GELF message");
            return;
        }

        let compressed = match encoder.finish() {
            Ok(b) => b,
            Err(e) => {
                error!("failed to finish GELF compression: {}", e);
                return;
            }
        };

        match self.socket.send_to(&compressed, &self.target) {
            Ok(_) => debug!("GELF sent to {}", self.target),
            Err(e) => {
                if e.kind() != std::io::ErrorKind::WouldBlock {
                    error!("GELF send failed: {}", e);
                }
            }
        }
    }

    fn to_gelf(&self, event: &Value) -> Value {
        let event_type = event["event_type"].as_str().unwrap_or("UNKNOWN");
        let short_message = format!(
            "[{}] {} @ {}",
            event_type,
            event["session_user"].as_str().unwrap_or("?"),
            event["database"].as_str().unwrap_or("?")
        );

        let mut gelf = json!({
            "version": "1.1",
            "host": self.hostname,
            "short_message": short_message,
            "level": if event["success"].as_bool().unwrap_or(true) { 6 } else { 3 },
            "_event_type": event_type,
            "_success": event["success"],
            "_session_user": event["session_user"],
            "_database": event["database"],
            "_pid": event["pid"],
            "_command_tag": event["command_tag"],
            "_client_addr": event["client_addr"],
            "_sqlstate": event["sqlstate"],
            "_event_hash": event["event_hash"],
            "_source": "vibe_audit"
        });

        if let Some(qt) = event["query_text"].as_str() {
            if !qt.is_empty() {
                gelf["full_message"] = Value::String(qt.to_string());
            }
        }

        if let Some(obj) = event["object_type"].as_str() {
            gelf["_object_type"] = Value::String(obj.to_string());
        }
        if let Some(obj) = event["object_name"].as_str() {
            gelf["_object_name"] = Value::String(obj.to_string());
        }

        gelf
    }
}
