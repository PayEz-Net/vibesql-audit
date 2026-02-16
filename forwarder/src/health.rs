use axum::{extract::State, routing::get, Json, Router};
use serde::Serialize;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tracing::info;

#[derive(Clone)]
pub struct HealthState {
    pub inner: Arc<Mutex<HealthData>>,
}

pub struct HealthData {
    pub events_processed: u64,
    pub chain_length: u64,
    pub last_event_time: Option<String>,
}

#[derive(Clone)]
struct AppState {
    health: HealthState,
    wal_enabled: bool,
    wal_event_count: Arc<std::sync::atomic::AtomicU64>,
    udp_event_count: Arc<std::sync::atomic::AtomicU64>,
    wal_lsn: Arc<tokio::sync::RwLock<String>>,
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    events_processed: u64,
    chain_length: u64,
    last_event_time: Option<String>,
    wal_enabled: bool,
    wal_lsn: String,
    wal_events: u64,
    udp_events: u64,
}

impl HealthState {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HealthData {
                events_processed: 0,
                chain_length: 0,
                last_event_time: None,
            })),
        }
    }

    pub fn update(&self, chain_length: u64, last_time: Option<String>) {
        let mut data = self.inner.lock().unwrap();
        data.events_processed += 1;
        data.chain_length = chain_length;
        data.last_event_time = last_time;
    }
}

pub async fn run(
    port: u16,
    state: HealthState,
    wal_enabled: bool,
    wal_event_count: Arc<std::sync::atomic::AtomicU64>,
    udp_event_count: Arc<std::sync::atomic::AtomicU64>,
    wal_lsn: Arc<tokio::sync::RwLock<String>>,
) {
    let app_state = AppState {
        health: state,
        wal_enabled,
        wal_event_count,
        udp_event_count,
        wal_lsn,
    };

    let app = Router::new()
        .route("/health", get(health_handler))
        .with_state(app_state);

    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("failed to bind health endpoint on {}: {}", addr, e));

    info!("health endpoint listening on {}", addr);

    axum::serve(listener, app)
        .await
        .expect("health server failed");
}

async fn health_handler(State(state): State<AppState>) -> Json<HealthResponse> {
    let (events_processed, chain_length, last_event_time) = {
        let data = state.health.inner.lock().unwrap();
        (data.events_processed, data.chain_length, data.last_event_time.clone())
    };
    let lsn = state.wal_lsn.read().await.clone();

    Json(HealthResponse {
        status: "ok",
        events_processed,
        chain_length,
        last_event_time,
        wal_enabled: state.wal_enabled,
        wal_lsn: lsn,
        wal_events: state.wal_event_count.load(std::sync::atomic::Ordering::Relaxed),
        udp_events: state.udp_event_count.load(std::sync::atomic::Ordering::Relaxed),
    })
}

pub async fn heartbeat_loop(
    gelf: Arc<crate::gelf::GelfForwarder>,
    state: HealthState,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));

    loop {
        interval.tick().await;

        let (events_processed, chain_length) = {
            let data = state.inner.lock().unwrap();
            (data.events_processed, data.chain_length)
        };

        let event = serde_json::json!({
            "event_type": "SYSTEM_EVENT",
            "event_time": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "success": true,
            "session_user": "vibe_audit_forwarder",
            "client_addr": null,
            "client_port": null,
            "database": null,
            "pid": std::process::id(),
            "application": "vibe-audit-forwarder",
            "command_tag": "heartbeat",
            "object_type": null,
            "object_name": null,
            "schema_name": null,
            "query_text": null,
            "sqlstate": null,
            "detail": {
                "type": "heartbeat",
                "events_processed": events_processed,
                "chain_length": chain_length
            }
        });

        gelf.send(&event).await;
    }
}
