mod gelf;
mod hashchain;
mod health;
mod listener;
mod sensitive;
mod walcapture;
mod writer;

use hashchain::HashChain;
use health::HealthState;
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{self, Duration};
use tracing::info;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_bool(key: &str, default: bool) -> bool {
    std::env::var(key)
        .map(|v| v == "true" || v == "1" || v == "yes")
        .unwrap_or(default)
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .json()
        .init();

    let udp_port: u16 = env_or("VIBE_AUDIT_UDP_PORT", "5514").parse().unwrap();
    let db_url = env_or("VIBE_AUDIT_DB_URL", "postgresql://postgres:postgres@127.0.0.1:5432/vibesql");
    let gelf_host = env_or("VIBE_AUDIT_GELF_HOST", "127.0.0.1");
    let gelf_port: u16 = env_or("VIBE_AUDIT_GELF_PORT", "12201").parse().unwrap();
    let health_port: u16 = env_or("VIBE_AUDIT_HEALTH_PORT", "9100").parse().unwrap();

    let wal_enabled = env_bool("VIBE_AUDIT_WAL_ENABLED", true);
    let wal_slot = env_or("VIBE_AUDIT_WAL_SLOT", "vibe_audit_slot");
    let wal_publication = env_or("VIBE_AUDIT_WAL_PUBLICATION", "vibe_audit_pub");
    let sensitive_fields_csv = env_or("VIBE_AUDIT_SENSITIVE_FIELDS", "");

    info!(
        udp_port,
        %db_url,
        %gelf_host,
        gelf_port,
        health_port,
        wal_enabled,
        %wal_slot,
        %wal_publication,
        "vibe-audit-forwarder starting"
    );

    let gelf_forwarder = Arc::new(gelf::GelfForwarder::new(&gelf_host, gelf_port).await);
    let batch_writer = Arc::new(writer::BatchWriter::new(&db_url).await);
    let health_state = HealthState::new();

    let wal_event_count = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let udp_event_count = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let wal_lsn = Arc::new(tokio::sync::RwLock::new(String::new()));

    let (tx, mut rx) = mpsc::channel::<Value>(10_000);

    let listener_handle = tokio::spawn(listener::run(udp_port, tx.clone()));
    let health_handle = tokio::spawn(health::run(
        health_port,
        health_state.clone(),
        wal_enabled,
        wal_event_count.clone(),
        udp_event_count.clone(),
        wal_lsn.clone(),
    ));
    let heartbeat_handle = tokio::spawn(health::heartbeat_loop(
        gelf_forwarder.clone(),
        health_state.clone(),
    ));

    let sensitive_registry = Arc::new(sensitive::SensitiveFieldRegistry::new(
        batch_writer.pool().clone(),
        &sensitive_fields_csv,
    ));
    sensitive_registry.refresh_cache().await;

    let wal_handle = if wal_enabled {
        let wal_config = walcapture::WalCaptureConfig {
            slot_name: wal_slot,
        };
        let wal_tx = tx.clone();
        let wal_registry = sensitive_registry.clone();
        let wal_count = wal_event_count.clone();
        let wal_lsn_ref = wal_lsn.clone();
        let wal_pool = batch_writer.pool().clone();
        Some(tokio::spawn(walcapture::run(
            wal_config,
            wal_tx,
            wal_registry,
            wal_count,
            wal_lsn_ref,
            wal_pool,
        )))
    } else {
        info!("WAL capture disabled");
        None
    };

    let sensitive_refresh = tokio::spawn({
        let reg = sensitive_registry.clone();
        async move {
            let mut interval = time::interval(Duration::from_secs(300));
            loop {
                interval.tick().await;
                reg.refresh_cache().await;
            }
        }
    });

    let gelf_ref = gelf_forwarder.clone();
    let writer_ref = batch_writer.clone();
    let state_ref = health_state.clone();
    let udp_count = udp_event_count.clone();

    let processor_handle = tokio::spawn(async move {
        let mut chain = HashChain::new();
        let mut batch: Vec<Value> = Vec::with_capacity(100);
        let mut flush_interval = time::interval(Duration::from_secs(1));

        loop {
            tokio::select! {
                Some(mut event) = rx.recv() => {
                    let is_wal = event.get("detail")
                        .and_then(|d| d.get("source"))
                        .and_then(|s| s.as_str())
                        == Some("wal");

                    if !is_wal {
                        udp_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }

                    chain.apply(&mut event);

                    let event_time = event["event_time"].as_str().map(|s| s.to_string());
                    state_ref.update(chain.chain_length(), event_time);

                    gelf_ref.send(&event).await;
                    batch.push(event);

                    if batch.len() >= 100 {
                        writer_ref.write_batch(&batch).await;
                        batch.clear();
                    }
                }
                _ = flush_interval.tick() => {
                    if !batch.is_empty() {
                        writer_ref.write_batch(&batch).await;
                        batch.clear();
                    }
                }
            }
        }
    });

    let daily_partition = tokio::spawn({
        let w = batch_writer.clone();
        async move {
            let mut interval = time::interval(Duration::from_secs(86400));
            loop {
                interval.tick().await;
                w.ensure_partition().await;
            }
        }
    });

    tokio::select! {
        _ = listener_handle => {},
        _ = processor_handle => {},
        _ = health_handle => {},
        _ = heartbeat_handle => {},
        _ = daily_partition => {},
        _ = sensitive_refresh => {},
        _ = async { match wal_handle { Some(h) => h.await.ok(), None => futures_util::future::pending().await } } => {},
    }
}
