mod gelf;
mod hashchain;
mod health;
mod listener;
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

    info!(
        udp_port,
        %db_url,
        %gelf_host,
        gelf_port,
        health_port,
        "vibe-audit-forwarder starting"
    );

    let gelf_forwarder = Arc::new(gelf::GelfForwarder::new(&gelf_host, gelf_port));
    let batch_writer = Arc::new(writer::BatchWriter::new(&db_url).await);
    let health_state = HealthState::new();

    let (tx, mut rx) = mpsc::channel::<Value>(10_000);

    let listener_handle = tokio::spawn(listener::run(udp_port, tx));
    let health_handle = tokio::spawn(health::run(health_port, health_state.clone()));
    let heartbeat_handle = tokio::spawn(health::heartbeat_loop(
        gelf_forwarder.clone(),
        health_state.clone(),
    ));

    let gelf_ref = gelf_forwarder.clone();
    let writer_ref = batch_writer.clone();
    let state_ref = health_state.clone();

    let processor_handle = tokio::spawn(async move {
        let mut chain = HashChain::new();
        let mut batch: Vec<Value> = Vec::with_capacity(100);
        let mut flush_interval = time::interval(Duration::from_secs(1));

        loop {
            tokio::select! {
                Some(mut event) = rx.recv() => {
                    chain.apply(&mut event);

                    let event_time = event["event_time"].as_str().map(|s| s.to_string());
                    state_ref.update(chain.chain_length(), event_time);

                    gelf_ref.send(&event);
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
    }
}
