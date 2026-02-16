use serde_json::Value;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

pub async fn run(port: u16, tx: mpsc::Sender<Value>) {
    let addr = format!("127.0.0.1:{}", port);
    let socket = UdpSocket::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("failed to bind UDP on {}: {}", addr, e));

    tracing::info!("UDP listener bound on {}", addr);

    let mut buf = vec![0u8; 65535];

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, src)) => {
                debug!("received {} bytes from {}", len, src);

                match serde_json::from_slice::<Value>(&buf[..len]) {
                    Ok(event) => {
                        if tx.send(event).await.is_err() {
                            error!("event channel closed");
                            return;
                        }
                    }
                    Err(e) => {
                        warn!("malformed JSON from {}: {}", src, e);
                    }
                }
            }
            Err(e) => {
                error!("UDP recv error: {}", e);
            }
        }
    }
}
