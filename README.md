# VibeSQL Audit

**Compliance-grade PostgreSQL audit logging with tamper-evident hash chains.**

VibeSQL Audit is a PostgreSQL C extension paired with a Rust sidecar forwarder. Together they provide PCI DSS SAQ-D compliant audit logging: authentication tracking, DDL capture, privilege change monitoring, and a SHA-256 hash chain for tamper evidence — all without blocking database transactions.

This is not a fork of pgAudit. It's built from scratch for PCI compliance with a decoupled emission architecture: thin C hooks emit events over UDP on loopback, and a sidecar forwarder handles hash chaining, batch persistence, and GELF forwarding.

---

## What It Does

```
PostgreSQL Backend Process
  │
  ├─ ClientAuthentication_hook ──┐
  ├─ ProcessUtility_hook ────────┤  UDP (non-blocking)
  ├─ ExecutorEnd_hook ───────────┤  127.0.0.1:5514
  │                              │
  │                              ▼
  │                   ┌──────────────────┐
  │                   │  Forwarder       │
  │                   │  (Rust sidecar)  │
  │                   │                  │
  │                   │  ┌─ Hash Chain ──┤──▶ SHA-256 chain
  │                   │  ├─ Batch Write ─┤──▶ vibe_audit.events (append-only)
  │                   │  └─ GELF Forward─┤──▶ Graylog / SIEM
  │                   │                  │
  │                   │  /health ────────┤──▶ Monitoring
  │                   │  heartbeat ──────┤──▶ Liveness (10s)
  │                   └──────────────────┘
  │
  └─ Normal query processing (never blocked)
```

1. PostgreSQL hooks capture auth, DDL, and DML events
2. Events are serialized to JSON and sent over UDP to loopback (non-blocking, never stalls the backend)
3. The forwarder receives events, computes a SHA-256 hash chain linking each event to its predecessor
4. Events are batch-inserted into the append-only `vibe_audit.events` table (partitioned by month)
5. Each event is forwarded to Graylog via GELF for real-time alerting
6. A heartbeat every 10 seconds proves the audit pipeline is alive

---

## Key Features

**Non-Blocking Emission**
The C extension uses UDP `sendto()` on loopback. If the forwarder is overwhelmed, events are silently dropped — the database transaction is never blocked. After 10 consecutive failures, the extension falls back to PostgreSQL `elog(LOG)`.

**SHA-256 Hash Chain**
Every event includes `prev_hash` and `event_hash`. Each hash is computed as `SHA256(prev_hash || event_payload)`. Tampering with any event breaks the chain. Verify integrity with `SELECT * FROM vibe_audit.verify_chain()`.

**Append-Only Storage**
`UPDATE` and `DELETE` are revoked on `vibe_audit.events`. Monthly partitions are auto-created by the forwarder on startup and daily thereafter.

**GELF Forwarding**
Every event is forwarded to Graylog (or any GELF-compatible endpoint) for real-time dashboards and alerting.

**Multi-Version Support**
Built and tested against PostgreSQL 15, 16, and 17. Version guards (`PG_VERSION_NUM`) handle hook signature differences.

---

## Quick Start

### 1. Build the Extension

```bash
cd ext/
make PG_CONFIG=/usr/bin/pg_config
sudo make install
```

### 2. Configure PostgreSQL

```
# postgresql.conf
shared_preload_libraries = 'vibe_audit'
vibe_audit.enabled = on
vibe_audit.udp_port = 5514
vibe_audit.udp_host = '127.0.0.1'
```

Restart PostgreSQL after changing `shared_preload_libraries`.

### 3. Create the Extension

```sql
CREATE EXTENSION vibe_audit;
```

### 4. Build and Run the Forwarder

```bash
cd forwarder/
cargo build --release
./target/release/vibe-audit-forwarder
```

Or with environment variables:

```bash
VIBE_AUDIT_UDP_PORT=5514 \
VIBE_AUDIT_DB_URL=postgresql://postgres:postgres@localhost:5432/vibesql \
VIBE_AUDIT_GELF_HOST=127.0.0.1 \
VIBE_AUDIT_GELF_PORT=12201 \
VIBE_AUDIT_HEALTH_PORT=9100 \
./target/release/vibe-audit-forwarder
```

### 5. Verify

```bash
# Check health
curl http://localhost:9100/health

# Verify hash chain integrity
psql -c "SELECT * FROM vibe_audit.verify_chain();"
```

### Docker Compose (Full Stack)

```bash
cd deploy/
docker-compose up
```

Starts PostgreSQL (with extension), the Rust forwarder, and Graylog.

---

## Event Types

| Event Type | Hook | Captures |
|------------|------|----------|
| `AUTH_SUCCESS` | ClientAuthentication | Successful login (user, IP, database) |
| `AUTH_FAIL` | ClientAuthentication | Failed login attempt (user, IP, reason) |
| `DDL` | ProcessUtility | CREATE, DROP, ALTER statements |
| `GRANT` / `REVOKE` | ProcessUtility | Privilege changes |
| `DML` | ExecutorEnd | SELECT/INSERT/UPDATE/DELETE (superuser sessions, Phase 1) |
| `SYSTEM_EVENT` | Forwarder | Heartbeat (every 10s) |

---

## Hash Chain Verification

```sql
SELECT * FROM vibe_audit.verify_chain();
```

Returns:

| Column | Type | Description |
|--------|------|-------------|
| `checked_count` | bigint | Number of events verified |
| `valid` | boolean | Chain integrity status |
| `first_broken_id` | bigint | ID of first tampered event (null if valid) |

---

## Sensitive Table Tagging (Phase 3)

```sql
INSERT INTO vibe_audit.sensitive_tables (schema_name, table_name, sensitivity)
VALUES ('public', 'payment_cards', 'pci');
```

Phase 3 will replace the superuser-only DML filter with per-table audit filtering based on tagged sensitivity levels.

---

## PCI DSS SAQ-D Compliance Matrix

| Requirement | Description | Coverage |
|-------------|-------------|----------|
| **10.2.1** | Audit trails for individual user access to cardholder data | DML hook (Phase 3: tagged tables) |
| **10.2.2** | Actions by any individual with root/admin privileges | ExecutorEnd hook (superuser sessions) |
| **10.2.4** | Invalid logical access attempts | AUTH_FAIL events |
| **10.2.5** | Identification and authentication mechanism changes | DDL hook (CREATE/ALTER/DROP ROLE, GRANT, REVOKE) |
| **10.2.6** | Initialization, stopping, or pausing of audit logs | SYSTEM_EVENT heartbeat, extension enable/disable |
| **10.2.7** | Creation and deletion of system-level objects | DDL hook (CREATE/DROP TABLE, INDEX, etc.) |
| **10.3.1** | User identification in audit trail | `session_user` field on all events |
| **10.3.2** | Type of event | `event_type` + `command_tag` fields |
| **10.3.3** | Date and time | `event_time` (ISO 8601, millisecond precision) |
| **10.3.4** | Success or failure indication | `success` boolean field |
| **10.3.5** | Origination of event | `client_addr` + `client_port` + `application` |
| **10.3.6** | Identity or name of affected data/component | `object_type` + `object_name` + `schema_name` |
| **10.5.1** | Limit viewing of audit trails | PostgreSQL role-based access on `vibe_audit` schema |
| **10.5.2** | Protect audit trail files from unauthorized modification | Append-only (REVOKE UPDATE/DELETE), SHA-256 hash chain |
| **10.5.5** | Use file-integrity monitoring or change-detection | `vibe_audit.verify_chain()` — hash chain verification |
| **10.7** | Retain audit trail history for at least one year | Monthly partitions, configurable retention |

---

## Deployment Topology

```
┌────────────────────────────────────────┐
│  Application Server                    │
│                                        │
│  ┌──────────────┐  ┌────────────────┐  │
│  │ PostgreSQL   │  │ Forwarder      │  │
│  │              │  │ (Rust sidecar) │  │
│  │  vibe_audit  │──│                │  │
│  │  extension   │  │  UDP:5514      │  │
│  │              │  │  HTTP:9100     │──┼──▶ Monitoring
│  └──────┬───────┘  └───────┬────────┘  │
│         │                  │           │
│         │                  │ GELF UDP  │
│         ▼                  ▼           │
│  ┌──────────────┐  ┌────────────────┐  │
│  │ vibe_audit.  │  │ Graylog / SIEM │  │
│  │ events table │  │                │  │
│  │ (append-only)│  │ Dashboards     │  │
│  │ (partitioned)│  │ Alerts         │  │
│  └──────────────┘  └────────────────┘  │
└────────────────────────────────────────┘
```

---

## Configuration

### Extension (postgresql.conf)

| Parameter | Default | Description |
|-----------|---------|-------------|
| `vibe_audit.enabled` | `on` | Enable/disable audit logging |
| `vibe_audit.udp_port` | `5514` | UDP port for event emission |
| `vibe_audit.udp_host` | `127.0.0.1` | UDP host for event emission |

### Forwarder (environment variables)

| Variable | Default | Description |
|----------|---------|-------------|
| `VIBE_AUDIT_UDP_PORT` | `5514` | UDP listen port |
| `VIBE_AUDIT_DB_URL` | `postgresql://postgres:postgres@127.0.0.1:5432/vibesql` | PostgreSQL connection |
| `VIBE_AUDIT_GELF_HOST` | `127.0.0.1` | Graylog GELF host |
| `VIBE_AUDIT_GELF_PORT` | `12201` | Graylog GELF port |
| `VIBE_AUDIT_HEALTH_PORT` | `9100` | Health endpoint port |

---

## Related Projects

- [VibeSQL Server](https://github.com/PayEz-Net/vibesql-server) — Production multi-tenant PostgreSQL server
- [VibeSQL Micro](https://github.com/PayEz-Net/vibesql-micro) — Single-binary dev tool
- [VibeSQL Edge](https://github.com/PayEz-Net/vibesql-edge) — Authentication gateway
- [Vibe SDK](https://github.com/PayEz-Net/vibe-sdk) — TypeScript ORM with live schema sync
- [Website](https://vibesql.online) — Documentation and overview

---

## License

Apache 2.0 License. See [LICENSE](LICENSE).

---

<div align="right">
  <sub>Powered by <a href="https://idealvibe.online">IdealVibe</a></sub>
</div>
