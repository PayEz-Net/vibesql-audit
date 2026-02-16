# VibeSQL Audit

**PostgreSQL extension for PCI DSS compliant audit logging.**

A native C extension with three hooks, WAL-based change capture, and a Rust sidecar forwarder. Tamper-evident SHA-256 hash chains, append-only storage, JSONB field-level diffing, and GELF forwarding to your SIEM — without blocking database transactions.

This is not a fork of pgAudit. Built from scratch for PCI DSS v4.0 SAQ-D compliance with a decoupled emission architecture.

---

## How It Works

```
PostgreSQL
  │
  ├─ ClientAuthentication_hook ──┐
  ├─ ProcessUtility_hook ────────┤  UDP 127.0.0.1:5514
  ├─ ExecutorEnd_hook ───────────┤  (non-blocking)
  │                              │
  │  WAL logical decoding ───────┤  DML_CHANGE events
  │  (test_decoding plugin)      │  JSONB field diffing
  │                              │
  │                              ▼
  │                   ┌──────────────────────┐
  │                   │  vibe-audit-forwarder │
  │                   │  (Rust sidecar)       │
  │                   │                       │
  │                   │  ├─ Hash Chain ───────┤──▶ SHA-256 tamper evidence
  │                   │  ├─ Batch Insert ─────┤──▶ vibe_audit.events
  │                   │  ├─ JSONB Diffing ────┤──▶ Sensitive field tracking
  │                   │  ├─ GELF Forward ─────┤──▶ Graylog / SIEM
  │                   │  └─ Heartbeat (10s) ──┤──▶ Liveness canary
  │                   │                       │
  │                   │  :9100/health ────────┤──▶ Monitoring
  │                   └───────────────────────┘
  │
  └─ Normal query processing (never blocked)
```

**Two capture methods:**

1. **C hooks** — Auth events, DDL, privilege changes, DML access by superusers. Emit via UDP on loopback. Zero impact on transaction latency.
2. **WAL logical decoding** — Full DML change stream with before/after JSONB document visibility. Captures what hooks cannot: the actual data that changed inside JSONB columns. Uses the standard `test_decoding` output plugin.

---

## Extension Details

```
Name:       vibe_audit
Version:    1.1
Schema:     vibe_audit
Relocatable: no
License:    Apache 2.0
PostgreSQL: 15, 16, 17
```

### Installation

```bash
cd ext/
make PG_CONFIG=/usr/bin/pg_config
sudo make install
```

### PostgreSQL Configuration

```ini
# postgresql.conf

# Required
shared_preload_libraries = 'vibe_audit'

# Extension settings
vibe_audit.enabled = on
vibe_audit.udp_port = 5514
vibe_audit.udp_host = '127.0.0.1'
vibe_audit.executor_mode = 'emit'    # emit | counter | off

# Required for WAL capture (DML change tracking)
wal_level = logical
max_replication_slots = 4
```

Restart PostgreSQL after changing `shared_preload_libraries` or `wal_level`.

### Create Extension

```sql
CREATE EXTENSION vibe_audit;
```

This creates the `vibe_audit` schema with:
- `events` — Partitioned append-only audit log (monthly partitions)
- `sensitive_tables` — Registry for tables requiring audit
- `sensitive_fields` — Registry for JSONB fields with redaction control
- `ensure_partition()` — Auto-creates monthly partitions
- `verify_chain()` — Validates SHA-256 hash chain integrity

### WAL Replication Slot

```sql
-- Create a logical replication slot for change capture
SELECT pg_create_logical_replication_slot('vibe_audit_slot', 'test_decoding');
```

---

## Forwarder Setup

The Rust sidecar receives UDP events from the extension and WAL changes from logical decoding, then persists, chains, and forwards them.

```bash
cd forwarder/
cargo build --release

VIBE_AUDIT_UDP_PORT=5514 \
VIBE_AUDIT_DB_URL="postgresql://postgres:postgres@localhost:5432/vibesql" \
VIBE_AUDIT_GELF_HOST=127.0.0.1 \
VIBE_AUDIT_GELF_PORT=12201 \
VIBE_AUDIT_HEALTH_PORT=9100 \
VIBE_AUDIT_WAL_ENABLED=true \
./target/release/vibe-audit-forwarder
```

### Docker Compose (Full Stack)

```bash
cd deploy/
docker-compose up
```

Starts PostgreSQL (with extension + logical replication), the Rust forwarder, and Graylog.

### Verify

```bash
# Forwarder health (event counts, WAL LSN position)
curl http://localhost:9100/health

# Hash chain integrity
psql -c "SELECT * FROM vibe_audit.verify_chain();"
```

---

## Event Types

| Event Type | Source | Captures |
|------------|--------|----------|
| `AUTH_SUCCESS` | ClientAuthentication_hook | Successful login (user, IP, database) |
| `AUTH_FAIL` | ClientAuthentication_hook | Failed login attempt (user, IP, reason) |
| `DDL` | ProcessUtility_hook | CREATE, DROP, ALTER statements |
| `GRANT` / `REVOKE` | ProcessUtility_hook | Privilege changes |
| `DML` | ExecutorEnd_hook | SELECT/INSERT/UPDATE/DELETE on sensitive tables |
| `DML_CHANGE` | WAL logical decoding | Full before/after JSONB diff on tagged tables |
| `SYSTEM_EVENT` | Forwarder | Heartbeat canary (every 10s) |

---

## Sensitive Data Tracking

### Tag Tables for Audit

```sql
INSERT INTO vibe_audit.sensitive_tables (schema_name, table_name, sensitivity)
VALUES ('public', 'payment_cards', 'pci');
```

### Tag JSONB Fields

Track specific fields inside JSONB columns. Fields marked `redact_in_log = true` are captured for change detection but redacted in log output.

```sql
INSERT INTO vibe_audit.sensitive_fields (schema_name, table_name, json_path, redact_in_log, description)
VALUES
  ('public', 'payment_cards', '$.card_number', true, 'PAN — log change events but redact value'),
  ('public', 'payment_cards', '$.cardholder_name', true, 'Cardholder name'),
  ('public', 'payment_cards', '$.status', false, 'Card status — log full value');
```

The forwarder refreshes the sensitive field registry every 5 minutes and applies JSONB diffing to WAL changes on tagged tables.

---

## Hash Chain

Every event includes `prev_hash` and `event_hash`:

```
hash_n = SHA256(hash_{n-1} || event_type || timestamp || session_user || database || command_tag || query_text)
```

Tampering with any event breaks the chain. Verify integrity:

```sql
SELECT * FROM vibe_audit.verify_chain();
```

| Column | Type | Description |
|--------|------|-------------|
| `checked_count` | bigint | Events verified |
| `valid` | boolean | Chain integrity status |
| `first_broken_id` | bigint | First tampered event (null if valid) |

---

## PCI DSS v4.0 Compliance Matrix

| Requirement | Description | Implementation |
|-------------|-------------|----------------|
| **10.2.1.1** | Individual user access to cardholder data | WAL capture + sensitive table tagging + JSONB diffing |
| **10.2.1.2** | Actions by privileged users | ExecutorEnd_hook on superuser sessions |
| **10.2.1.4** | Invalid logical access attempts | AUTH_FAIL events via ClientAuthentication_hook |
| **10.2.1.5** | Changes to identification/authentication mechanisms | ProcessUtility_hook (CREATE/ALTER/DROP ROLE, GRANT, REVOKE) |
| **10.2.1.6** | Initialization, stopping, or pausing of audit logs | SYSTEM_EVENT heartbeat, `vibe_audit.enabled` GUC tracking |
| **10.2.1.7** | Creation and deletion of system-level objects | ProcessUtility_hook (DDL) |
| **10.3.1** | User identification | `session_user` field on all events |
| **10.3.2** | Type of event | `event_type` + `command_tag` fields |
| **10.3.3** | Date and time | `event_time` (ISO 8601, millisecond precision) |
| **10.3.4** | Success or failure indication | `success` boolean + SHA-256 hash chain for tamper detection |
| **10.3.5** | Origination of event | `client_addr` + `client_port` + `application` |
| **10.3.6** | Affected data/system component | `object_type` + `object_name` + `schema_name` |
| **10.5.1** | Restrict audit trail access | PostgreSQL RBAC on `vibe_audit` schema |
| **10.5.1.2** | Protect from unauthorized modification | Append-only (REVOKE UPDATE/DELETE) + SHA-256 hash chain |
| **10.7.1** | Retain at least 12 months | Monthly partitions, configurable retention policy |

---

## Configuration Reference

### Extension GUCs (postgresql.conf)

| Parameter | Default | Description |
|-----------|---------|-------------|
| `vibe_audit.enabled` | `on` | Enable/disable audit logging |
| `vibe_audit.udp_port` | `5514` | UDP port for event emission |
| `vibe_audit.udp_host` | `127.0.0.1` | UDP host (loopback only) |
| `vibe_audit.executor_mode` | `emit` | `emit` = full audit, `counter` = count only, `off` = disable DML hooks |

### Forwarder Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VIBE_AUDIT_UDP_PORT` | `5514` | UDP listen port |
| `VIBE_AUDIT_DB_URL` | `postgresql://...@127.0.0.1:5432/vibesql` | PostgreSQL connection string |
| `VIBE_AUDIT_GELF_HOST` | `127.0.0.1` | Graylog GELF host |
| `VIBE_AUDIT_GELF_PORT` | `12201` | Graylog GELF port |
| `VIBE_AUDIT_HEALTH_PORT` | `9100` | Health endpoint port |
| `VIBE_AUDIT_WAL_ENABLED` | `false` | Enable WAL logical decoding capture |

---

## Repository Structure

```
vibesql-audit/
├── ext/                          # PostgreSQL C extension
│   ├── vibe_audit.c              # Entry point, GUC registration
│   ├── vibe_hooks.c              # Auth, ProcessUtility, ExecutorEnd hooks
│   ├── vibe_emit.c               # UDP emission (non-blocking sendto)
│   ├── vibe_tags.c               # Sensitive table/field tag lookups
│   ├── vibe_compat.h             # PG version compatibility guards
│   ├── vibe_audit.control        # Extension metadata
│   ├── vibe_audit--1.0.sql       # Initial schema
│   ├── vibe_audit--1.0--1.1.sql  # Migration (adds sensitive_fields)
│   ├── vibe_audit--1.1.sql       # Full v1.1 schema
│   └── Makefile                  # PGXS build
├── forwarder/                    # Rust sidecar
│   ├── Cargo.toml
│   └── src/                      # Hash chain, batch insert, WAL, GELF, health
├── ci/                           # CI Dockerfiles (PG 15, 16, 17)
├── deploy/                       # Docker Compose stack
├── test/                         # Test suite
└── LICENSE                       # Apache 2.0
```

---

## Performance

Target: **< 3% overhead** on non-tagged tables, **< 8%** on sensitive tables with WAL capture.

The C extension uses non-blocking UDP `sendto()` on loopback. If the forwarder is unavailable, events are silently dropped — the database transaction is never blocked. After 10 consecutive failures, the extension falls back to `elog(LOG)`.

WAL capture polls `pg_logical_slot_get_changes()` every 200ms. No impact on write transactions.

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
