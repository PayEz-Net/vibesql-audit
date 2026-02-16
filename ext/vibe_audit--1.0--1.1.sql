-- VibeSQL Audit 1.0 -> 1.1 upgrade — sensitive field registry for WAL-based JSONB capture
\echo Use "ALTER EXTENSION vibe_audit UPDATE TO '1.1'" to load this file. \quit

CREATE TABLE IF NOT EXISTS vibe_audit.sensitive_fields (
    id              SERIAL PRIMARY KEY,
    schema_name     VARCHAR(128) NOT NULL,
    table_name      VARCHAR(128) NOT NULL,
    json_path       VARCHAR(500) NOT NULL,
    redact_in_log   BOOLEAN NOT NULL DEFAULT TRUE,
    description     VARCHAR(500),
    tagged_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    tagged_by       TEXT NOT NULL DEFAULT current_user,
    UNIQUE (schema_name, table_name, json_path)
);
