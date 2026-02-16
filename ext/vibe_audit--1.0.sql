-- VibeSQL Audit 1.0 — PCI DSS compliant audit logging
\echo Use "CREATE EXTENSION vibe_audit" to load this file. \quit

CREATE SCHEMA IF NOT EXISTS vibe_audit;

CREATE TABLE vibe_audit.events (
    id              BIGSERIAL,
    event_type      TEXT        NOT NULL,
    event_time      TIMESTAMPTZ NOT NULL DEFAULT now(),
    success         BOOLEAN     NOT NULL,
    session_user    TEXT,
    client_addr     INET,
    client_port     INTEGER,
    database        TEXT,
    pid             INTEGER,
    application     TEXT,
    command_tag     TEXT,
    object_type     TEXT,
    object_name     TEXT,
    schema_name     TEXT,
    query_text      TEXT,
    sqlstate        TEXT,
    detail          JSONB,
    prev_hash       TEXT,
    event_hash      TEXT,
    inserted_at     TIMESTAMPTZ NOT NULL DEFAULT now()
) PARTITION BY RANGE (event_time);

CREATE INDEX idx_events_event_type ON vibe_audit.events (event_type);
CREATE INDEX idx_events_session_user ON vibe_audit.events (session_user);
CREATE INDEX idx_events_event_time ON vibe_audit.events (event_time);
CREATE INDEX idx_events_database ON vibe_audit.events (database);

REVOKE UPDATE, DELETE ON vibe_audit.events FROM PUBLIC;

CREATE TABLE vibe_audit.sensitive_tables (
    id              SERIAL PRIMARY KEY,
    schema_name     TEXT NOT NULL,
    table_name      TEXT NOT NULL,
    sensitivity     TEXT NOT NULL DEFAULT 'high',
    tagged_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    tagged_by       TEXT NOT NULL DEFAULT current_user,
    UNIQUE (schema_name, table_name)
);

CREATE OR REPLACE FUNCTION vibe_audit.ensure_partition(target_date DATE DEFAULT CURRENT_DATE)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
DECLARE
    partition_name TEXT;
    start_date DATE;
    end_date DATE;
BEGIN
    start_date := date_trunc('month', target_date)::DATE;
    end_date := (start_date + INTERVAL '1 month')::DATE;
    partition_name := 'events_' || to_char(start_date, 'YYYY_MM');

    IF NOT EXISTS (
        SELECT 1 FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'vibe_audit' AND c.relname = partition_name
    ) THEN
        EXECUTE format(
            'CREATE TABLE vibe_audit.%I PARTITION OF vibe_audit.events FOR VALUES FROM (%L) TO (%L)',
            partition_name, start_date, end_date
        );

        EXECUTE format(
            'REVOKE UPDATE, DELETE ON vibe_audit.%I FROM PUBLIC', partition_name
        );
    END IF;

    RETURN partition_name;
END;
$$;

CREATE OR REPLACE FUNCTION vibe_audit.verify_chain(
    OUT checked_count BIGINT,
    OUT valid BOOLEAN,
    OUT first_broken_id BIGINT
)
RETURNS RECORD
LANGUAGE plpgsql
AS $$
DECLARE
    rec RECORD;
    prev TEXT := '';
    computed TEXT;
    row_count BIGINT := 0;
BEGIN
    valid := true;
    first_broken_id := NULL;

    FOR rec IN
        SELECT id, event_hash, prev_hash,
               event_type || '|' || event_time::TEXT || '|' || COALESCE(session_user, '') ||
               '|' || COALESCE(database, '') || '|' || COALESCE(command_tag, '') ||
               '|' || COALESCE(query_text, '') AS event_payload
        FROM vibe_audit.events
        ORDER BY id
    LOOP
        row_count := row_count + 1;

        IF rec.prev_hash IS DISTINCT FROM prev THEN
            valid := false;
            first_broken_id := rec.id;
            checked_count := row_count;
            RETURN;
        END IF;

        computed := encode(digest(prev || rec.event_payload, 'sha256'), 'hex');

        IF rec.event_hash IS DISTINCT FROM computed THEN
            valid := false;
            first_broken_id := rec.id;
            checked_count := row_count;
            RETURN;
        END IF;

        prev := rec.event_hash;
    END LOOP;

    checked_count := row_count;
END;
$$;

SELECT vibe_audit.ensure_partition(CURRENT_DATE);
SELECT vibe_audit.ensure_partition(CURRENT_DATE + INTERVAL '1 month');
