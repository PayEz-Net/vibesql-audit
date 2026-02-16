-- Basic regression test for vibe_audit extension
CREATE EXTENSION IF NOT EXISTS vibe_audit;

-- Verify schema exists
SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname = 'vibe_audit') AS schema_exists;

-- Verify tables exist
SELECT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'vibe_audit' AND c.relname = 'events') AS events_exists;
SELECT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'vibe_audit' AND c.relname = 'sensitive_tables') AS sensitive_tables_exists;

-- Verify partition creation
SELECT vibe_audit.ensure_partition(CURRENT_DATE) AS current_partition;
SELECT vibe_audit.ensure_partition(CURRENT_DATE + INTERVAL '1 month') AS next_partition;

-- Verify chain verification function works on empty table
SELECT * FROM vibe_audit.verify_chain();

-- Verify UPDATE/DELETE are revoked on events
SELECT has_table_privilege('public', 'vibe_audit.events', 'UPDATE') AS can_update;
SELECT has_table_privilege('public', 'vibe_audit.events', 'DELETE') AS can_delete;
