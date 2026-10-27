-- usg-provision control-plane schema, migration 0002: privileges.
--
-- Grants and revocations only. The roles themselves are created by the
-- database administrator (or scripts/pg-test-setup.sh in CI) as LOGIN roles
-- with no password (decision 0012): `usgp_owner` runs migrations and owns
-- the schema; `usgp_app` is the server's runtime role. This migration fails
-- if `usgp_app` does not exist. The audit triggers (the "guards" of plan
-- section 3.4) are in 0001 with the tables they protect.
--
-- The database-level statements need the migrating role to own the
-- database (true in CI and for databases the owner role creates).
--
-- COMPLIANCE MAPPING:
-- - NIST 800-53: AC-6 (Least Privilege) - the application role gets only
--   the table privileges the server uses; no DDL, no TRUNCATE.
-- - NIST 800-53: AU-9 (Protection of Audit Information) - the application
--   role cannot UPDATE or DELETE audit records or checkpoints, and can only
--   UPDATE the chain head.
-- - SPEC: specs/operator-access.md#REQ-AUD-005
-- - Decisions 0008, 0012

DO $$
BEGIN
    EXECUTE format('REVOKE ALL ON DATABASE %I FROM PUBLIC', current_database());
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO usgp_app', current_database());
END;
$$;

REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO usgp_app;

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM usgp_app;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;

-- Schema version check at server start (plan section 3.4).
GRANT SELECT ON schema_migrations TO usgp_app;

-- Control-plane records. Content, editions and uploads change state but
-- are never deleted; packages are deleted by the operator (REQ-IMG-014).
GRANT SELECT, INSERT, UPDATE ON operator, content, edition, upload TO usgp_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON package TO usgp_app;

-- Audit: append and read only; the head row is pre-created in 0001, so the
-- application needs SELECT and UPDATE on it, never INSERT or DELETE.
GRANT SELECT, INSERT ON audit_record, audit_checkpoint TO usgp_app;
GRANT SELECT, UPDATE ON audit_head TO usgp_app;

-- Trigger functions run as the invoker; the application role may execute
-- them (it never calls them directly).
GRANT EXECUTE ON FUNCTION usgp_audit_append_only(), usgp_audit_record_extends_head(),
    usgp_audit_head_guard() TO usgp_app;
