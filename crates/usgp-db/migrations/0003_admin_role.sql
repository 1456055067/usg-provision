-- usg-provision control-plane schema, migration 0003: administrative role.
--
-- Grants and revocations only (decision 0016). The role `usgp_admin` is
-- created by the database administrator (or scripts/pg-test-setup.sh in
-- CI) as a LOGIN role with no password and its own TLS client
-- certificate (decision 0012). Only the local administrative commands
-- (`operator enrol`, `operator disable`, `audit verify`) log in with it.
-- This migration fails if `usgp_admin` does not exist.
--
-- The network-facing application role `usgp_app` loses INSERT and UPDATE
-- on operator records: a compromise of the API process can no longer
-- create or re-enable an operator. It keeps SELECT, which authentication
-- needs on every request.
--
-- COMPLIANCE MAPPING:
-- - NIST 800-53: AC-6, AC-6(1) (Least Privilege; Authorize Access to
--   Security Functions) - operator management only through the
--   administrative role.
-- - NIST 800-53: AC-2 (Account Management) - operator records changed only
--   by local administrators.
-- - NIST 800-53: AU-9 (Protection of Audit Information) - the
--   administrative role appends to and reads the chain but cannot UPDATE
--   or DELETE records or checkpoints.
-- - SPEC: specs/operator-access.md#REQ-RBAC-004, #REQ-AUD-007
-- - Decisions 0012, 0015, 0016

REVOKE INSERT, UPDATE, DELETE ON operator FROM usgp_app;

DO $$
BEGIN
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO usgp_admin', current_database());
END;
$$;

GRANT USAGE ON SCHEMA public TO usgp_admin;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM usgp_admin;

-- Schema version check before every administrative command.
GRANT SELECT ON schema_migrations TO usgp_admin;

-- Operator enrolment and disabling (no DELETE: operators are disabled,
-- never removed).
GRANT SELECT, INSERT, UPDATE ON operator TO usgp_admin;

-- Audit: the same append-and-read rights as the application role, so
-- operator changes are audited in the same chain (decision 0016 item 4)
-- and `audit verify` can read it.
GRANT SELECT, INSERT ON audit_record, audit_checkpoint TO usgp_admin;
GRANT SELECT, UPDATE ON audit_head TO usgp_admin;

GRANT EXECUTE ON FUNCTION usgp_audit_append_only(), usgp_audit_record_extends_head(),
    usgp_audit_head_guard() TO usgp_admin;
