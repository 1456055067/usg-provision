-- usg-provision control-plane schema, migration 0001 (plan M2 section 3.4).
--
-- Run by the migration runner (crates/usgp-db/src/migrate.rs) as the owner
-- role, inside one transaction. Must not contain transaction control.
--
-- Conventions:
-- - Timestamps are UTC microseconds since the Unix epoch in `bigint`
--   columns named `*_us` (the unit of the audit chain, plan section 5.6).
-- - Value lists in CHECK constraints are exactly the usgp-proto wire values
--   (`X::ALL`); a unit test in usgp-db compares them.
-- - Digests and key ids are 32-byte `bytea`.
--
-- COMPLIANCE MAPPING:
-- - NIST 800-53: AU-9 (Protection of Audit Information) - append-only audit
--   tables enforced by triggers (defence in depth; the hash chain is the
--   detection mechanism), chain-head continuity checked on every write.
-- - NIST 800-53: SI-10 (Information Input Validation) - closed value sets,
--   lengths and cross-column rules as constraints.
-- - SPEC: specs/operator-access.md#REQ-AUD-005, specs/os-images.md#REQ-IMG-020
-- - Decisions 0008 (PostgreSQL, ordered migrations), 0013 (declared facts)

-- --------------------------------------------------------------- audit --

CREATE TABLE audit_record (
    seq             bigint  PRIMARY KEY CHECK (seq >= 1),
    ts_us           bigint  NOT NULL,
    event           text    NOT NULL,
    outcome         text    NOT NULL,
    actor_kind      text    NOT NULL,
    actor_id        text    NULL,
    actor_label     text    NULL,
    interface       text    NOT NULL,
    node            text    NOT NULL,
    source          text    NULL,
    target_kind     text    NULL,
    target_id       text    NULL,
    reason          text    NULL,
    -- Exact rendered JSON text; `text`, never `jsonb` (key order and bytes
    -- must survive the round trip unchanged, plan section 5.6).
    detail          text    NOT NULL,
    initiating_seq  bigint  NULL CHECK (initiating_seq >= 1),
    prev_hash       bytea   NOT NULL CHECK (length(prev_hash) = 32),
    record_hash     bytea   NOT NULL CHECK (length(record_hash) = 32),
    UNIQUE (seq, record_hash)
);

CREATE TABLE audit_head (
    id              smallint PRIMARY KEY CHECK (id = 1),
    seq             bigint   NOT NULL CHECK (seq >= 0),
    record_hash     bytea    NOT NULL CHECK (length(record_hash) = 32)
);

-- The single head row exists from the start (seq 0 = empty chain), so
-- `SELECT ... FOR UPDATE` always has a row to lock and the genesis append
-- is serialised like every other append.
INSERT INTO audit_head (id, seq, record_hash) VALUES (1, 0, decode(repeat('00', 32), 'hex'));

CREATE TABLE audit_checkpoint (
    seq             bigint  PRIMARY KEY,
    record_hash     bytea   NOT NULL CHECK (length(record_hash) = 32),
    signed_at_us    bigint  NOT NULL,
    key_id          bytea   NOT NULL CHECK (length(key_id) = 32),
    signature       bytea   NOT NULL CHECK (length(signature) BETWEEN 1 AND 104),
    FOREIGN KEY (seq, record_hash) REFERENCES audit_record (seq, record_hash)
);

-- Append-only: no UPDATE, DELETE or TRUNCATE on records and checkpoints,
-- for any role that does not first disable the triggers (only the table
-- owner can). The application role also lacks the privileges (0002).
CREATE FUNCTION usgp_audit_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit table % is append-only', TG_TABLE_NAME
        USING ERRCODE = 'insufficient_privilege';
END;
$$;

CREATE TRIGGER audit_record_append_only
    BEFORE UPDATE OR DELETE ON audit_record
    FOR EACH ROW EXECUTE FUNCTION usgp_audit_append_only();
CREATE TRIGGER audit_record_no_truncate
    BEFORE TRUNCATE ON audit_record
    FOR EACH STATEMENT EXECUTE FUNCTION usgp_audit_append_only();
CREATE TRIGGER audit_checkpoint_append_only
    BEFORE UPDATE OR DELETE ON audit_checkpoint
    FOR EACH ROW EXECUTE FUNCTION usgp_audit_append_only();
CREATE TRIGGER audit_checkpoint_no_truncate
    BEFORE TRUNCATE ON audit_checkpoint
    FOR EACH STATEMENT EXECUTE FUNCTION usgp_audit_append_only();

-- A new record must extend the current head: seq = head + 1 and
-- prev_hash = head hash.
CREATE FUNCTION usgp_audit_record_extends_head() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    h_seq  bigint;
    h_hash bytea;
BEGIN
    SELECT seq, record_hash INTO h_seq, h_hash FROM audit_head WHERE id = 1;
    IF NOT FOUND OR NEW.seq <> h_seq + 1 OR NEW.prev_hash <> h_hash THEN
        RAISE EXCEPTION 'audit record does not extend the chain head'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER audit_record_extends_head
    BEFORE INSERT ON audit_record
    FOR EACH ROW EXECUTE FUNCTION usgp_audit_record_extends_head();

-- The head only moves forward by one, onto a stored record; it is never
-- deleted or truncated.
CREATE FUNCTION usgp_audit_head_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP <> 'UPDATE' THEN
        RAISE EXCEPTION 'audit head cannot be removed'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF NEW.id <> OLD.id OR NEW.seq <> OLD.seq + 1 THEN
        RAISE EXCEPTION 'audit head must advance by one'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM audit_record r
                   WHERE r.seq = NEW.seq AND r.record_hash = NEW.record_hash) THEN
        RAISE EXCEPTION 'audit head must name a stored record'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER audit_head_guard
    BEFORE UPDATE OR DELETE ON audit_head
    FOR EACH ROW EXECUTE FUNCTION usgp_audit_head_guard();
CREATE TRIGGER audit_head_no_truncate
    BEFORE TRUNCATE ON audit_head
    FOR EACH STATEMENT EXECUTE FUNCTION usgp_audit_append_only();

-- ----------------------------------------------------------- operators --

CREATE TABLE operator (
    id                  uuid    PRIMARY KEY,
    display_name        text    NOT NULL,
    cert_sha256         bytea   NOT NULL UNIQUE CHECK (length(cert_sha256) = 32),
    cert_subject        text    NOT NULL,
    cert_issuer         text    NOT NULL,
    cert_serial         text    NOT NULL,
    cert_not_after_us   bigint  NOT NULL,
    role                text    NULL CHECK (role IN ('administrator')),
    status              text    NOT NULL CHECK (status IN ('active', 'disabled')),
    created_at_us       bigint  NOT NULL CHECK (created_at_us >= 0),
    created_by          text    NOT NULL
);

-- ------------------------------------------------------------- content --

CREATE TABLE content (
    id                      uuid    PRIMARY KEY,
    kind                    text    NOT NULL CHECK (kind IN ('image', 'pe')),
    display_name            text    NOT NULL,
    file_name               text    NOT NULL,
    size                    bigint  NOT NULL CHECK (size > 0),
    -- The operator's declared digest; equal to the server-computed digest
    -- once Ready (a mismatch fails the upload, plan section 5.7).
    sha256                  bytea   NOT NULL CHECK (length(sha256) = 32),
    state                   text    NOT NULL CHECK (state IN ('receiving', 'checking', 'ready', 'failed', 'deleted')),
    reason_code             text    NULL,
    reason_text             text    NULL,
    created_by              uuid    NOT NULL REFERENCES operator (id),
    initiating_audit_seq    bigint  NULL REFERENCES audit_record (seq) DEFERRABLE INITIALLY DEFERRED,
    created_at_us           bigint  NOT NULL CHECK (created_at_us >= 0),
    updated_at_us           bigint  NOT NULL CHECK (updated_at_us >= 0),
    ready_at_us             bigint  NULL CHECK (ready_at_us >= 0),
    compression             text    NULL CHECK (compression IN ('none', 'xpress')),
    image_count             integer NULL CHECK (image_count >= 1),
    boot_index              integer NULL CHECK (boot_index >= 0),
    usable_index            integer NULL CHECK (usable_index >= 1),
    pe_arch                 text    NULL CHECK (pe_arch IN ('x64', 'x86', 'arm64', 'arm')),
    pe_arch_source          text    NULL CHECK (pe_arch_source IN ('declared', 'verified')),
    pe_kit_version          text    NULL CHECK (length(pe_kit_version) BETWEEN 3 AND 23),
    pe_kit_version_source   text    NULL CHECK (pe_kit_version_source IN ('declared', 'verified')),
    manifest                bytea   NULL,
    manifest_sig            bytea   NULL,
    manifest_key_id         bytea   NULL CHECK (length(manifest_key_id) = 32),
    UNIQUE (id, kind),
    -- A PE carries its declaration from creation (plan 3.2); an image never.
    CHECK ((kind = 'pe') = (pe_arch IS NOT NULL)),
    CHECK (num_nulls(pe_arch, pe_arch_source, pe_kit_version, pe_kit_version_source) IN (0, 4)),
    CHECK (num_nulls(manifest, manifest_sig, manifest_key_id) IN (0, 3)),
    CHECK (state <> 'ready' OR num_nulls(manifest, compression, image_count, boot_index, ready_at_us) = 0),
    CHECK (state <> 'ready' OR kind <> 'pe' OR usable_index IS NOT NULL),
    CHECK (state <> 'failed' OR reason_code IS NOT NULL)
);

-- One live item per digest (a duplicate upload is refused with the
-- existing id, plan 3.2). Failed and deleted items do not block a re-upload.
CREATE UNIQUE INDEX content_live_sha256 ON content (sha256)
    WHERE state IN ('receiving', 'checking', 'ready');

CREATE TABLE edition (
    content_id          uuid    NOT NULL REFERENCES content (id),
    idx                 integer NOT NULL CHECK (idx >= 1),
    name                text    NOT NULL,
    description         text    NOT NULL,
    total_bytes         bigint  NULL CHECK (total_bytes >= 0),
    decl_release        text    NULL CHECK (decl_release IN ('windows-11', 'windows-10', 'other')),
    decl_edition        text    NULL CHECK (decl_edition IN ('enterprise', 'enterprise-ltsc', 'iot-enterprise', 'education', 'pro', 'home', 'other')),
    decl_arch           text    NULL CHECK (decl_arch IN ('x64', 'x86', 'arm64', 'arm')),
    release_source      text    NULL CHECK (release_source IN ('declared', 'verified')),
    edition_source      text    NULL CHECK (edition_source IN ('declared', 'verified')),
    arch_source         text    NULL CHECK (arch_source IN ('declared', 'verified')),
    declared_by         uuid    NULL REFERENCES operator (id),
    declared_at_us      bigint  NULL CHECK (declared_at_us >= 0),
    declared_audit_seq  bigint  NULL REFERENCES audit_record (seq) DEFERRABLE INITIALLY DEFERRED,
    support_status      text    NOT NULL CHECK (support_status IN ('supported', 'not_supported', 'unknown')),
    support_reason      text    NULL,
    PRIMARY KEY (content_id, idx),
    -- A declaration is all or nothing (decision 0013).
    CHECK (num_nulls(decl_release, decl_edition, decl_arch, release_source, edition_source,
                     arch_source, declared_by, declared_at_us, declared_audit_seq) IN (0, 9)),
    -- Undeclared means unknown (REQ-OS-009).
    CHECK (decl_release IS NOT NULL OR support_status = 'unknown')
);

CREATE TABLE upload (
    id                  uuid    PRIMARY KEY,
    content_id          uuid    NOT NULL UNIQUE REFERENCES content (id),
    operator_id         uuid    NOT NULL REFERENCES operator (id),
    declared_size       bigint  NOT NULL CHECK (declared_size > 0),
    declared_sha256     bytea   NOT NULL CHECK (length(declared_sha256) = 32),
    state               text    NOT NULL CHECK (state IN ('open', 'streaming', 'complete', 'failed', 'cancelled')),
    staging_name        text    NOT NULL UNIQUE,
    created_at_us       bigint  NOT NULL CHECK (created_at_us >= 0),
    expires_at_us       bigint  NOT NULL,
    CHECK (expires_at_us >= created_at_us)
);

-- ------------------------------------------------------------ packages --

CREATE TABLE package (
    id                  uuid    PRIMARY KEY,
    name                text    NOT NULL,
    description         text    NULL,
    image_id            uuid    NOT NULL,
    image_kind          text    NOT NULL DEFAULT 'image' CHECK (image_kind = 'image'),
    edition_index       integer NOT NULL,
    pe_id               uuid    NOT NULL,
    pe_kind             text    NOT NULL DEFAULT 'pe' CHECK (pe_kind = 'pe'),
    revision            bigint  NOT NULL CHECK (revision >= 1),
    status              text    NOT NULL CHECK (status IN ('ready', 'not_usable')),
    status_reason       text    NULL,
    manifest            bytea   NULL,
    manifest_sig        bytea   NULL,
    manifest_key_id     bytea   NULL CHECK (length(manifest_key_id) = 32),
    created_by          uuid    NOT NULL REFERENCES operator (id),
    created_at_us       bigint  NOT NULL CHECK (created_at_us >= 0),
    updated_at_us       bigint  NOT NULL CHECK (updated_at_us >= 0),
    -- The image is an image, the PE is a PE, and the edition exists.
    FOREIGN KEY (image_id, image_kind) REFERENCES content (id, kind),
    FOREIGN KEY (pe_id, pe_kind) REFERENCES content (id, kind),
    FOREIGN KEY (image_id, edition_index) REFERENCES edition (content_id, idx),
    CHECK (num_nulls(manifest, manifest_sig, manifest_key_id) IN (0, 3)),
    CHECK (status <> 'ready' OR manifest IS NOT NULL),
    CHECK (status = 'ready' OR status_reason IS NOT NULL)
);

CREATE INDEX package_image ON package (image_id);
CREATE INDEX package_pe ON package (pe_id);
