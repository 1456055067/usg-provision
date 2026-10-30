-- usg-provision control-plane schema, migration 0005 (M4 plan section
-- 3.5): driver archives and agent packages as content, package
-- configuration, per-device values, the nine-step job, post-setup resume
-- nonces and tokens, and the administrator-password escrow.
--
-- Run by the migration runner (crates/usgp-db/src/migrate.rs) as the owner
-- role, inside one transaction. Must not contain transaction control.
-- Forward-only, like 0001 to 0004.
--
-- Conventions (as 0001 and 0004):
-- - Timestamps are UTC microseconds since the Unix epoch in `bigint`
--   columns named `*_us`.
-- - Value lists in CHECK constraints are exactly the usgp-proto or
--   usgp-db wire values (`X::ALL`); a unit test in usgp-db compares them.
-- - Digests, token hashes and key ids are 32-byte `bytea`.
-- - The plan's `values` column is named `config_values` / `device_values`
--   (`values` is an SQL reserved word).
--
-- Existing constraints of 0001 and 0004 that this migration widens were
-- created unnamed. They are found by the columns they cover (never by a
-- guessed generated name) and the migration stops unless exactly the
-- expected ones are found.
--
-- At rest (SC-28): the escrow table holds only the sealed form of the
-- administrator password (ephemeral public key, nonce, ciphertext); the
-- plaintext and the escrow private key are never stored here. Resume
-- nonces and tokens are stored only as SHA-256.
--
-- COMPLIANCE MAPPING:
-- - NIST 800-53: AC-6 (Least Privilege) - grants per role below; column
--   UPDATE grant on the escrow; no DELETE on escrow, resume or job rows.
-- - NIST 800-53: SC-28, SC-28(1) - escrow stores ciphertext only; the
--   ciphertext is immutable (trigger).
-- - NIST 800-53: IA-5 - resume tokens and nonces stored only as SHA-256;
--   single use and revocation enforced by guards.
-- - NIST 800-53: SI-7 - archive and agent content Ready only with a
--   signed v2 manifest; kinds pinned by foreign keys.
-- - NIST 800-53: SI-10 - closed value sets, lengths and cross-column
--   rules as constraints.
-- - SPEC: specs/drivers.md#REQ-DRV-003, #REQ-DRV-006;
--   specs/configuration.md#REQ-CFG-004, #REQ-CFG-008, #REQ-CFG-009;
--   specs/workflow.md#REQ-SEQ-002, #REQ-SEQ-006;
--   specs/agent-handoff.md#REQ-AGT-001
-- - Decisions 0018, 0024, 0025

-- ------------------------------------------------------------- content --

-- Drop the 0001 kind check and the WIM-only ready check.
DO $$
DECLARE
    a_kind  smallint;
    a_state smallint;
    a_count smallint;
    c       record;
    n       integer := 0;
BEGIN
    SELECT attnum INTO a_kind FROM pg_attribute
        WHERE attrelid = 'content'::regclass AND attname = 'kind';
    SELECT attnum INTO a_state FROM pg_attribute
        WHERE attrelid = 'content'::regclass AND attname = 'state';
    SELECT attnum INTO a_count FROM pg_attribute
        WHERE attrelid = 'content'::regclass AND attname = 'image_count';
    FOR c IN
        SELECT conname FROM pg_constraint
        WHERE conrelid = 'content'::regclass AND contype = 'c'
          AND (conkey = ARRAY[a_kind] OR conkey @> ARRAY[a_state, a_count])
    LOOP
        EXECUTE format('ALTER TABLE content DROP CONSTRAINT %I', c.conname);
        n := n + 1;
    END LOOP;
    IF n <> 2 THEN
        RAISE EXCEPTION 'migration 0005: expected 2 content checks to replace, found %', n;
    END IF;
END;
$$;

ALTER TABLE content
    ADD COLUMN manifest_schema smallint NOT NULL DEFAULT 1,
    ADD COLUMN archive_format text NULL,
    ADD COLUMN archive_entries integer NULL,
    ADD COLUMN archive_expanded_bytes bigint NULL,
    -- A driver archive file replaced by a newer one (REQ-DRV-003). Still
    -- served to ready packages that pin it (OPEN-DRV-2 default); never
    -- attached again. POAM-new-G: superseded rows are not purged in M4.
    ADD COLUMN superseded_at_us bigint NULL,
    ADD CONSTRAINT content_kind_values
        CHECK (kind IN ('image', 'pe', 'driver_archive', 'agent_package')),
    ADD CONSTRAINT content_manifest_schema_values CHECK (manifest_schema IN (1, 2)),
    ADD CONSTRAINT content_manifest_schema_kind
        CHECK ((kind IN ('image', 'pe')) = (manifest_schema = 1)),
    ADD CONSTRAINT content_archive_format_values CHECK (archive_format IN ('zip', 'cab')),
    ADD CONSTRAINT content_archive_entries_range CHECK (archive_entries >= 1),
    ADD CONSTRAINT content_archive_expanded_range CHECK (archive_expanded_bytes >= 0),
    ADD CONSTRAINT content_archive_together
        CHECK (num_nulls(archive_format, archive_entries, archive_expanded_bytes) IN (0, 3)),
    -- WIM facts only on WIM kinds, archive facts only on archive kinds.
    ADD CONSTRAINT content_facts_by_kind
        CHECK (CASE WHEN kind IN ('image', 'pe')
                    THEN archive_format IS NULL
                    ELSE num_nulls(compression, image_count, boot_index, usable_index) = 4
               END),
    ADD CONSTRAINT content_superseded_archive
        CHECK (superseded_at_us IS NULL OR kind = 'driver_archive'),
    ADD CONSTRAINT content_ready_facts
        CHECK (state <> 'ready'
               OR (num_nulls(manifest, ready_at_us) = 0
                   AND CASE WHEN kind IN ('image', 'pe')
                            THEN num_nulls(compression, image_count, boot_index) = 0
                            ELSE archive_format IS NOT NULL
                       END));

-- ------------------------------------------------------------ operator --

-- The escrow-officer role (M4 plan section 1.3; WU-6 follow-up U-2). The
-- 0001 role check is unnamed; it is found by its single column.
DO $$
DECLARE
    c   record;
    n   integer := 0;
BEGIN
    FOR c IN
        SELECT conname FROM pg_constraint
        WHERE conrelid = 'operator'::regclass AND contype = 'c'
          AND conkey = ARRAY[(SELECT attnum FROM pg_attribute
                              WHERE attrelid = 'operator'::regclass AND attname = 'role')]
    LOOP
        EXECUTE format('ALTER TABLE operator DROP CONSTRAINT %I', c.conname);
        n := n + 1;
    END LOOP;
    IF n <> 1 THEN
        RAISE EXCEPTION 'migration 0005: expected 1 operator role check to replace, found %', n;
    END IF;
END;
$$;

ALTER TABLE operator
    ADD CONSTRAINT operator_role_values CHECK (role IN ('administrator', 'escrow_officer'));

-- --------------------------------------------------------------- tags --

-- A tag list: one dimension (or empty), at most 64 entries, each 1 to 128
-- characters, no control characters (usgp-proto `Tag`, `MAX_TAGS`).
CREATE FUNCTION usgp_tags_valid(t text[]) RETURNS boolean
LANGUAGE sql IMMUTABLE AS $$
    SELECT t IS NOT NULL
       AND cardinality(t) <= 64
       AND (cardinality(t) = 0 OR array_ndims(t) = 1)
       AND NOT EXISTS (SELECT 1 FROM unnest(t) AS x(tag)
                       WHERE tag IS NULL
                          OR char_length(tag) NOT BETWEEN 1 AND 128
                          OR tag ~ '[[:cntrl:]]')
$$;

-- ------------------------------------------------------- driver archives --

-- A driver archive keeps its id when its file is replaced (REQ-DRV-003):
-- the content reference moves to the new file and the row returns to
-- `checking`. The INF list and facts are copied from the archive's signed
-- v2 content manifest when it becomes ready.
CREATE TABLE driver_archive (
    id                  uuid    PRIMARY KEY,
    content_id          uuid    NOT NULL UNIQUE,
    content_kind        text    NOT NULL DEFAULT 'driver_archive'
                                CHECK (content_kind = 'driver_archive'),
    name                text    NOT NULL CHECK (char_length(name) BETWEEN 1 AND 128),
    kind                text    NULL CHECK (kind IN ('zip', 'cab')),
    status              text    NOT NULL CHECK (status IN ('checking', 'ready', 'refused', 'deleted')),
    refusal             text    NULL CHECK (length(refusal) BETWEEN 1 AND 128),
    inf_list            jsonb   NOT NULL DEFAULT '[]'::jsonb
                                CHECK (jsonb_typeof(inf_list) = 'array'
                                       AND jsonb_array_length(inf_list) <= 4096),
    expanded_bytes      bigint  NULL CHECK (expanded_bytes >= 0),
    created_by          uuid    NOT NULL REFERENCES operator (id),
    created_at_us       bigint  NOT NULL CHECK (created_at_us >= 0),
    updated_at_us       bigint  NOT NULL CHECK (updated_at_us >= 0),
    replaced_at_us      bigint  NULL CHECK (replaced_at_us >= 0),
    FOREIGN KEY (content_id, content_kind) REFERENCES content (id, kind),
    CHECK (status <> 'refused' OR refusal IS NOT NULL),
    CHECK (status IN ('refused', 'deleted') OR refusal IS NULL),
    CHECK (num_nulls(kind, expanded_bytes) IN (0, 2)),
    CHECK (status <> 'ready' OR (kind IS NOT NULL AND jsonb_array_length(inf_list) >= 1)),
    CHECK (status <> 'checking' OR (kind IS NULL AND jsonb_array_length(inf_list) = 0))
);

-- The ordered driver archives of a package (at most 64, REQ-DRV-006).
CREATE TABLE package_driver (
    package_id          uuid     NOT NULL REFERENCES package (id) ON DELETE CASCADE,
    archive_id          uuid     NOT NULL REFERENCES driver_archive (id),
    ord                 smallint NOT NULL CHECK (ord BETWEEN 1 AND 64),
    PRIMARY KEY (package_id, archive_id),
    UNIQUE (package_id, ord)
);

CREATE INDEX package_driver_archive ON package_driver (archive_id);

-- ------------------------------------------------------- agent packages --

-- Keys that may sign agent packages (decision 0025 item 5), registered by
-- an administrator. `key_id` is the SHA-256 of `spki` (checked by the
-- repository through usgp-crypto on write and read).
CREATE TABLE agent_signer (
    id                  uuid    PRIMARY KEY,
    spki                bytea   NOT NULL UNIQUE CHECK (length(spki) = 120),
    key_id              bytea   NOT NULL UNIQUE CHECK (length(key_id) = 32),
    name                text    NOT NULL CHECK (char_length(name) BETWEEN 1 AND 128),
    added_by            uuid    NOT NULL REFERENCES operator (id),
    added_at_us         bigint  NOT NULL CHECK (added_at_us >= 0),
    revoked_at_us       bigint  NULL,
    revoked_by          uuid    NULL REFERENCES operator (id),
    CHECK (num_nulls(revoked_at_us, revoked_by) IN (0, 2))
);

CREATE TABLE agent_package (
    id                  uuid    PRIMARY KEY,
    content_id          uuid    NOT NULL UNIQUE,
    content_kind        text    NOT NULL DEFAULT 'agent_package'
                                CHECK (content_kind = 'agent_package'),
    signer_id           uuid    NULL REFERENCES agent_signer (id),
    -- `agent.json` (`AgentPackageManifestV1`), re-validated on read.
    manifest            jsonb   NULL CHECK (jsonb_typeof(manifest) = 'object'
                                            AND octet_length(manifest::text) <= 65536),
    status              text    NOT NULL CHECK (status IN ('checking', 'ready', 'refused')),
    refusal             text    NULL CHECK (length(refusal) BETWEEN 1 AND 128),
    created_by          uuid    NOT NULL REFERENCES operator (id),
    created_at_us       bigint  NOT NULL CHECK (created_at_us >= 0),
    updated_at_us       bigint  NOT NULL CHECK (updated_at_us >= 0),
    FOREIGN KEY (content_id, content_kind) REFERENCES content (id, kind),
    CHECK ((status = 'refused') = (refusal IS NOT NULL)),
    CHECK (status <> 'ready' OR num_nulls(signer_id, manifest) = 0)
);

-- ------------------------------------------------ package configuration --

-- One configuration per package (M4 plan section 3.2). Removed with its
-- package. The answer-file template is stored inline (WU-6 follow-up
-- U-1): at most 1 MiB, with its SHA-256 (checked through usgp-crypto by
-- the repository on write and read).
CREATE TABLE package_config (
    package_id          uuid    PRIMARY KEY REFERENCES package (id) ON DELETE CASCADE,
    answer_template     bytea   NOT NULL CHECK (length(answer_template) BETWEEN 1 AND 1048576),
    answer_sha256       bytea   NOT NULL CHECK (length(answer_sha256) = 32),
    config_values       jsonb   NOT NULL
                                CHECK (jsonb_typeof(config_values) = 'object'
                                       AND config_values - ARRAY['computer_name', 'time_zone', 'domain', 'machine_ou'] = '{}'::jsonb
                                       AND octet_length(config_values::text) <= 65536),
    tags                text[]  NOT NULL CHECK (usgp_tags_valid(tags)),
    agent_package_id    uuid    NOT NULL REFERENCES agent_package (id),
    admin_password_mode text    NOT NULL CHECK (admin_password_mode IN ('generate_and_escrow', 'none')),
    updated_by          uuid    NOT NULL REFERENCES operator (id),
    updated_at_us       bigint  NOT NULL CHECK (updated_at_us >= 0)
);

CREATE INDEX package_config_agent_package ON package_config (agent_package_id);

-- Per-device values keyed by MAC (REQ-CFG-004 `device.<key>`).
CREATE TABLE device_value (
    mac                 bytea   PRIMARY KEY CHECK (length(mac) = 6),
    device_values       jsonb   NOT NULL
                                CHECK (jsonb_typeof(device_values) = 'object'
                                       AND octet_length(device_values::text) <= 524288),
    updated_by          uuid    NOT NULL REFERENCES operator (id),
    updated_at_us       bigint  NOT NULL CHECK (updated_at_us >= 0)
);

-- ---------------------------------------------------------------- jobs --

-- Drop the 0004 step-range checks that fixed five steps.
DO $$
DECLARE
    c   record;
    n   integer := 0;
BEGIN
    FOR c IN
        SELECT con.conname, rel.relname FROM pg_constraint con
        JOIN pg_class rel ON rel.oid = con.conrelid
        WHERE con.contype = 'c'
          AND ((con.conrelid = 'job'::regclass
                AND con.conkey IN (
                    ARRAY[(SELECT attnum FROM pg_attribute
                           WHERE attrelid = 'job'::regclass AND attname = 'current_step')],
                    ARRAY[(SELECT attnum FROM pg_attribute
                           WHERE attrelid = 'job'::regclass AND attname = 'failure_step')],
                    ARRAY[(SELECT attnum FROM pg_attribute
                           WHERE attrelid = 'job'::regclass AND attname = 'step_timeouts_s')]))
            OR (con.conrelid = 'job_step'::regclass
                AND con.conkey = ARRAY[(SELECT attnum FROM pg_attribute
                                        WHERE attrelid = 'job_step'::regclass AND attname = 'step')]))
    LOOP
        EXECUTE format('ALTER TABLE %I DROP CONSTRAINT %I', c.relname, c.conname);
        n := n + 1;
    END LOOP;
    IF n <> 4 THEN
        RAISE EXCEPTION 'migration 0005: expected 4 step checks to replace, found %', n;
    END IF;
END;
$$;

-- Plan schema 1 (M3, five steps) or 2 (M4, nine steps, REQ-SEQ-002). The
-- v2 columns are set exactly on v2 jobs.
ALTER TABLE job
    ADD COLUMN plan_schema smallint NOT NULL DEFAULT 1,
    -- The device-generated job key (decision 0025 item 1): public SPKI DER
    -- and its SHA-256 (checked by the repository through usgp-crypto).
    ADD COLUMN job_key_spki bytea NULL,
    ADD COLUMN job_key_id bytea NULL,
    ADD COLUMN rendered_answer_sha256 bytea NULL,
    ADD COLUMN tags text[] NULL,
    -- The agent installer asked for a restart (exit 3010, never performed).
    ADD COLUMN restart_pending boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT job_plan_schema_values CHECK (plan_schema IN (1, 2)),
    ADD CONSTRAINT job_key_spki_length CHECK (length(job_key_spki) = 120),
    ADD CONSTRAINT job_key_id_length CHECK (length(job_key_id) = 32),
    ADD CONSTRAINT job_rendered_answer_length CHECK (length(rendered_answer_sha256) = 32),
    ADD CONSTRAINT job_tags_valid CHECK (tags IS NULL OR usgp_tags_valid(tags)),
    ADD CONSTRAINT job_v2_columns
        CHECK (num_nulls(job_key_spki, job_key_id, rendered_answer_sha256, tags)
               = CASE plan_schema WHEN 2 THEN 0 ELSE 4 END),
    ADD CONSTRAINT job_restart_pending_v2 CHECK (plan_schema = 2 OR NOT restart_pending),
    ADD CONSTRAINT job_current_step_range
        CHECK (current_step BETWEEN 1 AND CASE plan_schema WHEN 1 THEN 5 ELSE 9 END),
    ADD CONSTRAINT job_failure_step_range
        CHECK (failure_step BETWEEN 1 AND CASE plan_schema WHEN 1 THEN 5 ELSE 9 END),
    ADD CONSTRAINT job_step_timeouts_shape
        CHECK (cardinality(step_timeouts_s) = CASE plan_schema WHEN 1 THEN 5 ELSE 9 END
               AND array_position(step_timeouts_s, NULL) IS NULL
               AND 0 < ALL (step_timeouts_s)),
    -- Lets the escrow and resume tables pin a v2 job.
    ADD CONSTRAINT job_id_plan_schema UNIQUE (id, plan_schema);

ALTER TABLE job_step
    ADD CONSTRAINT job_step_range CHECK (step BETWEEN 1 AND 9);

-- A step row exists only for the job's own steps (5 or 9).
CREATE FUNCTION usgp_job_step_range() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.step > (SELECT CASE j.plan_schema WHEN 1 THEN 5 ELSE 9 END
                   FROM job j WHERE j.id = NEW.job_id) THEN
        RAISE EXCEPTION 'step beyond the job''s plan'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER job_step_range
    BEFORE INSERT ON job_step
    FOR EACH ROW EXECUTE FUNCTION usgp_job_step_range();

-- The 0004 job guard, extended: the v2 identity columns never change; a
-- finished job keeps `restart_pending`; `restart_pending` never clears.
CREATE OR REPLACE FUNCTION usgp_job_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.id, NEW.session_id, NEW.boot_service_id, NEW.package_id, NEW.package_revision,
        NEW.image_content_id, NEW.edition_index, NEW.disk, NEW.macs, NEW.previous_job_id,
        NEW.wipe_audit_seq, NEW.wipe_record_hash, NEW.plan_sha256, NEW.plan_key_id,
        NEW.started_at_us, NEW.step_timeouts_s, NEW.stall_timeout_s, NEW.plan_schema,
        NEW.job_key_spki, NEW.job_key_id, NEW.rendered_answer_sha256, NEW.tags)
       IS DISTINCT FROM
       (OLD.id, OLD.session_id, OLD.boot_service_id, OLD.package_id, OLD.package_revision,
        OLD.image_content_id, OLD.edition_index, OLD.disk, OLD.macs, OLD.previous_job_id,
        OLD.wipe_audit_seq, OLD.wipe_record_hash, OLD.plan_sha256, OLD.plan_key_id,
        OLD.started_at_us, OLD.step_timeouts_s, OLD.stall_timeout_s, OLD.plan_schema,
        OLD.job_key_spki, OLD.job_key_id, OLD.rendered_answer_sha256, OLD.tags) THEN
        RAISE EXCEPTION 'a job identity and its wipe authorisation cannot be altered'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF OLD.state IN ('succeeded', 'failed') THEN
        IF (NEW.state, NEW.current_step, NEW.layout, NEW.failure_step, NEW.failure_category,
            NEW.failure_detail, NEW.attempts, NEW.bytes_done, NEW.bytes_total, NEW.last_seq,
            NEW.last_report_at_us, NEW.finished_at_us, NEW.restart_pending)
           IS DISTINCT FROM
           (OLD.state, OLD.current_step, OLD.layout, OLD.failure_step, OLD.failure_category,
            OLD.failure_detail, OLD.attempts, OLD.bytes_done, OLD.bytes_total, OLD.last_seq,
            OLD.last_report_at_us, OLD.finished_at_us, OLD.restart_pending) THEN
            RAISE EXCEPTION 'a finished job cannot change'
                USING ERRCODE = 'integrity_constraint_violation';
        END IF;
    ELSIF NEW.state <> OLD.state
          AND NOT ((OLD.state = 'running' AND NEW.state IN ('succeeded', 'failed', 'lost'))
                OR (OLD.state = 'lost' AND NEW.state IN ('running', 'succeeded', 'failed'))) THEN
        RAISE EXCEPTION 'job state transition not allowed'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.last_seq < OLD.last_seq OR NEW.current_step < OLD.current_step THEN
        RAISE EXCEPTION 'job progress cannot go backwards'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF OLD.restart_pending AND NOT NEW.restart_pending THEN
        RAISE EXCEPTION 'a pending restart cannot be cleared'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF OLD.acknowledged_by IS NOT NULL
       AND (NEW.acknowledged_by, NEW.acknowledged_at_us)
           IS DISTINCT FROM (OLD.acknowledged_by, OLD.acknowledged_at_us) THEN
        RAISE EXCEPTION 'an acknowledgement cannot be altered'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

-- The 0004 session guard, extended by one move: a confirmed session ends
-- once, when its job reaches step 6 (the WinPE session token is revoked,
-- M4 plan section 3.1), changing only its state, end time and reason.
CREATE OR REPLACE FUNCTION usgp_device_session_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.id, NEW.token_sha256, NEW.source_ip, NEW.macs, NEW.display_code, NEW.created_at_us)
       IS DISTINCT FROM
       (OLD.id, OLD.token_sha256, OLD.source_ip, OLD.macs, OLD.display_code, OLD.created_at_us) THEN
        RAISE EXCEPTION 'a session identity cannot be altered'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF OLD.state = 'confirmed' AND NEW.state = 'ended' THEN
        IF (NEW.boot_service_id, NEW.auth_method, NEW.auth_code_id, NEW.approved_by,
            NEW.failed_code_attempts, NEW.chosen_package_id, NEW.chosen_package_revision,
            NEW.chosen_disk, NEW.expires_at_us)
           IS DISTINCT FROM
           (OLD.boot_service_id, OLD.auth_method, OLD.auth_code_id, OLD.approved_by,
            OLD.failed_code_attempts, OLD.chosen_package_id, OLD.chosen_package_revision,
            OLD.chosen_disk, OLD.expires_at_us) THEN
            RAISE EXCEPTION 'closing a confirmed session changes only its state'
                USING ERRCODE = 'integrity_constraint_violation';
        END IF;
        RETURN NEW;
    END IF;
    -- A final session never changes state ...
    IF OLD.state IN ('confirmed', 'refused', 'cancelled', 'expired', 'ended')
       AND NEW.state IS DISTINCT FROM OLD.state THEN
        RAISE EXCEPTION 'a final session cannot change state'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    -- ... and keeps everything else except when it was last seen.
    IF OLD.state IN ('confirmed', 'refused', 'cancelled', 'expired', 'ended')
       AND (NEW.state, NEW.boot_service_id, NEW.auth_method, NEW.auth_code_id, NEW.approved_by,
            NEW.failed_code_attempts, NEW.chosen_package_id, NEW.chosen_package_revision,
            NEW.chosen_disk, NEW.expires_at_us, NEW.ended_at_us, NEW.end_reason)
           IS DISTINCT FROM
           (OLD.state, OLD.boot_service_id, OLD.auth_method, OLD.auth_code_id, OLD.approved_by,
            OLD.failed_code_attempts, OLD.chosen_package_id, OLD.chosen_package_revision,
            OLD.chosen_disk, OLD.expires_at_us, OLD.ended_at_us, OLD.end_reason) THEN
        RAISE EXCEPTION 'a final session cannot change'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

-- --------------------------------------------------------------- resume --

-- Challenge nonces (60 s, single use) and job-scoped resume tokens, both
-- stored only as SHA-256 (M4 plan section 3.1). v2 jobs only.
-- POAM-new-G: expired, used or revoked rows are not purged in M4; they are
-- inert (every lookup checks expiry, use and revocation) and bounded (16
-- live nonces, 10 tokens per job). Planned: a scheduled admin purge that
-- respects AU-11 retention (M5).
CREATE TABLE job_resume_nonce (
    nonce_hash          bytea    PRIMARY KEY CHECK (length(nonce_hash) = 32),
    job_id              uuid     NOT NULL,
    job_schema          smallint NOT NULL DEFAULT 2 CHECK (job_schema = 2),
    issued_at_us        bigint   NOT NULL CHECK (issued_at_us >= 0),
    expires_at_us       bigint   NOT NULL,
    used_at_us          bigint   NULL,
    FOREIGN KEY (job_id, job_schema) REFERENCES job (id, plan_schema),
    CHECK (expires_at_us > issued_at_us)
);

CREATE INDEX job_resume_nonce_job ON job_resume_nonce (job_id);

CREATE TABLE job_resume_token (
    token_hash          bytea    PRIMARY KEY CHECK (length(token_hash) = 32),
    job_id              uuid     NOT NULL,
    job_schema          smallint NOT NULL DEFAULT 2 CHECK (job_schema = 2),
    issued_at_us        bigint   NOT NULL CHECK (issued_at_us >= 0),
    expires_at_us       bigint   NOT NULL,
    revoked_at_us       bigint   NULL,
    FOREIGN KEY (job_id, job_schema) REFERENCES job (id, plan_schema),
    CHECK (expires_at_us > issued_at_us)
);

CREATE INDEX job_resume_token_job ON job_resume_token (job_id);

-- --------------------------------------------------------------- escrow --

-- The administrator password, sealed on the device to the server's escrow
-- key (M4 plan section 1.3). One per job; only ciphertext at rest.
CREATE TABLE admin_password_escrow (
    job_id              uuid     PRIMARY KEY,
    job_schema          smallint NOT NULL DEFAULT 2 CHECK (job_schema = 2),
    account             text     NOT NULL CHECK (account IN ('administrator')),
    key_id              bytea    NOT NULL CHECK (length(key_id) = 32),
    -- Uncompressed P-384 point (RFC 5480 section 2.2).
    eph_pub             bytea    NOT NULL CHECK (length(eph_pub) = 97
                                                 AND substring(eph_pub FROM 1 FOR 1) = '\x04'::bytea),
    nonce               bytea    NOT NULL CHECK (length(nonce) = 12),
    ciphertext          bytea    NOT NULL CHECK (length(ciphertext) BETWEEN 17 AND 512),
    received_at_us      bigint   NOT NULL CHECK (received_at_us >= 0),
    state               text     NOT NULL CHECK (state IN ('received', 'applied', 'not_applied')),
    applied_at_us       bigint   NULL,
    reveal_count        integer  NOT NULL DEFAULT 0 CHECK (reveal_count >= 0),
    FOREIGN KEY (job_id, job_schema) REFERENCES job (id, plan_schema),
    CHECK ((state = 'received') = (applied_at_us IS NULL))
);

-- -------------------------------------------------------------- guards --

CREATE FUNCTION usgp_driver_archive_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.id, NEW.created_by, NEW.created_at_us) IS DISTINCT FROM
       (OLD.id, OLD.created_by, OLD.created_at_us) THEN
        RAISE EXCEPTION 'a driver archive identity cannot be altered'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF OLD.status = 'deleted' THEN
        RAISE EXCEPTION 'a deleted driver archive cannot change'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    -- The file moves only by a replacement, which restarts the check.
    IF NEW.content_id <> OLD.content_id AND NEW.status <> 'checking' THEN
        RAISE EXCEPTION 'a driver archive file changes only by replacement'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER driver_archive_guard
    BEFORE UPDATE ON driver_archive
    FOR EACH ROW EXECUTE FUNCTION usgp_driver_archive_guard();

CREATE FUNCTION usgp_agent_signer_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.id, NEW.spki, NEW.key_id, NEW.name, NEW.added_by, NEW.added_at_us)
       IS DISTINCT FROM
       (OLD.id, OLD.spki, OLD.key_id, OLD.name, OLD.added_by, OLD.added_at_us) THEN
        RAISE EXCEPTION 'a registered signer cannot be altered'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF OLD.revoked_at_us IS NOT NULL
       AND (NEW.revoked_at_us, NEW.revoked_by) IS DISTINCT FROM (OLD.revoked_at_us, OLD.revoked_by) THEN
        RAISE EXCEPTION 'a revoked signer stays revoked'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER agent_signer_guard
    BEFORE UPDATE ON agent_signer
    FOR EACH ROW EXECUTE FUNCTION usgp_agent_signer_guard();

CREATE FUNCTION usgp_agent_package_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.id, NEW.content_id, NEW.created_by, NEW.created_at_us) IS DISTINCT FROM
       (OLD.id, OLD.content_id, OLD.created_by, OLD.created_at_us) THEN
        RAISE EXCEPTION 'an agent package identity cannot be altered'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    -- The one move out of ready: its signer was revoked (WU-6 follow-up
    -- U-3); only the status, reason and time change.
    IF OLD.status = 'ready' AND NEW.status = 'refused' AND NEW.refusal = 'signer_revoked'
       AND (NEW.signer_id, NEW.manifest) IS NOT DISTINCT FROM (OLD.signer_id, OLD.manifest)
       AND EXISTS (SELECT 1 FROM agent_signer s
                   WHERE s.id = OLD.signer_id AND s.revoked_at_us IS NOT NULL) THEN
        RETURN NEW;
    END IF;
    IF OLD.status IN ('ready', 'refused')
       AND (NEW.status, NEW.signer_id, NEW.manifest, NEW.refusal, NEW.updated_at_us)
           IS DISTINCT FROM
           (OLD.status, OLD.signer_id, OLD.manifest, OLD.refusal, OLD.updated_at_us) THEN
        RAISE EXCEPTION 'a checked agent package cannot change'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER agent_package_guard
    BEFORE UPDATE ON agent_package
    FOR EACH ROW EXECUTE FUNCTION usgp_agent_package_guard();

-- Superseded content stays superseded (U-4).
CREATE FUNCTION usgp_content_superseded_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.superseded_at_us IS NOT NULL
       AND NEW.superseded_at_us IS DISTINCT FROM OLD.superseded_at_us THEN
        RAISE EXCEPTION 'superseded content stays superseded'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER content_superseded_guard
    BEFORE UPDATE ON content
    FOR EACH ROW EXECUTE FUNCTION usgp_content_superseded_guard();

-- A driver archive never (re)attaches superseded content (U-4).
CREATE FUNCTION usgp_driver_archive_content_live() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF (TG_OP = 'INSERT' OR NEW.content_id IS DISTINCT FROM OLD.content_id)
       AND EXISTS (SELECT 1 FROM content c
                   WHERE c.id = NEW.content_id AND c.superseded_at_us IS NOT NULL) THEN
        RAISE EXCEPTION 'superseded content cannot be attached'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER driver_archive_content_live
    BEFORE INSERT OR UPDATE ON driver_archive
    FOR EACH ROW EXECUTE FUNCTION usgp_driver_archive_content_live();

CREATE FUNCTION usgp_job_resume_nonce_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.nonce_hash, NEW.job_id, NEW.job_schema, NEW.issued_at_us, NEW.expires_at_us)
       IS DISTINCT FROM
       (OLD.nonce_hash, OLD.job_id, OLD.job_schema, OLD.issued_at_us, OLD.expires_at_us)
       OR OLD.used_at_us IS NOT NULL THEN
        RAISE EXCEPTION 'a resume nonce is used once and never altered'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER job_resume_nonce_guard
    BEFORE UPDATE ON job_resume_nonce
    FOR EACH ROW EXECUTE FUNCTION usgp_job_resume_nonce_guard();

CREATE FUNCTION usgp_job_resume_token_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.token_hash, NEW.job_id, NEW.job_schema, NEW.issued_at_us, NEW.expires_at_us)
       IS DISTINCT FROM
       (OLD.token_hash, OLD.job_id, OLD.job_schema, OLD.issued_at_us, OLD.expires_at_us)
       OR OLD.revoked_at_us IS NOT NULL THEN
        RAISE EXCEPTION 'a resume token is revoked once and never altered'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER job_resume_token_guard
    BEFORE UPDATE ON job_resume_token
    FOR EACH ROW EXECUTE FUNCTION usgp_job_resume_token_guard();

-- The sealed password never changes (SC-28): an update may change only
-- the state (received to applied or not_applied, once), the time of that
-- change and the reveal count (which only grows).
CREATE FUNCTION usgp_escrow_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'received' OR NEW.reveal_count <> 0 THEN
            RAISE EXCEPTION 'an escrow starts received and unrevealed'
                USING ERRCODE = 'integrity_constraint_violation';
        END IF;
        RETURN NEW;
    END IF;
    IF (NEW.job_id, NEW.job_schema, NEW.account, NEW.key_id, NEW.eph_pub, NEW.nonce,
        NEW.ciphertext, NEW.received_at_us)
       IS DISTINCT FROM
       (OLD.job_id, OLD.job_schema, OLD.account, OLD.key_id, OLD.eph_pub, OLD.nonce,
        OLD.ciphertext, OLD.received_at_us) THEN
        RAISE EXCEPTION 'an escrowed password cannot be altered'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF OLD.state <> 'received'
       AND (NEW.state, NEW.applied_at_us) IS DISTINCT FROM (OLD.state, OLD.applied_at_us) THEN
        RAISE EXCEPTION 'an escrow outcome is recorded once'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.reveal_count < OLD.reveal_count THEN
        RAISE EXCEPTION 'the reveal count only grows'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER admin_password_escrow_guard
    BEFORE INSERT OR UPDATE ON admin_password_escrow
    FOR EACH ROW EXECUTE FUNCTION usgp_escrow_guard();

-- ---------------------------------------------------------- privileges --

REVOKE ALL ON FUNCTION usgp_tags_valid(text[]), usgp_job_step_range(),
    usgp_driver_archive_guard(), usgp_agent_signer_guard(), usgp_agent_package_guard(),
    usgp_job_resume_nonce_guard(), usgp_job_resume_token_guard(), usgp_escrow_guard(),
    usgp_content_superseded_guard(), usgp_driver_archive_content_live()
    FROM PUBLIC;
REVOKE ALL ON driver_archive, package_driver, agent_signer, agent_package, package_config,
    device_value, job_resume_nonce, job_resume_token, admin_password_escrow FROM PUBLIC;

-- Application role (plan section 3.5). Package drivers are replaced
-- (INSERT, DELETE); device values are deleted by an operator route;
-- everything else changes state but is never deleted. The escrow is
-- written once and only its state, outcome time and reveal count change.
GRANT SELECT, INSERT, UPDATE ON driver_archive, agent_signer, agent_package, package_config,
    job_resume_nonce, job_resume_token TO usgp_app;
GRANT SELECT, INSERT, DELETE ON package_driver TO usgp_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON device_value TO usgp_app;
GRANT SELECT, INSERT ON admin_password_escrow TO usgp_app;
GRANT UPDATE (state, applied_at_us, reveal_count) ON admin_password_escrow TO usgp_app;
GRANT EXECUTE ON FUNCTION usgp_tags_valid(text[]), usgp_job_step_range(),
    usgp_driver_archive_guard(), usgp_agent_signer_guard(), usgp_agent_package_guard(),
    usgp_job_resume_nonce_guard(), usgp_job_resume_token_guard(), usgp_escrow_guard(),
    usgp_content_superseded_guard(), usgp_driver_archive_content_live()
    TO usgp_app;
