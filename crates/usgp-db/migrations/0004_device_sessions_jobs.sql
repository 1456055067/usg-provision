-- usg-provision control-plane schema, migration 0004 (plan M3 section 3.8):
-- boot services, device sessions, operator codes, jobs, job steps, boot
-- stops and boot-policy generations.
--
-- Run by the migration runner (crates/usgp-db/src/migrate.rs) as the owner
-- role, inside one transaction. Must not contain transaction control.
-- Forward-only, like 0001 to 0003.
--
-- Conventions (as 0001):
-- - Timestamps are UTC microseconds since the Unix epoch in `bigint`
--   columns named `*_us`.
-- - Value lists in CHECK constraints are exactly the usgp-proto wire values
--   (`X::ALL`); a unit test in usgp-db compares them.
-- - Digests, HMAC tags and key ids are 32-byte `bytea`; MAC addresses are
--   6-byte `bytea`.
-- - JSON documents (disk descriptor, layout report, failure) are stored as
--   the exact rendered `text`, never `jsonb`, and re-validated on read.
--
-- Guards (triggers, defence in depth behind the privileges below):
-- - an operator code is stored only as its HMAC-SHA-256; the HMAC and the
--   issue fields never change; a used or revoked code stays so;
-- - a finished job (succeeded or failed) never changes again, except that a
--   failure is acknowledged once; state moves only along the documented
--   transitions; the wipe authorisation reference never changes;
-- - a finished step, a final session and a cleared boot stop stay so;
-- - the boot-policy generation only increases.
--
-- Wipe guard (REQ-DISK-006, decision 0018 item 7): every job names the
-- `disk.wipe.authorised` audit record that authorised it, by sequence
-- number and record hash. The reference is a deferred foreign key into
-- audit_record and a deferred constraint trigger that checks the record's
-- event, outcome and target (this job). Both are checked when the
-- transaction ends, so the job, its audit records and the session change
-- become durable together or not at all, before the server signs the plan.
-- Each wipe record authorises exactly one job (unique reference).
--
-- COMPLIANCE MAPPING:
-- - NIST 800-53: AC-6 (Least Privilege) - grants per role below.
-- - NIST 800-53: IA-5 (Authenticator Management) - codes stored only as
--   keyed HMAC; single use enforced by a guard; no code value at rest.
-- - NIST 800-53: AU-9, AU-12 - the wipe authorisation is an audit record
--   the job must reference.
-- - NIST 800-53: SI-10 (Information Input Validation) - closed value sets,
--   lengths and cross-column rules as constraints.
-- - NIST 800-53: SI-7 - plan digest and signing key recorded with the job.
-- - SPEC: specs/targeting.md#REQ-TGT-001, #REQ-TGT-013, #REQ-TGT-014,
--   #REQ-TGT-016; specs/disk.md#REQ-DISK-006; specs/progress.md#REQ-JOB-001,
--   #REQ-JOB-002, #REQ-JOB-006, #REQ-JOB-009, #REQ-JOB-012;
--   specs/boot-network.md#REQ-BOOT-067
-- - Decisions 0008, 0016, 0018, 0020, 0021

-- --------------------------------------------------------- functions --

-- A device's MAC list: one dimension, 1 to 16 entries, each 6 bytes.
CREATE FUNCTION usgp_macs_valid(m bytea[]) RETURNS boolean
LANGUAGE sql IMMUTABLE AS $$
    SELECT m IS NOT NULL
       AND array_ndims(m) = 1
       AND cardinality(m) BETWEEN 1 AND 16
       AND NOT EXISTS (SELECT 1 FROM unnest(m) AS x(mac) WHERE mac IS NULL OR length(mac) <> 6)
$$;

-- ------------------------------------------------------ boot services --

-- Written only by the administrative role (decision 0021 item 1: manual
-- enrolment by an administrative server command).
CREATE TABLE boot_service (
    id                  uuid    PRIMARY KEY,
    name                text    NOT NULL UNIQUE,
    cert_sha256         bytea   NOT NULL UNIQUE CHECK (length(cert_sha256) = 32),
    cert_not_after_us   bigint  NOT NULL,
    served_subnets      text[]  NOT NULL CHECK (array_ndims(served_subnets) = 1
                                    AND cardinality(served_subnets) BETWEEN 1 AND 64),
    status              text    NOT NULL CHECK (status IN ('active', 'disabled')),
    created_at_us       bigint  NOT NULL CHECK (created_at_us >= 0),
    created_by          text    NOT NULL
);

-- Packages offered through a boot service (REQ-TGT-001). A package that is
-- assigned cannot be deleted until it is unassigned (foreign key).
CREATE TABLE boot_service_package (
    boot_service_id     uuid    NOT NULL REFERENCES boot_service (id),
    package_id          uuid    NOT NULL REFERENCES package (id),
    added_by            uuid    NOT NULL REFERENCES operator (id),
    added_at_us         bigint  NOT NULL CHECK (added_at_us >= 0),
    PRIMARY KEY (boot_service_id, package_id)
);

CREATE INDEX boot_service_package_package ON boot_service_package (package_id);

-- ------------------------------------------------------ operator codes --

-- No code value is stored: only HMAC-SHA-256 under the server's code key
-- (plan section 5), looked up through the unique index.
CREATE TABLE auth_code (
    id                  uuid    PRIMARY KEY,
    code_hmac           bytea   NOT NULL UNIQUE CHECK (length(code_hmac) = 32),
    issued_by           uuid    NOT NULL REFERENCES operator (id),
    issued_at_us        bigint  NOT NULL CHECK (issued_at_us >= 0),
    expires_at_us       bigint  NOT NULL,
    used_at_us          bigint  NULL,
    used_by_session     uuid    NULL,
    revoked_at_us       bigint  NULL,
    revoked_by          uuid    NULL REFERENCES operator (id),
    note                text    NULL CHECK (char_length(note) BETWEEN 1 AND 200),
    CHECK (expires_at_us > issued_at_us),
    CHECK (num_nulls(used_at_us, used_by_session) IN (0, 2)),
    CHECK (num_nulls(revoked_at_us, revoked_by) IN (0, 2)),
    CHECK (used_at_us IS NULL OR revoked_at_us IS NULL)
);

-- ----------------------------------------------------- device sessions --

CREATE TABLE device_session (
    id                      uuid     PRIMARY KEY,
    -- SHA-256 of the bearer token; the token itself is never stored.
    token_sha256            bytea    NOT NULL UNIQUE CHECK (length(token_sha256) = 32),
    boot_service_id         uuid     NULL REFERENCES boot_service (id),
    source_ip               inet     NOT NULL,
    macs                    bytea[]  NOT NULL CHECK (usgp_macs_valid(macs)),
    firmware                text     NOT NULL CHECK (firmware IN ('uefi', 'bios', 'unknown')),
    arch                    text     NOT NULL CHECK (arch IN ('x64', 'x86', 'arm64', 'unknown')),
    secure_boot             text     NOT NULL CHECK (secure_boot IN ('on', 'off', 'unknown')),
    memory_bytes            bigint   NOT NULL CHECK (memory_bytes >= 0),
    agent_version           text     NOT NULL CHECK (length(agent_version) BETWEEN 1 AND 64),
    display_code            text     NOT NULL CHECK (length(display_code) = 7),
    state                   text     NOT NULL CHECK (state IN ('awaiting_authorisation', 'authorised', 'confirmed', 'refused', 'cancelled', 'expired', 'ended')),
    auth_method             text     NULL CHECK (auth_method IN ('code', 'approval')),
    auth_code_id            uuid     NULL REFERENCES auth_code (id),
    approved_by             uuid     NULL REFERENCES operator (id),
    failed_code_attempts    smallint NOT NULL DEFAULT 0 CHECK (failed_code_attempts >= 0),
    -- No foreign key: a session's choice is history and does not keep a
    -- package from being deleted.
    chosen_package_id       uuid     NULL,
    chosen_package_revision bigint   NULL CHECK (chosen_package_revision >= 1),
    chosen_disk             text     NULL CHECK (length(chosen_disk) BETWEEN 2 AND 65536),
    created_at_us           bigint   NOT NULL CHECK (created_at_us >= 0),
    last_seen_at_us         bigint   NOT NULL CHECK (last_seen_at_us >= 0),
    expires_at_us           bigint   NOT NULL,
    ended_at_us             bigint   NULL,
    end_reason              text     NULL CHECK (length(end_reason) BETWEEN 1 AND 128),
    CHECK (expires_at_us >= created_at_us),
    -- The method names exactly one authoriser.
    CHECK ((auth_method IS NULL) = (auth_code_id IS NULL AND approved_by IS NULL)),
    CHECK (auth_method IS DISTINCT FROM 'code' OR (auth_code_id IS NOT NULL AND approved_by IS NULL)),
    CHECK (auth_method IS DISTINCT FROM 'approval' OR (approved_by IS NOT NULL AND auth_code_id IS NULL)),
    -- No package list, choice or job before authorisation (REQ-TGT-013/014).
    CHECK (state NOT IN ('authorised', 'confirmed') OR auth_method IS NOT NULL),
    CHECK (state <> 'awaiting_authorisation' OR auth_method IS NULL),
    CHECK (num_nulls(chosen_package_id, chosen_package_revision) IN (0, 2)),
    CHECK (chosen_disk IS NULL OR chosen_package_id IS NOT NULL),
    CHECK (state <> 'confirmed' OR chosen_disk IS NOT NULL),
    CHECK ((state IN ('refused', 'cancelled', 'expired', 'ended')) = (ended_at_us IS NOT NULL))
);

-- Display codes are unique among live sessions, so an approval names one
-- device (plan section 6).
CREATE UNIQUE INDEX device_session_live_display_code ON device_session (display_code)
    WHERE state IN ('awaiting_authorisation', 'authorised');
CREATE INDEX device_session_state ON device_session (state);

-- A code is used by at most one session.
ALTER TABLE auth_code
    ADD FOREIGN KEY (used_by_session) REFERENCES device_session (id);

-- ---------------------------------------------------------------- jobs --

CREATE TABLE job (
    id                  uuid     PRIMARY KEY,
    session_id          uuid     NOT NULL UNIQUE REFERENCES device_session (id),
    boot_service_id     uuid     NOT NULL REFERENCES boot_service (id),
    -- No foreign key on the package (history survives its deletion); the
    -- signed plan carries the package manifest digest.
    package_id          uuid     NOT NULL,
    package_revision    bigint   NOT NULL CHECK (package_revision >= 1),
    image_content_id    uuid     NOT NULL REFERENCES content (id),
    edition_index       integer  NOT NULL CHECK (edition_index >= 1),
    disk                text     NOT NULL CHECK (length(disk) BETWEEN 2 AND 65536),
    layout              text     NULL CHECK (length(layout) BETWEEN 2 AND 65536),
    macs                bytea[]  NOT NULL CHECK (usgp_macs_valid(macs)),
    state               text     NOT NULL CHECK (state IN ('running', 'succeeded', 'failed', 'lost')),
    current_step        smallint NOT NULL CHECK (current_step BETWEEN 1 AND 5),
    failure_step        smallint NULL CHECK (failure_step BETWEEN 1 AND 5),
    failure_category    text     NULL CHECK (failure_category IN ('network', 'integrity', 'refused', 'local', 'timeout')),
    failure_detail      text     NULL CHECK (length(failure_detail) BETWEEN 2 AND 65536),
    attempts            integer  NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    bytes_done          bigint   NULL CHECK (bytes_done >= 0),
    bytes_total         bigint   NULL CHECK (bytes_total >= 0),
    last_seq            bigint   NOT NULL DEFAULT 0 CHECK (last_seq >= 0),
    started_at_us       bigint   NOT NULL CHECK (started_at_us >= 0),
    last_report_at_us   bigint   NULL,
    finished_at_us      bigint   NULL,
    previous_job_id     uuid     NULL REFERENCES job (id),
    -- The `disk.wipe.authorised` record (REQ-DISK-006).
    wipe_audit_seq      bigint   NOT NULL UNIQUE,
    wipe_record_hash    bytea    NOT NULL CHECK (length(wipe_record_hash) = 32),
    plan_sha256         bytea    NOT NULL CHECK (length(plan_sha256) = 32),
    plan_key_id         bytea    NOT NULL CHECK (length(plan_key_id) = 32),
    acknowledged_by     uuid     NULL REFERENCES operator (id),
    acknowledged_at_us  bigint   NULL,
    FOREIGN KEY (wipe_audit_seq, wipe_record_hash) REFERENCES audit_record (seq, record_hash)
        DEFERRABLE INITIALLY DEFERRED,
    CHECK (previous_job_id IS NULL OR previous_job_id <> id),
    CHECK (num_nulls(failure_step, failure_category, failure_detail) IN (0, 3)),
    CHECK ((state = 'failed') = (failure_detail IS NOT NULL)),
    CHECK ((state IN ('succeeded', 'failed')) = (finished_at_us IS NOT NULL)),
    CHECK (num_nulls(acknowledged_by, acknowledged_at_us) IN (0, 2)),
    CHECK (acknowledged_by IS NULL OR state = 'failed'),
    CHECK (bytes_done IS NULL OR bytes_total IS NULL OR bytes_done <= bytes_total)
);

CREATE INDEX job_state ON job (state);

CREATE TABLE job_step (
    job_id              uuid     NOT NULL REFERENCES job (id),
    step                smallint NOT NULL CHECK (step BETWEEN 1 AND 5),
    state               text     NOT NULL CHECK (state IN ('pending', 'running', 'done', 'failed')),
    started_at_us       bigint   NULL,
    finished_at_us      bigint   NULL,
    PRIMARY KEY (job_id, step),
    CHECK ((state = 'pending') = (started_at_us IS NULL)),
    CHECK ((state IN ('done', 'failed')) = (finished_at_us IS NOT NULL))
);

-- ------------------------------------------------------ boot stops --

-- Devices the boot service must no longer answer (REQ-BOOT-067).
CREATE TABLE boot_stop (
    id                  uuid    PRIMARY KEY,
    boot_service_id     uuid    NOT NULL REFERENCES boot_service (id),
    mac                 bytea   NOT NULL CHECK (length(mac) = 6),
    job_id              uuid    NOT NULL REFERENCES job (id),
    created_at_us       bigint  NOT NULL CHECK (created_at_us >= 0),
    cleared_at_us       bigint  NULL,
    cleared_by          uuid    NULL REFERENCES operator (id),
    CHECK (num_nulls(cleared_at_us, cleared_by) IN (0, 2))
);

CREATE UNIQUE INDEX boot_stop_active ON boot_stop (boot_service_id, mac)
    WHERE cleared_at_us IS NULL;

-- The generation of each boot service's signed stop list (decision 0021
-- item 2); relays refuse a lower one.
CREATE TABLE boot_policy_generation (
    boot_service_id     uuid    PRIMARY KEY REFERENCES boot_service (id),
    generation          bigint  NOT NULL CHECK (generation >= 1)
);

-- -------------------------------------------------------------- guards --

CREATE FUNCTION usgp_auth_code_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.id, NEW.code_hmac, NEW.issued_by, NEW.issued_at_us, NEW.expires_at_us, NEW.note)
       IS DISTINCT FROM
       (OLD.id, OLD.code_hmac, OLD.issued_by, OLD.issued_at_us, OLD.expires_at_us, OLD.note) THEN
        RAISE EXCEPTION 'an issued code cannot be altered'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF OLD.used_at_us IS NOT NULL
       AND (NEW.used_at_us, NEW.used_by_session) IS DISTINCT FROM (OLD.used_at_us, OLD.used_by_session) THEN
        RAISE EXCEPTION 'a used code stays used'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF OLD.revoked_at_us IS NOT NULL
       AND (NEW.revoked_at_us, NEW.revoked_by) IS DISTINCT FROM (OLD.revoked_at_us, OLD.revoked_by) THEN
        RAISE EXCEPTION 'a revoked code stays revoked'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER auth_code_guard
    BEFORE UPDATE ON auth_code
    FOR EACH ROW EXECUTE FUNCTION usgp_auth_code_guard();

CREATE FUNCTION usgp_device_session_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.id, NEW.token_sha256, NEW.source_ip, NEW.macs, NEW.display_code, NEW.created_at_us)
       IS DISTINCT FROM
       (OLD.id, OLD.token_sha256, OLD.source_ip, OLD.macs, OLD.display_code, OLD.created_at_us) THEN
        RAISE EXCEPTION 'a session identity cannot be altered'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    -- A final session keeps everything except when it was last seen.
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

CREATE TRIGGER device_session_guard
    BEFORE UPDATE ON device_session
    FOR EACH ROW EXECUTE FUNCTION usgp_device_session_guard();

CREATE FUNCTION usgp_job_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.id, NEW.session_id, NEW.boot_service_id, NEW.package_id, NEW.package_revision,
        NEW.image_content_id, NEW.edition_index, NEW.disk, NEW.macs, NEW.previous_job_id,
        NEW.wipe_audit_seq, NEW.wipe_record_hash, NEW.plan_sha256, NEW.plan_key_id,
        NEW.started_at_us)
       IS DISTINCT FROM
       (OLD.id, OLD.session_id, OLD.boot_service_id, OLD.package_id, OLD.package_revision,
        OLD.image_content_id, OLD.edition_index, OLD.disk, OLD.macs, OLD.previous_job_id,
        OLD.wipe_audit_seq, OLD.wipe_record_hash, OLD.plan_sha256, OLD.plan_key_id,
        OLD.started_at_us) THEN
        RAISE EXCEPTION 'a job identity and its wipe authorisation cannot be altered'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF OLD.state IN ('succeeded', 'failed') THEN
        IF (NEW.state, NEW.current_step, NEW.layout, NEW.failure_step, NEW.failure_category,
            NEW.failure_detail, NEW.attempts, NEW.bytes_done, NEW.bytes_total, NEW.last_seq,
            NEW.last_report_at_us, NEW.finished_at_us)
           IS DISTINCT FROM
           (OLD.state, OLD.current_step, OLD.layout, OLD.failure_step, OLD.failure_category,
            OLD.failure_detail, OLD.attempts, OLD.bytes_done, OLD.bytes_total, OLD.last_seq,
            OLD.last_report_at_us, OLD.finished_at_us) THEN
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
    IF OLD.acknowledged_by IS NOT NULL
       AND (NEW.acknowledged_by, NEW.acknowledged_at_us)
           IS DISTINCT FROM (OLD.acknowledged_by, OLD.acknowledged_at_us) THEN
        RAISE EXCEPTION 'an acknowledgement cannot be altered'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER job_guard
    BEFORE UPDATE ON job
    FOR EACH ROW EXECUTE FUNCTION usgp_job_guard();

-- Wipe guard: checked when the transaction ends (see the header).
CREATE FUNCTION usgp_job_wipe_authorised() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM audit_record r
                   WHERE r.seq = NEW.wipe_audit_seq
                     AND r.record_hash = NEW.wipe_record_hash
                     AND r.event = 'disk.wipe.authorised'
                     AND r.outcome = 'success'
                     AND r.target_kind = 'job'
                     AND r.target_id = NEW.id::text) THEN
        RAISE EXCEPTION 'job lacks its disk.wipe.authorised record'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER job_wipe_authorised
    AFTER INSERT ON job
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION usgp_job_wipe_authorised();

CREATE FUNCTION usgp_job_step_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.job_id, NEW.step) IS DISTINCT FROM (OLD.job_id, OLD.step) THEN
        RAISE EXCEPTION 'a job step cannot move'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF OLD.state IN ('done', 'failed')
       AND (NEW.state, NEW.started_at_us, NEW.finished_at_us)
           IS DISTINCT FROM (OLD.state, OLD.started_at_us, OLD.finished_at_us) THEN
        RAISE EXCEPTION 'a finished step cannot change'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER job_step_guard
    BEFORE UPDATE ON job_step
    FOR EACH ROW EXECUTE FUNCTION usgp_job_step_guard();

CREATE FUNCTION usgp_boot_stop_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.id, NEW.boot_service_id, NEW.mac, NEW.job_id, NEW.created_at_us)
       IS DISTINCT FROM
       (OLD.id, OLD.boot_service_id, OLD.mac, OLD.job_id, OLD.created_at_us) THEN
        RAISE EXCEPTION 'a boot stop cannot be altered'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF OLD.cleared_at_us IS NOT NULL
       AND (NEW.cleared_at_us, NEW.cleared_by) IS DISTINCT FROM (OLD.cleared_at_us, OLD.cleared_by) THEN
        RAISE EXCEPTION 'a cleared boot stop stays cleared'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER boot_stop_guard
    BEFORE UPDATE ON boot_stop
    FOR EACH ROW EXECUTE FUNCTION usgp_boot_stop_guard();

CREATE FUNCTION usgp_boot_policy_generation_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.boot_service_id <> OLD.boot_service_id OR NEW.generation <= OLD.generation THEN
        RAISE EXCEPTION 'the boot-policy generation only increases'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER boot_policy_generation_guard
    BEFORE UPDATE ON boot_policy_generation
    FOR EACH ROW EXECUTE FUNCTION usgp_boot_policy_generation_guard();

-- ---------------------------------------------------------- privileges --

-- New functions are executable by PUBLIC by default; restrict them as 0002
-- does for the audit guards.
REVOKE ALL ON FUNCTION usgp_macs_valid(bytea[]), usgp_auth_code_guard(),
    usgp_device_session_guard(), usgp_job_guard(), usgp_job_wipe_authorised(),
    usgp_job_step_guard(), usgp_boot_stop_guard(), usgp_boot_policy_generation_guard()
    FROM PUBLIC;
REVOKE ALL ON boot_service, boot_service_package, auth_code, device_session, job, job_step,
    boot_stop, boot_policy_generation FROM PUBLIC;

-- Application role (plan section 3.8). Boot services are read only;
-- assignments are replaced (INSERT, DELETE); everything else changes
-- state but is never deleted.
GRANT SELECT ON boot_service TO usgp_app;
GRANT SELECT, INSERT, DELETE ON boot_service_package TO usgp_app;
GRANT SELECT, INSERT, UPDATE ON device_session, auth_code, job, job_step, boot_stop,
    boot_policy_generation TO usgp_app;
GRANT EXECUTE ON FUNCTION usgp_macs_valid(bytea[]), usgp_auth_code_guard(),
    usgp_device_session_guard(), usgp_job_guard(), usgp_job_wipe_authorised(),
    usgp_job_step_guard(), usgp_boot_stop_guard(), usgp_boot_policy_generation_guard()
    TO usgp_app;

-- Administrative role (decisions 0016, 0021): boot-service enrolment and
-- disabling only; no DELETE.
GRANT SELECT, INSERT, UPDATE ON boot_service TO usgp_admin;
