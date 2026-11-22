-- Control-plane state (WI-10a). Invariants live in columns with constraints; evolving payloads are JSONB.

-- Audit chains. Each chain has a head row that is locked FOR UPDATE to serialize appends. The record is stored as
-- bytea holding the exact JSON the log sealed, so no jsonb normalization or NUL-character limit can change what a
-- hash covers.
CREATE TABLE audit_chain_heads (
    chain text PRIMARY KEY CHECK (chain IN ('decision', 'denial')),
    seq   bigint NOT NULL CHECK (seq >= 0),
    hash  bytea  NOT NULL CHECK (length(hash) = 32)
);
INSERT INTO audit_chain_heads (chain, seq, hash)
VALUES ('decision', 0, '\x0000000000000000000000000000000000000000000000000000000000000000'),
       ('denial',   0, '\x0000000000000000000000000000000000000000000000000000000000000000');

CREATE TABLE audit_entries (
    chain     text   NOT NULL REFERENCES audit_chain_heads (chain),
    seq       bigint NOT NULL CHECK (seq >= 1),
    format    integer NOT NULL CHECK (format >= 1),
    at        timestamptz NOT NULL,
    record    bytea  NOT NULL,
    prev_hash bytea  NOT NULL CHECK (length(prev_hash) = 32),
    hash      bytea  NOT NULL CHECK (length(hash) = 32),
    PRIMARY KEY (chain, seq)
);

-- Appends go through these SECURITY DEFINER functions, which run as the owner. The runtime role has only SELECT on
-- audit_entries and audit_chain_heads, so it cannot insert an entry ahead of the head, move a head or plant a
-- wedge: audit_append checks seq = head.seq + 1 and prev_hash = head.hash under the head's row lock and inserts
-- the entry and advances the head in one step. audit_lock_head returns the locked head for the caller to seal
-- against (FOR UPDATE needs an UPDATE privilege that the runtime role does not hold).
CREATE FUNCTION audit_lock_head(p_chain text) RETURNS TABLE (head_seq bigint, head_hash bytea)
LANGUAGE sql SECURITY DEFINER AS $$
    SELECT seq, hash FROM audit_chain_heads WHERE chain = p_chain FOR UPDATE
$$;

CREATE FUNCTION audit_append(p_chain text, p_seq bigint, p_format integer, p_at timestamptz, p_record bytea,
                             p_prev_hash bytea, p_hash bytea) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
    h audit_chain_heads%ROWTYPE;
BEGIN
    SELECT * INTO h FROM audit_chain_heads WHERE chain = p_chain FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'audit_append: unknown chain %', p_chain USING ERRCODE = 'restrict_violation';
    END IF;
    IF p_seq <> h.seq + 1 OR p_prev_hash <> h.hash THEN
        RAISE EXCEPTION 'audit_append: entry does not extend the head of chain %', p_chain USING ERRCODE = 'restrict_violation';
    END IF;
    INSERT INTO audit_entries (chain, seq, format, at, record, prev_hash, hash)
    VALUES (p_chain, p_seq, p_format, p_at, p_record, p_prev_hash, p_hash);
    UPDATE audit_chain_heads SET seq = p_seq, hash = p_hash WHERE chain = p_chain;
END
$$;

-- A SECURITY DEFINER function must not resolve names through a schema the caller controls: pin its search_path to
-- this schema with pg_temp last (otherwise a temporary table of the caller's would shadow a real one), and take
-- EXECUTE away from PUBLIC. The migrator grants it to the runtime role only.
DO $$
BEGIN
    EXECUTE format('ALTER FUNCTION audit_lock_head(text) SET search_path = %I, pg_temp', current_schema());
    EXECUTE format('ALTER FUNCTION audit_append(text, bigint, integer, timestamptz, bytea, bytea, bytea) SET search_path = %I, pg_temp', current_schema());
END
$$;
REVOKE ALL ON FUNCTION audit_lock_head(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit_append(text, bigint, integer, timestamptz, bytea, bytea, bytea) FROM PUBLIC;

-- The consumed set, the delivery receipts and the audit entries are append-only for the life of the installation
-- (NFR-4). The triggers make an accidental UPDATE, DELETE or TRUNCATE fail; they do not stop a superuser, which is
-- what the external checkpoints are for.
CREATE FUNCTION forbid_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% on % is not allowed: append-only', TG_OP, TG_TABLE_NAME USING ERRCODE = 'restrict_violation';
END
$$;

CREATE TABLE consumed_decisions (
    decision_id text PRIMARY KEY CHECK (length(decision_id) BETWEEN 1 AND 256),
    consumed_at timestamptz NOT NULL
);

CREATE TABLE deliveries (
    forge       text  NOT NULL CHECK (length(forge) BETWEEN 1 AND 256),
    delivery_id text  NOT NULL CHECK (length(delivery_id) BETWEEN 1 AND 256),
    digest      bytea NOT NULL CHECK (length(digest) = 32),
    received_at timestamptz NOT NULL,
    PRIMARY KEY (forge, delivery_id)
);

-- A head row only ever advances by exactly one, and is never deleted or truncated: it moves with an append.
CREATE FUNCTION head_advance_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.chain <> OLD.chain OR NEW.seq <> OLD.seq + 1 THEN
        RAISE EXCEPTION 'audit chain head % may only advance by one', OLD.chain USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER audit_chain_heads_advance BEFORE UPDATE ON audit_chain_heads
    FOR EACH ROW EXECUTE FUNCTION head_advance_only();
CREATE TRIGGER audit_chain_heads_no_delete BEFORE DELETE ON audit_chain_heads
    FOR EACH ROW EXECUTE FUNCTION forbid_change();
CREATE TRIGGER audit_chain_heads_no_truncate BEFORE TRUNCATE ON audit_chain_heads
    FOR EACH STATEMENT EXECUTE FUNCTION forbid_change();

CREATE TRIGGER audit_entries_append_only_row BEFORE UPDATE OR DELETE ON audit_entries
    FOR EACH ROW EXECUTE FUNCTION forbid_change();
CREATE TRIGGER audit_entries_append_only_stmt BEFORE TRUNCATE ON audit_entries
    FOR EACH STATEMENT EXECUTE FUNCTION forbid_change();
CREATE TRIGGER consumed_decisions_append_only_row BEFORE UPDATE OR DELETE ON consumed_decisions
    FOR EACH ROW EXECUTE FUNCTION forbid_change();
CREATE TRIGGER consumed_decisions_append_only_stmt BEFORE TRUNCATE ON consumed_decisions
    FOR EACH STATEMENT EXECUTE FUNCTION forbid_change();
CREATE TRIGGER deliveries_append_only_row BEFORE UPDATE OR DELETE ON deliveries
    FOR EACH ROW EXECUTE FUNCTION forbid_change();
CREATE TRIGGER deliveries_append_only_stmt BEFORE TRUNCATE ON deliveries
    FOR EACH STATEMENT EXECUTE FUNCTION forbid_change();

-- State rows: issues, changes, features and trains. version is the CAS counter, current_revision the subject's
-- current proposal revision (the guard a grant's CAS compares), approved_revision the last approved revision and
-- schema_version the payload schema version; the four are distinct.
CREATE TABLE state_rows (
    kind              text   NOT NULL CHECK (kind IN ('issue', 'change', 'feature', 'train')),
    id                text   NOT NULL CHECK (length(id) BETWEEN 1 AND 256),
    repo              text   NOT NULL CHECK (length(repo) BETWEEN 1 AND 256),
    version           bigint NOT NULL CHECK (version >= 1),
    current_revision  text   NOT NULL DEFAULT '' CHECK (current_revision = '' OR current_revision ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'),
    approved_revision text   NOT NULL DEFAULT '' CHECK (approved_revision = '' OR approved_revision ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'),
    schema_version    integer NOT NULL CHECK (schema_version >= 1),
    payload           jsonb  NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    PRIMARY KEY (kind, id)
);

-- Work items. key is unique for the life of the installation. generation fences leases.
CREATE TABLE work_items (
    seq          bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
    key          text   PRIMARY KEY CHECK (length(key) BETWEEN 1 AND 256),
    kind         text   NOT NULL CHECK (length(kind) BETWEEN 1 AND 256),
    payload      jsonb  NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    generation   bigint NOT NULL DEFAULT 0 CHECK (generation >= 0),
    owner        text   NOT NULL DEFAULT '',
    leased_until timestamptz,
    not_before   timestamptz,
    attempts     integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    completed    boolean NOT NULL DEFAULT false,
    dead         boolean NOT NULL DEFAULT false,
    dead_reason  text    NOT NULL DEFAULT '',
    CHECK (NOT (completed AND dead))
);
CREATE INDEX work_items_pending ON work_items (seq) WHERE NOT completed AND NOT dead;
