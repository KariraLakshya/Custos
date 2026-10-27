-- The audit seal store (ADR 0017, part 2a): copies of the audit ledger's
-- seals, kept on a server separate from the audit database. Run as an admin
-- role, which owns the table; the audit service and auditors must never be
-- that owner, since an owner can drop the table or disable its triggers.
-- Safe to run again. Expects the roles custos_sealer and custos_auditor.

CREATE TABLE IF NOT EXISTS audit_seal_copies (
  -- The audit log's DID: one store can hold the copies of several logs.
  log text NOT NULL,
  seq integer NOT NULL,
  -- The signed seal, exactly as the audit service issued it.
  seal text NOT NULL,
  stored_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (log, seq)
);

-- A backstop under the privileges below: any change or removal is an error,
-- never silently ignored. Row triggers do not fire on TRUNCATE, hence the
-- statement trigger.
CREATE OR REPLACE FUNCTION audit_seal_copies_refuse() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit seal copies are append-only (%)', TG_OP;
END $$;

CREATE OR REPLACE TRIGGER audit_seal_copies_no_change
  BEFORE UPDATE OR DELETE ON audit_seal_copies
  FOR EACH ROW EXECUTE FUNCTION audit_seal_copies_refuse();

CREATE OR REPLACE TRIGGER audit_seal_copies_no_truncate
  BEFORE TRUNCATE ON audit_seal_copies
  FOR EACH STATEMENT EXECUTE FUNCTION audit_seal_copies_refuse();

REVOKE ALL ON audit_seal_copies FROM PUBLIC;
GRANT SELECT, INSERT ON audit_seal_copies TO custos_sealer;
GRANT SELECT ON audit_seal_copies TO custos_auditor;
