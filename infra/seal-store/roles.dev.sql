-- Development roles for the audit seal store (ADR 0017, part 2a). Run once,
-- as an admin, on the seal store server. The passwords are local-only
-- placeholders: production creates these roles with its own secrets.
DO $$
BEGIN
  CREATE ROLE custos_sealer LOGIN PASSWORD 'custos_sealer';
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$
BEGIN
  CREATE ROLE custos_auditor LOGIN PASSWORD 'custos_auditor';
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
