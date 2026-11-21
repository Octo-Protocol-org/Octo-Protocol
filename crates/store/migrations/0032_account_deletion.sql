-- Account export and deletion (issue #466).
--
-- Deleting an account tombstones the `users` row instead of removing it: `audit_logs` cascades on
-- user delete, and the trail must outlive the account. The row keeps only its id; email, username
-- and password hash are scrubbed by the application in the same transaction that sets deleted_at.
--
-- Retained audit rows are anonymised (target and ip_address nulled) and re-linked under the audit
-- chain key. The append-only trigger gets one more narrow exception for exactly that edit.

ALTER TABLE users ADD COLUMN deleted_at TIMESTAMPTZ;

-- Both flows are confirmed by an emailed code; each gets its own purpose so codes never cross over.
ALTER TABLE email_otps DROP CONSTRAINT email_otps_purpose_check;
ALTER TABLE email_otps ADD CONSTRAINT email_otps_purpose_check
    CHECK (purpose IN ('signup', 'withdrawal', 'password_reset', 'email_change',
                       'account_export', 'account_delete'));

-- Same as 0031, plus: a deleted user's rows may have target / ip_address nulled and their chain
-- hashes rewritten. Nothing else may change, and the hashes can only be made valid with the key.
CREATE OR REPLACE FUNCTION audit_logs_block_mutation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    owner_gone boolean;
    owner_deleted boolean;
BEGIN
    IF audit_logs_retention_allowed() THEN
        RETURN COALESCE(NEW, OLD);
    END IF;
    -- Legacy-row adoption into the hash chain: fill the chain columns of an unchained row only.
    IF TG_OP = 'UPDATE'
       AND OLD.seq IS NULL AND OLD.prev_hash IS NULL AND OLD.row_hash IS NULL
       AND NEW.seq IS NOT NULL
       AND (to_jsonb(NEW) - 'seq' - 'prev_hash' - 'row_hash')
           = (to_jsonb(OLD) - 'seq' - 'prev_hash' - 'row_hash') THEN
        RETURN NEW;
    END IF;
    -- Anonymisation of a deleted account: null the PII columns and re-link, nothing more.
    IF TG_OP = 'UPDATE'
       AND NEW.target IS NULL AND NEW.ip_address IS NULL
       AND (to_jsonb(NEW) - 'target' - 'ip_address' - 'prev_hash' - 'row_hash')
           = (to_jsonb(OLD) - 'target' - 'ip_address' - 'prev_hash' - 'row_hash') THEN
        EXECUTE format(
            'SELECT EXISTS (SELECT 1 FROM %I.users WHERE id = $1 AND deleted_at IS NOT NULL)',
            TG_TABLE_SCHEMA)
            INTO owner_deleted USING OLD.user_id;
        IF owner_deleted THEN
            RETURN NEW;
        END IF;
    END IF;
    -- Cascade from a deleted user: the owning row (same schema as audit_logs) is already gone.
    IF TG_OP = 'DELETE' THEN
        EXECUTE format('SELECT NOT EXISTS (SELECT 1 FROM %I.users WHERE id = $1)', TG_TABLE_SCHEMA)
            INTO owner_gone USING OLD.user_id;
        IF owner_gone THEN
            RETURN OLD;
        END IF;
    END IF;
    RAISE EXCEPTION 'audit_logs is append-only: % is not permitted', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$;
