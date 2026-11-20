//! Tamper-evident audit log: a per-user HMAC-SHA256 hash chain over `audit_logs` (migration 0029).
//!
//! Each row's `row_hash` is `HMAC(key, prev_hash || fields)`, and `audit_chain_heads` pins the
//! newest link under its own MAC. The key lives outside the database, so a DB-only attacker can't
//! forge links: editing a row breaks its hash, deleting one leaves a `seq` gap, and deleting from
//! the end disagrees with the head. Appends are serialized per user with a transaction-scoped
//! advisory lock, so concurrent writers produce one linear chain. Limitations: see
//! `docs/audit-log.md`.

use crate::{Store, StoreError};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use sqlx::{FromRow, Postgres, Transaction};
use uuid::Uuid;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// Length of the audit chain HMAC key, in bytes.
pub const AUDIT_CHAIN_KEY_LEN: usize = 32;

/// `prev_hash` of the first row in every user's chain.
const GENESIS_PREV_HASH: [u8; 32] = [0u8; 32];
/// Domain separators so a row MAC can never be replayed as a head MAC (or vice versa).
const ROW_DOMAIN: &[u8] = b"octo/audit-row/v1";
const HEAD_DOMAIN: &[u8] = b"octo/audit-head/v1";
/// Advisory-lock namespace ("AUDT"), keeping the per-user lock clear of any other lock users.
const LOCK_NAMESPACE: i32 = 0x4155_4454;
/// Rows fetched per verification round trip.
const VERIFY_BATCH: i64 = 1000;

/// Secret HMAC key for the audit chain (`AUDIT_CHAIN_KEY`). Zeroized on drop, redacted in `Debug`.
#[derive(Clone)]
pub struct AuditChainKey(Zeroizing<[u8; AUDIT_CHAIN_KEY_LEN]>);

impl AuditChainKey {
    pub fn new(key: Zeroizing<[u8; AUDIT_CHAIN_KEY_LEN]>) -> Self {
        Self(key)
    }

    /// Build the HMAC state for this key. HMAC accepts any key length, so this only fails on a
    /// broken `hmac`/`sha2` build; surface it as a `StoreError` rather than panicking.
    fn mac(&self) -> Result<HmacSha256, StoreError> {
        <HmacSha256 as Mac>::new_from_slice(&self.0[..])
            .map_err(|_| StoreError::AuditChainCorrupt("invalid audit chain HMAC key".into()))
    }
}

impl std::fmt::Debug for AuditChainKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuditChainKey(<redacted>)")
    }
}

/// Outcome of verifying one user's chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditChainStatus {
    /// Every row links correctly and the last row matches the head.
    Intact,
    /// The user has only rows written before chaining existed; nothing to verify yet.
    Unchained,
    /// Verification failed. `seq` is the first chain position that failed, when there is one.
    Broken {
        seq: Option<i64>,
        reason: &'static str,
    },
}

/// Per-user verification result.
#[derive(Debug, Clone)]
pub struct AuditChainReport {
    pub user_id: Uuid,
    pub rows_verified: u64,
    pub unchained_rows: u64,
    pub status: AuditChainStatus,
}

/// The hashed fields of one audit row.
struct LinkFields<'a> {
    id: Uuid,
    user_id: Uuid,
    seq: i64,
    action: &'a str,
    category: &'a str,
    target: Option<&'a str>,
    ip_address: Option<&'a str>,
    created_at: DateTime<Utc>,
}

#[derive(FromRow)]
struct ChainRow {
    id: Uuid,
    user_id: Uuid,
    seq: i64,
    prev_hash: Option<Vec<u8>>,
    row_hash: Option<Vec<u8>>,
    action: String,
    category: String,
    target: Option<String>,
    ip_address: Option<String>,
    created_at: DateTime<Utc>,
}

#[derive(FromRow)]
struct LegacyRow {
    id: Uuid,
    action: String,
    category: String,
    target: Option<String>,
    ip_address: Option<String>,
    created_at: DateTime<Utc>,
}

#[derive(FromRow)]
struct HeadRow {
    seq: i64,
    row_hash: Vec<u8>,
    head_mac: Vec<u8>,
}

/// Length-prefixed string, so field boundaries can't be shifted between adjacent fields.
fn put_str(mac: &mut HmacSha256, s: &str) {
    mac.update(&(s.len() as u64).to_be_bytes());
    mac.update(s.as_bytes());
}

/// Tagged optional string, so `None` and `Some("")` hash differently.
fn put_opt(mac: &mut HmacSha256, s: Option<&str>) {
    match s {
        None => mac.update(&[0]),
        Some(s) => {
            mac.update(&[1]);
            put_str(mac, s);
        }
    }
}

fn finish(mac: HmacSha256) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

fn row_hash(
    key: &AuditChainKey,
    prev_hash: &[u8; 32],
    f: &LinkFields<'_>,
) -> Result<[u8; 32], StoreError> {
    let mut mac = key.mac()?;
    mac.update(ROW_DOMAIN);
    mac.update(prev_hash);
    mac.update(f.id.as_bytes());
    mac.update(f.user_id.as_bytes());
    mac.update(&f.seq.to_be_bytes());
    // Postgres stores microseconds, so that is the precision that round-trips.
    mac.update(&f.created_at.timestamp_micros().to_be_bytes());
    put_str(&mut mac, f.action);
    put_str(&mut mac, f.category);
    put_opt(&mut mac, f.target);
    put_opt(&mut mac, f.ip_address);
    Ok(finish(mac))
}

fn head_mac(
    key: &AuditChainKey,
    user_id: Uuid,
    seq: i64,
    row_hash: &[u8; 32],
) -> Result<[u8; 32], StoreError> {
    let mut mac = key.mac()?;
    mac.update(HEAD_DOMAIN);
    mac.update(user_id.as_bytes());
    mac.update(&seq.to_be_bytes());
    mac.update(row_hash);
    Ok(finish(mac))
}

fn to_hash(bytes: &[u8]) -> Option<[u8; 32]> {
    bytes.try_into().ok()
}

/// Truncate to the microsecond precision Postgres keeps, so the hashed value equals the stored one.
fn now_micros() -> DateTime<Utc> {
    let now = Utc::now();
    DateTime::from_timestamp_micros(now.timestamp_micros()).unwrap_or(now)
}

impl HeadRow {
    /// The head's `(seq, row_hash)` if its MAC checks out.
    fn verified(&self, key: &AuditChainKey, user_id: Uuid) -> Result<Option<(i64, [u8; 32])>, StoreError> {
        let Some(hash) = to_hash(&self.row_hash) else {
            return Ok(None);
        };
        let mac = head_mac(key, user_id, self.seq, &hash)?;
        Ok((mac.as_slice() == self.head_mac.as_slice()).then_some((self.seq, hash)))
    }
}

impl Store {
    /// Append an audit-log entry to the user's hash chain. Best-effort: failures are surfaced to
    /// the caller, which logs and continues (auditing must never block the primary operation).
    ///
    /// Refuses with [`StoreError::AuditChainCorrupt`] when the chain head is missing or fails its
    /// MAC — appending would otherwise sign over the tampering and hide it.
    pub async fn record_audit(
        &self,
        key: &AuditChainKey,
        user_id: Uuid,
        action: &str,
        category: &str,
        target: Option<&str>,
        ip_address: Option<&str>,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await?;
        append_link(&mut tx, key, user_id, action, category, target, ip_address).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Verify one user's audit chain end to end, in batches of [`VERIFY_BATCH`] rows.
    pub async fn verify_audit_chain(
        &self,
        key: &AuditChainKey,
        user_id: Uuid,
    ) -> Result<AuditChainReport, StoreError> {
        let unchained: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_logs WHERE user_id = $1 AND seq IS NULL",
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await?;
        let mut report = AuditChainReport {
            user_id,
            rows_verified: 0,
            unchained_rows: u64::try_from(unchained).unwrap_or(0),
            status: AuditChainStatus::Intact,
        };
        let broken = |seq, reason| AuditChainStatus::Broken { seq, reason };

        let mut last_seq = 0i64;
        let mut prev = GENESIS_PREV_HASH;
        loop {
            let rows = sqlx::query_as::<_, ChainRow>(
                "SELECT id, user_id, seq, prev_hash, row_hash, action, category, target,
                        ip_address, created_at
                 FROM audit_logs
                 WHERE user_id = $1 AND seq > $2
                 ORDER BY seq
                 LIMIT $3",
            )
            .bind(user_id)
            .bind(last_seq)
            .bind(VERIFY_BATCH)
            .fetch_all(&self.pool)
            .await?;
            if rows.is_empty() {
                break;
            }
            for row in &rows {
                let expected = last_seq + 1;
                if row.seq != expected {
                    report.status = broken(Some(expected), "sequence gap");
                    return Ok(report);
                }
                let Some(stored_prev) = row.prev_hash.as_deref().and_then(to_hash) else {
                    report.status = broken(Some(row.seq), "missing prev_hash");
                    return Ok(report);
                };
                if stored_prev != prev {
                    report.status = broken(Some(row.seq), "prev_hash mismatch");
                    return Ok(report);
                }
                let fields = LinkFields {
                    id: row.id,
                    user_id: row.user_id,
                    seq: row.seq,
                    action: &row.action,
                    category: &row.category,
                    target: row.target.as_deref(),
                    ip_address: row.ip_address.as_deref(),
                    created_at: row.created_at,
                };
                let expected_hash = row_hash(key, &prev, &fields)?;
                let Some(stored_hash) = row.row_hash.as_deref().and_then(to_hash) else {
                    report.status = broken(Some(row.seq), "missing row_hash");
                    return Ok(report);
                };
                if stored_hash != expected_hash {
                    report.status = broken(Some(row.seq), "row_hash mismatch");
                    return Ok(report);
                }
                prev = stored_hash;
                last_seq = row.seq;
                report.rows_verified += 1;
            }
        }

        if report.rows_verified == 0 {
            report.status = AuditChainStatus::Unchained;
            return Ok(report);
        }

        let head = sqlx::query_as::<_, HeadRow>(
            "SELECT seq, row_hash, head_mac FROM audit_chain_heads WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;
        match head {
            None => report.status = broken(None, "missing chain head"),
            Some(head) => match head.verified(key, user_id)? {
                None => report.status = broken(Some(head.seq), "head MAC mismatch"),
                Some((seq, hash)) if seq != last_seq || hash != prev => {
                    report.status = broken(Some(seq), "head disagrees with chain")
                }
                Some(_) => {}
            },
        }
        Ok(report)
    }
}

async fn append_link(
    tx: &mut Transaction<'_, Postgres>,
    key: &AuditChainKey,
    user_id: Uuid,
    action: &str,
    category: &str,
    target: Option<&str>,
    ip_address: Option<&str>,
) -> Result<(), StoreError> {
    sqlx::query("SELECT pg_advisory_xact_lock($1, $2)")
        .bind(LOCK_NAMESPACE)
        .bind(user_id.as_u64() as i64)
        .execute(&mut **tx)
        .await?;

    let head = sqlx::query_as::<_, HeadRow>(
        "SELECT seq, row_hash, head_mac FROM audit_chain_heads WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await?;

    let (seq, prev) = match head {
        None => (1i64, GENESIS_PREV_HASH),
        Some(head) => head
            .verified(key, user_id)?
            .ok_or_else(|| StoreError::AuditChainCorrupt("chain head MAC mismatch".into()))?,
    };

    let id = Uuid::new_v4();
    let created_at = now_micros();
    let fields = LinkFields {
        id,
        user_id,
        seq,
        action,
        category,
        target,
        ip_address,
        created_at,
    };
    let hash = row_hash(key, &prev, &fields)?;
    let mac = head_mac(key, user_id, seq, &hash)?;

    sqlx::query(
        "INSERT INTO audit_logs
            (id, user_id, seq, prev_hash, row_hash, action, category, target, ip_address, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(id)
    .bind(user_id)
    .bind(seq)
    .bind(prev.as_slice())
    .bind(hash.as_slice())
    .bind(action)
    .bind(category)
    .bind(target)
    .bind(ip_address)
    .bind(created_at)
    .execute(&mut **tx)
    .await?;

    sqlx::query(
        "INSERT INTO audit_chain_heads (user_id, seq, row_hash, head_mac)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (user_id) DO UPDATE
            SET seq = EXCLUDED.seq, row_hash = EXCLUDED.row_hash, head_mac = EXCLUDED.head_mac",
    )
    .bind(user_id)
    .bind(seq)
    .bind(hash.as_slice())
    .bind(mac.as_slice())
    .execute(&mut **tx)
    .await?;

    Ok(())
}
