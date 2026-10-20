//! Payment links: creation, lifecycle (activate/cancel/expire), and intent tracking.

use uuid::Uuid;

use crate::error::StoreError;
use crate::models::{NewPaymentLink, PaymentLink, PaymentLinkPayment, PaymentLinkUpdate};
use crate::Store;

impl Store {
    /// Create a payment link backed by an already-allocated deposit address.
    pub async fn create_payment_link(
        &self,
        link: NewPaymentLink<'_>,
    ) -> Result<PaymentLink, StoreError> {
        let row = sqlx::query_as::<_, PaymentLink>(
            r#"
            INSERT INTO payment_links
                (wallet_id, address_id, slug, name, description, image_url, redirect_url,
                 amount_usdc_stroops, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING *
            "#,
        )
        .bind(link.wallet_id)
        .bind(link.address_id)
        .bind(link.slug)
        .bind(link.name)
        .bind(link.description)
        .bind(link.image_url)
        .bind(link.redirect_url)
        .bind(link.amount_usdc_stroops)
        .bind(link.expires_at)
        .fetch_one(&self.pool)
        .await
        .map_err(StoreError::from_sqlx_conflict)?;
        Ok(row)
    }

    /// Fetch a payment link owned by `wallet_id` (scoped so one merchant can't read another's).
    pub async fn get_payment_link(
        &self,
        wallet_id: Uuid,
        id: Uuid,
    ) -> Result<PaymentLink, StoreError> {
        sqlx::query_as::<_, PaymentLink>(
            "SELECT * FROM payment_links WHERE id = $1 AND wallet_id = $2",
        )
        .bind(id)
        .bind(wallet_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StoreError::NotFound)
    }

    /// Public lookup by slug — no wallet scoping, this is the pay-page entry point.
    pub async fn get_payment_link_by_slug(&self, slug: &str) -> Result<PaymentLink, StoreError> {
        sqlx::query_as::<_, PaymentLink>("SELECT * FROM payment_links WHERE slug = $1")
            .bind(slug)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(StoreError::NotFound)
    }

    /// Unscoped lookup by id — for internal (non-owner-facing) callers that already know which
    /// row they want, e.g. the expiry sweep resolving a payment's link to build its webhook.
    pub async fn get_payment_link_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<PaymentLink>, StoreError> {
        let row = sqlx::query_as::<_, PaymentLink>("SELECT * FROM payment_links WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row)
    }

    /// The payment link whose dedicated deposit address is `address_id`, if any.
    pub async fn get_payment_link_by_address(
        &self,
        address_id: Uuid,
    ) -> Result<Option<PaymentLink>, StoreError> {
        let row =
            sqlx::query_as::<_, PaymentLink>("SELECT * FROM payment_links WHERE address_id = $1")
                .bind(address_id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row)
    }

    /// List payment links for a wallet (most recent first), with cursor-based pagination.
    pub async fn list_payment_links(
        &self,
        wallet_id: Uuid,
        limit: i64,
        before_id: Option<Uuid>,
    ) -> Result<Vec<PaymentLink>, StoreError> {
        let rows = sqlx::query_as::<_, PaymentLink>(
            r#"
            SELECT * FROM payment_links
            WHERE wallet_id = $1
              AND ($2::uuid IS NULL OR (created_at, id) < (
                  SELECT created_at, id FROM payment_links WHERE id = $2
              ))
            ORDER BY created_at DESC, id DESC
            LIMIT $3
            "#,
        )
        .bind(wallet_id)
        .bind(before_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Toggle a link's `active` flag. Returns `Conflict` when re-activating a cancelled link (#454).
    pub async fn set_payment_link_active(
        &self,
        wallet_id: Uuid,
        id: Uuid,
        active: bool,
    ) -> Result<PaymentLink, StoreError> {
        let updated = sqlx::query_as::<_, PaymentLink>(
            r#"
            UPDATE payment_links SET active = $1, updated_at = now()
            WHERE id = $2 AND wallet_id = $3
              AND (cancelled_at IS NULL OR NOT $1)
            RETURNING *
            "#,
        )
        .bind(active)
        .bind(id)
        .bind(wallet_id)
        .fetch_optional(&self.pool)
        .await?;

        match updated {
            Some(link) => Ok(link),
            // No row: either it isn't this wallet's link, or it is cancelled.
            None => {
                self.get_payment_link(wallet_id, id).await?;
                Err(StoreError::Conflict)
            }
        }
    }

    /// Permanently cancel a link and flip its pending intents to `cancelled`, atomically (#454).
    ///
    /// Idempotent: a second call keeps the original `cancelled_at` and returns no intents. The
    /// intents are returned so the caller can notify once per cancelled payment.
    pub async fn cancel_payment_link(
        &self,
        wallet_id: Uuid,
        id: Uuid,
    ) -> Result<(PaymentLink, Vec<PaymentLinkPayment>), StoreError> {
        let mut tx = self.pool.begin().await?;
        let link = sqlx::query_as::<_, PaymentLink>(
            r#"
            UPDATE payment_links
            SET cancelled_at = COALESCE(cancelled_at, now()), active = false, updated_at = now()
            WHERE id = $1 AND wallet_id = $2
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(wallet_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(StoreError::NotFound)?;
        let cancelled = sqlx::query_as::<_, PaymentLinkPayment>(
            r#"
            UPDATE payment_link_payments SET status = 'cancelled'
            WHERE payment_link_id = $1 AND status = 'pending'
            RETURNING *
            "#,
        )
        .bind(link.id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok((link, cancelled))
    }

    /// Apply owner edits to a payment link that has not been paid (#455).
    ///
    /// A link is locked once any payment against it is in flight or has landed (`pending`,
    /// `confirmed`, `underpaid`, `overpaid`): a payer was quoted the current terms. The check runs
    /// inside the UPDATE so a payment confirming concurrently can't slip between check and write.
    /// Returns `NotFound` for a missing or foreign link and `Conflict` for a locked one.
    pub async fn update_unpaid_payment_link(
        &self,
        wallet_id: Uuid,
        id: Uuid,
        update: PaymentLinkUpdate<'_>,
    ) -> Result<PaymentLink, StoreError> {
        let updated = sqlx::query_as::<_, PaymentLink>(
            r#"
            UPDATE payment_links SET
                description = CASE WHEN $3 THEN $4 ELSE description END,
                redirect_url = CASE WHEN $5 THEN $6 ELSE redirect_url END,
                amount_usdc_stroops = CASE WHEN $7 THEN $8 ELSE amount_usdc_stroops END,
                updated_at = now()
            WHERE id = $1 AND wallet_id = $2
              AND NOT EXISTS (
                  SELECT 1 FROM payment_link_payments p
                  WHERE p.payment_link_id = payment_links.id
                    AND p.status IN ('pending', 'confirmed', 'underpaid', 'overpaid')
              )
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(wallet_id)
        .bind(update.description.is_some())
        .bind(update.description.flatten())
        .bind(update.redirect_url.is_some())
        .bind(update.redirect_url.flatten())
        .bind(update.amount_usdc_stroops.is_some())
        .bind(update.amount_usdc_stroops.flatten())
        .fetch_optional(&self.pool)
        .await?;

        match updated {
            Some(link) => Ok(link),
            // No row: either it isn't this wallet's link, or it exists but is locked.
            None => {
                self.get_payment_link(wallet_id, id).await?;
                Err(StoreError::Conflict)
            }
        }
    }

    /// Record a payer's intent to pay (the "Continue" step, before any on-chain payment lands).
    pub async fn record_payment_link_intent(
        &self,
        payment_link_id: Uuid,
        payer_name: Option<&str>,
        payer_email: Option<&str>,
        amount_usdc_stroops: i64,
        address_id: Option<Uuid>,
    ) -> Result<PaymentLinkPayment, StoreError> {
        let row = sqlx::query_as::<_, PaymentLinkPayment>(
            r#"
            INSERT INTO payment_link_payments
                (payment_link_id, payer_name, payer_email, amount_usdc_stroops, address_id)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            "#,
        )
        .bind(payment_link_id)
        .bind(payer_name)
        .bind(payer_email)
        .bind(amount_usdc_stroops)
        .bind(address_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    /// The pending intent owning `address_id`, if any — ingest's exact deposit match.
    pub async fn pending_payment_by_address(
        &self,
        address_id: Uuid,
    ) -> Result<Option<PaymentLinkPayment>, StoreError> {
        let row = sqlx::query_as::<_, PaymentLinkPayment>(
            r#"
            SELECT * FROM payment_link_payments
            WHERE address_id = $1 AND status = 'pending'
            ORDER BY created_at ASC
            LIMIT 1
            "#,
        )
        .bind(address_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    /// Fetch a specific payment row scoped to its parent link.
    pub async fn get_payment_link_payment(
        &self,
        payment_link_id: Uuid,
        id: Uuid,
    ) -> Result<PaymentLinkPayment, StoreError> {
        sqlx::query_as::<_, PaymentLinkPayment>(
            "SELECT * FROM payment_link_payments WHERE id = $1 AND payment_link_id = $2",
        )
        .bind(id)
        .bind(payment_link_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StoreError::NotFound)
    }

    /// The oldest still-pending payment on a link — ingest matches deposits against this one.
    pub async fn oldest_pending_payment_link_payment(
        &self,
        payment_link_id: Uuid,
    ) -> Result<Option<PaymentLinkPayment>, StoreError> {
        let row = sqlx::query_as::<_, PaymentLinkPayment>(
            r#"
            SELECT * FROM payment_link_payments
            WHERE payment_link_id = $1 AND status = 'pending'
            ORDER BY created_at ASC
            LIMIT 1
            "#,
        )
        .bind(payment_link_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    /// Confirm a still-`pending` payment. Returns `false` if it was already settled, expired or
    /// cancelled, so a late or replayed deposit can never resurrect it.
    pub async fn confirm_payment_link_payment(
        &self,
        id: Uuid,
        transaction_id: Uuid,
    ) -> Result<bool, StoreError> {
        let res = sqlx::query(
            r#"
            UPDATE payment_link_payments
            SET status = 'confirmed', transaction_id = $1
            WHERE id = $2 AND status = 'pending'
            "#,
        )
        .bind(transaction_id)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() == 1)
    }

    /// Record a deposit that landed on this payment's address but for the wrong amount.
    /// `status` must be `"underpaid"` or `"overpaid"` — the transaction is still linked (so the
    /// merchant/payer can see what actually arrived) but the payment is deliberately NOT marked
    /// `confirmed`.
    pub async fn mark_payment_link_payment_mismatched(
        &self,
        id: Uuid,
        transaction_id: Uuid,
        status: &str,
    ) -> Result<bool, StoreError> {
        let res = sqlx::query(
            r#"
            UPDATE payment_link_payments
            SET status = $1, transaction_id = $2
            WHERE id = $3 AND status = 'pending'
            "#,
        )
        .bind(status)
        .bind(transaction_id)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() == 1)
    }

    /// Mark payments still `pending` past their 1-hour deadline, or whose link's `expires_at` has
    /// passed (#454), as `expired`, returning the flipped rows so the caller can fire one webhook
    /// per expiry without a second query.
    pub async fn expire_stale_payment_link_payments(
        &self,
    ) -> Result<Vec<PaymentLinkPayment>, StoreError> {
        let rows = sqlx::query_as::<_, PaymentLinkPayment>(
            r#"
            UPDATE payment_link_payments p
            SET status = 'expired'
            WHERE p.status = 'pending'
              AND (
                  p.created_at < now() - interval '1 hour'
                  OR EXISTS (
                      SELECT 1 FROM payment_links l
                      WHERE l.id = p.payment_link_id AND l.expires_at <= now()
                  )
              )
            RETURNING p.*
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Payments recorded against a link (newest first), with cursor pagination.
    ///
    /// Includes pending intents, not just confirmed ones — a merchant wants to see that someone
    /// started paying, and pending rows are how an abandoned checkout shows up.
    pub async fn list_payment_link_payments(
        &self,
        payment_link_id: Uuid,
        limit: i64,
        before_id: Option<Uuid>,
    ) -> Result<Vec<PaymentLinkPayment>, StoreError> {
        let rows = sqlx::query_as::<_, PaymentLinkPayment>(
            r#"
            SELECT * FROM payment_link_payments
            WHERE payment_link_id = $1
              AND ($2::uuid IS NULL OR (created_at, id) < (
                  SELECT created_at, id FROM payment_link_payments WHERE id = $2
              ))
            ORDER BY created_at DESC, id DESC
            LIMIT $3
            "#,
        )
        .bind(payment_link_id)
        .bind(before_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Lifetime total (in USDC stroops) confirmed on a payment link.
    pub async fn sum_payment_link_collected(
        &self,
        payment_link_id: Uuid,
    ) -> Result<i64, StoreError> {
        let total: Option<i64> = sqlx::query_scalar(
            r#"
            SELECT COALESCE(SUM(amount_usdc_stroops), 0)::bigint
            FROM payment_link_payments
            WHERE payment_link_id = $1 AND status = 'confirmed'
            "#,
        )
        .bind(payment_link_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(total.unwrap_or(0))
    }

    /// Batched version of [`Store::sum_payment_link_collected`] for a link list page.
    pub async fn sum_payment_link_collected_batch(
        &self,
        payment_link_ids: &[Uuid],
    ) -> Result<Vec<(Uuid, i64)>, StoreError> {
        if payment_link_ids.is_empty() {
            return Ok(Vec::new());
        }
        let rows: Vec<(Uuid, i64)> = sqlx::query_as(
            r#"
            SELECT payment_link_id, COALESCE(SUM(amount_usdc_stroops), 0)::bigint AS total
            FROM payment_link_payments
            WHERE payment_link_id = ANY($1) AND status = 'confirmed'
            GROUP BY payment_link_id
            "#,
        )
        .bind(payment_link_ids)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }
}
