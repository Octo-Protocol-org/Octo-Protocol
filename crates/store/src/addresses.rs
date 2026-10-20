//! Address allocation (muxed-id counter bump + insert, all-or-nothing).

use uuid::Uuid;

use crate::error::StoreError;
use crate::models::Address;
use crate::{NewAddress, Store};

impl Store {
    /// Atomically allocate the next muxed id for `wallet_id` and insert the address row.
    ///
    /// The counter bump and the insert happen in one transaction with a row lock, so two
    /// concurrent callers always get distinct, gap-free-enough ids and never collide.
    pub async fn allocate_address(
        &self,
        wallet_id: Uuid,
        muxed_address_for: impl FnOnce(i64) -> Result<String, ()>,
        customer_ref: Option<&str>,
        metadata: serde_json::Value,
    ) -> Result<Address, StoreError> {
        let mut muxed_address_for = Some(muxed_address_for);
        let mut rows = self
            .allocate_addresses(
                wallet_id,
                |id| match muxed_address_for.take() {
                    Some(derive) => derive(id),
                    None => Err(()),
                },
                vec![NewAddress {
                    customer_ref,
                    metadata,
                }],
            )
            .await?;
        rows.pop().ok_or(StoreError::NotFound)
    }

    /// Allocate one address per entry in `new`, all-or-nothing.
    ///
    /// One `UPDATE ... RETURNING` reserves a contiguous block of muxed ids under the wallet's row
    /// lock, so concurrent batches serialize and never overlap; any failed insert (e.g. a
    /// duplicate `customer_ref`) rolls back the whole batch, counter bump included.
    pub async fn allocate_addresses(
        &self,
        wallet_id: Uuid,
        mut muxed_address_for: impl FnMut(i64) -> Result<String, ()>,
        new: Vec<NewAddress<'_>>,
    ) -> Result<Vec<Address>, StoreError> {
        if new.is_empty() {
            return Ok(Vec::new());
        }
        let count = i64::try_from(new.len()).map_err(|_| StoreError::NotFound)?;
        let mut tx = self.pool.begin().await?;

        // Reserve ids [first_id, first_id + count) and hold the row lock until commit.
        let first_id: i64 = sqlx::query_scalar(
            "UPDATE wallets SET next_muxed_id = next_muxed_id + $2, updated_at = now()
             WHERE id = $1 RETURNING next_muxed_id - $2",
        )
        .bind(wallet_id)
        .bind(count)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(StoreError::NotFound)?;

        let mut addresses = Vec::with_capacity(new.len());
        for (muxed_id, item) in (first_id..).zip(new) {
            // Derive the muxed address for this id via the caller-provided closure (wallet-core).
            let muxed_address = muxed_address_for(muxed_id).map_err(|_| StoreError::NotFound)?;
            let address = sqlx::query_as::<_, Address>(
                r#"
                INSERT INTO addresses (wallet_id, muxed_id, muxed_address, customer_ref, metadata)
                VALUES ($1, $2, $3, $4, $5)
                RETURNING *
                "#,
            )
            .bind(wallet_id)
            .bind(muxed_id)
            .bind(&muxed_address)
            .bind(item.customer_ref)
            .bind(item.metadata)
            .fetch_one(&mut *tx)
            .await
            .map_err(StoreError::from_sqlx_conflict)?;
            addresses.push(address);
        }

        tx.commit().await?;
        Ok(addresses)
    }

    /// List addresses for a wallet (most recent first), with optional cursor-based pagination.
    pub async fn list_addresses(
        &self,
        wallet_id: Uuid,
        limit: i64,
        before_id: Option<Uuid>,
    ) -> Result<Vec<Address>, StoreError> {
        let rows = sqlx::query_as::<_, Address>(
            r#"
            SELECT * FROM addresses
            WHERE wallet_id = $1
              AND ($2::uuid IS NULL OR (created_at, id) < (
                  SELECT created_at, id FROM addresses WHERE id = $2
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

    /// Paginated version of [`list_addresses`]: returns at most `limit` rows, newest first.
    /// Pass the last page's final address id as `before_id` to fetch the next page.
    pub async fn list_addresses_page(
        &self,
        wallet_id: Uuid,
        limit: i64,
        before_id: Option<Uuid>,
    ) -> Result<Vec<Address>, StoreError> {
        let rows = sqlx::query_as::<_, Address>(
            r#"
            SELECT * FROM addresses
            WHERE wallet_id = $1
              AND ($2::uuid IS NULL OR (created_at, id) < (
                    SELECT created_at, id FROM addresses WHERE id = $2
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

    /// Fetch an address by id.
    pub async fn get_address(&self, id: Uuid) -> Result<Option<Address>, StoreError> {
        let row = sqlx::query_as::<_, Address>("SELECT * FROM addresses WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row)
    }

    /// Find a wallet's address by the integrator's `customer_ref` (unique per wallet, indexed).
    pub async fn address_by_customer_ref(
        &self,
        wallet_id: Uuid,
        customer_ref: &str,
    ) -> Result<Option<Address>, StoreError> {
        let row = sqlx::query_as::<_, Address>(
            "SELECT * FROM addresses WHERE wallet_id = $1 AND customer_ref = $2",
        )
        .bind(wallet_id)
        .bind(customer_ref)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    /// Find the address for a given `(wallet_id, muxed_id)`, if any.
    pub async fn address_by_muxed_id(
        &self,
        wallet_id: Uuid,
        muxed_id: i64,
    ) -> Result<Option<Address>, StoreError> {
        let row = sqlx::query_as::<_, Address>(
            "SELECT * FROM addresses WHERE wallet_id = $1 AND muxed_id = $2",
        )
        .bind(wallet_id)
        .bind(muxed_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }
}
