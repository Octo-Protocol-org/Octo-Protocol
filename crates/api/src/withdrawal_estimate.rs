//! Withdrawal fee and reserve estimate (#464).
//!
//! Pure arithmetic over the same [`AccountInfo`] the withdrawal pre-flight reads (balances,
//! subentries, sponsorships, [`BASE_RESERVE_STROOPS`]) plus cached Horizon [`FeeStats`], so the
//! preview and the real check can never disagree on their inputs. No I/O, so it is unit-tested
//! without Horizon.

use crate::error::ApiError;
use crate::horizon::{AccountInfo, FeeStats, BASE_RESERVE_STROOPS};
use serde::Serialize;

/// Stellar caps a transaction at 100 operations.
pub const MAX_OPERATIONS: i64 = 100;

/// What the caller intends to send.
#[derive(Debug, Clone, Default)]
pub struct EstimateRequest {
    /// `None` for native XLM, else `(code, issuer)` of a credit asset.
    pub asset: Option<(String, String)>,
    /// Optional amount to check for sufficiency.
    pub amount_stroops: Option<i64>,
    /// Operations in the transaction to be built (fees are charged per operation).
    pub operations: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WithdrawalEstimate {
    pub operations: i64,
    /// Network minimum fee per operation in the last closed ledger.
    pub base_fee_stroops: i64,
    /// Per-operation fee to bid: the larger of the base fee and the p90 fee recently charged.
    pub recommended_fee_stroops: i64,
    /// `recommended_fee_stroops * operations` — the transaction `fee` to build with.
    pub estimated_fee_stroops: i64,
    pub base_reserve_stroops: i64,
    /// Native balance the account must keep: `base_reserve * (2 + subentries + sponsoring - sponsored)`.
    pub min_reserve_stroops: i64,
    pub native_balance_stroops: i64,
    pub asset_code: Option<String>,
    pub asset_issuer: Option<String>,
    /// Balance of the requested credit asset; `None` for native.
    pub asset_balance_stroops: Option<i64>,
    /// Whether native balance above the reserve covers the estimated fee.
    pub fee_covered: bool,
    /// Largest amount of the requested asset that can leave after fee and reserve.
    pub max_withdrawable_stroops: i64,
    pub amount_stroops: Option<i64>,
    /// `Some` only when an amount was supplied: fee covered and amount within the maximum.
    pub sufficient: Option<bool>,
}

/// Compute the estimate. Fails only on invalid input (bad amount/operation count, no trustline).
pub fn estimate(
    info: &AccountInfo,
    fees: FeeStats,
    req: &EstimateRequest,
) -> Result<WithdrawalEstimate, ApiError> {
    if !(1..=MAX_OPERATIONS).contains(&req.operations) {
        return Err(ApiError::BadRequest(format!(
            "operations must be between 1 and {MAX_OPERATIONS}"
        )));
    }
    if req.amount_stroops.is_some_and(|a| a <= 0) {
        return Err(ApiError::BadRequest("amount_stroops must be > 0".into()));
    }

    let base_fee = fees.last_ledger_base_fee.max(0);
    let recommended = base_fee.max(fees.fee_charged_p90);
    let estimated_fee = recommended.saturating_mul(req.operations);
    let min_reserve = info.min_reserve_stroops();
    let native = info.native_balance_stroops();
    // Native left after the reserve; the fee is always paid from here, whatever the asset.
    let native_spendable = native.saturating_sub(min_reserve);
    let fee_covered = native_spendable >= estimated_fee;

    let (asset_balance, max_withdrawable) = match &req.asset {
        None => (None, native_spendable.saturating_sub(estimated_fee).max(0)),
        Some((code, issuer)) => {
            let balance = info.asset_balance_stroops(code, issuer).ok_or_else(|| {
                ApiError::BadRequest("wallet has no trustline for this asset".into())
            })?;
            let max = if fee_covered { balance.max(0) } else { 0 };
            (Some(balance), max)
        }
    };

    Ok(WithdrawalEstimate {
        operations: req.operations,
        base_fee_stroops: base_fee,
        recommended_fee_stroops: recommended,
        estimated_fee_stroops: estimated_fee,
        base_reserve_stroops: BASE_RESERVE_STROOPS,
        min_reserve_stroops: min_reserve,
        native_balance_stroops: native,
        asset_code: req.asset.as_ref().map(|(c, _)| c.clone()),
        asset_issuer: req.asset.as_ref().map(|(_, i)| i.clone()),
        asset_balance_stroops: asset_balance,
        fee_covered,
        max_withdrawable_stroops: max_withdrawable,
        amount_stroops: req.amount_stroops,
        sufficient: req
            .amount_stroops
            .map(|a| fee_covered && a <= max_withdrawable),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::horizon::Balance;

    const USDC: &str = "USDC";
    const ISSUER: &str = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";

    fn account(native: &str, usdc: Option<&str>, subentries: i64) -> AccountInfo {
        let mut balances = vec![Balance {
            balance: native.into(),
            asset_type: "native".into(),
            asset_code: None,
            asset_issuer: None,
        }];
        if let Some(b) = usdc {
            balances.push(Balance {
                balance: b.into(),
                asset_type: "credit_alphanum4".into(),
                asset_code: Some(USDC.into()),
                asset_issuer: Some(ISSUER.into()),
            });
        }
        AccountInfo {
            balances,
            sequence: 1,
            subentry_count: subentries,
            num_sponsoring: 0,
            num_sponsored: 0,
        }
    }

    fn fees(base: i64, p90: i64) -> FeeStats {
        FeeStats {
            last_ledger_base_fee: base,
            fee_charged_p50: base,
            fee_charged_p90: p90,
        }
    }

    fn native_req(amount: Option<i64>) -> EstimateRequest {
        EstimateRequest {
            asset: None,
            amount_stroops: amount,
            operations: 1,
        }
    }

    #[test]
    fn native_max_subtracts_reserve_and_fee() {
        // 10 XLM, one trustline → reserve 1.5 XLM; fee bid is the p90 of 300.
        let est = estimate(&account("10", Some("0"), 1), fees(100, 300), &native_req(None)).unwrap();
        assert_eq!(est.min_reserve_stroops, 15_000_000);
        assert_eq!(est.min_reserve_stroops, account("10", Some("0"), 1).min_reserve_stroops());
        assert_eq!(est.recommended_fee_stroops, 300);
        assert_eq!(est.max_withdrawable_stroops, 100_000_000 - 15_000_000 - 300);
        assert!(est.fee_covered);
        assert_eq!(est.sufficient, None);
    }

    #[test]
    fn recommended_fee_never_drops_below_base_fee() {
        let est = estimate(&account("10", None, 0), fees(100, 50), &native_req(None)).unwrap();
        assert_eq!(est.recommended_fee_stroops, 100);
    }

    #[test]
    fn fee_scales_with_operation_count() {
        let req = EstimateRequest {
            operations: 3,
            ..native_req(None)
        };
        let est = estimate(&account("10", None, 0), fees(100, 200), &req).unwrap();
        assert_eq!(est.estimated_fee_stroops, 600);
    }

    #[test]
    fn sufficiency_is_exact_at_the_boundary() {
        let info = account("2", None, 0); // reserve 1 XLM
        let max = 10_000_000 - 100;
        let ok = estimate(&info, fees(100, 100), &native_req(Some(max))).unwrap();
        assert_eq!(ok.sufficient, Some(true));
        let over = estimate(&info, fees(100, 100), &native_req(Some(max + 1))).unwrap();
        assert_eq!(over.sufficient, Some(false));
    }

    #[test]
    fn below_reserve_account_can_withdraw_nothing() {
        let est = estimate(&account("0.5", None, 0), fees(100, 100), &native_req(Some(1))).unwrap();
        assert_eq!(est.max_withdrawable_stroops, 0);
        assert!(!est.fee_covered);
        assert_eq!(est.sufficient, Some(false));
    }

    #[test]
    fn credit_asset_needs_native_for_the_fee() {
        let req = EstimateRequest {
            asset: Some((USDC.into(), ISSUER.into())),
            amount_stroops: Some(50_000_000),
            operations: 1,
        };
        let funded = estimate(&account("5", Some("25"), 1), fees(100, 100), &req).unwrap();
        assert_eq!(funded.asset_balance_stroops, Some(250_000_000));
        assert_eq!(funded.max_withdrawable_stroops, 250_000_000);
        assert_eq!(funded.sufficient, Some(true));

        // Exactly at the reserve: no XLM left to pay the fee, so nothing can move.
        let starved = estimate(&account("1.5", Some("25"), 1), fees(100, 100), &req).unwrap();
        assert!(!starved.fee_covered);
        assert_eq!(starved.max_withdrawable_stroops, 0);
        assert_eq!(starved.sufficient, Some(false));
    }

    #[test]
    fn missing_trustline_is_rejected() {
        let req = EstimateRequest {
            asset: Some((USDC.into(), ISSUER.into())),
            ..native_req(None)
        };
        assert!(estimate(&account("5", None, 0), fees(100, 100), &req).is_err());
    }

    #[test]
    fn invalid_inputs_are_rejected() {
        let info = account("5", None, 0);
        let zero_ops = EstimateRequest {
            operations: 0,
            ..native_req(None)
        };
        let too_many = EstimateRequest {
            operations: MAX_OPERATIONS + 1,
            ..native_req(None)
        };
        assert!(estimate(&info, fees(100, 100), &zero_ops).is_err());
        assert!(estimate(&info, fees(100, 100), &too_many).is_err());
        assert!(estimate(&info, fees(100, 100), &native_req(Some(0))).is_err());
    }
}
