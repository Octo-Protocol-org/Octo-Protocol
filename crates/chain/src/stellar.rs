//! The Stellar [`ChainAdapter`] — a thin forwarding layer over `octo-wallet-core`.
//!
//! Every method here delegates to an existing `octo-wallet-core` function; none reimplements
//! Stellar address/muxed-address logic. That is deliberate (see the parent issue): this crate
//! must not fork behaviour that already lives, tested, in `wallet-core`.

use crate::adapter::{ChainAdapter, DepositAddress, DepositFallback};
use crate::capabilities::{ChainCapabilities, ChainKind};
use crate::error::ChainError;
use crate::id::ChainId;
use async_trait::async_trait;
use octo_wallet_core::StellarNetwork;

/// Stellar's native asset (XLM) is denominated in stroops: 1 XLM = 10^7 stroops.
const STELLAR_NATIVE_DECIMALS: u8 = 7;

/// The Stellar [`ChainAdapter`]. Stateless beyond its fixed [`ChainId`] — every method forwards
/// to the corresponding free function in `octo_wallet_core`.
pub struct StellarAdapter {
    chain_id: ChainId,
}

impl StellarAdapter {
    /// Build the adapter for `network`. The chain id is derived once, at construction, from
    /// [`StellarNetwork`] — callers never pass a chain id string themselves.
    pub fn new(network: StellarNetwork) -> Self {
        let slug = match network {
            StellarNetwork::Public => ChainId::STELLAR_PUBNET,
            StellarNetwork::Testnet => ChainId::STELLAR_TESTNET,
            StellarNetwork::Standalone => ChainId::STELLAR_STANDALONE,
        };
        // The three slugs above are fixed, workspace-wide constants already covered by
        // crate::id's own parse tests — a parse failure here would be a programming error in
        // this crate, not bad external input, so unwrap is appropriate.
        #[allow(clippy::expect_used)]
        let chain_id =
            ChainId::parse(slug).expect("Octo's own Stellar chain-id slugs are valid CAIP-2");
        Self { chain_id }
    }
}

#[async_trait]
impl ChainAdapter for StellarAdapter {
    fn chain_id(&self) -> &ChainId {
        &self.chain_id
    }

    fn capabilities(&self) -> ChainCapabilities {
        ChainCapabilities {
            kind: ChainKind::Stellar,
            supports_memo: true,
            supports_muxed_addresses: true,
            has_reorgs: false,
            native_decimals: STELLAR_NATIVE_DECIMALS,
        }
    }

    async fn validate_address(&self, address: &str) -> Result<(), ChainError> {
        if octo_wallet_core::is_valid_account(address)
            || octo_wallet_core::decode_muxed(address).is_ok()
        {
            Ok(())
        } else {
            Err(ChainError::InvalidAddress)
        }
    }

    async fn normalize_address(&self, address: &str) -> Result<String, ChainError> {
        octo_wallet_core::to_base_account(address).map_err(|_| ChainError::InvalidAddress)
    }

    async fn derive_deposit_address(
        &self,
        base_identity: &str,
        customer_id: u64,
    ) -> Result<DepositAddress, ChainError> {
        let addr = octo_wallet_core::deposit_address(base_identity, customer_id)
            .map_err(|_| ChainError::InvalidAddress)?;
        Ok(DepositAddress {
            primary: addr.muxed_address,
            fallback: Some(DepositFallback {
                address: addr.base_address,
                memo: addr.memo_id.to_string(),
            }),
        })
    }

    /// Ported verbatim from `explain_code` in `crates/api/src/routes/submit.rs` — see that
    /// module for the Horizon result-code reference this mirrors.
    async fn explain_failure(&self, code: &str) -> String {
        match code {
            "op_underfunded" => "Insufficient balance to cover this amount.".into(),
            "op_low_reserve" => {
                "Not enough XLM to satisfy the base reserve (each trustline/subentry reserves 0.5 XLM)."
                    .into()
            }
            "op_no_destination" => "The destination account does not exist on this network.".into(),
            "op_no_trust" => {
                "The destination has no trustline for this asset — they must add one first.".into()
            }
            "op_no_issuer" => "The asset issuer does not exist on this network.".into(),
            "op_invalid_limit" => "The trust limit is invalid.".into(),
            "op_line_full" => "The destination's trustline limit would be exceeded.".into(),
            "tx_bad_seq" => {
                "Stale sequence number — refresh signing info and rebuild the transaction.".into()
            }
            "tx_bad_auth" => {
                "Signature verification failed — the transaction was not signed by this wallet's key."
                    .into()
            }
            "tx_insufficient_fee" => "The network fee was too low; rebuild with a higher fee.".into(),
            other => format!("Transaction failed ({other})."),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conformance::{chain_conformance_suite, ConformanceVectors};

    // The SEP-0005 Test 1 vector account, also used in crates/wallet-core/src/address.rs and
    // crates/wallet-core/src/derive.rs — kept identical so this adapter's tests stay anchored to
    // the same fixture as the code it forwards to.
    const BASE: &str = "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6";

    #[test]
    fn chain_id_matches_network() {
        assert_eq!(
            StellarAdapter::new(StellarNetwork::Public)
                .chain_id()
                .as_str(),
            "stellar:pubnet"
        );
        assert_eq!(
            StellarAdapter::new(StellarNetwork::Testnet)
                .chain_id()
                .as_str(),
            "stellar:testnet"
        );
        assert_eq!(
            StellarAdapter::new(StellarNetwork::Standalone)
                .chain_id()
                .as_str(),
            "stellar:standalone"
        );
    }

    #[test]
    fn capabilities_reflect_stellar() {
        let caps = StellarAdapter::new(StellarNetwork::Testnet).capabilities();
        assert_eq!(caps.kind, ChainKind::Stellar);
        assert!(caps.supports_memo);
        assert!(caps.supports_muxed_addresses);
        assert!(!caps.has_reorgs);
        assert_eq!(caps.native_decimals, 7);
    }

    /// Byte-identical to calling `octo_wallet_core::deposit_address` directly — the adapter must
    /// add zero behaviour of its own.
    #[tokio::test]
    async fn derive_deposit_address_matches_wallet_core_directly() {
        let adapter = StellarAdapter::new(StellarNetwork::Testnet);
        let direct = octo_wallet_core::deposit_address(BASE, 42).unwrap();

        let via_adapter = adapter.derive_deposit_address(BASE, 42).await.unwrap();

        assert_eq!(via_adapter.primary, direct.muxed_address);
        let fallback = via_adapter
            .fallback
            .expect("Stellar always has a memo fallback");
        assert_eq!(fallback.address, direct.base_address);
        assert_eq!(fallback.memo, direct.memo_id.to_string());
    }

    #[tokio::test]
    async fn validate_and_normalize_match_wallet_core_directly() {
        let adapter = StellarAdapter::new(StellarNetwork::Testnet);
        let muxed = octo_wallet_core::encode_muxed(BASE, 7).unwrap();

        assert!(adapter.validate_address(BASE).await.is_ok());
        assert!(adapter.validate_address(&muxed).await.is_ok());
        assert!(adapter.validate_address("not-an-address").await.is_err());

        assert_eq!(
            adapter.normalize_address(&muxed).await.unwrap(),
            octo_wallet_core::to_base_account(&muxed).unwrap()
        );
        assert_eq!(
            adapter.normalize_address(BASE).await.unwrap(),
            octo_wallet_core::to_base_account(BASE).unwrap()
        );
    }

    #[tokio::test]
    async fn explain_failure_matches_known_and_unknown_codes() {
        let adapter = StellarAdapter::new(StellarNetwork::Testnet);
        assert_eq!(
            adapter.explain_failure("op_underfunded").await,
            "Insufficient balance to cover this amount."
        );
        assert_eq!(
            adapter.explain_failure("op_totally_made_up").await,
            "Transaction failed (op_totally_made_up)."
        );
    }

    /// The reusable adapter-conformance harness #217's EVM adapter will also be required to
    /// pass. Running it here proves the Stellar adapter itself is honest.
    #[tokio::test]
    async fn passes_the_chain_conformance_suite() {
        let adapter = StellarAdapter::new(StellarNetwork::Testnet);
        let muxed = octo_wallet_core::encode_muxed(BASE, 1).unwrap();
        chain_conformance_suite(
            &adapter,
            ConformanceVectors {
                valid_address: BASE,
                valid_address_alt_form: Some(&muxed),
                invalid_address: "not-a-real-address",
                base_identity: BASE,
                customer_id: 99,
                unknown_failure_code: "totally_unrecognized_code",
            },
        )
        .await;
    }
}
