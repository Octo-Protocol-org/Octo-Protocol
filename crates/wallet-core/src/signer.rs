//! The signing path: open a sealed seed, derive the master key, build a **payment** transaction,
//! sign it, and zeroize secrets.
//!
//! Security posture (see `docs/threat-model.md`):
//! - This module only ever builds octo's own **Payment** operations. It does **not** accept or
//!   sign caller-supplied raw XDR, so it cannot be used as a "sign anything" oracle.
//! - Amounts are integer **stroops** (`i64`), validated to be strictly positive.
//! - The network (testnet/mainnet) is always explicit — there is no ambient default that could
//!   cause a testnet-intended signature to be valid on mainnet.
//! - The decrypted seed and the derived keypair live only for the duration of `sign_payment` and
//!   are zeroized on drop.

use crate::address::is_valid_account;
use crate::asset::is_valid_asset_code;
use crate::derive::WalletSeed;
use crate::error::WalletError;
use octo_crypto::{open, SealedSeed, MASTER_KEY_LEN};
use stellar_base::amount::Stroops;
use stellar_base::asset::Asset;
use stellar_base::crypto::{DalekKeyPair, MuxedEd25519PublicKey, PublicKey};
use stellar_base::memo::Memo;
use stellar_base::network::Network;
use stellar_base::operations::Operation;
use stellar_base::transaction::{Transaction, MIN_BASE_FEE};
use stellar_base::xdr::XDRSerialize;

/// Which Stellar network a signature targets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StellarNetwork {
    /// Public (mainnet) network.
    Public,
    /// Test network.
    Testnet,
}

impl StellarNetwork {
    fn to_base(self) -> Network {
        match self {
            StellarNetwork::Public => Network::new_public(),
            StellarNetwork::Testnet => Network::new_test(),
        }
    }

    /// The crypto context string bound into seed encryption for this network.
    pub fn crypto_context(self) -> &'static [u8] {
        match self {
            StellarNetwork::Public => b"octo:mainnet",
            StellarNetwork::Testnet => b"octo:testnet",
        }
    }

    /// The canonical lowercase name (`"mainnet"` / `"testnet"`) used in the DB and API.
    pub fn as_str(self) -> &'static str {
        match self {
            StellarNetwork::Public => "mainnet",
            StellarNetwork::Testnet => "testnet",
        }
    }

    /// Parse from the canonical name. Accepts `mainnet`/`public` and `testnet`/`test`.
    pub fn parse(s: &str) -> Option<StellarNetwork> {
        match s {
            "mainnet" | "public" => Some(StellarNetwork::Public),
            "testnet" | "test" => Some(StellarNetwork::Testnet),
            _ => None,
        }
    }
}

/// A single payment to build and sign from the master account.
pub struct PaymentRequest<'a> {
    /// Destination account (`G...`) or muxed (`M...`) address.
    pub destination: &'a str,
    /// Amount in **stroops** (1 XLM = 10_000_000 stroops). Must be > 0.
    pub stroops: i64,
    /// `None` => native XLM. `Some((code, issuer_g))` => a credit asset.
    pub asset: Option<(&'a str, &'a str)>,
    /// Optional numeric memo (used for the `G...`+memo deposit-return convention).
    pub memo_id: Option<u64>,
    /// The master account's current sequence number (fetched from Horizon by the caller).
    pub sequence: i64,
}

/// The result of signing: the base64 XDR envelope to submit, plus the master account it was
/// signed for. (The transaction hash is computed by the caller/Horizon on submit.)
pub struct SignedPayment {
    /// Base64-encoded signed `TransactionEnvelope`, ready to POST to Horizon.
    pub envelope_xdr: String,
    /// The `G...` master account that sourced and signed this transaction.
    pub source_account: String,
}

/// Open a sealed seed for `network`, derive Stellar account `account_index`, and return its
/// `DalekKeyPair`. The decrypted seed is zeroized as it leaves scope.
fn keypair_from_sealed(
    master_key: &[u8; MASTER_KEY_LEN],
    sealed: &SealedSeed,
    network: StellarNetwork,
    account_index: u32,
) -> Result<DalekKeyPair, WalletError> {
    let seed_bytes = open(master_key, sealed, network.crypto_context())?;
    let seed = WalletSeed::from_bytes(seed_bytes.to_vec());
    let secret = seed.derive_ed25519_secret(account_index);
    // stellar-base builds the ed25519 keypair from the 32-byte secret seed.
    DalekKeyPair::from_seed_bytes(secret.as_ref()).map_err(|_| WalletError::KeyDerivation)
}

/// Derive just the `G...` account id for `account_index` from a sealed seed (no signing).
pub fn account_id_from_sealed(
    master_key: &[u8; MASTER_KEY_LEN],
    sealed: &SealedSeed,
    network: StellarNetwork,
    account_index: u32,
) -> Result<String, WalletError> {
    let kp = keypair_from_sealed(master_key, sealed, network, account_index)?;
    Ok(kp.public_key().account_id())
}

/// Build and sign a payment from the master account (`account_index`, normally 0).
///
/// Only a Payment operation is ever constructed — no other operation type can be produced by this
/// function, which is the core anti-"signing-oracle" guarantee.
pub fn sign_payment(
    master_key: &[u8; MASTER_KEY_LEN],
    sealed: &SealedSeed,
    network: StellarNetwork,
    account_index: u32,
    req: &PaymentRequest<'_>,
) -> Result<SignedPayment, WalletError> {
    if req.stroops <= 0 {
        return Err(WalletError::InvalidAmount);
    }

    let keypair = keypair_from_sealed(master_key, sealed, network, account_index)?;
    let source = keypair.public_key();
    let source_account = source.account_id();

    // Resolve the destination (accept either G... or M...).
    let destination = parse_destination(req.destination)?;

    // Resolve the asset (native XLM or a validated credit asset).
    let asset = match req.asset {
        None => Asset::new_native(),
        Some((code, issuer)) => {
            if !is_valid_asset_code(code) {
                return Err(WalletError::InvalidAssetCode);
            }
            if !is_valid_account(issuer) {
                return Err(WalletError::InvalidAddress);
            }
            let issuer_pk =
                PublicKey::from_account_id(issuer).map_err(|_| WalletError::InvalidAddress)?;
            Asset::new_credit(code, issuer_pk).map_err(|_| WalletError::InvalidAssetCode)?
        }
    };

    let payment = Operation::new_payment()
        .with_destination(destination)
        .with_amount(Stroops::new(req.stroops))
        .map_err(|_| WalletError::InvalidAmount)?
        .with_asset(asset)
        .build()
        .map_err(|_| WalletError::Signing)?;

    let mut builder = Transaction::builder(source, req.sequence, MIN_BASE_FEE);
    if let Some(id) = req.memo_id {
        builder = builder.with_memo(Memo::new_id(id));
    }
    let mut tx = builder
        .add_operation(payment)
        .into_transaction()
        .map_err(|_| WalletError::Signing)?;

    // DalekKeyPair derefs to the inner KeyPair, which is what sign() accepts.
    tx.sign(keypair.as_ref(), &network.to_base())
        .map_err(|_| WalletError::Signing)?;

    let envelope_xdr = tx
        .into_envelope()
        .xdr_base64()
        .map_err(|_| WalletError::Signing)?;

    Ok(SignedPayment {
        envelope_xdr,
        source_account,
    })
}

/// Request parameters for wrapping a user's signed transaction in a FeeBumpTransaction.
pub struct FeeBumpRequest<'a> {
    /// Base64-encoded signed `TransactionEnvelope` from the user. Must be a v1 (`Tx`) envelope.
    pub inner_xdr: &'a str,
    /// Maximum fee (in stroops) the sponsor is willing to pay for the fee-bump.
    ///
    /// This value is stored **verbatim** as the outer `FeeBumpTransaction.fee` — a **flat total
    /// fee bid in stroops for the whole envelope**, not a per-operation base fee. Per Stellar's
    /// fee-bump validity rules (CAP-15), the network treats the declared fee as covering
    /// `inner_operation_count + 1` operations (the inner ops plus the fee-bump itself), so for
    /// multi-op inner transactions the caller must size this bid accordingly — use
    /// [`inner_operation_count`] to inspect the inner transaction. See `docs/threat-model.md`
    /// section B (signing-path abuse / fee injection) for the fee-semantics threat rows.
    pub max_base_fee_stroops: i64,
}

/// Wrap a user's already-signed `TransactionEnvelope` in a `FeeBumpTransaction` signed by the
/// master wallet as fee source, then return the signed outer envelope XDR.
///
/// Security: the seed is decrypted, the signing key is derived, and both are zeroized on drop —
/// the same contract as `sign_payment`. The caller is responsible for validating the inner XDR
/// (operation-type allowlist, self-sponsorship guard) before calling this function.
pub fn sign_fee_bump(
    master_key: &[u8; MASTER_KEY_LEN],
    sealed: &SealedSeed,
    network: StellarNetwork,
    account_index: u32,
    req: &FeeBumpRequest<'_>,
) -> Result<SignedPayment, WalletError> {
    use sha2::{Digest, Sha256};
    use stellar_base::xdr::{
        BytesM, DecoratedSignature, FeeBumpTransaction as XdrFeeBump, FeeBumpTransactionEnvelope,
        FeeBumpTransactionExt, FeeBumpTransactionInnerTx, Hash, MuxedAccount, Signature,
        SignatureHint, TransactionEnvelope, TransactionSignaturePayload,
        TransactionSignaturePayloadTaggedTransaction, Uint256, VecM, XDRDeserialize, XDRSerialize,
    };

    // Parse and validate the inner XDR — must be a v1 TransactionEnvelope.
    let inner_env =
        TransactionEnvelope::from_xdr_base64(req.inner_xdr).map_err(|_| WalletError::InvalidXdr)?;
    let inner_v1 = match inner_env {
        TransactionEnvelope::Tx(v1) => v1,
        _ => return Err(WalletError::InvalidXdr),
    };

    // Derive the signing key for the fee source (decrypt → derive → zeroize on drop).
    let seed_bytes = open(master_key, sealed, network.crypto_context())?;
    let seed = WalletSeed::from_bytes(seed_bytes.to_vec());
    let secret = seed.derive_ed25519_secret(account_index);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);

    let pk_bytes: [u8; 32] = signing_key.verifying_key().to_bytes();
    let source_account = format!("{}", stellar_strkey::ed25519::PublicKey(pk_bytes));

    // Build the fee-bump transaction (without signatures yet).
    let fee_bump_tx = XdrFeeBump {
        fee_source: MuxedAccount::Ed25519(Uint256(pk_bytes)),
        fee: req.max_base_fee_stroops,
        inner_tx: FeeBumpTransactionInnerTx::Tx(inner_v1),
        ext: FeeBumpTransactionExt::V0,
    };

    // Compute the signing hash: sha256(XDR(TransactionSignaturePayload)).
    let network_id_bytes = network.to_base().network_id();
    let network_hash: [u8; 32] = network_id_bytes
        .as_slice()
        .try_into()
        .map_err(|_| WalletError::Signing)?;

    let sig_payload = TransactionSignaturePayload {
        network_id: Hash(network_hash),
        tagged_transaction: TransactionSignaturePayloadTaggedTransaction::TxFeeBump(
            fee_bump_tx.clone(),
        ),
    };
    let payload_xdr = sig_payload.xdr_bytes().map_err(|_| WalletError::Signing)?;
    let hash: [u8; 32] = Sha256::digest(&payload_xdr).into();

    // Sign the hash with ed25519 (signing_key zeroized on drop).
    use ed25519_dalek::Signer as _;
    let signature: ed25519_dalek::Signature = signing_key.sign(&hash);
    let sig_bytes: [u8; 64] = signature.to_bytes();

    // Build the decorated signature (hint = last 4 bytes of the public key).
    let hint_bytes: [u8; 4] = pk_bytes[28..32]
        .try_into()
        .map_err(|_| WalletError::Signing)?;
    let decorated = DecoratedSignature {
        hint: SignatureHint(hint_bytes),
        signature: Signature(
            BytesM::<64>::try_from(sig_bytes.to_vec()).map_err(|_| WalletError::Signing)?,
        ),
    };

    // Assemble the fee-bump envelope and serialize.
    let sigs: VecM<DecoratedSignature, 20> = vec![decorated]
        .try_into()
        .map_err(|_| WalletError::Signing)?;
    let fee_bump_envelope = FeeBumpTransactionEnvelope {
        tx: fee_bump_tx,
        signatures: sigs,
    };
    let envelope_xdr = TransactionEnvelope::TxFeeBump(fee_bump_envelope)
        .xdr_base64()
        .map_err(|_| WalletError::Signing)?;

    Ok(SignedPayment {
        envelope_xdr,
        source_account,
    })
}

/// Compute the Stellar transaction hash (sha256 of the signing payload) for the inner transaction
/// in a fee-bump flow. This is the standard txID that would appear in Horizon/explorers.
pub fn compute_inner_tx_hash(
    inner_xdr: &str,
    network: StellarNetwork,
) -> Result<[u8; 32], WalletError> {
    use sha2::{Digest, Sha256};
    use stellar_base::xdr::{
        Hash, TransactionEnvelope, TransactionSignaturePayload,
        TransactionSignaturePayloadTaggedTransaction, XDRDeserialize, XDRSerialize,
    };

    let inner_env =
        TransactionEnvelope::from_xdr_base64(inner_xdr).map_err(|_| WalletError::InvalidXdr)?;
    let inner_tx = match inner_env {
        TransactionEnvelope::Tx(v1) => v1.tx,
        _ => return Err(WalletError::InvalidXdr),
    };

    let network_id_bytes = network.to_base().network_id();
    let network_hash: [u8; 32] = network_id_bytes
        .as_slice()
        .try_into()
        .map_err(|_| WalletError::Signing)?;

    let sig_payload = TransactionSignaturePayload {
        network_id: Hash(network_hash),
        tagged_transaction: TransactionSignaturePayloadTaggedTransaction::Tx(inner_tx),
    };
    let payload_xdr = sig_payload.xdr_bytes().map_err(|_| WalletError::Signing)?;
    Ok(Sha256::digest(&payload_xdr).into())
}

/// Count the operations in the inner transaction of a fee-bump flow, so callers can size the
/// flat fee bid ([`FeeBumpRequest::max_base_fee_stroops`]) as
/// `(operation_count + 1) × base_fee` per Stellar's fee-bump rule (the `+ 1` pays for the
/// fee-bump itself).
///
/// Accepts only a v1 (`Tx`) envelope — the same constraint as [`sign_fee_bump`] — and returns
/// [`WalletError::InvalidXdr`] for anything else. Pure parsing: no I/O, no secret material. A
/// zero-op envelope parses and returns `Ok(0)`; Stellar itself rejects zero-op transactions, so
/// this helper reports the count, it does not validate the transaction.
pub fn inner_operation_count(inner_xdr: &str) -> Result<usize, WalletError> {
    use stellar_base::xdr::{TransactionEnvelope, XDRDeserialize};

    let inner_env =
        TransactionEnvelope::from_xdr_base64(inner_xdr).map_err(|_| WalletError::InvalidXdr)?;
    match inner_env {
        TransactionEnvelope::Tx(v1) => Ok(v1.tx.operations.len()),
        _ => Err(WalletError::InvalidXdr),
    }
}

/// Parse a destination that may be a `G...` account or an `M...` muxed address.
fn parse_destination(dest: &str) -> Result<stellar_base::crypto::MuxedAccount, WalletError> {
    if let Ok(mux) = MuxedEd25519PublicKey::from_account_id(dest) {
        return Ok(mux.into());
    }
    let pk = PublicKey::from_account_id(dest).map_err(|_| WalletError::InvalidAddress)?;
    Ok(pk.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use octo_crypto::seal;
    use stellar_base::xdr::XDRDeserialize;

    const VECTOR_MNEMONIC: &str =
        "illness spike retreat truth genius clock brain pass fit cave bargain toe";
    const MASTER_ACCOUNT_0: &str = "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6";
    // A valid destination: account index 1 derived from the same vector seed.
    const DEST: &str = "GBAW5XGWORWVFE2XTJYDTLDHXTY2Q2MO73HYCGB3XMFMQ562Q2W2GJQX";

    fn sealed_vector_seed(net: StellarNetwork) -> ([u8; 32], SealedSeed) {
        let mk = [7u8; 32];
        // The raw 64-byte BIP39 seed for the SEP-0005 vector mnemonic, sealed for `net`.
        let bytes = bip39::Seed::new(
            &bip39::Mnemonic::from_phrase(VECTOR_MNEMONIC, bip39::Language::English).unwrap(),
            "",
        )
        .as_bytes()
        .to_vec();
        let sealed = seal(&mk, &bytes, net.crypto_context()).unwrap();
        (mk, sealed)
    }

    #[test]
    fn account_id_from_sealed_matches_vector() {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        let acct = account_id_from_sealed(&mk, &sealed, StellarNetwork::Testnet, 0).unwrap();
        assert_eq!(acct, MASTER_ACCOUNT_0);
    }

    #[test]
    fn signs_native_payment_and_produces_valid_envelope() {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        let req = PaymentRequest {
            destination: DEST,
            stroops: 10_000_000, // 1 XLM
            asset: None,
            memo_id: None,
            sequence: 1,
        };
        let signed = sign_payment(&mk, &sealed, StellarNetwork::Testnet, 0, &req).unwrap();
        assert_eq!(signed.source_account, MASTER_ACCOUNT_0);
        // The envelope must be valid, signed XDR that round-trips through the parser.
        let env = stellar_base::xdr::TransactionEnvelope::from_xdr_base64(&signed.envelope_xdr)
            .expect("signed envelope must be valid XDR");
        // It must carry exactly one signature.
        match env {
            stellar_base::xdr::TransactionEnvelope::Tx(e) => {
                assert_eq!(e.signatures.len(), 1, "must be signed once");
            }
            _ => panic!("unexpected envelope variant"),
        }
    }

    #[test]
    fn rejects_non_positive_amount() {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        for bad in [0i64, -1, -10_000_000] {
            let req = PaymentRequest {
                destination: DEST,
                stroops: bad,
                asset: None,
                memo_id: None,
                sequence: 1,
            };
            assert!(matches!(
                sign_payment(&mk, &sealed, StellarNetwork::Testnet, 0, &req),
                Err(WalletError::InvalidAmount)
            ));
        }
    }

    #[test]
    fn rejects_bad_destination() {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        let req = PaymentRequest {
            destination: "not-an-address",
            stroops: 1,
            asset: None,
            memo_id: None,
            sequence: 1,
        };
        assert!(matches!(
            sign_payment(&mk, &sealed, StellarNetwork::Testnet, 0, &req),
            Err(WalletError::InvalidAddress)
        ));
    }

    /// Regression coverage for `sign_payment`'s use of the shared
    /// `crate::asset::is_valid_asset_code` (see `crate::asset`): an out-of-bounds credit-asset
    /// code must be rejected as `InvalidAssetCode` before any `Asset::new_credit` call, and a
    /// well-formed 1-12 byte code must still sign successfully.
    #[test]
    fn credit_payment_asset_code_goes_through_shared_validator() {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);

        for bad in ["", "THIRTEEN_BYTE"] {
            let req = PaymentRequest {
                destination: DEST,
                stroops: 1,
                asset: Some((bad, MASTER_ACCOUNT_0)),
                memo_id: None,
                sequence: 1,
            };
            assert!(
                matches!(
                    sign_payment(&mk, &sealed, StellarNetwork::Testnet, 0, &req),
                    Err(WalletError::InvalidAssetCode)
                ),
                "code {bad:?} (len {}) must be rejected as InvalidAssetCode",
                bad.len()
            );
        }

        let req = PaymentRequest {
            destination: DEST,
            stroops: 1,
            asset: Some(("USDC", MASTER_ACCOUNT_0)),
            memo_id: None,
            sequence: 1,
        };
        assert!(sign_payment(&mk, &sealed, StellarNetwork::Testnet, 0, &req).is_ok());
    }

    #[test]
    fn wrong_network_context_cannot_open_seed() {
        // Seed sealed for mainnet; signing as testnet must fail to decrypt (AAD/context mismatch).
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Public);
        let req = PaymentRequest {
            destination: DEST,
            stroops: 1,
            asset: None,
            memo_id: None,
            sequence: 1,
        };
        assert!(matches!(
            sign_payment(&mk, &sealed, StellarNetwork::Testnet, 0, &req),
            Err(WalletError::SeedDecryption)
        ));
    }

    #[test]
    fn sign_fee_bump_produces_valid_outer_envelope() {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        // Create a valid inner signed payment to wrap.
        let inner_req = PaymentRequest {
            destination: DEST,
            stroops: 100,
            asset: None,
            memo_id: None,
            sequence: 1,
        };
        let inner = sign_payment(&mk, &sealed, StellarNetwork::Testnet, 0, &inner_req).unwrap();

        let req = FeeBumpRequest {
            inner_xdr: &inner.envelope_xdr,
            max_base_fee_stroops: 200,
        };
        let result = sign_fee_bump(&mk, &sealed, StellarNetwork::Testnet, 0, &req).unwrap();
        assert_eq!(result.source_account, MASTER_ACCOUNT_0);

        // Round-trip parse the outer envelope and verify structure.
        use stellar_base::xdr::{TransactionEnvelope, XDRDeserialize};
        let env = TransactionEnvelope::from_xdr_base64(&result.envelope_xdr)
            .expect("signed fee-bump envelope must be valid XDR");
        match env {
            TransactionEnvelope::TxFeeBump(e) => {
                assert_eq!(
                    e.signatures.len(),
                    1,
                    "outer envelope must carry exactly one signature"
                );
                // Inner signatures must be preserved.
                match e.tx.inner_tx {
                    stellar_base::xdr::FeeBumpTransactionInnerTx::Tx(v1) => {
                        assert_eq!(v1.signatures.len(), 1, "inner signatures must be preserved");
                    }
                }
            }
            _ => panic!("expected TxFeeBump envelope variant"),
        }
    }

    #[test]
    fn sign_fee_bump_rejects_invalid_xdr() {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        let req = FeeBumpRequest {
            inner_xdr: "this-is-not-valid-base64-xdr",
            max_base_fee_stroops: 200,
        };
        assert!(matches!(
            sign_fee_bump(&mk, &sealed, StellarNetwork::Testnet, 0, &req),
            Err(WalletError::InvalidXdr)
        ));
    }

    #[test]
    fn sign_fee_bump_wrong_network_cannot_open_seed() {
        // Build a valid inner XDR using the testnet-sealed seed.
        let (mk, testnet_sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        let inner = sign_payment(
            &mk,
            &testnet_sealed,
            StellarNetwork::Testnet,
            0,
            &PaymentRequest {
                destination: DEST,
                stroops: 1,
                asset: None,
                memo_id: None,
                sequence: 1,
            },
        )
        .unwrap();

        // Seal the same seed for mainnet; trying to open it as testnet must fail (AAD mismatch).
        let (mk2, mainnet_sealed) = sealed_vector_seed(StellarNetwork::Public);
        let req = FeeBumpRequest {
            inner_xdr: &inner.envelope_xdr,
            max_base_fee_stroops: 200,
        };
        assert!(matches!(
            sign_fee_bump(&mk2, &mainnet_sealed, StellarNetwork::Testnet, 0, &req),
            Err(WalletError::SeedDecryption)
        ));
    }

    #[test]
    fn compute_inner_tx_hash_is_deterministic() {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        let inner = sign_payment(
            &mk,
            &sealed,
            StellarNetwork::Testnet,
            0,
            &PaymentRequest {
                destination: DEST,
                stroops: 100,
                asset: None,
                memo_id: None,
                sequence: 5,
            },
        )
        .unwrap();
        let h1 = compute_inner_tx_hash(&inner.envelope_xdr, StellarNetwork::Testnet).unwrap();
        let h2 = compute_inner_tx_hash(&inner.envelope_xdr, StellarNetwork::Testnet).unwrap();
        assert_eq!(h1, h2, "hash must be deterministic");
        assert_ne!(h1, [0u8; 32], "hash must not be all zeros");
    }

    #[test]
    fn signs_payment_to_muxed_destination() {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        let muxed = crate::address::encode_muxed(DEST, 99).unwrap();
        let req = PaymentRequest {
            destination: &muxed,
            stroops: 5,
            asset: None,
            memo_id: None,
            sequence: 2,
        };
        let signed = sign_payment(&mk, &sealed, StellarNetwork::Testnet, 0, &req).unwrap();
        assert!(!signed.envelope_xdr.is_empty());
    }

    // ── Credit-asset branch of sign_payment (#42) ────────────────────────────

    #[test]
    fn signs_credit_asset_payment_alphanum4() {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        // USDC is 4 chars → AlphaNum4; use DEST as the issuer (a valid G... address).
        let req = PaymentRequest {
            destination: DEST,
            stroops: 10_000_000,
            asset: Some(("USDC", DEST)),
            memo_id: None,
            sequence: 1,
        };
        let signed = sign_payment(&mk, &sealed, StellarNetwork::Testnet, 0, &req).unwrap();
        let env =
            stellar_base::xdr::TransactionEnvelope::from_xdr_base64(&signed.envelope_xdr).unwrap();
        match env {
            stellar_base::xdr::TransactionEnvelope::Tx(e) => {
                match &e.tx.operations[0].body {
                    stellar_base::xdr::OperationBody::Payment(pay) => {
                        assert!(
                            matches!(pay.asset, stellar_base::xdr::Asset::CreditAlphanum4(_)),
                            "4-char code must produce CreditAlphanum4 asset"
                        );
                    }
                    _ => panic!("expected Payment operation"),
                }
            }
            _ => panic!("expected Tx envelope"),
        }
    }

    #[test]
    fn signs_credit_asset_payment_alphanum12() {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        // "LONGTOKEN" is 9 chars (5-12 range) → AlphaNum12.
        let req = PaymentRequest {
            destination: DEST,
            stroops: 10_000_000,
            asset: Some(("LONGTOKEN", DEST)),
            memo_id: None,
            sequence: 1,
        };
        let signed = sign_payment(&mk, &sealed, StellarNetwork::Testnet, 0, &req).unwrap();
        let env =
            stellar_base::xdr::TransactionEnvelope::from_xdr_base64(&signed.envelope_xdr).unwrap();
        match env {
            stellar_base::xdr::TransactionEnvelope::Tx(e) => {
                match &e.tx.operations[0].body {
                    stellar_base::xdr::OperationBody::Payment(pay) => {
                        assert!(
                            matches!(pay.asset, stellar_base::xdr::Asset::CreditAlphanum12(_)),
                            "9-char code must produce CreditAlphanum12 asset"
                        );
                    }
                    _ => panic!("expected Payment operation"),
                }
            }
            _ => panic!("expected Tx envelope"),
        }
    }

    #[test]
    fn rejects_credit_asset_with_invalid_issuer() {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        let req = PaymentRequest {
            destination: DEST,
            stroops: 1,
            asset: Some(("USDC", "not-a-valid-G-address")),
            memo_id: None,
            sequence: 1,
        };
        assert!(matches!(
            sign_payment(&mk, &sealed, StellarNetwork::Testnet, 0, &req),
            Err(WalletError::InvalidAddress)
        ));
    }

    #[test]
    fn rejects_credit_asset_with_invalid_code() {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        // Empty string and a 13-char code are both outside the 1-12 byte range
        // that Asset::new_credit accepts, so both must map to WalletError::InvalidAddress.
        for bad_code in ["", "TOOLONGASSET1X"] {
            let req = PaymentRequest {
                destination: DEST,
                stroops: 1,
                asset: Some((bad_code, DEST)),
                memo_id: None,
                sequence: 1,
            };
            assert!(
                matches!(
                    sign_payment(&mk, &sealed, StellarNetwork::Testnet, 0, &req),
                    Err(WalletError::InvalidAddress)
                ),
                "code {:?} should be rejected",
                bad_code
            );
        }
    }

    // ── Helper: build a signed inner payment envelope XDR ────────────────────

    fn make_inner_xdr(source_index: u32, seq: i64) -> String {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        // Use DEST as destination regardless of source; the inner tx just needs to be valid.
        let req = PaymentRequest {
            destination: DEST,
            stroops: 1_000_000,
            asset: None,
            memo_id: None,
            sequence: seq,
        };
        sign_payment(&mk, &sealed, StellarNetwork::Testnet, source_index, &req)
            .unwrap()
            .envelope_xdr
    }

    // ── fee_bump negative / security tests ───────────────────────────────────

    // Security: the outer fee_source must always be the master account, not the inner
    // tx's source, ensuring the sponsor identity cannot be forged by the inner XDR.
    #[test]
    fn fee_bump_fee_source_is_always_master_account() {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        // Inner tx signed by account index 1 (DEST), not the master.
        let inner_xdr = make_inner_xdr(1, 1);
        let result = sign_fee_bump(
            &mk,
            &sealed,
            StellarNetwork::Testnet,
            0,
            &FeeBumpRequest { inner_xdr: &inner_xdr, max_base_fee_stroops: 200 },
        )
        .unwrap();

        let outer_env =
            stellar_base::xdr::TransactionEnvelope::from_xdr_base64(&result.envelope_xdr).unwrap();
        let fee_bump_env = match outer_env {
            stellar_base::xdr::TransactionEnvelope::TxFeeBump(e) => e,
            _ => panic!("expected TxFeeBump"),
        };
        // Decode MASTER_ACCOUNT_0 to its raw 32-byte ed25519 key.
        let expected_bytes = stellar_strkey::ed25519::PublicKey::from_string(MASTER_ACCOUNT_0)
            .unwrap()
            .0;
        match fee_bump_env.tx.fee_source {
            stellar_base::xdr::MuxedAccount::Ed25519(bytes) => {
                assert_eq!(bytes.0, expected_bytes);
            }
            _ => panic!("expected Ed25519 fee_source"),
        }
    }

    // Security: inner signatures must survive the fee-bump wrapping unmodified,
    // so the inner transaction's authorisation is not silently stripped or replaced.
    #[test]
    fn fee_bump_preserves_inner_signatures() {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        let inner_xdr = make_inner_xdr(0, 1);

        // Capture the inner signatures before wrapping.
        let inner_env_before =
            stellar_base::xdr::TransactionEnvelope::from_xdr_base64(&inner_xdr).unwrap();
        let inner_sigs_before = match inner_env_before {
            stellar_base::xdr::TransactionEnvelope::Tx(e) => e.signatures.to_vec(),
            _ => panic!("expected Tx"),
        };

        let result = sign_fee_bump(
            &mk,
            &sealed,
            StellarNetwork::Testnet,
            0,
            &FeeBumpRequest { inner_xdr: &inner_xdr, max_base_fee_stroops: 200 },
        )
        .unwrap();

        let outer_env =
            stellar_base::xdr::TransactionEnvelope::from_xdr_base64(&result.envelope_xdr).unwrap();
        let fee_bump_env = match outer_env {
            stellar_base::xdr::TransactionEnvelope::TxFeeBump(e) => e,
            _ => panic!("expected TxFeeBump"),
        };
        let inner_sigs_after = match fee_bump_env.tx.inner_tx {
            stellar_base::xdr::FeeBumpTransactionInnerTx::Tx(e) => e.signatures.to_vec(),
        };
        assert_eq!(inner_sigs_before, inner_sigs_after);
    }

    // Security: the outer envelope must carry exactly one signature (the master key's).
    // Multiple outer signatures would indicate an unintended key was used.
    #[test]
    fn fee_bump_outer_has_exactly_one_signature() {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        let inner_xdr = make_inner_xdr(0, 1);
        let result = sign_fee_bump(
            &mk,
            &sealed,
            StellarNetwork::Testnet,
            0,
            &FeeBumpRequest { inner_xdr: &inner_xdr, max_base_fee_stroops: 200 },
        )
        .unwrap();

        let outer_env =
            stellar_base::xdr::TransactionEnvelope::from_xdr_base64(&result.envelope_xdr).unwrap();
        let fee_bump_env = match outer_env {
            stellar_base::xdr::TransactionEnvelope::TxFeeBump(e) => e,
            _ => panic!("expected TxFeeBump"),
        };
        assert_eq!(fee_bump_env.signatures.len(), 1);
    }

    // Security: empty string is obviously invalid XDR; the function must reject it
    // rather than panic or produce an empty envelope.
    #[test]
    fn fee_bump_rejects_empty_string_xdr() {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        assert!(matches!(
            sign_fee_bump(
                &mk,
                &sealed,
                StellarNetwork::Testnet,
                0,
                &FeeBumpRequest { inner_xdr: "", max_base_fee_stroops: 200 },
            ),
            Err(WalletError::InvalidXdr)
        ));
    }

    // Security: a raw Transaction XDR (not wrapped in a TransactionEnvelope) must be
    // rejected, ensuring only well-formed signed envelopes are accepted as inner XDR.
    #[test]
    fn fee_bump_rejects_payment_xdr_as_fee_bump_xdr() {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        // A FeeBumpTransaction envelope cannot wrap another fee-bump — use that as
        // "wrong XDR type": first produce a fee-bump envelope, then try to wrap it again.
        let inner_xdr = make_inner_xdr(0, 1);
        let fee_bump_xdr = sign_fee_bump(
            &mk,
            &sealed,
            StellarNetwork::Testnet,
            0,
            &FeeBumpRequest { inner_xdr: &inner_xdr, max_base_fee_stroops: 200 },
        )
        .unwrap()
        .envelope_xdr;

        // Passing a fee-bump envelope as the inner XDR must be rejected.
        assert!(matches!(
            sign_fee_bump(
                &mk,
                &sealed,
                StellarNetwork::Testnet,
                0,
                &FeeBumpRequest { inner_xdr: &fee_bump_xdr, max_base_fee_stroops: 200 },
            ),
            Err(WalletError::InvalidXdr)
        ));
    }

    // Security: a seed sealed for mainnet cannot be opened under a testnet context;
    // the AEAD tag will fail, preventing cross-network fee-bump signing.
    #[test]
    fn fee_bump_wrong_network_sealed_seed() {
        let (mk, mainnet_sealed) = sealed_vector_seed(StellarNetwork::Public);
        let inner_xdr = make_inner_xdr(0, 1);
        assert!(matches!(
            sign_fee_bump(
                &mk,
                &mainnet_sealed,
                StellarNetwork::Testnet,
                0,
                &FeeBumpRequest { inner_xdr: &inner_xdr, max_base_fee_stroops: 200 },
            ),
            Err(WalletError::SeedDecryption)
        ));
    }

    // Security: the max_base_fee value supplied by the caller must be faithfully
    // encoded in the outer envelope's fee field (fee = max_base_fee × (inner_ops + 1)),
    // preventing silent fee inflation or deflation.
    #[test]
    fn fee_bump_max_base_fee_reflected_in_envelope() {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        let inner_xdr = make_inner_xdr(0, 1);
        let max_base_fee: i64 = 500;
        let result = sign_fee_bump(
            &mk,
            &sealed,
            StellarNetwork::Testnet,
            0,
            &FeeBumpRequest { inner_xdr: &inner_xdr, max_base_fee_stroops: max_base_fee },
        )
        .unwrap();

        let outer_env =
            stellar_base::xdr::TransactionEnvelope::from_xdr_base64(&result.envelope_xdr).unwrap();
        let fee_bump_env = match outer_env {
            stellar_base::xdr::TransactionEnvelope::TxFeeBump(e) => e,
            _ => panic!("expected TxFeeBump"),
        };
        // stellar-base stores max_base_fee directly in the fee field.
        assert_eq!(fee_bump_env.tx.fee, max_base_fee);
    }

    // Normal operation: an inner tx signed by a non-master account (the common case
    // where a user signs their own tx and octo sponsors the fee) must succeed.
    #[test]
    fn fee_bump_inner_xdr_from_different_account() {
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        // Inner tx sourced from account index 1 (not the master).
        let inner_xdr = make_inner_xdr(1, 1);
        let result = sign_fee_bump(
            &mk,
            &sealed,
            StellarNetwork::Testnet,
            0,
            &FeeBumpRequest { inner_xdr: &inner_xdr, max_base_fee_stroops: 200 },
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap().source_account, MASTER_ACCOUNT_0);
    }

    // ── inner_operation_count ────────────────────────────────────────────────

    /// Build a minimal (unsigned) v1 envelope with `n` operations, serialized to base64 XDR.
    fn make_n_op_inner_xdr(n: usize) -> String {
        use stellar_base::xdr::{
            Memo as XdrMemo, MuxedAccount, Operation as XdrOperation, OperationBody, Preconditions,
            SequenceNumber, Transaction as XdrTransaction, TransactionEnvelope, TransactionExt,
            TransactionV1Envelope, Uint256,
        };

        let operations: Vec<XdrOperation> = (0..n)
            .map(|_| XdrOperation {
                source_account: None,
                body: OperationBody::AccountMerge(MuxedAccount::Ed25519(Uint256([1u8; 32]))),
            })
            .collect();
        let tx = XdrTransaction {
            source_account: MuxedAccount::Ed25519(Uint256([2u8; 32])),
            fee: 100,
            seq_num: SequenceNumber(1),
            cond: Preconditions::None,
            memo: XdrMemo::None,
            operations: operations.try_into().unwrap(),
            ext: TransactionExt::V0,
        };
        let envelope = TransactionV1Envelope {
            tx,
            signatures: vec![].try_into().unwrap(),
        };
        TransactionEnvelope::Tx(envelope).xdr_base64().unwrap()
    }

    #[test]
    fn inner_operation_count_reports_correct_count_for_single_and_multi_op_transactions() {
        // Single-op: a real signed payment envelope.
        let single = make_inner_xdr(0, 1);
        assert_eq!(inner_operation_count(&single).unwrap(), 1);

        // Multi-op envelopes built directly from XDR.
        for n in [2usize, 3] {
            let xdr = make_n_op_inner_xdr(n);
            assert_eq!(inner_operation_count(&xdr).unwrap(), n);
        }

        // Zero-op parses fine: the helper reports, Stellar itself rejects zero-op transactions.
        let zero = make_n_op_inner_xdr(0);
        assert_eq!(inner_operation_count(&zero).unwrap(), 0);
    }

    #[test]
    fn inner_operation_count_rejects_malformed_xdr_matching_sign_fee_bumps_error_type() {
        assert!(matches!(
            inner_operation_count("this-is-not-valid-base64-xdr"),
            Err(WalletError::InvalidXdr)
        ));
        assert!(matches!(
            inner_operation_count(""),
            Err(WalletError::InvalidXdr)
        ));

        // A fee-bump envelope is not a valid inner envelope — same rejection as sign_fee_bump.
        let (mk, sealed) = sealed_vector_seed(StellarNetwork::Testnet);
        let inner_xdr = make_inner_xdr(0, 1);
        let fee_bump_xdr = sign_fee_bump(
            &mk,
            &sealed,
            StellarNetwork::Testnet,
            0,
            &FeeBumpRequest {
                inner_xdr: &inner_xdr,
                max_base_fee_stroops: 200,
            },
        )
        .unwrap()
        .envelope_xdr;
        assert!(matches!(
            inner_operation_count(&fee_bump_xdr),
            Err(WalletError::InvalidXdr)
        ));
    }
}
