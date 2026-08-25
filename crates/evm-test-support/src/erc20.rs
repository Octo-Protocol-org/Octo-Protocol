//! Deploys and drives a minimal ERC-20 (`contracts/MockERC20.sol`) against an [`AnvilInstance`],
//! with `decimals` fixed at construction time so tests can exercise 6 (USDC-style), 18
//! (DAI-style), and 0 decimal configurations against a real deployed contract and real `Transfer`
//! logs — this is where decimal-handling bugs in the ingest/amount code actually show up.
//!
//! Transactions go through plain `eth_sendTransaction` against Anvil's default accounts, which
//! are pre-unlocked (Anvil holds and signs with the private keys derived from its own default
//! mnemonic) — no client-side signing needed here, that's the production signer's job, not this
//! harness's.

use crate::abi::{self, Address};
use crate::anvil::{AnvilError, AnvilInstance};
use crate::rpc::RpcError;
use serde_json::{json, Value};
use std::time::{Duration, Instant};

/// Precompiled creation bytecode for `contracts/MockERC20.sol` (solc 0.8.24, optimizer on, 200
/// runs — see the header comment in that file for how to regenerate it). Cargo never invokes
/// solc: only `anvil` needs to be on PATH to run these tests.
const MOCK_ERC20_BYTECODE: &str = include_str!("../contracts/MockERC20.bin");

const RECEIPT_WAIT: Duration = Duration::from_secs(10);

pub struct MockErc20<'a> {
    anvil: &'a AnvilInstance,
    address: Address,
    deployer: Address,
    decimals: u8,
}

impl<'a> MockErc20<'a> {
    pub async fn deploy(
        anvil: &'a AnvilInstance,
        deployer: Address,
        name: &str,
        symbol: &str,
        decimals: u8,
        initial_supply: u128,
    ) -> Result<MockErc20<'a>, AnvilError> {
        let ctor_args = abi::encode_constructor_args(name, symbol, decimals, initial_supply);
        let data = format!("{}{}", MOCK_ERC20_BYTECODE.trim(), hex::encode(ctor_args));

        let tx_hash = send_transaction(anvil, deployer, None, &data).await?;
        let receipt = wait_for_receipt(anvil, &tx_hash).await?;
        let address = receipt
            .get("contractAddress")
            .and_then(Value::as_str)
            .and_then(Address::from_hex)
            .ok_or_else(|| RpcError::Malformed("deploy receipt had no contractAddress".into()))?;

        Ok(MockErc20 {
            anvil,
            address,
            deployer,
            decimals,
        })
    }

    pub fn address(&self) -> Address {
        self.address
    }

    pub fn decimals(&self) -> u8 {
        self.decimals
    }

    /// Mints `amount` to `to`. Reverts on-chain (surfaced as an `AnvilError`) unless called by
    /// the deploying account, matching the contract's owner-only `mint`.
    pub async fn mint(&self, to: Address, amount: u128) -> Result<String, AnvilError> {
        let data = abi::encode_address_uint256_call("mint(address,uint256)", to, amount);
        let tx_hash = send_transaction(
            self.anvil,
            self.deployer,
            Some(self.address),
            &format!("0x{}", hex::encode(data)),
        )
        .await?;
        wait_for_receipt(self.anvil, &tx_hash).await?;
        Ok(tx_hash)
    }

    /// Transfers `amount` from `from` to `to`, producing a real `Transfer` log — this is the
    /// event downstream ingest/reorg tests scan for.
    pub async fn transfer(
        &self,
        from: Address,
        to: Address,
        amount: u128,
    ) -> Result<String, AnvilError> {
        let data = abi::encode_address_uint256_call("transfer(address,uint256)", to, amount);
        let tx_hash = send_transaction(
            self.anvil,
            from,
            Some(self.address),
            &format!("0x{}", hex::encode(data)),
        )
        .await?;
        wait_for_receipt(self.anvil, &tx_hash).await?;
        Ok(tx_hash)
    }

    pub async fn balance_of(&self, who: Address) -> Result<u128, AnvilError> {
        let data = abi::encode_address_call("balanceOf(address)", who);
        let value = self
            .anvil
            .rpc()
            .call(
                "eth_call",
                json!([
                    { "to": self.address.to_hex(), "data": format!("0x{}", hex::encode(data)) },
                    "latest",
                ]),
            )
            .await?;
        let bytes = hex::decode(value.as_str().unwrap_or("0x").trim_start_matches("0x"))
            .unwrap_or_default();
        Ok(abi::decode_uint256(&bytes))
    }
}

async fn send_transaction(
    anvil: &AnvilInstance,
    from: Address,
    to: Option<Address>,
    data: &str,
) -> Result<String, AnvilError> {
    let mut params = serde_json::Map::new();
    params.insert("from".to_string(), json!(from.to_hex()));
    if let Some(to) = to {
        params.insert("to".to_string(), json!(to.to_hex()));
    }
    params.insert("data".to_string(), json!(data));

    let value = anvil
        .rpc()
        .call("eth_sendTransaction", json!([Value::Object(params)]))
        .await?;
    Ok(value.as_str().unwrap_or_default().to_string())
}

/// Polls for a transaction receipt until one appears (Anvil auto-mines, so this resolves in
/// practice within one or two polls), then errors out if the transaction reverted.
async fn wait_for_receipt(anvil: &AnvilInstance, tx_hash: &str) -> Result<Value, AnvilError> {
    let deadline = Instant::now() + RECEIPT_WAIT;
    loop {
        if let Some(receipt) = anvil.transaction_receipt(tx_hash).await? {
            let status = receipt
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("0x0");
            if status != "0x1" {
                return Err(RpcError::Malformed(format!(
                    "transaction {tx_hash} reverted (status {status})"
                ))
                .into());
            }
            return Ok(receipt);
        }
        if Instant::now() >= deadline {
            return Err(
                RpcError::Malformed(format!("timed out waiting for receipt of {tx_hash}")).into(),
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
