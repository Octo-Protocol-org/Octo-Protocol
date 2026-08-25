//! `AnvilInstance`: spawns a per-test, isolated `anvil` process on a random free port and tears
//! it down in `Drop` (including on panic, since `Drop::drop` runs during unwinding) — the local
//! EVM devnet story `StellarNetwork::Standalone` already gives Stellar work
//! (`crates/wallet-core/src/signer.rs`).

use crate::abi::Address;
use crate::rpc::{hex_to_u64, u64_to_hex, RpcClient, RpcError};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AnvilError {
    #[error("failed to spawn `anvil` (is Foundry installed and on PATH?): {0}")]
    Spawn(#[source] std::io::Error),
    #[error("anvil did not print a `Listening on` line within {0:?}")]
    NoListenLine(Duration),
    #[error("anvil did not respond to eth_chainId within {0:?}: {1}")]
    NotReady(Duration, RpcError),
    #[error(transparent)]
    Rpc(#[from] RpcError),
}

const LISTEN_WAIT: Duration = Duration::from_secs(10);
const READY_WAIT: Duration = Duration::from_secs(10);

/// A single isolated local Anvil chain. Each instance gets its own OS process and port, so tests
/// can run in parallel (`cargo test` runs test binaries' `#[test]` functions concurrently by
/// default) without sharing chain state.
pub struct AnvilInstance {
    child: Child,
    port: u16,
    rpc_url: String,
    rpc: RpcClient,
    chain_id: u64,
}

impl AnvilInstance {
    /// Spawns `anvil --port 0` (letting the OS assign a free port), parses the port back out of
    /// its startup banner (`Listening on 127.0.0.1:<port>`), then confirms readiness with a
    /// polling `eth_chainId` call before returning.
    pub async fn spawn() -> Result<Self, AnvilError> {
        let mut child = Command::new("anvil")
            .arg("--port")
            .arg("0")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(AnvilError::Spawn)?;

        let stdout = child.stdout.take().expect("stdout was piped");
        let stderr = child.stderr.take().expect("stderr was piped");

        // Drain stderr unconditionally in the background so anvil never blocks on a full pipe.
        thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines() {
                if line.is_err() {
                    break;
                }
            }
        });

        let (port_tx, port_rx) = mpsc::channel();
        thread::spawn(move || {
            let reader = BufReader::new(stdout);
            let mut reported = false;
            for line in reader.lines() {
                let Ok(line) = line else { break };
                if !reported {
                    if let Some(port) = parse_listening_port(&line) {
                        reported = true;
                        let _ = port_tx.send(port);
                    }
                }
                // Keep draining after the match: anvil keeps writing to stdout for its lifetime,
                // and an unread pipe would eventually block the child process.
            }
        });

        let port = match port_rx.recv_timeout(LISTEN_WAIT) {
            Ok(port) => port,
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(AnvilError::NoListenLine(LISTEN_WAIT));
            }
        };

        let rpc_url = format!("http://127.0.0.1:{port}");
        let rpc = RpcClient::new(rpc_url.clone());

        let chain_id = match wait_until_ready(&rpc, READY_WAIT).await {
            Ok(chain_id) => chain_id,
            Err(source) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(AnvilError::NotReady(READY_WAIT, source));
            }
        };

        Ok(Self {
            child,
            port,
            rpc_url,
            rpc,
            chain_id,
        })
    }

    pub fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Unix PID of the anvil process — exposed only for tests that need to assert liveness
    /// externally (e.g. `kill -0`); not meaningful once the instance has been dropped.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    pub(crate) fn rpc(&self) -> &RpcClient {
        &self.rpc
    }

    /// The deterministic, pre-funded, pre-unlocked accounts Anvil derives from its default
    /// mnemonic (`test test test ... junk`) — no `--mnemonic` flag needed since that's already
    /// Anvil's default when none is given.
    pub async fn accounts(&self) -> Result<Vec<Address>, AnvilError> {
        let value = self.rpc.call("eth_accounts", json!([])).await?;
        let addresses = value
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|v| v.as_str().and_then(Address::from_hex))
            .collect();
        Ok(addresses)
    }

    pub async fn block_number(&self) -> Result<u64, AnvilError> {
        let value = self.rpc.call("eth_blockNumber", json!([])).await?;
        Ok(hex_to_u64(value.as_str().unwrap_or("0x0")))
    }

    /// Fetches a transaction receipt if one exists, or `None` if the transaction hasn't been
    /// mined yet — or, after a [`Self::revert_to`] past the block that mined it, no longer
    /// exists. This is the observable that proves `snapshot`/`revert_to` actually reorg the
    /// chain rather than merely resetting some in-memory counter.
    pub async fn transaction_receipt(&self, tx_hash: &str) -> Result<Option<Value>, AnvilError> {
        let value = self
            .rpc
            .call("eth_getTransactionReceipt", json!([tx_hash]))
            .await?;
        Ok(if value.is_null() { None } else { Some(value) })
    }

    /// Takes an EVM state snapshot, returning an opaque id to pass to [`Self::revert_to`].
    pub async fn snapshot(&self) -> Result<String, AnvilError> {
        let value = self.rpc.call("anvil_snapshot", json!([])).await?;
        Ok(value.as_str().unwrap_or_default().to_string())
    }

    /// Reverts chain state (balances, code, and mined blocks) back to a prior [`Self::snapshot`].
    /// This is the reorg primitive #222 depends on: it removes blocks that were already mined,
    /// which is exactly what a real chain reorg does and what cannot be induced on-demand against
    /// a public testnet.
    pub async fn revert_to(&self, snapshot_id: &str) -> Result<bool, AnvilError> {
        let value = self.rpc.call("anvil_revert", json!([snapshot_id])).await?;
        Ok(value.as_bool().unwrap_or(false))
    }

    /// Mines `n` new blocks, one `evm_mine` call at a time.
    pub async fn mine(&self, n: u32) -> Result<(), AnvilError> {
        for _ in 0..n {
            self.rpc.call("evm_mine", json!([])).await?;
        }
        Ok(())
    }

    /// Sets the base fee that will apply to the *next* mined block.
    pub async fn set_base_fee(&self, wei: u64) -> Result<(), AnvilError> {
        self.rpc
            .call("anvil_setNextBlockBaseFeePerGas", json!([u64_to_hex(wei)]))
            .await?;
        Ok(())
    }
}

impl Drop for AnvilInstance {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn parse_listening_port(line: &str) -> Option<u16> {
    let rest = line.strip_prefix("Listening on ")?;
    let (_, port) = rest.rsplit_once(':')?;
    port.trim().parse().ok()
}

async fn wait_until_ready(rpc: &RpcClient, timeout: Duration) -> Result<u64, RpcError> {
    let deadline = Instant::now() + timeout;
    let mut last_err = None;
    while Instant::now() < deadline {
        match rpc.call("eth_chainId", json!([])).await {
            Ok(value) => return Ok(hex_to_u64(value.as_str().unwrap_or("0x0"))),
            Err(e) => last_err = Some(e),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(last_err.unwrap_or_else(|| RpcError::Malformed("eth_chainId never responded".into())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_real_anvil_startup_line() {
        assert_eq!(
            parse_listening_port("Listening on 127.0.0.1:44061"),
            Some(44061)
        );
        assert_eq!(parse_listening_port("Available Accounts"), None);
    }
}
