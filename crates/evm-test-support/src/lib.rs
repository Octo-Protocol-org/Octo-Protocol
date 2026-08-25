//! Anvil-based local EVM devnet harness for integration tests.
//!
//! Gives EVM work the same local-devnet story Stellar already has via
//! `StellarNetwork::Standalone` (`crates/wallet-core/src/signer.rs`): per-test isolated chain
//! instances on random free ports, deterministic funded accounts, a mock ERC-20 with
//! configurable `decimals`, and reorg controls (`snapshot`/`revert_to`) — the one thing a public
//! testnet cannot give you on demand.
//!
//! Call [`gate`] at the top of every test that needs a live Anvil and return early when it
//! returns `Some(reason)`, mirroring the `OCTO_LIVE_TESTS` pattern in
//! `crates/api/tests/horizon_live_tests.rs`. A contributor without Foundry installed still gets a
//! green `just test`; `just test-evm` sets `OCTO_EVM_TESTS=1` to opt in.

pub mod abi;
pub mod anvil;
pub mod erc20;
pub mod rpc;

pub use abi::Address;
pub use anvil::{AnvilError, AnvilInstance};
pub use erc20::MockErc20;

/// `None` if EVM integration tests should run; `Some(reason)` if they should skip cleanly.
pub fn gate() -> Option<&'static str> {
    let evm_tests_enabled = std::env::var("OCTO_EVM_TESTS").as_deref() == Ok("1");
    gate_impl(evm_tests_enabled, anvil_on_path())
}

fn gate_impl(evm_tests_enabled: bool, anvil_present: bool) -> Option<&'static str> {
    if !evm_tests_enabled {
        return Some(
            "SKIPPED: set OCTO_EVM_TESTS=1 to run EVM integration tests (requires Foundry's \
             `anvil` on PATH) — see `just test-evm`",
        );
    }
    if !anvil_present {
        return Some(
            "SKIPPED: OCTO_EVM_TESTS=1 but `anvil` was not found on PATH — install Foundry: \
             https://getfoundry.sh",
        );
    }
    None
}

fn anvil_on_path() -> bool {
    anvil_present_in(std::env::var_os("PATH").as_deref())
}

fn anvil_present_in(path_var: Option<&std::ffi::OsStr>) -> bool {
    let Some(path) = path_var else {
        return false;
    };
    std::env::split_paths(path).any(|dir| dir.join("anvil").is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_skips_when_env_var_unset() {
        assert!(gate_impl(false, true).is_some());
    }

    #[test]
    fn gate_skips_when_anvil_missing_even_with_env_var_set() {
        assert!(gate_impl(true, false).is_some());
    }

    #[test]
    fn gate_runs_when_both_conditions_are_met() {
        assert!(gate_impl(true, true).is_none());
    }

    #[test]
    fn anvil_present_in_returns_false_for_a_directory_without_anvil() {
        assert!(!anvil_present_in(Some(std::ffi::OsStr::new(
            "/nonexistent-dir-xyz-octo-test"
        ))));
    }
}
