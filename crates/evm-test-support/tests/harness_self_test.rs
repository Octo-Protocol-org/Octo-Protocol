//! Required self-tests for the Anvil harness itself (issue #219 / doc "Issue #7", Anvil-based EVM
//! integration test harness). If `snapshot_and_revert_undoes_a_mined_transfer` does not pass,
//! #222 (reorg handling) cannot be verified — `snapshot`/`revert_to` is the reorg primitive it
//! depends on.
//!
//! Every test below calls `require_anvil!()` first and returns (not panics/fails) when Anvil
//! isn't available, so `just test` (no `OCTO_EVM_TESTS`, no Foundry) stays green.

use octo_evm_test_support::{gate, AnvilInstance, MockErc20};

macro_rules! require_anvil {
    () => {
        if let Some(reason) = gate() {
            eprintln!("{reason}");
            return;
        }
    };
}

#[tokio::test]
async fn anvil_boots_and_mining_advances_the_chain() {
    require_anvil!();

    let anvil = AnvilInstance::spawn().await.expect("anvil should spawn");
    let before = anvil.block_number().await.expect("block number");

    anvil.mine(3).await.expect("mine 3 blocks");

    let after = anvil.block_number().await.expect("block number");
    assert_eq!(
        after,
        before + 3,
        "eth_blockNumber should advance by exactly 3"
    );
}

#[tokio::test]
async fn snapshot_and_revert_undoes_a_mined_transfer() {
    require_anvil!();

    let anvil = AnvilInstance::spawn().await.expect("anvil should spawn");
    let accounts = anvil.accounts().await.expect("accounts");
    let (alice, bob) = (accounts[0], accounts[1]);

    let token = MockErc20::deploy(
        &anvil,
        alice,
        "Dai Stablecoin",
        "DAI",
        18,
        1_000_000_000_000_000_000_000,
    )
    .await
    .expect("deploy MockERC20");

    let snapshot_id = anvil.snapshot().await.expect("snapshot");

    let transfer_tx = token
        .transfer(alice, bob, 5_000_000_000_000_000_000)
        .await
        .expect("transfer");

    assert!(
        anvil
            .transaction_receipt(&transfer_tx)
            .await
            .expect("receipt lookup")
            .is_some(),
        "transfer receipt should exist before the revert"
    );

    anvil.mine(2).await.expect("mine past the transfer");

    let reverted = anvil.revert_to(&snapshot_id).await.expect("revert");
    assert!(reverted, "anvil_revert should report success");

    // The block that mined the transfer no longer exists post-revert — this is the reorg
    // primitive #222 depends on: it proves a reorg can be induced on demand at all, which is
    // impossible against a public testnet.
    assert!(
        anvil
            .transaction_receipt(&transfer_tx)
            .await
            .expect("receipt lookup")
            .is_none(),
        "transfer receipt should be gone after reverting past it"
    );
}

/// The env-var half of the skip-cleanly requirement (the PATH-probe half is unit-tested
/// deterministically in `src/lib.rs`, since mutating `PATH` here would race other tests running
/// in parallel in the same process). This asserts `gate()` — the actual function every test in
/// this file calls — returns a reason rather than panicking when `OCTO_EVM_TESTS` isn't set,
/// which is exactly the code path a contributor without Foundry hits on a plain `cargo test`.
#[test]
fn suite_skips_cleanly_when_the_env_var_is_unset() {
    if std::env::var("OCTO_EVM_TESTS").as_deref() != Ok("1") {
        assert!(gate().is_some());
    }
}

#[tokio::test]
async fn mock_erc20_supports_usdc_dai_and_zero_decimal_configs() {
    require_anvil!();

    let anvil = AnvilInstance::spawn().await.expect("anvil should spawn");
    let accounts = anvil.accounts().await.expect("accounts");
    let (deployer, recipient) = (accounts[0], accounts[1]);

    // 6 (USDC), 18 (DAI), and 0 decimals — the configurations that break decimal-handling code.
    let configs: [(&str, u8, u128, u128); 3] = [
        ("USDC-style", 6, 1_000_000_000, 250_000_000),
        (
            "DAI-style",
            18,
            1_000_000_000_000_000_000_000,
            1_000_000_000_000_000_000,
        ),
        ("zero-decimal", 0, 1_000, 42),
    ];

    for (label, decimals, initial_supply, transfer_amount) in configs {
        let token = MockErc20::deploy(&anvil, deployer, label, "TOK", decimals, initial_supply)
            .await
            .unwrap_or_else(|e| panic!("deploy {label} (decimals={decimals}): {e}"));
        assert_eq!(token.decimals(), decimals);

        token
            .transfer(deployer, recipient, transfer_amount)
            .await
            .unwrap_or_else(|e| panic!("transfer for {label}: {e}"));

        let balance = token
            .balance_of(recipient)
            .await
            .unwrap_or_else(|e| panic!("balance_of for {label}: {e}"));
        assert_eq!(balance, transfer_amount, "{label} balance after transfer");
    }
}

#[cfg(unix)]
#[tokio::test]
async fn drop_kills_the_anvil_process_even_when_the_test_panics() {
    require_anvil!();

    let anvil = AnvilInstance::spawn().await.expect("anvil should spawn");
    let pid = anvil.pid();

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _anvil = anvil; // moved in; Drop runs here while unwinding past this closure.
        panic!("simulated test failure after acquiring an AnvilInstance");
    }));
    assert!(result.is_err(), "the inner closure should have panicked");

    // Give the OS a brief moment to reap the killed process before checking.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let status = std::process::Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .status()
        .expect("`kill -0` should run");
    assert!(
        !status.success(),
        "anvil process {pid} should be dead after Drop ran during unwind"
    );
}
