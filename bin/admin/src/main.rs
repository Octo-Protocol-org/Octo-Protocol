#![forbid(unsafe_code)]

use anyhow::{bail, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::{Parser, Subcommand};
use octo_store::{AuditChainKey, AuditChainStatus, Store, AUDIT_CHAIN_KEY_LEN};
use octo_webhooks::{allow_local_webhooks, status, WebhookSender, PING_EVENT};
use serde_json::json;
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Read Octo operational state or perform explicitly authorized writes",
    after_help = "Set DATABASE_URL for all commands and AUDIT_CHAIN_KEY (base64, 32 bytes) for verification and writes. Change commands require --apply and an existing --actor user ID."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// List wallet IDs, public accounts, networks and ingest status.
    ListWallets,
    /// Pause ingest for one wallet without moving its cursor.
    PauseIngest {
        /// Wallet UUID.
        wallet_id: Uuid,
        /// Existing Octo user UUID to attribute the audit entry to.
        #[arg(long, requires = "apply")]
        actor: Uuid,
        /// Apply the mutation.
        #[arg(long)]
        apply: bool,
    },
    /// Verify the audit chain and exit unsuccessfully if any link is broken.
    VerifyAuditChain {
        /// Restrict verification to this user UUID. Defaults to all users.
        #[arg(long)]
        user: Option<Uuid>,
    },
    /// Retry one dead webhook delivery immediately using the configured retry policy.
    RequeueDeliveries {
        /// Endpoint UUID.
        endpoint_id: Uuid,
        /// Dead delivery UUID belonging to this endpoint.
        delivery_id: Uuid,
        /// Existing Octo user UUID to attribute the audit entry to.
        #[arg(long, requires = "apply")]
        actor: Uuid,
        /// Apply the mutation.
        #[arg(long)]
        apply: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let database_url = Zeroizing::new(std::env::var("DATABASE_URL").context("set DATABASE_URL")?);
    let store = Store::connect(&database_url)
        .await
        .context("connect to Octo database")?;
    match cli.command {
        Command::ListWallets => {
            for wallet in store.list_wallets().await? {
                println!(
                    "{}",
                    json!({
                        "id": wallet.id,
                        "network": wallet.network,
                        "account": wallet.stellar_account_g,
                        "ingest_paused": wallet.ingest_paused,
                        "archived": wallet.archived_at.is_some(),
                    })
                );
            }
        }
        Command::PauseIngest {
            wallet_id,
            actor,
            apply,
        } => {
            ensure!(apply, "pause-ingest requires --apply");
            store
                .admin_pause_ingest(&audit_key()?, actor, wallet_id)
                .await?;
            println!("Paused ingest for {wallet_id}");
        }
        Command::VerifyAuditChain { user } => verify(&store, &audit_key()?, user).await?,
        Command::RequeueDeliveries {
            endpoint_id,
            delivery_id,
            actor,
            apply,
        } => {
            ensure!(apply, "requeue-deliveries requires --apply");
            requeue(store, &audit_key()?, actor, endpoint_id, delivery_id).await?;
        }
    }
    Ok(())
}

fn audit_key() -> Result<AuditChainKey> {
    let encoded = Zeroizing::new(std::env::var("AUDIT_CHAIN_KEY").context("set AUDIT_CHAIN_KEY")?);
    let mut bytes = Zeroizing::new([0u8; 48]);
    let len = STANDARD
        .decode_slice(encoded.trim(), &mut bytes[..])
        .context("invalid AUDIT_CHAIN_KEY encoding")?;
    ensure!(
        len == AUDIT_CHAIN_KEY_LEN,
        "AUDIT_CHAIN_KEY must encode 32 bytes"
    );
    let mut key = Zeroizing::new([0; AUDIT_CHAIN_KEY_LEN]);
    key.copy_from_slice(&bytes[..len]);
    Ok(AuditChainKey::new(key))
}

async fn verify(store: &Store, key: &AuditChainKey, user: Option<Uuid>) -> Result<()> {
    let reports = match user {
        Some(user) => vec![store.verify_audit_chain(key, user).await?],
        None => store.verify_all_audit_chains(key).await?,
    };
    let mut broken = 0;
    for report in reports {
        println!(
            "{}: {:?}; verified={}, legacy={}",
            report.user_id, report.status, report.rows_verified, report.unchained_rows
        );
        if matches!(report.status, AuditChainStatus::Broken { .. }) {
            broken += 1;
        }
    }
    ensure!(broken == 0, "{broken} audit chains failed verification");
    Ok(())
}

async fn requeue(
    store: Store,
    key: &AuditChainKey,
    actor: Uuid,
    endpoint_id: Uuid,
    delivery_id: Uuid,
) -> Result<()> {
    ensure!(
        !allow_local_webhooks(),
        "disable the local webhook override before retrying a delivery"
    );
    let endpoint = store.get_webhook_endpoint(endpoint_id).await?;
    ensure!(
        endpoint.active && endpoint.deleted_at.is_none(),
        "webhook endpoint is inactive"
    );
    ensure!(
        !store.get_wallet(endpoint.wallet_id).await?.is_archived(),
        "webhook endpoint belongs to an archived wallet"
    );
    let delivery = store.get_webhook_delivery(endpoint_id, delivery_id).await?;
    ensure!(
        delivery.status == status::DEAD && delivery.event_type != PING_EVENT,
        "only dead event deliveries can be retried"
    );
    // Persist the intent before the sender can contact the receiver.
    store
        .record_audit(
            key,
            actor,
            "requested webhook redelivery",
            "webhook",
            Some(&delivery_id.to_string()),
            None,
        )
        .await?;
    let result = WebhookSender::new(store)
        .redeliver(&endpoint, &delivery)
        .await;
    println!(
        "Retry of {delivery_id}: {} ({} attempts; new delivery {:?})",
        result.status, result.attempts, result.delivery_id
    );
    if !result.is_delivered() {
        bail!("receiver did not accept the delivery");
    }
    ensure!(
        result.delivery_id.is_some(),
        "receiver accepted the delivery but its outcome could not be recorded"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_require_flag_and_actor() {
        let id = "00000000-0000-0000-0000-000000000001";
        for mut args in [
            vec!["octo-admin", "pause-ingest", id],
            vec!["octo-admin", "requeue-deliveries", id, id],
        ] {
            let mut without_actor = args.clone();
            without_actor.push("--apply");
            assert!(Cli::try_parse_from(without_actor).is_err());
            args.extend(["--actor", id]);
            assert!(Cli::try_parse_from(&args).is_err());
            args.push("--apply");
            assert!(Cli::try_parse_from(args).is_ok());
        }
    }

    #[test]
    fn reads_require_no_mutation_flag() {
        for command in ["list-wallets", "verify-audit-chain"] {
            assert!(Cli::try_parse_from(["octo-admin", command]).is_ok());
        }
    }
}
