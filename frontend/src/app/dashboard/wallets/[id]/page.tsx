"use client";

import { use, useEffect, useState } from "react";
import Link from "next/link";
import { useAuth } from "@/lib/useAuth";
import {
  getWallet,
  getBalances,
  listAddresses,
  listTransactions,
  createAddress,
  withdraw,
  amountToStroops,
  stroopsToAmount,
  listWebhooks,
  listWebhookDeliveries,
  type WalletView,
  type Balance,
  type Address,
  type Transaction,
  type WebhookEndpoint,
  type WebhookDelivery,
} from "@/lib/wallets";
import { WalletSidebar } from "@/components/dashboard/WalletSidebar";
import { Modal, CopyField } from "@/components/dashboard/Modal";
import { ApiError } from "@/lib/api";

export default function WalletOverview({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = use(params);
  const { user, token, loading, logout } = useAuth();

  const [wallet, setWallet] = useState<WalletView | null>(null);
  const [balances, setBalances] = useState<Balance[]>([]);
  const [addresses, setAddresses] = useState<Address[]>([]);
  const [txns, setTxns] = useState<Transaction[]>([]);
  const [creating, setCreating] = useState(false);
  const [showDeposit, setShowDeposit] = useState(false);
  const [showWithdraw, setShowWithdraw] = useState(false);
  const [endpoints, setEndpoints] = useState<WebhookEndpoint[]>([]);
  const [deliveries, setDeliveries] = useState<WebhookDelivery[]>([]);
  const [loadingDeliveries, setLoadingDeliveries] = useState(false);

  const loadWebhooksAndDeliveries = (authToken: string) => {
    listWebhooks(authToken, id)
      .then((eps) => {
        setEndpoints(eps);
        const active = eps.find((ep) => ep.active);
        if (active) {
          setLoadingDeliveries(true);
          listWebhookDeliveries(authToken, id, active.id)
            .then(setDeliveries)
            .catch(() => setDeliveries([]))
            .finally(() => setLoadingDeliveries(false));
        } else {
          setDeliveries([]);
        }
      })
      .catch(() => {
        setEndpoints([]);
        setDeliveries([]);
      });
  };

  function refresh() {
    if (!token) return;
    getBalances(token, id).then(setBalances).catch(() => {});
    listTransactions(token, id).then(setTxns).catch(() => {});
    loadWebhooksAndDeliveries(token);
  }

  useEffect(() => {
    if (!token) return;
    getWallet(token, id).then(setWallet).catch(() => setWallet(null));
    getBalances(token, id).then(setBalances).catch(() => setBalances([]));
    listAddresses(token, id).then(setAddresses).catch(() => setAddresses([]));
    listTransactions(token, id).then(setTxns).catch(() => setTxns([]));
    loadWebhooksAndDeliveries(token);
  }, [token, id]);

  async function onNewAddress() {
    if (!token) return;
    setCreating(true);
    try {
      const addr = await createAddress(token, id);
      setAddresses((a) => [addr, ...a]);
    } finally {
      setCreating(false);
    }
  }

  if (loading || !user) {
    return (
      <div className="flex min-h-screen items-center justify-center text-muted">
        Loading…
      </div>
    );
  }

  const xlm = balances.find((b) => b.asset_type === "native");
  const xlmAmount = xlm ? xlm.balance : "0";

  return (
    <div className="flex min-h-screen flex-col bg-background">
      <div className="bg-burgundy/20 py-2 text-center text-xs text-burgundy-bright">
        You are currently on <strong>test mode</strong> (Stellar testnet).
      </div>
      <div className="flex flex-1">
        <WalletSidebar
          walletId={id}
          walletName={wallet?.label ?? "Master wallet"}
        />

        <div className="flex flex-1 flex-col">
          {/* topbar */}
          <header className="flex items-center justify-between border-b border-white/10 px-8 py-4">
            <div className="flex items-center gap-2 text-sm text-muted">
              <Link href="/dashboard" className="hover:text-foreground">
                My Wallets
              </Link>
              <span>›</span>
              <span className="text-foreground">Overview</span>
            </div>
            <button
              onClick={logout}
              className="text-sm text-muted hover:text-foreground"
            >
              ⏻
            </button>
          </header>

          <main className="flex-1 space-y-6 px-8 py-8">
            {/* header */}
            <div>
              <h1 className="text-2xl font-semibold text-foreground">
                {wallet?.label ?? "Master wallet"}
              </h1>
              <p className="mt-1 text-sm text-muted">
                {wallet?.description ?? "Stellar master wallet"}
              </p>
              <div className="mt-3 flex flex-wrap gap-x-6 gap-y-1 text-xs">
                <span className="text-muted">
                  Address:{" "}
                  <span className="font-mono text-foreground">
                    {wallet
                      ? `${wallet.address.slice(0, 10)}…${wallet.address.slice(-8)}`
                      : "—"}
                  </span>
                </span>
                <span className="text-muted">
                  ID: <span className="font-mono text-foreground">{id.slice(0, 8)}…</span>
                </span>
              </div>
            </div>

            {/* stat cards */}
            <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
              <Stat label="Total Balance" value={`${xlmAmount} XLM`} />
              <Stat label="Current Balance" value={`${xlmAmount} XLM`} />
              <Stat label="Unswept Balance" value="0 XLM" sub="No sweep needed (muxed)" />
              <Stat label="No. of Assets" value={String(balances.length || 1)} />
            </div>

            {/* action row */}
            <div className="flex flex-wrap gap-3">
              <ActionButton label="New address" onClick={onNewAddress} loading={creating} />
              <ActionButton label="Deposit" onClick={() => setShowDeposit(true)} />
              <ActionButton label="Withdraw" onClick={() => setShowWithdraw(true)} />
              <ActionButton
                label="Refresh balances"
                onClick={() => token && getBalances(token, id).then(setBalances)}
              />
            </div>

            <div className="grid gap-6 lg:grid-cols-[1.6fr_1fr]">
              {/* assets */}
              <Panel title="Assets">
                {balances.length === 0 ? (
                  <Empty>No assets yet.</Empty>
                ) : (
                  <ul className="divide-y divide-white/5">
                    {balances.map((b, i) => (
                      <li
                        key={i}
                        className="flex items-center justify-between py-3"
                      >
                        <span className="flex items-center gap-3">
                          <span className="flex h-8 w-8 items-center justify-center rounded-full bg-burgundy/30 text-xs text-burgundy-bright">
                            {b.asset_type === "native" ? "XLM" : b.asset_code ?? "?"}
                          </span>
                          <span className="text-sm text-foreground">
                            {b.asset_type === "native" ? "Stellar Lumens" : b.asset_code}
                          </span>
                        </span>
                        <span className="text-sm font-medium text-foreground">
                          {b.balance}{" "}
                          {b.asset_type === "native" ? "XLM" : b.asset_code}
                        </span>
                      </li>
                    ))}
                  </ul>
                )}
              </Panel>

              {/* addresses */}
              <Panel title="Addresses">
                {addresses.length === 0 ? (
                  <Empty>No addresses generated yet.</Empty>
                ) : (
                  <ul className="space-y-3">
                    {addresses.slice(0, 5).map((a) => (
                      <li key={a.id}>
                        <p className="font-mono text-xs text-burgundy-bright">
                          {a.muxed_address.slice(0, 8)}…{a.muxed_address.slice(-6)}
                        </p>
                        <p className="text-[11px] text-muted">
                          memo id {a.memo_id}
                          {a.customer_ref ? ` · ${a.customer_ref}` : ""}
                        </p>
                      </li>
                    ))}
                  </ul>
                )}
                <p className="mt-4 text-right text-xs text-muted">
                  Showing last {Math.min(addresses.length, 5)} generated
                </p>
              </Panel>
            </div>

            {/* recent transactions */}
            <Panel title="Most recent transactions">
              {txns.length === 0 ? (
                <Empty>No transactions yet.</Empty>
              ) : (
                <table className="w-full text-left text-sm">
                  <thead className="text-xs text-muted">
                    <tr>
                      <th className="py-2">ID</th>
                      <th className="py-2">Amount</th>
                      <th className="py-2">Hash</th>
                      <th className="py-2">Type</th>
                      <th className="py-2">Status</th>
                      <th className="py-2">Date</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/5">
                    {txns.map((t) => (
                      <tr key={t.id} className="text-foreground/90">
                        <td className="py-3 font-mono text-xs">
                          {t.id.slice(0, 8)}…
                        </td>
                        <td className="py-3">
                          {stroopsToAmount(t.amount_stroops)}{" "}
                          {t.asset_code === "native" ? "XLM" : t.asset_code}
                        </td>
                        <td className="py-3 font-mono text-xs">
                          {t.stellar_tx_hash
                            ? `${t.stellar_tx_hash.slice(0, 8)}…`
                            : "—"}
                        </td>
                        <td className="py-3">
                          <span className="rounded-md bg-white/5 px-2 py-0.5 text-xs capitalize">
                            {t.direction}
                          </span>
                        </td>
                        <td className="py-3">
                          <span className="text-xs text-burgundy-bright capitalize">
                            ● {t.status}
                          </span>
                        </td>
                        <td className="py-3 text-xs text-muted">
                          {new Date(t.created_at).toLocaleDateString()}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </Panel>

            {/* Webhook Delivery History */}
            <Panel title="Webhook delivery history">
              {endpoints.length === 0 ? (
                <Empty>
                  No webhook endpoints registered. Register one in the{" "}
                  <Link href={`/dashboard/wallets/${id}/api`} className="text-burgundy-bright hover:underline">
                    Developers tab
                  </Link>{" "}
                  to start receiving event notifications.
                </Empty>
              ) : loadingDeliveries ? (
                <Empty>Loading delivery history…</Empty>
              ) : deliveries.length === 0 ? (
                <Empty>No webhook deliveries logged yet.</Empty>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-sm">
                    <thead className="text-xs uppercase tracking-wide text-muted">
                      <tr>
                        <th className="py-2 pr-4">Date</th>
                        <th className="py-2 pr-4">Event Type</th>
                        <th className="py-2 pr-4">Status</th>
                        <th className="py-2 pr-4 text-center">Attempts</th>
                        <th className="py-2 text-right">Response Code</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-white/5">
                      {deliveries.map((d) => {
                        const isSuccess = d.status === "delivered";
                        const isFailed = d.status === "failed";
                        const statusCls = isSuccess
                          ? "bg-emerald-500/15 text-emerald-400"
                          : isFailed
                            ? "bg-red-500/15 text-red-400"
                            : "bg-amber-500/15 text-amber-400";
                        
                        let codeCls = "text-muted";
                        if (d.response_code !== null) {
                          if (d.response_code >= 200 && d.response_code < 300) {
                            codeCls = "text-emerald-400 font-semibold";
                          } else {
                            codeCls = "text-red-400 font-semibold";
                          }
                        }

                        return (
                          <tr key={d.id} className="text-foreground/90">
                            <td className="py-3 pr-4 text-xs text-muted whitespace-nowrap">
                              {formatDateTime(d.created_at)}
                            </td>
                            <td className="py-3 pr-4 font-mono text-xs text-foreground/80">
                              {d.event_type}
                            </td>
                            <td className="py-3 pr-4">
                              <span className={`rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase ${statusCls}`}>
                                {d.status}
                              </span>
                            </td>
                            <td className="py-3 pr-4 text-center text-xs">
                              {d.attempts}
                            </td>
                            <td className={`py-3 text-right font-mono text-xs ${codeCls}`}>
                              {d.response_code ?? "—"}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </Panel>
          </main>
        </div>
      </div>

      {showDeposit && (
        <DepositModal
          addresses={addresses}
          baseAddress={wallet?.address ?? ""}
          onClose={() => setShowDeposit(false)}
          onNewAddress={onNewAddress}
          creating={creating}
        />
      )}
      {showWithdraw && token && (
        <WithdrawModal
          token={token}
          walletId={id}
          available={xlmAmount}
          onClose={() => setShowWithdraw(false)}
          onDone={() => {
            setShowWithdraw(false);
            refresh();
          }}
        />
      )}
    </div>
  );
}

function DepositModal({
  addresses,
  baseAddress,
  onClose,
  onNewAddress,
  creating,
}: {
  addresses: Address[];
  baseAddress: string;
  onClose: () => void;
  onNewAddress: () => void;
  creating: boolean;
}) {
  const latest = addresses[0];
  return (
    <Modal title="Deposit" onClose={onClose}>
      <p className="text-sm text-muted">
        Share a deposit address with the sender. Funds sent to it land directly
        in this master wallet and are attributed to the customer.
      </p>

      {latest ? (
        <div className="mt-5 space-y-4">
          <CopyField label="Muxed address (recommended)" value={latest.muxed_address} />
          <CopyField label="Base address (G…+memo fallback)" value={baseAddress} />
          <div className="rounded-lg border border-white/10 bg-black/30 px-3 py-2 text-xs text-muted">
            If the sender can&apos;t use the <code className="text-foreground">M…</code>{" "}
            address, send to the base address with memo (id){" "}
            <span className="text-foreground">{latest.memo_id}</span>.
          </div>
        </div>
      ) : (
        <div className="mt-5 rounded-lg border border-dashed border-white/15 p-5 text-center text-sm text-muted">
          No addresses yet. Generate one to receive a deposit.
          <button
            onClick={onNewAddress}
            disabled={creating}
            className="mt-3 block w-full rounded-lg bg-burgundy py-2 text-sm font-semibold text-white hover:bg-burgundy-bright disabled:opacity-60"
          >
            {creating ? "Generating…" : "Generate address"}
          </button>
        </div>
      )}
    </Modal>
  );
}

function WithdrawModal({
  token,
  walletId,
  available,
  onClose,
  onDone,
}: {
  token: string;
  walletId: string;
  available: string;
  onClose: () => void;
  onDone: () => void;
}) {
  const [destination, setDestination] = useState("");
  const [amount, setAmount] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<{ status: string; hash: string | null } | null>(
    null,
  );

  async function submit() {
    setError(null);
    const stroops = amountToStroops(amount);
    if (!destination.startsWith("G") && !destination.startsWith("M")) {
      setError("Destination must be a Stellar address (G… or M…).");
      return;
    }
    if (stroops === null) {
      setError("Enter a valid amount greater than 0.");
      return;
    }
    setSubmitting(true);
    try {
      // A fresh idempotency key per submit attempt.
      const key = `wd-${crypto.randomUUID()}`;
      const res = await withdraw(token, walletId, destination, stroops, key);
      setResult({ status: res.status, hash: res.stellar_tx_hash });
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Withdrawal failed.");
    } finally {
      setSubmitting(false);
    }
  }

  if (result) {
    const ok = result.status === "confirmed";
    return (
      <Modal title="Withdrawal" onClose={onDone}>
        <div className="text-center">
          <p className={`text-3xl ${ok ? "text-burgundy-bright" : "text-amber-400"}`}>
            {ok ? "✓" : "!"}
          </p>
          <p className="mt-2 font-medium capitalize text-foreground">
            {result.status}
          </p>
          {result.hash && (
            <p className="mt-2 break-all font-mono text-xs text-muted">
              {result.hash}
            </p>
          )}
          <button
            onClick={onDone}
            className="mt-6 w-full rounded-lg bg-burgundy py-2.5 text-sm font-semibold text-white hover:bg-burgundy-bright"
          >
            Done
          </button>
        </div>
      </Modal>
    );
  }

  return (
    <Modal title="Withdraw" onClose={onClose}>
      <p className="text-sm text-muted">
        Send XLM from this master wallet. Available:{" "}
        <span className="text-foreground">{available} XLM</span>.
      </p>

      <div className="mt-5 space-y-4">
        <div>
          <label className="text-xs text-muted">Destination address</label>
          <input
            value={destination}
            onChange={(e) => setDestination(e.target.value.trim())}
            placeholder="G… or M…"
            className="mt-1 w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 font-mono text-sm text-foreground placeholder:text-muted/50 focus:border-burgundy-bright focus:outline-none"
          />
        </div>
        <div>
          <label className="text-xs text-muted">Amount (XLM)</label>
          <input
            value={amount}
            onChange={(e) => setAmount(e.target.value)}
            inputMode="decimal"
            placeholder="0.0000000"
            className="mt-1 w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-foreground placeholder:text-muted/50 focus:border-burgundy-bright focus:outline-none"
          />
        </div>

        {error && (
          <p className="rounded-lg border border-burgundy/40 bg-burgundy/10 px-3 py-2 text-sm text-burgundy-bright">
            {error}
          </p>
        )}

        <button
          onClick={submit}
          disabled={submitting}
          className="w-full rounded-lg bg-burgundy py-2.5 text-sm font-semibold text-white hover:bg-burgundy-bright disabled:opacity-60"
        >
          {submitting ? "Submitting…" : "Withdraw"}
        </button>
      </div>
    </Modal>
  );
}

function Stat({
  label,
  value,
  sub,
}: {
  label: string;
  value: string;
  sub?: string;
}) {
  return (
    <div className="rounded-xl border border-white/10 bg-burgundy-soft/30 p-4">
      <p className="text-[11px] text-muted">{label}</p>
      <p className="mt-1 text-xl font-semibold text-foreground">{value}</p>
      {sub && <p className="mt-1 text-[11px] text-muted">{sub}</p>}
    </div>
  );
}

function ActionButton({
  label,
  onClick,
  disabled,
  loading,
}: {
  label: string;
  onClick?: () => void;
  disabled?: boolean;
  loading?: boolean;
}) {
  return (
    <button
      onClick={onClick}
      disabled={disabled || loading}
      className="rounded-lg border border-white/10 bg-white/[0.03] px-4 py-2 text-sm text-foreground transition-colors hover:border-burgundy/50 disabled:cursor-not-allowed disabled:opacity-40"
    >
      {loading ? "…" : label}
    </button>
  );
}

function Panel({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section className="rounded-2xl border border-white/10 bg-burgundy-soft/20 p-5">
      <h3 className="text-sm font-semibold text-foreground">{title}</h3>
      <div className="mt-4">{children}</div>
    </section>
  );
}

function Empty({ children }: { children: React.ReactNode }) {
  return <p className="py-6 text-center text-sm text-muted">{children}</p>;
}

function formatDateTime(iso: string): string {
  const d = new Date(iso);
  const date = d.toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    timeZone: "UTC",
  });
  const time = d.toLocaleTimeString("en-US", {
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
    timeZone: "UTC",
  });
  return `${date} · ${time} UTC`;
}
