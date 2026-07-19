"use client";

import { use, useEffect, useState } from "react";
import Link from "next/link";
import { useAuth } from "@/lib/useAuth";
import { getWallet, stroopsToAmount, amountToStroops, type WalletView } from "@/lib/wallets";
import {
  getSponsorshipConfig,
  updateSponsorshipConfig,
  formatXlm,
  type SponsorshipConfig,
} from "@/lib/sponsorship";
import { WalletSidebar } from "@/components/dashboard/WalletSidebar";
import { SponsoredTransactionsTable } from "@/components/dashboard/SponsoredTransactionsTable";
import { ApiError } from "@/lib/api";

export default function SponsorshipSettingsPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = use(params);
  const { user, token, loading, logout } = useAuth();

  const [wallet, setWallet] = useState<WalletView | null>(null);
  const [config, setConfig] = useState<SponsorshipConfig | null>(null);

  // form state (XLM strings, converted to stroops only at the API boundary)
  const [enabled, setEnabled] = useState(false);
  const [maxFee, setMaxFee] = useState("");
  const [dailyBudget, setDailyBudget] = useState("");

  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [toast, setToast] = useState<string | null>(null);

  useEffect(() => {
    if (!token) return;
    getWallet(token, id).then(setWallet).catch(() => {});
    getSponsorshipConfig(id, token)
      .then((c) => {
        setConfig(c);
        setEnabled(c.enabled);
        setMaxFee(
          c.per_tx_fee_cap_stroops != null
            ? stroopsToAmount(c.per_tx_fee_cap_stroops)
            : "",
        );
        setDailyBudget(
          c.daily_budget_stroops != null
            ? stroopsToAmount(c.daily_budget_stroops)
            : "",
        );
      })
      .catch(() => {});
  }, [token, id]);

  async function onSave() {
    if (!token) return;
    setError(null);

    const feeStroops = amountToStroops(maxFee);
    const budgetStroops = amountToStroops(dailyBudget);

    if (feeStroops === null || budgetStroops === null) {
      setError("Enter a max fee and daily budget greater than 0 XLM.");
      return;
    }
    if (feeStroops > budgetStroops) {
      setError("Max fee per transaction cannot exceed the daily budget.");
      return;
    }

    setSaving(true);
    try {
      const updated = await updateSponsorshipConfig(id, token, {
        enabled,
        per_tx_fee_cap_stroops: feeStroops,
        daily_budget_stroops: budgetStroops,
      });
      setConfig(updated);
      setToast("Sponsorship settings saved.");
      setTimeout(() => setToast(null), 3000);
    } catch (err) {
      setError(
        err instanceof ApiError ? err.message : "Failed to save settings.",
      );
    } finally {
      setSaving(false);
    }
  }

  if (loading || !user) {
    return (
      <div className="flex min-h-screen items-center justify-center text-muted">
        Loading…
      </div>
    );
  }

  const spentToday = config?.spent_today_stroops ?? 0;
  const budgetStroops = config?.daily_budget_stroops;
  const hasBudget = typeof budgetStroops === "number" && budgetStroops > 0;
  const remaining = hasBudget ? Math.max(0, budgetStroops - spentToday) : 0;
  const pct = hasBudget
    ? Math.min(100, Math.max(0, (spentToday / budgetStroops) * 100))
    : 0;

  return (
    <div className="flex min-h-screen flex-col bg-background">
      <div className="bg-burgundy/20 py-2 text-center text-xs text-burgundy-bright">
        You are currently on <strong>test mode</strong> (Stellar testnet).
      </div>
      <div className="flex flex-1">
        <WalletSidebar walletId={id} walletName={wallet?.label ?? "Master wallet"} />

        <div className="flex flex-1 flex-col">
          <header className="flex items-center justify-between border-b border-white/10 px-8 py-4">
            <div className="flex items-center gap-2 text-sm text-muted">
              <Link href="/dashboard" className="hover:text-foreground">
                My Wallets
              </Link>
              <span>›</span>
              <span className="text-foreground">Sponsorship</span>
            </div>
            <button onClick={logout} className="text-sm text-muted hover:text-foreground">
              ⏻
            </button>
          </header>

          <main className="flex-1 px-8 py-8">
            <div className="mx-auto max-w-2xl space-y-6">
              <div>
                <h1 className="text-xl font-semibold text-foreground">
                  Gas Sponsorship
                </h1>
                <p className="mt-1 text-sm text-muted">
                  Pay Stellar network fees on behalf of this wallet&apos;s users.
                  Set spend controls to keep costs predictable.
                </p>
              </div>

              {/* Today's spend */}
              <section className="rounded-2xl border border-white/10 bg-burgundy-soft/30 p-5">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-muted">Today&apos;s spend</span>
                  <span className="text-foreground">
                    {hasBudget
                      ? `${formatXlm(spentToday)} / ${formatXlm(budgetStroops)} XLM today`
                      : "no daily cap"}
                  </span>
                </div>
                {hasBudget ? (
                  <>
                    <div className="mt-3 h-1.5 w-full overflow-hidden rounded-full bg-white/10">
                      <div
                        className="h-full rounded-full bg-burgundy-bright transition-all"
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                    <p className="mt-2 text-xs text-muted">
                      {formatXlm(remaining)} XLM remaining today
                    </p>
                  </>
                ) : (
                  <p className="mt-2 text-xs text-muted">
                    No daily budget limit is configured for gas sponsorship.
                  </p>
                )}
              </section>

              {/* Settings form */}
              <section className="space-y-5 rounded-2xl border border-white/10 bg-burgundy-soft/30 p-5">
                {/* toggle */}
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-foreground">
                      Enable gas sponsorship
                    </p>
                    <p className="text-xs text-muted">
                      Octo fee-bumps eligible transactions for this wallet.
                    </p>
                  </div>
                  <button
                    type="button"
                    role="switch"
                    aria-checked={enabled}
                    aria-label="Enable gas sponsorship"
                    onClick={() => setEnabled((v) => !v)}
                    className={`relative inline-flex h-6 w-11 shrink-0 items-center rounded-full transition-colors ${
                      enabled ? "bg-burgundy-bright" : "bg-white/15"
                    }`}
                  >
                    <span
                      className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                        enabled ? "translate-x-6" : "translate-x-1"
                      }`}
                    />
                  </button>
                </div>

                {/* max fee */}
                <div>
                  <label
                    htmlFor="max-fee"
                    className="text-sm font-medium text-foreground"
                  >
                    Max fee per transaction (XLM)
                  </label>
                  <input
                    id="max-fee"
                    value={maxFee}
                    onChange={(e) => setMaxFee(e.target.value)}
                    inputMode="decimal"
                    placeholder="0.0000000"
                    className="mt-1.5 w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-foreground placeholder:text-muted/50 focus:border-burgundy-bright focus:outline-none"
                  />
                  <p className="mt-1 text-xs text-muted">
                    Maximum fee the master wallet will pay per sponsored
                    transaction.
                  </p>
                </div>

                {/* daily budget */}
                <div>
                  <label
                    htmlFor="daily-budget"
                    className="text-sm font-medium text-foreground"
                  >
                    Daily budget (XLM)
                  </label>
                  <input
                    id="daily-budget"
                    value={dailyBudget}
                    onChange={(e) => setDailyBudget(e.target.value)}
                    inputMode="decimal"
                    placeholder="0.0000000"
                    className="mt-1.5 w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-foreground placeholder:text-muted/50 focus:border-burgundy-bright focus:outline-none"
                  />
                  <p className="mt-1 text-xs text-muted">
                    {hasBudget
                      ? `${formatXlm(remaining)} XLM remaining of today's budget.`
                      : "No daily budget limit set."}
                  </p>
                </div>

                {error && (
                  <p className="rounded-lg border border-burgundy/40 bg-burgundy/10 px-3 py-2 text-sm text-burgundy-bright">
                    {error}
                  </p>
                )}

                <button
                  onClick={onSave}
                  disabled={saving}
                  className="w-full rounded-lg bg-burgundy py-2.5 text-sm font-semibold text-white transition-colors hover:bg-burgundy-bright disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {saving ? "Saving…" : "Save settings"}
                </button>
              </section>

              {token && (
                <SponsoredTransactionsTable walletId={id} token={token} />
              )}
            </div>
          </main>
        </div>
      </div>

      {toast && (
        <div className="fixed bottom-6 right-6 rounded-xl border border-burgundy/40 bg-burgundy/20 px-4 py-3 text-sm text-burgundy-bright shadow-lg">
          ✓ {toast}
        </div>
      )}
    </div>
  );
}
