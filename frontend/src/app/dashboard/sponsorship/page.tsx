"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useAuth } from "@/lib/useAuth";
import { listWallets, type WalletView } from "@/lib/wallets";
import {
  getSponsorshipConfig,
  stroopsToXlm,
  type SponsorshipConfig,
} from "@/lib/sponsorship";
import { DashboardShell } from "@/components/dashboard/DashboardShell";

type Row = {
  wallet: WalletView;
  config: SponsorshipConfig | null;
};

export default function SponsorshipPage() {
  const { user, token, loading, logout } = useAuth();
  const [rows, setRows] = useState<Row[] | null>(null);

  useEffect(() => {
    if (!token) return;
    listWallets(token)
      .then(async (wallets) => {
        // Fetch only the sponsorship config per wallet (not full wallet details).
        const settled = await Promise.all(
          wallets.map(async (wallet) => {
            const config = await getSponsorshipConfig(wallet.id, token).catch(
              () => null,
            );
            return { wallet, config };
          }),
        );
        setRows(settled);
      })
      .catch(() => setRows([]));
  }, [token]);

  if (loading || !user) {
    return (
      <div className="flex min-h-screen items-center justify-center text-muted">
        Loading…
      </div>
    );
  }

  return (
    <DashboardShell email={user.email} title="Gas Sponsorship" onLogout={logout}>
      <div className="mx-auto max-w-5xl">
        {/* How it works */}
        <div className="rounded-2xl border border-white/10 bg-burgundy-soft/30 p-6">
          <div className="flex items-center gap-3">
            <span className="flex h-9 w-9 items-center justify-center rounded-full bg-burgundy/40 text-burgundy-bright">
              ⛽
            </span>
            <h2 className="text-lg font-semibold text-foreground">
              How gas sponsorship works
            </h2>
          </div>
          <p className="mt-3 text-sm leading-relaxed text-muted">
            Gas sponsorship lets your wallets pay the Stellar network fee on
            behalf of your users, so they can transact without holding XLM.
            Enable it per wallet and set spend controls — a maximum fee per
            transaction and a daily budget — to keep costs predictable. Once a
            wallet hits its daily budget, sponsorship pauses automatically until
            the next day.
          </p>
          <Link
            href="/docs/gas-sponsorship"
            className="mt-4 inline-flex items-center gap-1.5 text-sm font-medium text-burgundy-bright hover:underline"
          >
            Read the documentation →
          </Link>
        </div>

        <div className="my-8 h-px bg-white/10" />

        <h3 className="text-sm font-medium text-foreground">
          Sponsorship across your wallets
        </h3>

        <div className="mt-5">
          {rows === null ? (
            <p className="text-sm text-muted">Loading wallets…</p>
          ) : rows.length === 0 ? (
            <EmptyState />
          ) : (
            <div className="grid gap-4 md:grid-cols-2">
              {rows.map((row) => (
                <SponsorshipCard key={row.wallet.id} row={row} />
              ))}
            </div>
          )}
        </div>
      </div>
    </DashboardShell>
  );
}

function EmptyState() {
  return (
    <div className="rounded-2xl border border-dashed border-white/15 bg-burgundy-soft/20 p-10 text-center">
      <p className="text-foreground">No master wallets yet</p>
      <p className="mt-1 text-sm text-muted">
        Create a master wallet first, then enable gas sponsorship to start
        covering network fees for your users.
      </p>
      <Link
        href="/dashboard/wallets/new"
        className="mt-5 inline-block rounded-full bg-burgundy px-5 py-2.5 text-sm font-medium text-white hover:bg-burgundy-bright"
      >
        New Master Wallet
      </Link>
    </div>
  );
}

function SponsorshipCard({ row }: { row: Row }) {
  const { wallet, config } = row;
  const enabled = config?.enabled ?? false;

  return (
    <div className="rounded-2xl border border-white/10 bg-burgundy-soft/30 p-5">
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="font-semibold text-foreground">
            {wallet.label ?? "Master wallet"}
          </p>
          <p className="mt-1 text-xs capitalize text-muted">
            {wallet.network}
          </p>
        </div>
        <span
          className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[11px] font-medium ${
            enabled
              ? "bg-emerald-500/15 text-emerald-300"
              : "bg-white/5 text-muted"
          }`}
        >
          <span
            className={`h-1.5 w-1.5 rounded-full ${
              enabled ? "bg-emerald-400" : "bg-white/40"
            }`}
          />
          {enabled ? "Enabled" : "Disabled"}
        </span>
      </div>

      <div className="mt-5 h-px bg-white/10" />

      <div className="mt-4 grid grid-cols-2 gap-3 text-xs">
        <div>
          <p className="text-muted">Max fee per tx</p>
          <p className="mt-1 font-medium text-foreground">
            {stroopsToXlm(config?.per_tx_fee_cap_stroops)}
          </p>
        </div>
        <div>
          <p className="text-muted">Daily budget</p>
          <p className="mt-1 font-medium text-foreground">
            {stroopsToXlm(config?.daily_budget_stroops)}
          </p>
        </div>
      </div>

      <Link
        href={`/dashboard/wallets/${wallet.id}/sponsorship`}
        className="mt-5 inline-flex items-center gap-1.5 text-sm font-medium text-burgundy-bright hover:underline"
      >
        Manage settings →
      </Link>
    </div>
  );
}
