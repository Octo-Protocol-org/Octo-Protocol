"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useAuth } from "@/lib/useAuth";
import { listWallets, type WalletView } from "@/lib/wallets";
import {
  getSponsorshipConfig,
  formatXlm,
  type SponsorshipConfig,
} from "@/lib/sponsorship";
import { DashboardShell } from "@/components/dashboard/DashboardShell";

export default function DashboardHome() {
  const { user, token, loading, logout } = useAuth();
  const [wallets, setWallets] = useState<WalletView[] | null>(null);
  const [sponsorshipByWalletId, setSponsorshipByWalletId] = useState<
    Map<string, SponsorshipConfig | null>
  >(new Map());

  useEffect(() => {
    if (!token) return;
    let aborted = false;
    listWallets(token)
      .then(async (ws) => {
        if (aborted) return;
        setWallets(ws);
        // Fetch sponsorship configs in parallel so the wallet list never has to wait on them.
        // A single failed sponsorship fetch must not blank out the whole row.
        const results = await Promise.allSettled(
          ws.map((w) => getSponsorshipConfig(token, w.id)),
        );
        if (aborted) return;
        const map = new Map<string, SponsorshipConfig | null>();
        ws.forEach((w, i) => {
          const r = results[i];
          map.set(w.id, r.status === "fulfilled" ? r.value : null);
        });
        setSponsorshipByWalletId(map);
      })
      .catch(() => {
        // Gate on the same `aborted` flag the .then already uses so we don't call
        // setState on an unmounted component when listWallets rejects late.
        if (aborted) return;
        setWallets([]);
      });
    return () => {
      aborted = true;
    };
  }, [token]);

  if (loading || !user) {
    return (
      <div className="flex min-h-screen items-center justify-center text-muted">
        Loading…
      </div>
    );
  }

  const greeting = (() => {
    const h = new Date().getHours();
    return h < 12 ? "Good morning" : h < 18 ? "Good afternoon" : "Good evening";
  })();

  return (
    <DashboardShell email={user.email} title="Wallets" onLogout={logout}>
      <div className="mx-auto max-w-5xl">
        <div className="flex items-start justify-between">
          <div>
            <h2 className="text-3xl font-semibold text-foreground">
              {greeting},{" "}
              <span className="text-burgundy-bright">
                {user.email.split("@")[0]}
              </span>
            </h2>
            <p className="mt-1 text-sm text-muted">
              It&apos;s{" "}
              {new Date().toLocaleDateString("en-US", {
                weekday: "long",
                month: "short",
                day: "numeric",
                year: "numeric",
              })}
              .
            </p>
          </div>
          <Link
            href="/dashboard/wallets/new"
            className="rounded-full bg-burgundy px-5 py-2.5 text-sm font-medium text-white transition-colors hover:bg-burgundy-bright"
          >
            New Master Wallet
          </Link>
        </div>

        <div className="my-8 h-px bg-white/10" />

        <h3 className="text-sm font-medium text-foreground">
          Your Master Wallets at a glance
        </h3>

        <div className="mt-5">
          {wallets === null ? (
            <p className="text-sm text-muted">Loading wallets…</p>
          ) : wallets.length === 0 ? (
            <EmptyState />
          ) : (
            <div className="grid gap-4 md:grid-cols-2">
              {wallets.map((w) => (
                <WalletCard
                  key={w.id}
                  wallet={w}
                  sponsorship={sponsorshipByWalletId.get(w.id) ?? undefined}
                />
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
        Create your first master wallet to start receiving deposits.
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

function WalletCard({
  wallet,
  sponsorship,
}: {
  wallet: WalletView;
  sponsorship?: SponsorshipConfig | null;
}) {
  const short = `${wallet.address.slice(0, 6)}…${wallet.address.slice(-6)}`;
  const sponsorEnabled = sponsorship?.enabled === true;
  const dailyBudget = sponsorship?.daily_budget_stroops;
  const spentToday = sponsorship?.spent_today_stroops ?? 0;
  const hasBudget = typeof dailyBudget === "number" && dailyBudget > 0;
  const pct = hasBudget
    ? Math.min(100, Math.max(0, (spentToday / dailyBudget) * 100))
    : 0;

  return (
    <div className="rounded-2xl border border-white/10 bg-burgundy-soft/30 p-5">
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-3">
          <span className="flex h-9 w-9 items-center justify-center rounded-full bg-burgundy/40 text-burgundy-bright">
            ◷
          </span>
          <div>
            <p className="font-semibold text-foreground">
              {wallet.label ?? "Master wallet"}
            </p>
            <p className="text-xs text-muted">
              {wallet.description ?? "Stellar master wallet"}
            </p>
          </div>
        </div>
        <ManageMenu walletId={wallet.id} />
      </div>

      <div className="mt-5 h-px bg-white/10" />

      <div className="mt-4 grid grid-cols-2 gap-3 text-xs sm:grid-cols-4">
        <div>
          <p className="text-muted">Network</p>
          <p className="mt-1 font-medium capitalize text-foreground">
            {wallet.network}
          </p>
        </div>
        <div>
          <p className="text-muted">Address</p>
          <p className="mt-1 font-mono text-foreground">{short}</p>
        </div>
        <div>
          <p className="text-muted">Base</p>
          <p className="mt-1 font-medium text-foreground">XLM</p>
        </div>
        <div>
          <p className="text-muted">Gas Sponsor</p>
          <div className="mt-1 flex items-center gap-1.5">
            <span
              className={`inline-block h-2 w-2 shrink-0 rounded-full ${
                sponsorEnabled ? "bg-emerald-400" : "bg-white/20"
              }`}
              aria-hidden
            />
            <span
              className={
                sponsorEnabled
                  ? "font-medium text-emerald-300"
                  : "text-muted"
              }
            >
              {sponsorEnabled ? "Enabled" : "Off"}
            </span>
          </div>
          {hasBudget ? (
            <div className="mt-1.5 space-y-1">
              <div className="h-1.5 w-full overflow-hidden rounded-full bg-white/10">
                <div
                  className="h-full rounded-full bg-burgundy-bright transition-all"
                  style={{ width: `${pct}%` }}
                />
              </div>
              <p className="text-[10px] text-muted">
                {formatXlm(spentToday)} / {formatXlm(dailyBudget)} XLM today
              </p>
            </div>
          ) : (
            <p className="mt-0.5 text-[10px] text-muted">no daily cap</p>
          )}
        </div>
      </div>
    </div>
  );
}

function ManageMenu({ walletId }: { walletId: string }) {
  const [open, setOpen] = useState(false);

  return (
    <div className="relative">
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-1 rounded-lg border border-white/15 px-3 py-1.5 text-xs text-foreground hover:border-white/30"
      >
        Manage <span className="text-muted">⋮</span>
      </button>

      {open && (
        <>
          {/* click-away */}
          <div
            className="fixed inset-0 z-10"
            onClick={() => setOpen(false)}
          />
          <div className="absolute right-0 z-20 mt-2 w-44 overflow-hidden rounded-xl border border-white/10 bg-black/90 backdrop-blur-md">
            <Link
              href={`/dashboard/wallets/${walletId}`}
              className="flex items-center gap-2 px-4 py-3 text-sm text-foreground hover:bg-white/5"
            >
              ▦ Go to dashboard
            </Link>
            <Link
              href={`/dashboard/wallets/${walletId}/api`}
              className="flex items-center gap-2 px-4 py-3 text-sm text-foreground hover:bg-white/5"
            >
              ↗ API settings
            </Link>
          </div>
        </>
      )}
    </div>
  );
}
