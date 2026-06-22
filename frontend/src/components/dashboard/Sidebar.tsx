"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Logo } from "@/components/Logo";

const NAV: { label: string; href: string; icon: string; soon?: boolean }[] = [
  { label: "Home", href: "/dashboard", icon: "⌂" },
  { label: "Gas Sponsorship", href: "/dashboard/sponsorship", icon: "⛽" },
  { label: "Asset Recovery", href: "/dashboard/recovery", icon: "↺" },
  { label: "Developers", href: "/dashboard/developers", icon: "›_" },
  { label: "Audit Logs", href: "/dashboard/audit", icon: "▤" },
];

export function Sidebar({ email }: { email?: string }) {
  const pathname = usePathname();

  return (
    <aside className="flex w-64 shrink-0 flex-col border-r border-white/10 bg-black/40 px-3 py-5">
      <div className="px-3">
        <Logo />
        <p className="mt-5 text-sm font-medium text-foreground">
          {email?.split("@")[0] ?? "Account"}
        </p>
        <p className="text-xs text-muted">
          {new Date().toLocaleDateString("en-US", {
            weekday: "short",
            month: "short",
            day: "numeric",
            year: "numeric",
          })}
        </p>
      </div>

      <nav className="mt-6 flex-1 space-y-1">
        {NAV.map((item) => {
          // Coming-soon items are shown disabled (not navigable).
          if (item.soon) {
            return (
              <div
                key={item.label}
                className="flex cursor-not-allowed items-center gap-3 rounded-lg px-3 py-2.5 text-sm text-muted/60"
                title="Coming soon"
              >
                <span className="w-4 text-center opacity-80">{item.icon}</span>
                <span className="flex-1">{item.label}</span>
                <span className="rounded-full border border-burgundy/40 px-1.5 py-0.5 text-[9px] uppercase text-burgundy-bright">
                  Soon
                </span>
              </div>
            );
          }
          const active =
            item.href === "/dashboard"
              ? pathname === "/dashboard"
              : pathname.startsWith(item.href);
          return (
            <Link
              key={item.label}
              href={item.href}
              className={`flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm transition-colors ${
                active
                  ? "bg-burgundy/25 text-foreground"
                  : "text-muted hover:bg-white/5 hover:text-foreground"
              }`}
            >
              <span className="w-4 text-center opacity-80">{item.icon}</span>
              {item.label}
            </Link>
          );
        })}
      </nav>

      <div className="rounded-xl border border-white/10 bg-burgundy-soft/30 p-4">
        <p className="text-sm font-semibold text-foreground">Free Plan</p>
        <p className="mt-1 text-[11px] text-muted">0 of 100 Addresses</p>
        <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-white/10">
          <div className="h-full w-[2%] rounded-full bg-burgundy-bright" />
        </div>
        <button className="mt-4 w-full rounded-lg bg-foreground py-2 text-xs font-semibold text-background">
          Upgrade
        </button>
      </div>
    </aside>
  );
}
