/** Gas sponsorship API calls + types, mirroring the octo backend. */

"use client";

import { apiFetch } from "./api";

export type SponsorshipConfig = {
  enabled: boolean;
  per_tx_fee_cap_stroops: number | null;
  daily_budget_stroops: number | null;
  spent_today_stroops: number;
};

/** Fetch a wallet's gas sponsorship config (enabled state + spend controls). */
export function getSponsorshipConfig(walletId: string, token: string) {
  return apiFetch<SponsorshipConfig>(`/v1/wallets/${walletId}/sponsorship`, {
    token,
  });
}

/**
 * Format integer stroops as a human-readable XLM string (2 dp).
 * Raw stroop values are for the API only and must never be shown to end users.
 * Returns "—" when no limit is configured.
 */
export function stroopsToXlm(stroops: number | null | undefined): string {
  if (stroops == null) return "—";
  return `${(stroops / 10_000_000).toFixed(2)} XLM`;
}
