/** Gas sponsorship config API calls + types, mirroring the octo backend. */

"use client";

import { apiFetch } from "./api";

export type SponsorshipConfig = {
  enabled: boolean;
  per_tx_fee_cap_stroops: number | null;
  daily_budget_stroops: number | null;
  /** Fees already reserved/spent today, used to show remaining budget. */
  spent_today_stroops: number;
};

export type SponsorshipConfigPayload = {
  enabled: boolean;
  per_tx_fee_cap_stroops: number | null;
  daily_budget_stroops: number | null;
};

/** Fetch the gas sponsorship config for a single wallet. */
export function getSponsorshipConfig(walletId: string, token: string) {
  return apiFetch<SponsorshipConfig>(`/v1/wallets/${walletId}/sponsorship`, {
    token,
  });
}

/** Update (upsert) the gas sponsorship config for a wallet. */
export function updateSponsorshipConfig(
  walletId: string,
  token: string,
  payload: SponsorshipConfigPayload,
) {
  return apiFetch<SponsorshipConfig>(`/v1/wallets/${walletId}/sponsorship`, {
    method: "PUT",
    token,
    body: JSON.stringify(payload),
  });
}

export type SponsoredTransaction = {
  id: string;
  wallet_id: string;
  inner_tx_hash: string;
  fee_bump_tx_hash: string | null;
  fee_stroops: number;
  status: string;
  error: string | null;
  created_at: string;
};

export type SponsoredTxnPage = {
  data: SponsoredTransaction[];
  /** Pass back as `cursor` to fetch the next page; null when there are no more. */
  next_cursor: string | null;
};

/**
 * List a wallet's sponsored transactions, newest first (50 per page).
 * Pass the previous page's `next_cursor` to fetch the following page.
 */
export function listSponsoredTransactions(
  walletId: string,
  token: string,
  cursor?: string,
) {
  const params = new URLSearchParams({ limit: "50" });
  if (cursor) params.set("before", cursor);
  return apiFetch<SponsoredTxnPage>(
    `/v1/wallets/${walletId}/sponsored-transactions?${params.toString()}`,
    { token },
  );
}

/**
 * Format integer stroops as a human-readable XLM string (2 dp).
 * Raw stroop values are for the API only — never expose them to end users.
 */
export function formatXlm(stroops: number): string {
  return (stroops / 10_000_000).toFixed(2);
}

export function stroopsToXlm(stroops: number): string {
  return `${(stroops / 10_000_000).toFixed(2)} XLM`;
}

