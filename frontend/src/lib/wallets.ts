/** Wallet API calls + types, mirroring the octo backend. */

"use client";

import { apiFetch } from "./api";

export type CreateWalletResponse = {
  id: string;
  network: string;
  address: string;
  recovery_mnemonic: string;
  funded: boolean;
};

export type WalletView = {
  id: string;
  network: string;
  address: string;
  label: string | null;
  description: string | null;
};

export type Balance = {
  balance: string;
  asset_type: string;
  asset_code?: string | null;
  asset_issuer?: string | null;
};

export type Address = {
  id: string;
  customer_ref: string | null;
  muxed_address: string;
  base_address: string;
  memo_id: number;
  metadata: unknown;
};

export type Transaction = {
  id: string;
  direction: string;
  asset_code: string;
  amount_stroops: number;
  source_account: string | null;
  destination_account: string | null;
  stellar_tx_hash: string | null;
  status: string;
  created_at: string;
};

/** Generic paginated response returned by list endpoints. */
export type Page<T> = {
  data: T[];
  /** Pass back as `before` to fetch the next page; null when there are no more. */
  next_cursor: string | null;
};

/** Create a master wallet. The server picks the network; name/description optional. */
export function createWallet(
  token: string,
  label?: string,
  description?: string,
) {
  return apiFetch<CreateWalletResponse>("/v1/wallets", {
    method: "POST",
    token,
    body: JSON.stringify({
      label: label || null,
      description: description || null,
    }),
  });
}

/** List the authenticated user's wallets (first page, newest first). */
export function listWallets(token: string, cursor?: string) {
  const params = new URLSearchParams({ limit: "50" });
  if (cursor) params.set("before", cursor);
  return apiFetch<Page<WalletView>>(`/v1/wallets?${params.toString()}`, {
    token,
  });
}

export function getWallet(token: string, id: string) {
  return apiFetch<WalletView>(`/v1/wallets/${id}`, { token });
}

export function getBalances(token: string, id: string) {
  return apiFetch<Balance[]>(`/v1/wallets/${id}/balances`, { token });
}

/** List addresses for a wallet (paginated, newest first). */
export function listAddresses(token: string, id: string, cursor?: string) {
  const params = new URLSearchParams({ limit: "50" });
  if (cursor) params.set("before", cursor);
  return apiFetch<Page<Address>>(
    `/v1/wallets/${id}/addresses?${params.toString()}`,
    { token },
  );
}

export function createAddress(
  token: string,
  id: string,
  customerRef?: string,
) {
  return apiFetch<Address>(`/v1/wallets/${id}/addresses`, {
    method: "POST",
    token,
    body: JSON.stringify({ customer_ref: customerRef || null }),
  });
}

/** List transactions for a wallet (paginated, newest first). */
export function listTransactions(token: string, id: string, cursor?: string) {
  const params = new URLSearchParams({ limit: "50" });
  if (cursor) params.set("before", cursor);
  return apiFetch<Page<Transaction>>(
    `/v1/wallets/${id}/transactions?${params.toString()}`,
    { token },
  );
}

/** Format integer stroops as a decimal XLM-style string (7 dp). */
export function stroopsToAmount(stroops: number): string {
  return (stroops / 10_000_000).toFixed(7);
}

/** Parse a decimal XLM amount string into integer stroops, or null if invalid. */
export function amountToStroops(xlm: string): number | null {
  const n = Number(xlm);
  if (!Number.isFinite(n) || n <= 0) return null;
  return Math.round(n * 10_000_000);
}

export type WithdrawResult = {
  id: string;
  status: string;
  stellar_tx_hash: string | null;
  destination: string;
  amount_stroops: number;
};

/** Withdraw funds from the master wallet (dashboard login token required). */
export function withdraw(
  token: string,
  id: string,
  destination: string,
  amountStroops: number,
  idempotencyKey: string,
) {
  return apiFetch<WithdrawResult>(`/v1/wallets/${id}/withdraw`, {
    method: "POST",
    token,
    headers: { "idempotency-key": idempotencyKey },
    body: JSON.stringify({
      destination,
      amount_stroops: amountStroops,
    }),
  });
}

export type ApiKeyInfo = {
  wallet_id: string;
  configured: boolean;
  prefix: string | null;
};

export type GeneratedKey = {
  wallet_id: string;
  api_key: string;
  prefix: string;
};

/** Metadata about the wallet's API key (prefix + whether configured) — never the secret. */
export function getApiKey(token: string, id: string) {
  return apiFetch<ApiKeyInfo>(`/v1/wallets/${id}/api-key`, { token });
}

/** Generate (or regenerate) the wallet's API key. Returns the full key once. */
export function generateApiKey(token: string, id: string) {
  return apiFetch<GeneratedKey>(`/v1/wallets/${id}/api-key`, {
    method: "POST",
    token,
  });
}

// Placeholder types and functions for webhook functionality (to be implemented)
export type WebhookEndpoint = {
  id: string;
  url: string;
  active?: boolean;
  created_at: string;
};

export type WebhookDelivery = {
  id: string;
  endpoint_id: string;
  event_type: string;
  status: string;
  response_code: number | null;
  attempts: number;
  created_at: string;
};

/** List webhook endpoints for a wallet (placeholder - to be implemented). */
export function listWebhooks(token: string, id: string, cursor?: string): Promise<WebhookEndpoint[]> {
  // Placeholder implementation - returns empty array
  return Promise.resolve([]);
}

/** List webhook deliveries for a wallet (placeholder - to be implemented). */
export function listWebhookDeliveries(token: string, id: string, endpointId?: string): Promise<WebhookDelivery[]> {
  // Placeholder implementation - returns empty array
  return Promise.resolve([]);
}
