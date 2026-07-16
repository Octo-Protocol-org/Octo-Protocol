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

/** List the authenticated user's wallets. */
export function listWallets(token: string) {
  return apiFetch<WalletView[]>("/v1/wallets", { token });
}

export function getWallet(token: string, id: string) {
  return apiFetch<WalletView>(`/v1/wallets/${id}`, { token });
}

export function getBalances(token: string, id: string) {
  return apiFetch<Balance[]>(`/v1/wallets/${id}/balances`, { token });
}

export function listAddresses(token: string, id: string) {
  return apiFetch<Address[]>(`/v1/wallets/${id}/addresses`, { token });
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

export function listTransactions(token: string, id: string) {
  return apiFetch<Transaction[]>(`/v1/wallets/${id}/transactions`, { token });
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

export type WebhookEndpoint = {
  id: string;
  wallet_id: string;
  url: string;
  secret: string;
  active: boolean;
};

export type WebhookDelivery = {
  id: string;
  endpoint_id: string;
  event_type: string;
  payload: any;
  status: string; // 'pending' | 'delivered' | 'failed'
  attempts: number;
  response_code: number | null;
  created_at: string;
  updated_at: string;
};

/** List registered webhook endpoints for a wallet. */
export function listWebhooks(token: string, id: string) {
  return apiFetch<WebhookEndpoint[]>(`/v1/wallets/${id}/webhooks`, { token });
}

/** List recent webhook deliveries for a specific endpoint. */
export function listWebhookDeliveries(token: string, id: string, endpointId: string) {
  return apiFetch<WebhookDelivery[]>(`/v1/wallets/${id}/webhooks/${endpointId}/deliveries`, { token });
}


