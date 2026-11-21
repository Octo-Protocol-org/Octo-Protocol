# Testnet Quickstart: From Signup to a Received Deposit

This tutorial walks you from zero to a confirmed, webhook-notified deposit on **testnet**, using only `curl`. Follow it verbatim. Every command is copy-pasteable; placeholders are marked with `<>`.

> **What you'll do**
> 1. Sign up
> 2. Verify your email
> 3. Create a wallet (client-generated keypair + ownership challenge)
> 4. Fund the wallet via Friendbot
> 5. Generate a deposit address
> 6. Send a testnet payment to that address
> 7. Register a webhook and observe a signed delivery

---

## 0. Prerequisites

- `curl` and `jq` installed.
- Node.js 18+ (used only for the challenge-signing helper script).
- A terminal you can leave running (for the webhook listener in step 7).
- The repository checked out locally (the helper script lives at `api-tests/scripts/sign-challenge.js`).

Set up shell variables once. **Replace `<your-email>` with a real inbox you can read.**

```bash
export API="https://api.testnet.example.com"   # testnet API base URL
export EMAIL="<your-email>"
export PASSWORD="CorrectHorseBatteryStaple1!"
```

> **Troubleshooting:** If `$API` is wrong you'll get connection errors or `404`. Confirm the testnet base URL with the team before starting.

---

## 1. Sign up

```bash
curl -sS -X POST "$API/v1/auth/signup" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" | jq
```

**Expected response** (`201 Created`):

```json
{
  "id": "usr_01H...",
  "email": "<your-email>",
  "status": "pending_verification"
}
```

Save the user id:

```bash
export USER_ID="<paste id from response>"
```

> **Troubleshooting**
> - `409 Conflict` — this email is already registered. Use a different address or continue to step 2 if you already signed up.
> - `422 Unprocessable Entity` — password fails policy (min length / complexity). Adjust `$PASSWORD`.
> - `400 Bad Request` — malformed JSON; check quoting.

---

## 2. Verify your email

Check your inbox for a verification email. It contains a link with a `token` query parameter, e.g. `...?token=abc123`. Copy the token value.

```bash
export VERIFY_TOKEN="<token from email>"

curl -sS -X POST "$API/v1/auth/verify-email" \
  -H "Content-Type: application/json" \
  -d "{\"token\":\"$VERIFY_TOKEN\"}" | jq
```

**Expected response** (`200 OK`):

```json
{
  "id": "usr_01H...",
  "email": "<your-email>",
  "status": "active"
}
```

Now log in to obtain an access token:

```bash
curl -sS -X POST "$API/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" | jq
```

**Expected response** (`200 OK`):

```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

Save it:

```bash
export TOKEN="<paste access_token>"
```

> **Troubleshooting**
> - `401 Unauthorized` on login — email not yet verified, or wrong password.
> - `400 Bad Request` on verify — token expired or already used. Request a new verification email (re-run signup with the same email if the API supports resend, or contact the team).
> - No email arrived — check spam; confirm `$EMAIL` is correct.

---

## 3. Create a wallet

Wallets use a **client-generated Stellar keypair**. The server never sees your secret key. You prove ownership by signing a server-issued challenge.

### 3a. Generate a keypair

```bash
node -e '
const { Keypair } = require("@stellar/stellar-sdk");
const kp = Keypair.random();
console.log("PUBLIC_KEY=" + kp.publicKey());
console.log("SECRET_KEY=" + kp.secret());
'
```

Copy both values into your shell:

```bash
export PUBLIC_KEY="<paste PUBLIC_KEY>"
export SECRET_KEY="<paste SECRET_KEY>"
```

> **Security:** `$SECRET_KEY` is a testnet secret. Never commit it or paste it into shared logs. It is only needed locally to sign the challenge.

### 3b. Request an ownership challenge

```bash
curl -sS -X POST "$API/v1/wallets/challenge" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"public_key\":\"$PUBLIC_KEY\"}" | jq
```

**Expected response** (`200 OK`):

```json
{
  "challenge": "muxed-wallet-ownership:1712345678:nonce-abc123",
  "expires_at": "2024-04-05T12:35:00Z"
}
```

Save the challenge string:

```bash
export CHALLENGE="<paste challenge>"
```

### 3c. Sign the challenge

Use the helper script from the repo:

```bash
export SIGNATURE=$(node api-tests/scripts/sign-challenge.js "$SECRET_KEY" "$CHALLENGE")
echo "$SIGNATURE"
```

The script prints a base64-encoded signature. If it errors, confirm you ran it from the repository root and that `@stellar/stellar-sdk` is installed (`npm install` in `api-tests/` if needed).

### 3d. Create the wallet

```bash
curl -sS -X POST "$API/v1/wallets" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"public_key\":\"$PUBLIC_KEY\",
    \"challenge\":\"$CHALLENGE\",
    \"signature\":\"$SIGNATURE\"
  }" | jq
```

**Expected response** (`201 Created`):

```json
{
  "id": "wal_01H...",
  "public_key": "G...",
  "network": "testnet",
  "status": "active",
  "created_at": "2024-04-05T12:30:00Z"
}
```

Save the wallet id:

```bash
export WALLET_ID="<paste id>"
```

> **Troubleshooting**
> - `401 Unauthorized` — `$TOKEN` missing/expired. Re-run login in step 2.
> - `422 Unprocessable Entity` — signature invalid or challenge expired. Re-run 3b–3d quickly (challenges are short-lived).
> - `409 Conflict` — this public key already has a wallet. Reuse the existing wallet id.

---

## 4. Fund the wallet via Friendbot

Testnet accounts must be funded before they can receive payments. Friendbot is Stellar's testnet faucet.

```bash
curl -sS "https://friendbot.stellar.org?addr=$PUBLIC_KEY" | jq
```

**Expected response** (`200 OK`):

```json
{
  "hash": "...",
  "ledger": 123456,
  "successful": true
}
```

Confirm the account now exists:

```bash
curl -sS "https://horizon-testnet.stellar.org/accounts/$PUBLIC_KEY" | jq '.balances'
```

You should see a native (XLM) balance of `10000.0000000`.

> **Troubleshooting**
> - Friendbot `400` with "account already funded" — fine, skip ahead.
> - Horizon `404` — funding hasn't propagated yet; wait a few seconds and retry.

---

## 5. Generate a deposit address

```bash
curl -sS -X POST "$API/v1/wallets/$WALLET_ID/addresses" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"asset":"native"}' | jq
```

**Expected response** (`201 Created`):

```json
{
  "id": "addr_01H...",
  "wallet_id": "wal_01H...",
  "address": "M...",
  "memo": null,
  "asset": "native",
  "created_at": "2024-04-05T12:31:00Z"
}
```

Save the deposit address (a **muxed** `M...` address):

```bash
export DEPOSIT_ADDRESS="<paste address>"
```

> **Troubleshooting**
> - `404 Not Found` — wrong `$WALLET_ID`; re-check step 3d.
> - `422` — unsupported `asset`; use `"native"` for XLM.

---

## 6. Send a testnet payment to the deposit address

Send a small amount of XLM from your funded wallet to the muxed deposit address. The helper below signs and submits a payment using your secret key.

```bash
node -e '
const { Keypair, Horizon, TransactionBuilder, Operation, Asset, Networks } = require("@stellar/stellar-sdk");
(async () => {
  const server = new Horizon.Server("https://horizon-testnet.stellar.org");
  const source = Keypair.fromSecret(process.env.SECRET_KEY);
  const account = await server.loadAccount(source.publicKey());
  const tx = new TransactionBuilder(account, { fee: "100", networkPassphrase: Networks.TESTNET })
    .addOperation(Operation.payment({
      destination: process.env.DEPOSIT_ADDRESS,
      asset: Asset.native(),
      amount: "1.0000000"
    }))
    .setTimeout(30)
    .build();
  tx.sign(source);
  const res = await server.submitTransaction(tx);
  console.log("TX_HASH=" + res.hash);
})().catch(e => { console.error(e.response ? e.response.data : e); process.exit(1); });
'
```

**Expected output:**

```
TX_HASH=abc123...
```

> **Troubleshooting**
> - `op_underfunded` — wallet not funded; re-run step 4.
> - `tx_bad_seq` — stale sequence; just re-run the command.
> - `op_no_destination` — the deposit address isn't recognized yet; wait a moment and retry.

The deposit should be detected within a few seconds. Confirm it was credited:

```bash
curl -sS "$API/v1/wallets/$WALLET_ID/deposits" \
  -H "Authorization: Bearer $TOKEN" | jq
```

**Expected response** (`200 OK`):

```json
{
  "data": [
    {
      "id": "dep_01H...",
      "wallet_id": "wal_01H...",
      "address": "M...",
      "amount": "1.0000000",
      "asset": "native",
      "tx_hash": "abc123...",
      "status": "confirmed",
      "created_at": "2024-04-05T12:32:00Z"
    }
  ]
}
```

---

## 7. Register a webhook and observe a signed delivery

### 7a. Start a local listener

In a **separate terminal**, start a tiny server that prints incoming requests and their signature header:

```bash
node -e '
const http = require("http");
http.createServer((req, res) => {
  let body = "";
  req.on("data", c => body += c);
  req.on("end", () => {
    console.log("--- webhook received ---");
    console.log("signature:", req.headers["x-webhook-signature"]);
    console.log("body:", body);
    res.writeHead(200); res.end("ok");
  });
}).listen(4000, () => console.log("listening on :4000"));
'
```

Expose it to the internet (the API must reach it). Use any tunnel, e.g.:

```bash
# in another terminal
npx localtunnel --port 4000
# or: ngrok http 4000
```

Note the public HTTPS URL, e.g. `https://your-tunnel.loca.lt`.

```bash
export WEBHOOK_URL="<public tunnel URL>/webhook"
```

### 7b. Register the webhook

```bash
curl -sS -X POST "$API/v1/wallets/$WALLET_ID/webhooks" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"url\":\"$WEBHOOK_URL\",
    \"events\":[\"deposit.confirmed\"]
  }" | jq
```

**Expected response** (`201 Created`):

```json
{
  "id": "whk_01H...",
  "wallet_id": "wal_01H...",
  "url": "https://your-tunnel.loca.lt/webhook",
  "events": ["deposit.confirmed"],
  "secret": "whsec_...",
  "status": "active",
  "created_at": "2024-04-05T12:33:00Z"
}
```

Save the signing secret:

```bash
export WEBHOOK_SECRET="<paste secret>"
```

> **Security:** the `secret` is shown once. Store it; you'll use it to verify signatures.

### 7c. Trigger a delivery

Send another payment (repeat step 6). Within a few seconds your listener terminal should print:

```
--- webhook received ---
signature: t=1712345678,v1=5f3a...
body: {"id":"evt_01H...","type":"deposit.confirmed","data":{"deposit_id":"dep_01H...","wallet_id":"wal_01H...","amount":"1.0000000","asset":"native","tx_hash":"def456..."}}
```

### 7d. Verify the signature

The `x-webhook-signature` header has the form `t=<timestamp>,v1=<hex>`. The signed payload is `<timestamp>.<raw_body>`, HMAC-SHA256'd with your `$WEBHOOK_SECRET`. Verify it:

```bash
node -e '
const crypto = require("crypto");
const [tPart, vPart] = process.env.SIG.split(",");
const t = tPart.split("=")[1];
const v1 = vPart.split("=")[1];
const expected = crypto.createHmac("sha256", process.env.WEBHOOK_SECRET)
  .update(t + "." + process.env.BODY).digest("hex");
console.log(expected === v1 ? "SIGNATURE OK" : "SIGNATURE MISMATCH");
'
```

Set `SIG` and `BODY` from the listener output before running. You should see `SIGNATURE OK`.

> **Troubleshooting**
> - No delivery — confirm the tunnel URL is publicly reachable (`curl $WEBHOOK_URL` from outside), and that the webhook `status` is `active`.
> - `SIGNATURE MISMATCH` — you hashed the wrong body (must be the **raw** bytes, not re-serialized JSON) or used the wrong secret.
> - `404` on registration — wrong `$WALLET_ID`.

---

## Done

You've completed the full flow: signup → verification → wallet creation → funding → deposit address → payment → signed webhook. You now have a working testnet integration to build on.

### Cleanup

- Delete the webhook: `curl -X DELETE "$API/v1/wallets/$WALLET_ID/webhooks/<webhook_id>" -H "Authorization: Bearer $TOKEN"`
- Stop the listener and tunnel with `Ctrl+C`.
- Discard the testnet keypair; it holds no real value.