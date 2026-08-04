# Octo API — Bruno collection

Manual + repeatable testing for every route in the API. Free, open-source, no account needed:
https://www.usebruno.com

## Setup

1. Install Bruno (desktop app, or `npm i -g @usebruno/cli` for the `bru` CLI).
2. Open this `api-tests/` folder as a collection in Bruno.
3. Pick an environment top-right: **Local** (`http://localhost:8080`, needs the backend running
   with `cargo run -p octo-server`) or **Production** (the live Render deploy).

## Suggested run order

1. **Auth → Signup** — creates a user, auto-saves `token`.
2. **Wallets → Get Ownership Challenge** — then run
   `node api-tests/scripts/sign-challenge.js "<challenge>"` (see that script's own README below)
   to get a signed body, paste it into **Wallets → Create Wallet**, run it. Auto-saves
   `wallet_id`.
3. From there every other request under Wallets/Addresses/Payment Links/Webhooks/Sponsorship/
   Whitelist just works — they all read `{{token}}` and `{{wallet_id}}`.
4. **Payment Links → Create Payment Link** auto-saves `link_slug`/`checkout_url`/`link_id`.
   Open `checkout_url` in a browser to see the real hosted pay page.
5. **Payment Links → Public - ...** requests exercise the same flow a real payer's browser
   would, with no auth — this is what a developer integrating checkout actually calls.

## Why some requests can't just be "run"

`Create Wallet` and `Public - Submit Signed` both require an ed25519 signature made with a
Stellar secret key Octo never sees (that's the point — it's non-custodial). Bruno has no
built-in Stellar signer, so:

- `api-tests/scripts/sign-challenge.js` — run `npm install` once in `api-tests/scripts/`, then
  `node sign-challenge.js "<challenge>"` to generate a keypair, sign it, and print a ready body
  for Create Wallet.
- `Public - Submit Signed` is documented for reference; actually driving it means building +
  signing a transaction with a Stellar SDK, which is exactly what the hosted checkout page's
  Freighter integration already does in the browser.

## What "easy to integrate" looks like

The **Payment Links** folder is the fastest way to answer "could a developer actually build a
checkout with this": create a link with an API key (no dashboard login needed —
`Generate API Key` under Wallets), get back a real `url`, and everything under `Public - *`
is what fires behind that URL with zero auth. See `/docs/checkout` on the frontend for the
narrative version of this same flow.
