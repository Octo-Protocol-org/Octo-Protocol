#!/usr/bin/env node
// Generates a Stellar keypair, signs an ownership challenge, and prints a ready-to-paste
// Create Wallet request body. Run: node sign-challenge.js "<challenge from Get Ownership Challenge>"
//
// Setup: npm install (in this scripts/ directory) once, first.

import { Keypair } from "@stellar/stellar-base";

const challenge = process.argv[2];
if (!challenge) {
  console.error('Usage: node sign-challenge.js "<challenge>"');
  console.error(
    "Get <challenge> from the Get Ownership Challenge request's response (data.challenge).",
  );
  process.exit(1);
}

const kp = Keypair.random();
const signature = kp.sign(Buffer.from(challenge)).toString("base64");

console.log("Public key (save this — you'll need it to sign future transactions too):");
console.log("  " + kp.publicKey());
console.log("Secret key (KEEP PRIVATE — Octo is non-custodial, it never sees this):");
console.log("  " + kp.secret());
console.log();
console.log("Paste this as the Create Wallet request body:");
console.log(
  JSON.stringify(
    {
      public_key: kp.publicKey(),
      challenge,
      signature,
      label: "test wallet",
    },
    null,
    2,
  ),
);
