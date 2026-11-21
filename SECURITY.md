# Security Policy

octo handles cryptographic seed material and signs blockchain transactions. We take security
seriously and appreciate responsible disclosure.

## Reporting a vulnerability

**Do not open a public GitHub issue for security reports.**

Report privately via GitHub's [private vulnerability reporting](https://github.com/octo/octo/security/advisories/new)
or email the project-owned mailbox **security@octo.dev** with:

- a description of the issue and its impact,
- steps to reproduce or a proof of concept,
- any suggested remediation.

We aim to acknowledge within **48 hours** and to provide a remediation timeline within
**7 days**. Please give us a reasonable window to fix the issue before public disclosure.

## Scope

In scope: key management, the signing path, seed encryption, deposit attribution, withdrawal
authorization, webhook signing, and API authentication.

## Security model (summary)

- The HD seed is stored **AES-256-GCM encrypted at rest** with a random nonce + salt; the master
  key comes from a KMS/secret manager (an env var only in development).
- The seed is decrypted **in-memory only**, inside the `wallet-core` crate, at signing time, and
  is **zeroized** immediately after. It is never written to disk or logs.
- Private keys are **derived on demand** (SEP-0005) and never persisted.

See [docs/architecture.md](docs/architecture.md) for details.

### Deployment responsibilities

Some controls only hold if the deployment is configured correctly. The following assumptions
are documented in full, with their owners and verification checks, in
[docs/threat-model.md](docs/threat-model.md).

- **Trusted proxies** — the deployment operator owns `TRUSTED_PROXY_CIDRS` and must keep it in
  sync with the real ingress CIDRs. If it is wrong, client IPs (and therefore rate-limit keys)
  can be spoofed via `X-Forwarded-For`.
- **Rate limiting** — the deployment operator must set `RATE_LIMIT_BACKEND=postgres` in any
  multi-replica deployment. The default per-process limiter only enforces limits per replica,
  so the effective limit scales with replica count.
- **CORS** — the deployment operator owns `ALLOWED_ORIGINS` and must list exact origins; `*`
  is never acceptable for an authenticated API.
- **Code paths** — the API team owns the limiter and CORS implementations and the checks that
  verify these assumptions at deploy time.

See [docs/threat-model.md](docs/threat-model.md) for the full assumptions and their
verification checks.