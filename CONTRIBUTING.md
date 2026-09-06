# Contributing to octo

Thanks for your interest! This project is built incrementally and values correctness and
security over speed (it handles crypto keys).

## Development setup

- **Rust 1.84.1** — pinned via `rust-toolchain.toml`; `rustup` will install it automatically.
- **Docker** — for the local Postgres (`docker compose up -d db`).
- **just** — task runner (`cargo install just`), optional but recommended.

```bash
cp .env.example .env
just build && just test
```

## Before opening a PR

Run the same checks CI runs:

```bash
just fmt        # cargo fmt
just lint       # cargo clippy -- -D warnings
just test       # cargo test
cargo deny check   # licenses + advisories (cargo install cargo-deny)
```

All of `fmt --check`, `clippy -D warnings`, and the test suite must pass.

> **Troubleshooting `E0514: found crate X compiled by an incompatible version of rustc`.**
> This appears when `target/` holds artifacts from two different `rustc` builds that share a
> version string but not their internal metadata format — e.g. a system `/usr/bin/rustc` vs. a
> rustup-managed toolchain, or after running `cargo clippy` (whose `clippy-driver` writes rmeta a
> plain `rustc` build then rejects). **Fix: `cargo clean && cargo test --workspace`** — a single
> clean rebuild makes all artifacts come from one toolchain. To avoid it: use one `cargo`
> consistently, and don't run `cargo clippy` locally on source-tarball toolchains (clippy is
> enforced in CI on an official toolchain). `cargo build`/`test`/`fmt` are otherwise unaffected.

## Conventions

- **Commits:** [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`,
  `docs:`, `refactor:`, `test:`, `chore:`).
- **Secrets:** never log seeds, private keys, or decrypted material. Secret-bearing types live in
  `wallet-core` and must `zeroize` on drop.
- **Tests:** crypto and derivation code must include test vectors (e.g. SEP-0005).

## Branching

Work on a feature branch; open a PR against `main`. CI must be green before merge.
