//! Error type for octo-evm-rpc.
//!
//! JSON-RPC is a trap: a node returns HTTP 200 with an `error` member for everything from a bad
//! request to a reverted call. [`RpcError`] keeps transport failure, protocol-level JSON-RPC
//! error, and execution revert as distinct variants so callers never have to guess which one they
//! got from a bare `Err`.

/// Errors returned by octo-evm-rpc operations.
#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    /// A network-level failure: connection refused, timed out, TLS error, or an HTTP 5xx. Worth
    /// retrying on read-only calls — see [`octo_resilience::CallKind`].
    #[error("transport error")]
    Transport,

    /// The RPC endpoint returned a well-formed JSON-RPC `error` object that isn't one of the more
    /// specific variants below (bad params, method not found, internal error, ...).
    #[error("json-rpc error {code}: {message}")]
    JsonRpc { code: i64, message: String },

    /// The call reverted on-chain. `data` is the revert payload (ABI-encoded `Error(string)` or a
    /// custom error selector), hex-encoded, when the node returned one.
    #[error("execution reverted")]
    Revert { data: Option<String> },

    /// `eth_getLogs` was rejected because the requested block range exceeds this provider's cap
    /// (e.g. Alchemy's ~2k-block limit, Infura's ~10k). Surfaced as a distinct, typed error (not
    /// folded into the generic [`RpcError::JsonRpc`]) so a caller can adaptively bisect the range
    /// and retry with smaller windows instead of failing outright.
    #[error("requested block range exceeds this provider's limit")]
    RangeTooLarge,

    /// The endpoint is rate-limiting this client (HTTP 429, or a JSON-RPC error whose message
    /// indicates rate limiting). `retry_after` is the provider's `Retry-After` header value in
    /// seconds, when present.
    #[error("rate limited")]
    RateLimited { retry_after: Option<u64> },

    /// The circuit breaker is open — no network call was made.
    #[error("circuit breaker open")]
    CircuitOpen,

    /// The response body could not be parsed as a JSON-RPC envelope (malformed JSON, or a
    /// response with neither a `result` nor an `error` member).
    #[error("failed to decode RPC response")]
    Decode,

    /// The response body exceeded the configured size cap before it could be fully read. Guards
    /// against a malicious or compromised RPC endpoint returning an unbounded body.
    #[error("response body exceeded the size cap")]
    ResponseTooLarge,

    /// The client was constructed with a CAIP-2 chain id string this crate could not parse (must
    /// be `"eip155:<decimal chain id>"`).
    #[error("invalid CAIP-2 chain id: {0}")]
    InvalidChainId(String),

    /// [`crate::EvmRpcClient::assert_chain_id`] found that the RPC endpoint's `eth_chainId`
    /// does not match the chain id the client was configured for. A misconfigured RPC pointing at
    /// the wrong chain is a fund-loss bug (e.g. broadcasting a mainnet-intended transaction to a
    /// testnet endpoint or vice versa) — this must be checked at startup, before any real traffic.
    #[error("configured chain id eip155:{expected} does not match RPC-reported eip155:{actual}")]
    ChainIdMismatch { expected: u64, actual: u64 },
}

impl octo_resilience::Retriable for RpcError {
    fn is_retriable(&self) -> bool {
        // Mirrors crates/api/src/horizon.rs and crates/ingest/src/horizon.rs: only a transport
        // failure (network error, timeout, or 5xx) is transient. Everything else is a settled
        // answer for this request — retrying a JSON-RPC error, a revert, or a range-too-large
        // response would reproduce the identical failure and needlessly count toward opening the
        // circuit breaker.
        matches!(self, RpcError::Transport)
    }
}
