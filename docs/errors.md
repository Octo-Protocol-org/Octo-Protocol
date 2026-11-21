# Error Code Reference

This page catalogues every error returned by the API. Each entry corresponds to a
variant of the `ApiError` enum in `crates/api/src/error.rs`, and lists its HTTP
status, meaning, and the remedy an integrator should apply.

> **Note:** This list is checked against the `ApiError` enum. When a variant is
> added, removed, or its status changes, this document must be updated in the same
> change. The enum is the source of truth.

## `ApiError` variants

| Variant | HTTP status | Meaning | Remedy |
| --- | --- | --- | --- |
| `BadRequest` | 400 Bad Request | The request was malformed or failed validation (bad parameters, invalid payload, unparseable input). | Fix the request body, query parameters, or headers. Do not retry unchanged. |
| `Unauthorized` | 401 Unauthorized | Authentication is missing or invalid (absent/expired/bad credentials or token). | Supply valid credentials or refresh the token, then retry. |
| `Forbidden` | 403 Forbidden | The caller is authenticated but not permitted to perform this action. | Use an identity with the required permissions. Retrying will not help. |
| `NotFound` | 404 Not Found | The addressed resource does not exist (or is not visible to the caller). | Verify the identifier/path. Do not retry unchanged. |
| `Conflict` | 409 Conflict | The request conflicts with the current state of the resource (e.g. duplicate create, illegal state transition). | Re-read the resource, reconcile state, and retry only if the operation is still valid. |
| `ConflictWith` | 409 Conflict | The request conflicts with a specific existing resource; the response identifies the conflicting entity. | Inspect the conflicting resource in the response, resolve the overlap, then retry. |
| `Gone` | 410 Gone | The resource existed but has been permanently removed and is no longer available. | Stop requesting this resource; treat it as deleted. |
| `TooManyRequests` | 429 Too Many Requests | A rate limit or quota has been exceeded. | Back off with exponential delay and retry. No `Retry-After` header is guaranteed; the API does not currently set one. |
| `StaleSequence` | 400 Bad Request | The supplied sequence number is stale or out of order relative to the current state. | Re-fetch the latest state/sequence and retry with the current value. |
| `Internal` | 500 Internal Server Error | An unexpected server-side failure occurred. | Retry with backoff; if it persists, contact support with the request ID. |
| `GatewayTimeout` | 504 Gateway Timeout | An upstream dependency did not respond in time. | Retry with backoff; the operation may or may not have completed, so reconcile state first where relevant. |
| `ServiceUnavailable` | 503 Service Unavailable | A dependency needed to make a safe decision (e.g. Horizon) is unavailable. | Retry with backoff; no state was changed. |

## Error mappings

Some errors originate in lower layers and are converted into `ApiError` via `From`
implementations. The resulting HTTP status is shown below.

### `From<StoreError>`

| `StoreError` | Resulting `ApiError` | HTTP status |
| --- | --- | --- |
| `Conflict` | `Conflict` | 409 Conflict |
| `NotFound` | `NotFound` | 404 Not Found |
| `WalletArchived` | `Forbidden` | 403 Forbidden |
| `InvalidMemoId` | `BadRequest` | 400 Bad Request |
| `BudgetExceeded` | `TooManyRequests` | 429 Too Many Requests |
| `DuplicateCustomerRef` | `ConflictWith` | 409 Conflict |
| All other variants (database, migration, audit chain) | `Internal` | 500 Internal Server Error |

### `From<WalletError>`

| `WalletError` | Resulting `ApiError` | HTTP status |
| --- | --- | --- |
| `InvalidMnemonic`, `InvalidChecksum`, `InvalidAddress`, `InvalidAssetCode`, `InvalidAmount`, `InvalidDerivationPath`, `InvalidXdr`, `InvalidSignature`, `InvalidSeedLength`, `WeakSeed`, `MnemonicAccountMismatch` | `BadRequest` | 400 Bad Request |
| `ReservedNativeAssetCode` | `BadRequest` | 400 Bad Request |
| `StaleSequence` | `StaleSequence` | 400 Bad Request |
| `KeyDerivation`, `Signing`, `SeedDecryption` | `Internal` | 500 Internal Server Error |

## Request body size limit

Requests whose body exceeds the configured maximum size are rejected with
**413 Payload Too Large** before reaching the handler. Reduce the payload size or
split the request into smaller ones.