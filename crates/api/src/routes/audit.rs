//! Audit log listing.

use crate::auth::authenticate;
use crate::error::{internal, ApiError, ApiResult, Envelope};
use crate::state::AppState;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::Json;
use serde::Deserialize;

/// Maximum length of the audit log search parameter.
const AUDIT_SEARCH_MAX: usize = 100;
/// Maximum number of audit log rows returned per request.
const AUDIT_LIST_LIMIT: i64 = 200;

#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    /// Filter by category (authentication, wallet, address, credentials, configuration).
    pub category: Option<String>,
    /// Case-insensitive search over action/target.
    pub search: Option<String>,
}

/// `GET /v1/audit-logs` — the authenticated user's activity, newest first.
pub async fn list_audit_logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<AuditQuery>,
) -> ApiResult<Json<Envelope<Vec<octo_store::AuditLog>>>> {
    let user_id = authenticate(&headers, &state).await?;
    let category = match q.category.filter(|c| !c.is_empty() && c != "all") {
        Some(cat) => {
            if !crate::audit::category::ALL.contains(&cat.as_str()) {
                return Err(ApiError::BadRequest(format!(
                    "invalid category filter '{}'; valid categories are: {}",
                    cat,
                    crate::audit::category::ALL.join(", ")
                )));
            }
            Some(cat)
        }
        None => None,
    };
    let search = match q.search.filter(|s| !s.is_empty()) {
        Some(s) => {
            let trimmed = s.trim();
            if trimmed.chars().count() > AUDIT_SEARCH_MAX {
                return Err(ApiError::BadRequest(format!(
                    "search parameter exceeds maximum length of {} characters",
                    AUDIT_SEARCH_MAX
                )));
            }
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
        None => None,
    };

    let rows = state
        .store()
        .list_audit_logs(
            user_id,
            category.as_deref(),
            search.as_deref(),
            AUDIT_LIST_LIMIT,
        )
        .await
        .map_err(internal)?;
    Ok(Envelope::ok(rows))
}