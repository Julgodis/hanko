use axum::{
    Json, Router,
    extract::{ConnectInfo, Extension, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::net::SocketAddr;
use uuid::Uuid;

use crate::{
    http::AppState,
    security::{
        BrowserSession, create_session, csrf_header_matches, digest, load_session, origin_is_valid,
        random_secret, set_session_cookies, source_ip, try_anonymous_state_slot, unix_now,
    },
};

const MAX_INVITATION_SECONDS: i64 = 10 * 365 * 24 * 60 * 60;

#[derive(Deserialize)]
struct CreateInvitation {
    label: String,
    email: Option<String>,
    max_uses: i64,
    expires_in: i64,
    expires_unit: String,
    #[serde(default)]
    groups: Vec<String>,
}

#[derive(Serialize)]
struct CreatedInvitation {
    id: String,
    enrollment_url: String,
    expires_at: i64,
}

#[derive(Deserialize)]
struct CreateGroup {
    name: String,
    display_name: String,
}

#[derive(Deserialize)]
struct CreateClient {
    name: String,
    client_type: String,
    #[serde(default)]
    token_endpoint_auth_method: Option<String>,
    redirect_uris: Vec<String>,
    #[serde(default)]
    post_logout_redirect_uris: Vec<String>,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    allowed_groups: Vec<String>,
    #[serde(default)]
    claims: Vec<ClaimMappingInput>,
}

#[derive(Deserialize)]
struct UpdateClient {
    name: String,
    enabled: bool,
    redirect_uris: Vec<String>,
    #[serde(default)]
    post_logout_redirect_uris: Vec<String>,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    allowed_groups: Vec<String>,
    #[serde(default)]
    claims: Vec<ClaimMappingInput>,
}

#[derive(Deserialize)]
struct ClaimMappingInput {
    claim_name: String,
    user_attribute_path: String,
    required_scope: Option<String>,
}

#[derive(Deserialize)]
struct ConsumeInvitation {
    token: String,
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
}

struct AdminError(StatusCode, &'static str);

impl AdminError {
    fn bad_request(message: &'static str) -> Self {
        Self(StatusCode::BAD_REQUEST, message)
    }
    fn unauthorized() -> Self {
        Self(StatusCode::UNAUTHORIZED, "authentication required")
    }
    fn forbidden() -> Self {
        Self(StatusCode::FORBIDDEN, "request rejected")
    }
    fn conflict(message: &'static str) -> Self {
        Self(StatusCode::CONFLICT, message)
    }
    fn not_found() -> Self {
        Self(StatusCode::NOT_FOUND, "client not found")
    }
    fn internal() -> Self {
        Self(StatusCode::INTERNAL_SERVER_ERROR, "internal server error")
    }
    fn rate_limited() -> Self {
        Self(
            StatusCode::TOO_MANY_REQUESTS,
            "too many requests; try again shortly",
        )
    }
}

impl IntoResponse for AdminError {
    fn into_response(self) -> Response {
        (self.0, Json(ErrorBody { error: self.1 })).into_response()
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/admin/users", get(list_users))
        .route(
            "/api/admin/invitations",
            get(list_invitations).post(create_invitation),
        )
        .route(
            "/api/admin/invitations/{id}/revoke",
            post(revoke_invitation),
        )
        .route("/api/admin/groups", get(list_groups).post(create_group))
        .route("/api/admin/clients", get(list_clients).post(create_client))
        .route(
            "/api/admin/clients/{client_id}",
            put(update_client).delete(delete_client),
        )
        .route(
            "/api/admin/signing-keys",
            get(list_signing_keys).post(rotate_signing_key),
        )
        .route("/api/invitations/consume", post(consume_invitation))
}

async fn list_users(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, AdminError> {
    let _admin = require_admin(&state, &headers, false).await?;
    let rows = sqlx::query("SELECT id, username, display_name, email, attributes, invitation_label, is_admin, disabled_at, created_at FROM users ORDER BY username")
        .fetch_all(&state.database.pool)
        .await
        .map_err(|_| AdminError::internal())?;
    let mut users = Vec::with_capacity(rows.len());
    for row in rows {
        let attributes: String = row
            .try_get("attributes")
            .map_err(|_| AdminError::internal())?;
        let id: String = row.try_get("id").map_err(|_| AdminError::internal())?;
        users.push(serde_json::json!({
            "id": id,
            "username": row.try_get::<String, _>("username").map_err(|_| AdminError::internal())?,
            "display_name": row.try_get::<String, _>("display_name").map_err(|_| AdminError::internal())?,
            "email": row.try_get::<Option<String>, _>("email").map_err(|_| AdminError::internal())?,
            "invitation_label": row.try_get::<Option<String>, _>("invitation_label").map_err(|_| AdminError::internal())?,
            "attributes": serde_json::from_str::<Value>(&attributes).map_err(|_| AdminError::internal())?,
            "is_admin": row.try_get::<bool, _>("is_admin").map_err(|_| AdminError::internal())?,
            "disabled": row.try_get::<Option<i64>, _>("disabled_at").map_err(|_| AdminError::internal())?.is_some(),
            "created_at": row.try_get::<i64, _>("created_at").map_err(|_| AdminError::internal())?,
            "groups": user_group_names(&state, &id).await?,
        }));
    }
    Ok(Json(Value::Array(users)))
}

async fn list_invitations(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, AdminError> {
    let _admin = require_admin(&state, &headers, false).await?;
    let rows = sqlx::query("SELECT id, label, email, max_uses, use_count, created_at, expires_at, revoked_at FROM invitation_links ORDER BY created_at DESC")
        .fetch_all(&state.database.pool)
        .await
        .map_err(|_| AdminError::internal())?;
    let invitations = rows
        .into_iter()
        .map(|row| {
            Ok(serde_json::json!({
                "id": row.try_get::<String, _>("id").map_err(|_| AdminError::internal())?,
                "label": row.try_get::<String, _>("label").map_err(|_| AdminError::internal())?,
                "email": row.try_get::<Option<String>, _>("email").map_err(|_| AdminError::internal())?,
                "max_uses": row.try_get::<i64, _>("max_uses").map_err(|_| AdminError::internal())?,
                "use_count": row.try_get::<i64, _>("use_count").map_err(|_| AdminError::internal())?,
                "created_at": row.try_get::<i64, _>("created_at").map_err(|_| AdminError::internal())?,
                "expires_at": row.try_get::<i64, _>("expires_at").map_err(|_| AdminError::internal())?,
                "revoked": row.try_get::<Option<i64>, _>("revoked_at").map_err(|_| AdminError::internal())?.is_some(),
            }))
        })
        .collect::<Result<Vec<_>, AdminError>>()?;
    Ok(Json(Value::Array(invitations)))
}

async fn create_invitation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreateInvitation>,
) -> Result<Json<CreatedInvitation>, AdminError> {
    let _admin = require_admin(&state, &headers, true).await?;
    let label = input.label.trim();
    if label.is_empty() || label.len() > 80 {
        return Err(AdminError::bad_request("invalid invitation label"));
    }
    if !(1..=500).contains(&input.max_uses) {
        return Err(AdminError::bad_request(
            "user limit must be between 1 and 500",
        ));
    }
    let unit_seconds = match input.expires_unit.as_str() {
        "seconds" => 1,
        "minutes" => 60,
        "hours" => 60 * 60,
        "days" => 24 * 60 * 60,
        "years" => 365 * 24 * 60 * 60,
        _ => return Err(AdminError::bad_request("invalid expiry unit")),
    };
    let expires_in_seconds = input
        .expires_in
        .checked_mul(unit_seconds)
        .filter(|duration| *duration > 0 && *duration <= MAX_INVITATION_SECONDS)
        .ok_or_else(|| AdminError::bad_request("expiry must be between 1 second and 10 years"))?;
    let email = input
        .email
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if email.is_some_and(|value| value.len() > 320 || !value.contains('@')) {
        return Err(AdminError::bad_request("invalid email"));
    }
    if email.is_some() && input.max_uses != 1 {
        return Err(AdminError::bad_request(
            "email invitations can only be used once",
        ));
    }

    let mut groups = input.groups;
    groups.sort();
    groups.dedup();
    let mut transaction = state
        .database
        .pool
        .begin()
        .await
        .map_err(|_| AdminError::internal())?;
    if let Some(email) = email {
        let already_used: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE email = ?)")
                .bind(email)
                .fetch_one(&mut *transaction)
                .await
                .map_err(|_| AdminError::internal())?;
        if already_used {
            return Err(AdminError::conflict("email already belongs to an account"));
        }
    }
    for group in &groups {
        let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM groups WHERE name = ?)")
            .bind(group)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| AdminError::internal())?;
        if !exists {
            return Err(AdminError::bad_request("unknown group"));
        }
    }

    let id = Uuid::new_v4().to_string();
    let token = random_secret();
    let now = unix_now();
    let expires_at = now + expires_in_seconds;
    sqlx::query("INSERT INTO invitation_links (id, token_hash, label, email, group_names, max_uses, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
        .bind(&id)
        .bind(digest(&token))
        .bind(label)
        .bind(email)
        .bind(serde_json::to_string(&groups).map_err(|_| AdminError::internal())?)
        .bind(input.max_uses)
        .bind(now)
        .bind(expires_at)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AdminError::internal())?;
    transaction
        .commit()
        .await
        .map_err(|_| AdminError::internal())?;

    Ok(Json(CreatedInvitation {
        id,
        enrollment_url: format!("{}/?enroll={token}", state.config.issuer()),
        expires_at,
    }))
}

async fn revoke_invitation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, AdminError> {
    let _admin = require_admin(&state, &headers, true).await?;
    let result = sqlx::query(
        "UPDATE invitation_links SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
    )
    .bind(unix_now())
    .bind(id)
    .execute(&state.database.pool)
    .await
    .map_err(|_| AdminError::internal())?;
    if result.rows_affected() == 0 {
        return Err(AdminError::conflict(
            "invitation is already revoked or unavailable",
        ));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn list_groups(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, AdminError> {
    let _admin = require_admin(&state, &headers, false).await?;
    let rows = sqlx::query("SELECT id, name, display_name, created_at FROM groups ORDER BY name")
        .fetch_all(&state.database.pool)
        .await
        .map_err(|_| AdminError::internal())?;
    let mut groups = Vec::with_capacity(rows.len());
    for row in rows {
        let id: String = row.try_get("id").map_err(|_| AdminError::internal())?;
        let members: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM user_groups WHERE group_id = ?")
                .bind(&id)
                .fetch_one(&state.database.pool)
                .await
                .map_err(|_| AdminError::internal())?;
        groups.push(serde_json::json!({
            "id": id,
            "name": row.try_get::<String, _>("name").map_err(|_| AdminError::internal())?,
            "display_name": row.try_get::<String, _>("display_name").map_err(|_| AdminError::internal())?,
            "member_count": members,
        }));
    }
    Ok(Json(Value::Array(groups)))
}

async fn create_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreateGroup>,
) -> Result<Json<Value>, AdminError> {
    let _admin = require_admin(&state, &headers, true).await?;
    let name =
        normalize_name(&input.name).ok_or_else(|| AdminError::bad_request("invalid group name"))?;
    let display_name = input.display_name.trim();
    if display_name.is_empty() || display_name.len() > 120 {
        return Err(AdminError::bad_request("invalid group display name"));
    }
    let id = Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO groups (id, name, display_name, created_at) VALUES (?, ?, ?, ?)")
        .bind(&id)
        .bind(&name)
        .bind(display_name)
        .bind(unix_now())
        .execute(&state.database.pool)
        .await
        .map_err(|_| AdminError::conflict("group already exists"))?;
    Ok(Json(
        serde_json::json!({ "id": id, "name": name, "display_name": display_name }),
    ))
}

async fn list_clients(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, AdminError> {
    let _admin = require_admin(&state, &headers, false).await?;
    let rows =
        sqlx::query("SELECT client_id, name, client_type, token_endpoint_auth_method, enabled FROM oidc_clients ORDER BY name")
            .fetch_all(&state.database.pool)
            .await
            .map_err(|_| AdminError::internal())?;
    let mut clients = Vec::with_capacity(rows.len());
    for row in rows {
        let client_id: String = row
            .try_get("client_id")
            .map_err(|_| AdminError::internal())?;
        let redirects: Vec<String> = sqlx::query_scalar(
            "SELECT uri FROM client_redirect_uris WHERE client_id = ? ORDER BY uri",
        )
        .bind(&client_id)
        .fetch_all(&state.database.pool)
        .await
        .map_err(|_| AdminError::internal())?;
        let scopes: Vec<String> = sqlx::query_scalar(
            "SELECT scope FROM client_scopes WHERE client_id = ? ORDER BY scope",
        )
        .bind(&client_id)
        .fetch_all(&state.database.pool)
        .await
        .map_err(|_| AdminError::internal())?;
        let groups: Vec<String> = sqlx::query_scalar("SELECT g.name FROM groups g JOIN client_allowed_groups cg ON cg.group_id = g.id WHERE cg.client_id = ? ORDER BY g.name")
            .bind(&client_id).fetch_all(&state.database.pool).await.map_err(|_| AdminError::internal())?;
        let post_logout_redirect_uris: Vec<String> = sqlx::query_scalar(
            "SELECT uri FROM client_post_logout_uris WHERE client_id = ? ORDER BY uri",
        )
        .bind(&client_id)
        .fetch_all(&state.database.pool)
        .await
        .map_err(|_| AdminError::internal())?;
        let claim_rows = sqlx::query("SELECT claim_name, user_attribute_path, required_scope FROM client_claim_mappings WHERE client_id = ? ORDER BY claim_name")
            .bind(&client_id)
            .fetch_all(&state.database.pool)
            .await
            .map_err(|_| AdminError::internal())?;
        let claims = claim_rows
            .into_iter()
            .map(|claim| {
                Ok(serde_json::json!({
                    "claim_name": claim.try_get::<String, _>("claim_name").map_err(|_| AdminError::internal())?,
                    "user_attribute_path": claim.try_get::<String, _>("user_attribute_path").map_err(|_| AdminError::internal())?,
                    "required_scope": claim.try_get::<Option<String>, _>("required_scope").map_err(|_| AdminError::internal())?,
                }))
            })
            .collect::<Result<Vec<_>, AdminError>>()?;
        let user_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM client_users WHERE client_id = ?")
                .bind(&client_id)
                .fetch_one(&state.database.pool)
                .await
                .map_err(|_| AdminError::internal())?;
        clients.push(serde_json::json!({
            "client_id": client_id,
            "name": row.try_get::<String, _>("name").map_err(|_| AdminError::internal())?,
            "client_type": row.try_get::<String, _>("client_type").map_err(|_| AdminError::internal())?,
            "token_endpoint_auth_method": row.try_get::<String, _>("token_endpoint_auth_method").map_err(|_| AdminError::internal())?,
            "enabled": row.try_get::<bool, _>("enabled").map_err(|_| AdminError::internal())?,
            "redirect_uris": redirects,
            "post_logout_redirect_uris": post_logout_redirect_uris,
            "scopes": scopes,
            "allowed_groups": groups,
            "claims": claims,
            "user_count": user_count,
        }));
    }
    Ok(Json(Value::Array(clients)))
}

async fn create_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreateClient>,
) -> Result<Json<Value>, AdminError> {
    let _admin = require_admin(&state, &headers, true).await?;
    let name = input.name.trim();
    if name.is_empty() || name.len() > 120 {
        return Err(AdminError::bad_request("invalid client name"));
    }
    if !matches!(input.client_type.as_str(), "public" | "confidential") {
        return Err(AdminError::bad_request("invalid client type"));
    }
    let expected_auth_method = match input.client_type.as_str() {
        "public" => "none",
        "confidential" => "client_secret_post",
        _ => unreachable!(),
    };
    let auth_method = input
        .token_endpoint_auth_method
        .as_deref()
        .unwrap_or(expected_auth_method);
    if auth_method != expected_auth_method {
        return Err(AdminError::bad_request(
            "client authentication method does not match client type",
        ));
    }
    if input.redirect_uris.is_empty() || input.redirect_uris.len() > 50 {
        return Err(AdminError::bad_request(
            "at least one redirect URI is required",
        ));
    }
    if input
        .redirect_uris
        .iter()
        .any(|uri| !valid_registered_uri(uri))
        || input
            .post_logout_redirect_uris
            .iter()
            .any(|uri| !valid_registered_uri(uri))
    {
        return Err(AdminError::bad_request(
            "redirect URIs must be absolute, fragment-free and use HTTPS (HTTP is allowed for loopback development)",
        ));
    }
    let mut scopes = input.scopes;
    if scopes.is_empty() {
        scopes.push("openid".to_owned());
    }
    if !scopes.iter().any(|scope| scope == "openid")
        || scopes.iter().any(|scope| {
            !matches!(
                scope.as_str(),
                "openid" | "profile" | "email" | "groups" | "offline_access"
            )
        })
    {
        return Err(AdminError::bad_request(
            "client scopes must include openid and use supported scopes",
        ));
    }
    scopes.sort();
    scopes.dedup();
    let mut transaction = state
        .database
        .pool
        .begin()
        .await
        .map_err(|_| AdminError::internal())?;
    let client_id = Uuid::new_v4().to_string();
    let secret = (input.client_type == "confidential").then(random_secret);
    let secret_hash = secret
        .as_deref()
        .map(|value| URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes())));
    sqlx::query("INSERT INTO oidc_clients (client_id, client_secret_hash, client_type, token_endpoint_auth_method, name, enabled, created_at) VALUES (?, ?, ?, ?, ?, 1, ?)")
        .bind(&client_id)
        .bind(secret_hash)
        .bind(&input.client_type)
        .bind(auth_method)
        .bind(name)
        .bind(unix_now())
        .execute(&mut *transaction)
        .await
        .map_err(|_| AdminError::internal())?;
    for uri in input.redirect_uris {
        sqlx::query("INSERT INTO client_redirect_uris (client_id, uri) VALUES (?, ?)")
            .bind(&client_id)
            .bind(uri)
            .execute(&mut *transaction)
            .await
            .map_err(|_| AdminError::internal())?;
    }
    for uri in input.post_logout_redirect_uris {
        sqlx::query("INSERT INTO client_post_logout_uris (client_id, uri) VALUES (?, ?)")
            .bind(&client_id)
            .bind(uri)
            .execute(&mut *transaction)
            .await
            .map_err(|_| AdminError::internal())?;
    }
    for scope in &scopes {
        sqlx::query("INSERT INTO client_scopes (client_id, scope) VALUES (?, ?)")
            .bind(&client_id)
            .bind(scope)
            .execute(&mut *transaction)
            .await
            .map_err(|_| AdminError::internal())?;
    }
    for group_name in &input.allowed_groups {
        let group_id: Option<String> = sqlx::query_scalar("SELECT id FROM groups WHERE name = ?")
            .bind(group_name)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|_| AdminError::internal())?;
        let Some(group_id) = group_id else {
            return Err(AdminError::bad_request("unknown allowed group"));
        };
        sqlx::query("INSERT INTO client_allowed_groups (client_id, group_id) VALUES (?, ?)")
            .bind(&client_id)
            .bind(group_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| AdminError::internal())?;
    }
    let mut seen_claims = std::collections::HashSet::new();
    for claim in input.claims {
        if !valid_claim_name(&claim.claim_name)
            || !seen_claims.insert(claim.claim_name.clone())
            || !valid_json_pointer(&claim.user_attribute_path)
        {
            return Err(AdminError::bad_request(
                "invalid or duplicate custom claim mapping",
            ));
        }
        if claim
            .required_scope
            .as_ref()
            .is_some_and(|scope| !scopes.contains(scope))
        {
            return Err(AdminError::bad_request(
                "claim scope is not enabled for this client",
            ));
        }
        sqlx::query("INSERT INTO client_claim_mappings (client_id, claim_name, user_attribute_path, required_scope) VALUES (?, ?, ?, ?)")
            .bind(&client_id).bind(claim.claim_name).bind(claim.user_attribute_path).bind(claim.required_scope)
            .execute(&mut *transaction).await.map_err(|_| AdminError::internal())?;
    }
    transaction
        .commit()
        .await
        .map_err(|_| AdminError::internal())?;
    Ok(Json(serde_json::json!({
        "client_id": client_id,
        "client_secret": secret,
        "name": name,
        "client_type": input.client_type,
        "token_endpoint_auth_method": auth_method,
        "scopes": scopes,
    })))
}

async fn update_client(
    State(state): State<AppState>,
    Path(client_id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<UpdateClient>,
) -> Result<StatusCode, AdminError> {
    let _admin = require_admin(&state, &headers, true).await?;
    let name = input.name.trim();
    if name.is_empty() || name.len() > 120 {
        return Err(AdminError::bad_request("invalid client name"));
    }
    if input.redirect_uris.is_empty() || input.redirect_uris.len() > 50 {
        return Err(AdminError::bad_request(
            "at least one redirect URI is required",
        ));
    }
    if input
        .redirect_uris
        .iter()
        .chain(input.post_logout_redirect_uris.iter())
        .any(|uri| !valid_registered_uri(uri))
    {
        return Err(AdminError::bad_request(
            "redirect URIs must be absolute, fragment-free and use HTTPS (HTTP is allowed for loopback development)",
        ));
    }
    let mut scopes = input.scopes;
    if scopes.is_empty() {
        scopes.push("openid".to_owned());
    }
    if !scopes.iter().any(|scope| scope == "openid")
        || scopes.iter().any(|scope| {
            !matches!(
                scope.as_str(),
                "openid" | "profile" | "email" | "groups" | "offline_access"
            )
        })
    {
        return Err(AdminError::bad_request(
            "client scopes must include openid and use supported scopes",
        ));
    }
    scopes.sort();
    scopes.dedup();
    let mut seen_claims = std::collections::HashSet::new();
    for claim in &input.claims {
        if !valid_claim_name(&claim.claim_name)
            || !seen_claims.insert(claim.claim_name.clone())
            || !valid_json_pointer(&claim.user_attribute_path)
        {
            return Err(AdminError::bad_request(
                "invalid or duplicate custom claim mapping",
            ));
        }
        if claim
            .required_scope
            .as_ref()
            .is_some_and(|scope| !scopes.contains(scope))
        {
            return Err(AdminError::bad_request(
                "claim scope is not enabled for this client",
            ));
        }
    }

    let mut transaction = state
        .database
        .pool
        .begin()
        .await
        .map_err(|_| AdminError::internal())?;
    let existing_client: Option<String> =
        sqlx::query_scalar("SELECT client_id FROM oidc_clients WHERE client_id = ?")
            .bind(&client_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|_| AdminError::internal())?;
    if existing_client.is_none() {
        return Err(AdminError::not_found());
    }
    sqlx::query("UPDATE oidc_clients SET name = ?, enabled = ? WHERE client_id = ?")
        .bind(name)
        .bind(input.enabled)
        .bind(&client_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AdminError::internal())?;

    for table in [
        "client_redirect_uris",
        "client_post_logout_uris",
        "client_scopes",
        "client_allowed_groups",
        "client_claim_mappings",
    ] {
        let query = format!("DELETE FROM {table} WHERE client_id = ?");
        sqlx::query(&query)
            .bind(&client_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| AdminError::internal())?;
    }
    for uri in input.redirect_uris {
        sqlx::query("INSERT INTO client_redirect_uris (client_id, uri) VALUES (?, ?)")
            .bind(&client_id)
            .bind(uri)
            .execute(&mut *transaction)
            .await
            .map_err(|_| AdminError::bad_request("duplicate redirect URI"))?;
    }
    for uri in input.post_logout_redirect_uris {
        sqlx::query("INSERT INTO client_post_logout_uris (client_id, uri) VALUES (?, ?)")
            .bind(&client_id)
            .bind(uri)
            .execute(&mut *transaction)
            .await
            .map_err(|_| AdminError::bad_request("duplicate post-logout redirect URI"))?;
    }
    for scope in &scopes {
        sqlx::query("INSERT INTO client_scopes (client_id, scope) VALUES (?, ?)")
            .bind(&client_id)
            .bind(scope)
            .execute(&mut *transaction)
            .await
            .map_err(|_| AdminError::internal())?;
    }
    for group_name in &input.allowed_groups {
        let group_id: Option<String> = sqlx::query_scalar("SELECT id FROM groups WHERE name = ?")
            .bind(group_name)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|_| AdminError::internal())?;
        let Some(group_id) = group_id else {
            return Err(AdminError::bad_request("unknown allowed group"));
        };
        sqlx::query("INSERT INTO client_allowed_groups (client_id, group_id) VALUES (?, ?)")
            .bind(&client_id)
            .bind(group_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| AdminError::internal())?;
    }
    for claim in input.claims {
        sqlx::query("INSERT INTO client_claim_mappings (client_id, claim_name, user_attribute_path, required_scope) VALUES (?, ?, ?, ?)")
            .bind(&client_id)
            .bind(claim.claim_name)
            .bind(claim.user_attribute_path)
            .bind(claim.required_scope)
            .execute(&mut *transaction)
            .await
            .map_err(|_| AdminError::internal())?;
    }
    transaction
        .commit()
        .await
        .map_err(|_| AdminError::internal())?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_client(
    State(state): State<AppState>,
    Path(client_id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, AdminError> {
    let _admin = require_admin(&state, &headers, true).await?;
    let result = sqlx::query("DELETE FROM oidc_clients WHERE client_id = ?")
        .bind(client_id)
        .execute(&state.database.pool)
        .await
        .map_err(|_| AdminError::internal())?;
    if result.rows_affected() == 0 {
        return Err(AdminError::not_found());
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn list_signing_keys(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, AdminError> {
    let _admin = require_admin(&state, &headers, false).await?;
    let rows = sqlx::query("SELECT kid, algorithm, status, created_at, retire_after FROM signing_keys ORDER BY created_at DESC")
        .fetch_all(&state.database.pool)
        .await
        .map_err(|_| AdminError::internal())?;
    let keys = rows.into_iter().map(|row| {
        Ok(serde_json::json!({
            "kid": row.try_get::<String, _>("kid").map_err(|_| AdminError::internal())?,
            "algorithm": row.try_get::<String, _>("algorithm").map_err(|_| AdminError::internal())?,
            "status": row.try_get::<String, _>("status").map_err(|_| AdminError::internal())?,
            "created_at": row.try_get::<i64, _>("created_at").map_err(|_| AdminError::internal())?,
            "retire_after": row.try_get::<Option<i64>, _>("retire_after").map_err(|_| AdminError::internal())?,
        }))
    }).collect::<Result<Vec<_>, AdminError>>()?;
    Ok(Json(Value::Array(keys)))
}

async fn rotate_signing_key(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, AdminError> {
    let _admin = require_admin(&state, &headers, true).await?;
    let kid = state
        .signing_keys
        .rotate(unix_now())
        .await
        .map_err(|error| {
            tracing::error!(%error, "signing key rotation failed");
            AdminError::internal()
        })?;
    Ok(Json(serde_json::json!({ "kid": kid, "status": "active" })))
}

async fn consume_invitation(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    Json(input): Json<ConsumeInvitation>,
) -> Result<Response, AdminError> {
    if !origin_is_valid(&headers, &state.config) {
        return Err(AdminError::forbidden());
    }
    let _slot = try_anonymous_state_slot().ok_or_else(AdminError::rate_limited)?;
    let source = source_ip(
        peer.map(|Extension(ConnectInfo(address))| address),
        &headers,
        &state.config,
    );
    if !crate::http::allow_anonymous_state_creation(&state, "consume_invitation", source, 10, 300)
        .await
        .map_err(|_| AdminError::internal())?
    {
        return Err(AdminError::rate_limited());
    }
    if input.token.len() < 32 || input.token.len() > 128 {
        return Err(AdminError::unauthorized());
    }
    let now = unix_now();
    let token_hash = digest(&input.token);
    let mut transaction = state
        .database
        .pool
        .begin()
        .await
        .map_err(|_| AdminError::internal())?;
    let invitation = sqlx::query("UPDATE invitation_links SET use_count = use_count + 1 WHERE token_hash = ? AND revoked_at IS NULL AND expires_at > ? AND use_count < max_uses RETURNING label, email, group_names")
        .bind(&token_hash)
        .bind(now)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| AdminError::internal())?;

    let user_id = if let Some(invitation) = invitation {
        let label: String = invitation
            .try_get("label")
            .map_err(|_| AdminError::internal())?;
        let email: Option<String> = invitation
            .try_get("email")
            .map_err(|_| AdminError::internal())?;
        let group_json: String = invitation
            .try_get("group_names")
            .map_err(|_| AdminError::internal())?;
        let groups: Vec<String> =
            serde_json::from_str(&group_json).map_err(|_| AdminError::internal())?;

        let user_id = Uuid::new_v4().to_string();
        let username = format!("user-{}", Uuid::new_v4().simple());
        sqlx::query("INSERT INTO users (id, username, email, display_name, attributes, hanko_seed, invitation_label, expose_preferred_username, expose_name, created_at, updated_at) VALUES (?, ?, ?, ?, '{}', ?, ?, 0, 0, ?, ?)")
            .bind(&user_id)
            .bind(&username)
            .bind(email)
            .bind(&username)
            .bind(random_secret())
            .bind(label)
            .bind(now)
            .bind(now)
            .execute(&mut *transaction)
            .await
            .map_err(|error| {
                tracing::warn!(%error, "invited user creation failed");
                AdminError::conflict("this invitation could not create an account")
            })?;

        for group in groups {
            let group_id: Option<String> =
                sqlx::query_scalar("SELECT id FROM groups WHERE name = ?")
                    .bind(group)
                    .fetch_optional(&mut *transaction)
                    .await
                    .map_err(|_| AdminError::internal())?;
            if let Some(group_id) = group_id {
                sqlx::query(
                    "INSERT INTO user_groups (user_id, group_id, created_at) VALUES (?, ?, ?)",
                )
                .bind(&user_id)
                .bind(group_id)
                .bind(now)
                .execute(&mut *transaction)
                .await
                .map_err(|_| AdminError::internal())?;
            }
        }
        transaction
            .commit()
            .await
            .map_err(|_| AdminError::internal())?;
        user_id
    } else {
        transaction
            .rollback()
            .await
            .map_err(|_| AdminError::internal())?;
        let row = sqlx::query("UPDATE enrollment_invitations SET consumed_at = ? WHERE token_hash = ? AND consumed_at IS NULL AND expires_at > ? AND EXISTS (SELECT 1 FROM users WHERE users.id = enrollment_invitations.user_id AND users.disabled_at IS NULL) AND NOT EXISTS (SELECT 1 FROM passkeys WHERE passkeys.user_id = enrollment_invitations.user_id) RETURNING user_id")
            .bind(now)
            .bind(token_hash)
            .bind(now)
            .fetch_optional(&state.database.pool)
            .await
            .map_err(|_| AdminError::internal())?
            .ok_or_else(AdminError::unauthorized)?;
        row.try_get("user_id").map_err(|_| AdminError::internal())?
    };
    let session = create_session(&state.database, &user_id, true, now)
        .await
        .map_err(|_| AdminError::internal())?;
    let mut response = Json(serde_json::json!({ "ok": true, "setup_only": true })).into_response();
    set_session_cookies(&mut response, &session, &state.config);
    Ok(response)
}

async fn require_admin(
    state: &AppState,
    headers: &HeaderMap,
    mutating: bool,
) -> Result<BrowserSession, AdminError> {
    if mutating && !origin_is_valid(headers, &state.config) {
        return Err(AdminError::forbidden());
    }
    let session = load_session(headers, &state.database)
        .await
        .map_err(|_| AdminError::internal())?
        .ok_or_else(AdminError::unauthorized)?;
    if !session.is_admin || session.setup_only {
        return Err(AdminError::forbidden());
    }
    if mutating && !csrf_header_matches(headers, &session) {
        return Err(AdminError::forbidden());
    }
    Ok(session)
}

async fn user_group_names(state: &AppState, user_id: &str) -> Result<Vec<String>, AdminError> {
    sqlx::query_scalar("SELECT g.name FROM groups g JOIN user_groups ug ON ug.group_id = g.id WHERE ug.user_id = ? ORDER BY g.name")
        .bind(user_id)
        .fetch_all(&state.database.pool)
        .await
        .map_err(|_| AdminError::internal())
}

fn normalize_name(value: &str) -> Option<String> {
    let value = value.trim().to_ascii_lowercase();
    (!value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')))
    .then_some(value)
}

fn valid_registered_uri(value: &str) -> bool {
    if value.contains('#') {
        return false;
    }
    let Ok(uri) = url::Url::parse(value) else {
        return false;
    };
    match uri.scheme() {
        "https" => uri.host_str().is_some(),
        "http" => matches!(uri.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")),
        "javascript" | "data" | "file" => false,
        _ => true,
    }
}

fn valid_claim_name(value: &str) -> bool {
    const RESERVED: &[&str] = &[
        "iss",
        "sub",
        "aud",
        "exp",
        "nbf",
        "iat",
        "jti",
        "auth_time",
        "nonce",
        "azp",
        "at_hash",
        "client_id",
        "token_use",
        "scope",
        "name",
        "preferred_username",
        "email",
        "groups",
    ];
    !value.is_empty()
        && value.len() <= 100
        && !RESERVED.contains(&value)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn valid_json_pointer(value: &str) -> bool {
    value.len() <= 256
        && value.starts_with('/')
        && value.as_bytes().iter().enumerate().all(|(index, byte)| {
            *byte != b'~' || matches!(value.as_bytes().get(index + 1), Some(b'0' | b'1'))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custom_claim_mappings_reject_reserved_claims_and_bad_pointers() {
        assert!(valid_claim_name("department"));
        assert!(!valid_claim_name("sub"));
        assert!(!valid_claim_name("groups"));
        assert!(valid_json_pointer("/organization/name"));
        assert!(valid_json_pointer("/a~0b"));
        assert!(!valid_json_pointer("not/a/pointer"));
        assert!(!valid_json_pointer("/bad~2escape"));
    }

    #[test]
    fn redirect_uri_validation_requires_https_except_loopback_http() {
        assert!(valid_registered_uri("https://client.example/cb"));
        assert!(valid_registered_uri("http://localhost:9000/cb"));
        assert!(!valid_registered_uri("http://client.example/cb"));
        assert!(!valid_registered_uri("https://client.example/cb#fragment"));
        assert!(!valid_registered_uri("javascript:alert(1)"));
    }
}
