use axum::{
    Form, Json, Router,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use p256::{
    ecdsa::VerifyingKey,
    pkcs8::{EncodePublicKey, LineEnding},
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use sqlx::Row;
use subtle::ConstantTimeEq;
use url::Url;
use uuid::Uuid;

use crate::{
    http::AppState,
    security::{PREAUTH_COOKIE, cookie_value, digest, load_session, unix_now},
};

const CODE_SECONDS: i64 = 60;
const ACCESS_SECONDS: i64 = 5 * 60;
const ID_SECONDS: i64 = 5 * 60;
const AUTH_REQUEST_SECONDS: i64 = 5 * 60;

#[derive(Deserialize)]
struct AuthorizeRequest {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    scope: String,
    state: String,
    nonce: Option<String>,
    code_challenge: String,
    code_challenge_method: String,
}

#[derive(Deserialize)]
struct ResumeRequest {
    request_id: String,
}

#[derive(Deserialize)]
struct ContinueRequest {
    request_id: String,
}

#[derive(Deserialize)]
struct TokenRequest {
    grant_type: String,
    code: String,
    redirect_uri: String,
    client_id: String,
    code_verifier: String,
    client_secret: Option<String>,
}

#[derive(Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: i64,
    id_token: String,
    scope: String,
}

#[derive(Deserialize)]
struct EndSessionRequest {
    client_id: Option<String>,
    id_token_hint: Option<String>,
    post_logout_redirect_uri: Option<String>,
    state: Option<String>,
}

#[derive(Deserialize)]
struct AccessClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: i64,
    client_id: String,
    token_use: String,
    scope: String,
    #[serde(flatten)]
    additional: Map<String, Value>,
}

#[derive(Debug)]
struct OAuthError {
    status: StatusCode,
    error: &'static str,
    description: &'static str,
}

impl OAuthError {
    fn invalid_request(description: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            error: "invalid_request",
            description,
        }
    }
    fn invalid_client() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            error: "invalid_client",
            description: "client authentication failed",
        }
    }
    fn invalid_grant() -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            error: "invalid_grant",
            description: "authorization grant is invalid or expired",
        }
    }
    fn server_error() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            error: "server_error",
            description: "identity provider error",
        }
    }
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        let mut response = (
            self.status,
            Json(serde_json::json!({
                "error": self.error,
                "error_description": self.description,
            })),
        )
            .into_response();
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
            .headers_mut()
            .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
        response
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/authorize", get(authorize))
        .route("/authorize/resume", get(resume_authorize))
        .route("/api/authorize/request", get(authorize_request_info))
        .route("/api/authorize/continue", post(continue_authorize))
        .route("/api/authorize/deny", post(deny_authorize))
        .route("/token", post(token))
        .route("/userinfo", get(userinfo).post(userinfo))
        .route("/logout", get(end_session))
}

async fn authorize(
    State(state): State<AppState>,
    Query(input): Query<AuthorizeRequest>,
) -> Result<Response, OAuthError> {
    let scopes = validate_authorize_request(&state, &input).await?;
    let preauth = crate::security::random_secret();
    let request_id = crate::security::random_secret();
    let now = unix_now();
    sqlx::query("INSERT INTO authorization_requests (request_hash, browser_hash, client_id, redirect_uri, state, nonce, code_challenge, scopes, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
        .bind(digest(&request_id))
        .bind(digest(&preauth))
        .bind(&input.client_id)
        .bind(&input.redirect_uri)
        .bind(&input.state)
        // The schema stores an empty string for an omitted optional nonce.
        .bind(input.nonce.as_deref().unwrap_or(""))
        .bind(&input.code_challenge)
        .bind(serde_json::to_string(&scopes).map_err(|_| OAuthError::server_error())?)
        .bind(now)
        .bind(now + AUTH_REQUEST_SECONDS)
        .execute(&state.database.pool)
        .await
        .map_err(|_| OAuthError::server_error())?;
    let location = format!(
        "{}/?request_id={}",
        state.config.issuer(),
        urlencoding(&request_id)
    );
    let mut response = redirect(&location)?;
    response.headers_mut().append(
        header::SET_COOKIE,
        crate::security::cookie_header(
            PREAUTH_COOKIE,
            &preauth,
            &state.config,
            true,
            AUTH_REQUEST_SECONDS,
        )
        .parse()
        .map_err(|_| OAuthError::server_error())?,
    );
    Ok(response)
}

async fn resume_authorize(
    State(state): State<AppState>,
    Query(input): Query<ResumeRequest>,
    headers: HeaderMap,
) -> Result<Response, OAuthError> {
    load_session(&headers, &state.database)
        .await
        .map_err(|_| OAuthError::server_error())?
        .ok_or_else(OAuthError::invalid_grant)?;
    redirect(&format!(
        "{}/?request_id={}",
        state.config.issuer(),
        urlencoding(&input.request_id)
    ))
}

async fn authorize_request_info(
    State(state): State<AppState>,
    Query(input): Query<ResumeRequest>,
    headers: HeaderMap,
) -> Result<Json<Value>, OAuthError> {
    let session = load_session(&headers, &state.database)
        .await
        .map_err(|_| OAuthError::server_error())?;
    let (row, client_name) = pending_authorization(&state, &headers, &input.request_id).await?;
    if let Some(session) = session {
        if session.setup_only {
            return Err(OAuthError::invalid_grant());
        }
        let client_id: String = row
            .try_get("client_id")
            .map_err(|_| OAuthError::server_error())?;
        if !user_allowed_for_client(&state, &client_id, &session.user_id).await? {
            return Err(OAuthError::invalid_request(
                "user is not allowed to access this client",
            ));
        }
    }
    let scopes_json: String = row
        .try_get("scopes")
        .map_err(|_| OAuthError::server_error())?;
    Ok(Json(serde_json::json!({
        "client_name": client_name,
        "redirect_uri": row.try_get::<String, _>("redirect_uri").map_err(|_| OAuthError::server_error())?,
        "scopes": serde_json::from_str::<Vec<String>>(&scopes_json).map_err(|_| OAuthError::server_error())?,
    })))
}

async fn continue_authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ContinueRequest>,
) -> Result<Json<Value>, OAuthError> {
    let session = require_browser_authorization(&state, &headers).await?;
    let (row, _) = pending_authorization(&state, &headers, &input.request_id).await?;
    let client_id: String = row
        .try_get("client_id")
        .map_err(|_| OAuthError::server_error())?;
    let redirect_uri: String = row
        .try_get("redirect_uri")
        .map_err(|_| OAuthError::server_error())?;
    let protocol_state: String = row
        .try_get("state")
        .map_err(|_| OAuthError::server_error())?;
    let nonce: String = row
        .try_get("nonce")
        .map_err(|_| OAuthError::server_error())?;
    let code_challenge: String = row
        .try_get("code_challenge")
        .map_err(|_| OAuthError::server_error())?;
    let scopes_json: String = row
        .try_get("scopes")
        .map_err(|_| OAuthError::server_error())?;
    let scopes: Vec<String> =
        serde_json::from_str(&scopes_json).map_err(|_| OAuthError::server_error())?;
    if !user_allowed_for_client(&state, &client_id, &session.user_id).await? {
        return Err(OAuthError::invalid_request(
            "user is not allowed to access this client",
        ));
    }
    validate_redirect(&state.database, &client_id, &redirect_uri).await?;
    ensure_scopes_still_allowed(&state, &client_id, &scopes).await?;
    let auth_time =
        sqlx::query_scalar::<_, i64>("SELECT created_at FROM sessions WHERE session_hash = ?")
            .bind(&session.session_hash)
            .fetch_one(&state.database.pool)
            .await
            .map_err(|_| OAuthError::server_error())?;
    let code = crate::security::random_secret();
    let now = unix_now();
    let request_hash = digest(&input.request_id);
    let preauth = cookie_value(&headers, PREAUTH_COOKIE).ok_or_else(OAuthError::invalid_grant)?;
    let browser_hash = digest(&preauth);
    let mut transaction = state
        .database
        .pool
        .begin()
        .await
        .map_err(|_| OAuthError::server_error())?;
    sqlx::query("INSERT INTO authorization_codes (code_hash, client_id, user_id, redirect_uri, scopes, nonce, code_challenge, created_at, expires_at, auth_time) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
        .bind(digest(&code)).bind(&client_id).bind(&session.user_id).bind(&redirect_uri)
        .bind(serde_json::to_string(&scopes).map_err(|_| OAuthError::server_error())?)
        .bind(nonce).bind(code_challenge).bind(now).bind(now + CODE_SECONDS).bind(auth_time)
        .execute(&mut *transaction).await.map_err(|_| OAuthError::server_error())?;
    let deleted = sqlx::query("DELETE FROM authorization_requests WHERE request_hash = ? AND browser_hash = ? AND expires_at > ?")
        .bind(request_hash).bind(browser_hash).bind(now).execute(&mut *transaction).await.map_err(|_| OAuthError::server_error())?;
    if deleted.rows_affected() != 1 {
        return Err(OAuthError::invalid_grant());
    }
    transaction
        .commit()
        .await
        .map_err(|_| OAuthError::server_error())?;
    Ok(Json(
        serde_json::json!({ "redirect_to": callback_with_code(&redirect_uri, &code, &protocol_state)? }),
    ))
}

async fn deny_authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ContinueRequest>,
) -> Result<Json<Value>, OAuthError> {
    require_browser_authorization(&state, &headers).await?;
    let preauth = cookie_value(&headers, PREAUTH_COOKIE).ok_or_else(OAuthError::invalid_grant)?;
    let row = sqlx::query("DELETE FROM authorization_requests WHERE request_hash = ? AND browser_hash = ? AND expires_at > ? RETURNING redirect_uri, state")
        .bind(digest(&input.request_id)).bind(digest(&preauth)).bind(unix_now())
        .fetch_optional(&state.database.pool).await.map_err(|_| OAuthError::server_error())?.ok_or_else(OAuthError::invalid_grant)?;
    let redirect_uri: String = row
        .try_get("redirect_uri")
        .map_err(|_| OAuthError::server_error())?;
    let protocol_state: String = row
        .try_get("state")
        .map_err(|_| OAuthError::server_error())?;
    let mut url = Url::parse(&redirect_uri).map_err(|_| OAuthError::server_error())?;
    url.query_pairs_mut()
        .append_pair("error", "access_denied")
        .append_pair("state", &protocol_state);
    Ok(Json(serde_json::json!({ "redirect_to": url.as_str() })))
}

async fn require_browser_authorization(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<crate::security::BrowserSession, OAuthError> {
    if !crate::security::origin_is_valid(headers, &state.config) {
        return Err(OAuthError::invalid_grant());
    }
    let session = load_session(headers, &state.database)
        .await
        .map_err(|_| OAuthError::server_error())?
        .ok_or_else(OAuthError::invalid_grant)?;
    if session.setup_only || !crate::security::csrf_header_matches(headers, &session) {
        return Err(OAuthError::invalid_grant());
    }
    Ok(session)
}

async fn pending_authorization(
    state: &AppState,
    headers: &HeaderMap,
    request_id: &str,
) -> Result<(sqlx::sqlite::SqliteRow, String), OAuthError> {
    let preauth = cookie_value(headers, PREAUTH_COOKIE).ok_or_else(OAuthError::invalid_grant)?;
    let row = sqlx::query("SELECT client_id, redirect_uri, state, nonce, code_challenge, scopes FROM authorization_requests WHERE request_hash = ? AND browser_hash = ? AND expires_at > ?")
        .bind(digest(request_id)).bind(digest(&preauth)).bind(unix_now())
        .fetch_optional(&state.database.pool).await.map_err(|_| OAuthError::server_error())?.ok_or_else(OAuthError::invalid_grant)?;
    let client_id: String = row
        .try_get("client_id")
        .map_err(|_| OAuthError::server_error())?;
    let client_name = sqlx::query_scalar::<_, String>(
        "SELECT name FROM oidc_clients WHERE client_id = ? AND enabled = 1",
    )
    .bind(client_id)
    .fetch_optional(&state.database.pool)
    .await
    .map_err(|_| OAuthError::server_error())?
    .ok_or_else(OAuthError::invalid_grant)?;
    Ok((row, client_name))
}

async fn token(
    State(state): State<AppState>,
    Form(input): Form<TokenRequest>,
) -> Result<Json<TokenResponse>, OAuthError> {
    if input.grant_type != "authorization_code" || !valid_pkce_verifier(&input.code_verifier) {
        return Err(OAuthError::invalid_grant());
    }
    let client = sqlx::query(
        "SELECT client_type, client_secret_hash, enabled FROM oidc_clients WHERE client_id = ?",
    )
    .bind(&input.client_id)
    .fetch_optional(&state.database.pool)
    .await
    .map_err(|_| OAuthError::server_error())?
    .ok_or_else(OAuthError::invalid_client)?;
    let client_type: String = client
        .try_get("client_type")
        .map_err(|_| OAuthError::server_error())?;
    let enabled: bool = client
        .try_get("enabled")
        .map_err(|_| OAuthError::server_error())?;
    if !enabled {
        return Err(OAuthError::invalid_client());
    }
    let stored_secret: Option<String> = client
        .try_get("client_secret_hash")
        .map_err(|_| OAuthError::server_error())?;
    match client_type.as_str() {
        "public" if input.client_secret.is_none() => {}
        "confidential" => {
            let Some(secret) = input.client_secret.as_deref() else {
                return Err(OAuthError::invalid_client());
            };
            let Some(stored) = stored_secret else {
                return Err(OAuthError::invalid_client());
            };
            let actual = URL_SAFE_NO_PAD.encode(Sha256::digest(secret.as_bytes()));
            if !constant_time_string_eq(&actual, &stored) {
                return Err(OAuthError::invalid_client());
            }
        }
        _ => return Err(OAuthError::invalid_client()),
    }

    let code_hash = digest(&input.code);
    let preview = sqlx::query("SELECT code_challenge, redirect_uri, scopes, user_id FROM authorization_codes WHERE code_hash = ? AND client_id = ? AND consumed_at IS NULL AND expires_at > ?")
        .bind(&code_hash)
        .bind(&input.client_id)
        .bind(unix_now())
        .fetch_optional(&state.database.pool)
        .await
        .map_err(|_| OAuthError::server_error())?
        .ok_or_else(OAuthError::invalid_grant)?;
    let expected_challenge: String = preview
        .try_get("code_challenge")
        .map_err(|_| OAuthError::server_error())?;
    let redirect_uri: String = preview
        .try_get("redirect_uri")
        .map_err(|_| OAuthError::server_error())?;
    let scopes_json: String = preview
        .try_get("scopes")
        .map_err(|_| OAuthError::server_error())?;
    let preview_user_id: String = preview
        .try_get("user_id")
        .map_err(|_| OAuthError::server_error())?;
    if input.redirect_uri != redirect_uri
        || !constant_time_string_eq(&s256_challenge(&input.code_verifier), &expected_challenge)
    {
        return Err(OAuthError::invalid_grant());
    }
    let scopes: Vec<String> =
        serde_json::from_str(&scopes_json).map_err(|_| OAuthError::server_error())?;
    ensure_scopes_still_allowed(&state, &input.client_id, &scopes).await?;
    if !user_allowed_for_client(&state, &input.client_id, &preview_user_id).await? {
        return Err(OAuthError::invalid_grant());
    }

    let now = unix_now();
    let mut transaction = state
        .database
        .pool
        .begin()
        .await
        .map_err(|_| OAuthError::server_error())?;
    let code = sqlx::query("UPDATE authorization_codes SET consumed_at = ? WHERE code_hash = ? AND client_id = ? AND redirect_uri = ? AND consumed_at IS NULL AND expires_at > ? RETURNING user_id, nonce, scopes, auth_time")
        .bind(now)
        .bind(code_hash)
        .bind(&input.client_id)
        .bind(&input.redirect_uri)
        .bind(now)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| OAuthError::server_error())?
        .ok_or_else(OAuthError::invalid_grant)?;
    let user_id: String = code
        .try_get("user_id")
        .map_err(|_| OAuthError::server_error())?;
    let nonce: String = code
        .try_get("nonce")
        .map_err(|_| OAuthError::server_error())?;
    let auth_time: i64 = code
        .try_get("auth_time")
        .map_err(|_| OAuthError::server_error())?;
    let code_scopes: String = code
        .try_get("scopes")
        .map_err(|_| OAuthError::server_error())?;
    let consumed_scopes: Vec<String> =
        serde_json::from_str(&code_scopes).map_err(|_| OAuthError::server_error())?;
    transaction
        .commit()
        .await
        .map_err(|_| OAuthError::server_error())?;

    let user = sqlx::query(
        "SELECT username, display_name, expose_preferred_username, expose_name, email, attributes FROM users WHERE id = ? AND disabled_at IS NULL",
    )
    .bind(&user_id)
    .fetch_optional(&state.database.pool)
    .await
    .map_err(|_| OAuthError::server_error())?
    .ok_or_else(OAuthError::invalid_grant)?;
    let username: String = user
        .try_get("username")
        .map_err(|_| OAuthError::server_error())?;
    let display_name: String = user
        .try_get("display_name")
        .map_err(|_| OAuthError::server_error())?;
    let expose_preferred_username: bool = user
        .try_get("expose_preferred_username")
        .map_err(|_| OAuthError::server_error())?;
    let expose_name: bool = user
        .try_get("expose_name")
        .map_err(|_| OAuthError::server_error())?;
    let email: Option<String> = user
        .try_get("email")
        .map_err(|_| OAuthError::server_error())?;
    let attributes: String = user
        .try_get("attributes")
        .map_err(|_| OAuthError::server_error())?;
    let attributes: Value =
        serde_json::from_str(&attributes).map_err(|_| OAuthError::server_error())?;
    let groups = user_groups(&state, &user_id).await?;
    let custom_claims =
        custom_claims(&state, &input.client_id, &attributes, &consumed_scopes).await?;

    let scope_string = consumed_scopes.join(" ");
    let access_exp = now + ACCESS_SECONDS;
    let id_exp = now + ID_SECONDS;
    let mut access_claims = Map::new();
    add_standard_claims(
        &mut access_claims,
        &state,
        &user_id,
        &input.client_id,
        now,
        access_exp,
        auth_time,
        "access",
    );
    access_claims.insert("scope".into(), Value::String(scope_string.clone()));
    add_user_claims(
        &mut access_claims,
        &consumed_scopes,
        expose_preferred_username.then_some(username.as_str()),
        expose_name.then_some(display_name.as_str()),
        email.as_deref(),
        &groups,
    );
    for (claim, value) in &custom_claims {
        access_claims.insert(claim.clone(), value.clone());
    }
    let access_token = state
        .signing_keys
        .sign(&Value::Object(access_claims))
        .await
        .map_err(|_| OAuthError::server_error())?;

    let mut id_claims = Map::new();
    add_standard_claims(
        &mut id_claims,
        &state,
        &user_id,
        &input.client_id,
        now,
        id_exp,
        auth_time,
        "id",
    );
    if !nonce.is_empty() {
        id_claims.insert("nonce".into(), Value::String(nonce));
    }
    let at_hash = Sha256::digest(access_token.as_bytes());
    id_claims.insert(
        "at_hash".into(),
        Value::String(URL_SAFE_NO_PAD.encode(&at_hash[..16])),
    );
    add_user_claims(
        &mut id_claims,
        &consumed_scopes,
        expose_preferred_username.then_some(username.as_str()),
        expose_name.then_some(display_name.as_str()),
        email.as_deref(),
        &groups,
    );
    for (claim, value) in custom_claims {
        id_claims.insert(claim, value);
    }
    let id_token = state
        .signing_keys
        .sign(&Value::Object(id_claims))
        .await
        .map_err(|_| OAuthError::server_error())?;

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: ACCESS_SECONDS,
        id_token,
        scope: scope_string,
    }))
}

async fn userinfo(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, OAuthError> {
    let auth = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(OAuthError::invalid_grant)?;
    let token = auth
        .strip_prefix("Bearer ")
        .ok_or_else(OAuthError::invalid_grant)?;
    let claims = verify_access_token(&state, token).await?;
    let scopes: Vec<&str> = claims.scope.split_ascii_whitespace().collect();
    let row = sqlx::query("SELECT username, display_name, expose_preferred_username, expose_name, email FROM users WHERE id = ? AND disabled_at IS NULL")
        .bind(&claims.sub)
        .fetch_optional(&state.database.pool)
        .await
        .map_err(|_| OAuthError::server_error())?
        .ok_or_else(OAuthError::invalid_grant)?;
    let username: String = row
        .try_get("username")
        .map_err(|_| OAuthError::server_error())?;
    let display_name: String = row
        .try_get("display_name")
        .map_err(|_| OAuthError::server_error())?;
    let expose_preferred_username: bool = row
        .try_get("expose_preferred_username")
        .map_err(|_| OAuthError::server_error())?;
    let expose_name: bool = row
        .try_get("expose_name")
        .map_err(|_| OAuthError::server_error())?;
    let email: Option<String> = row
        .try_get("email")
        .map_err(|_| OAuthError::server_error())?;
    let mut result = Map::new();
    result.insert("sub".into(), Value::String(claims.sub.clone()));
    if scopes.contains(&"profile") {
        if expose_name {
            result.insert("name".into(), Value::String(display_name));
        }
        if expose_preferred_username {
            result.insert("preferred_username".into(), Value::String(username));
        }
    }
    if scopes.contains(&"email") {
        if let Some(email) = email {
            result.insert("email".into(), Value::String(email));
        }
    }
    if scopes.contains(&"groups") {
        if let Some(groups) = claims.additional.get("groups") {
            result.insert("groups".into(), groups.clone());
        }
    }
    for (claim, value) in claims.additional {
        if !matches!(
            claim.as_str(),
            "groups"
                | "iss"
                | "sub"
                | "aud"
                | "exp"
                | "nbf"
                | "iat"
                | "jti"
                | "auth_time"
                | "nonce"
                | "azp"
                | "at_hash"
                | "client_id"
                | "token_use"
                | "scope"
                | "name"
                | "preferred_username"
                | "email"
        ) {
            result.insert(claim, value);
        }
    }
    Ok(Json(Value::Object(result)))
}

async fn end_session(
    State(state): State<AppState>,
    Query(input): Query<EndSessionRequest>,
    headers: HeaderMap,
) -> Result<Response, OAuthError> {
    let id_token_hint = input
        .id_token_hint
        .as_deref()
        .ok_or_else(|| OAuthError::invalid_request("id_token_hint is required"))?;
    let (claims, client_id) = verify_id_token_hint(&state, id_token_hint).await?;
    if input
        .client_id
        .as_deref()
        .is_some_and(|value| value != client_id)
    {
        return Err(OAuthError::invalid_request(
            "client_id does not match id_token_hint",
        ));
    }
    if let Some(uri) = input.post_logout_redirect_uri.as_deref() {
        let redirect_client = input.client_id.as_deref().unwrap_or(&client_id);
        let allowed = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM client_post_logout_uris WHERE client_id = ? AND uri = ?)",
        )
        .bind(redirect_client)
        .bind(uri)
        .fetch_one(&state.database.pool)
        .await
        .map_err(|_| OAuthError::server_error())?;
        if !allowed {
            return Err(OAuthError::invalid_request(
                "post_logout_redirect_uri is not registered",
            ));
        }
    }
    if let Some(session) = load_session(&headers, &state.database)
        .await
        .map_err(|_| OAuthError::server_error())?
    {
        if session.user_id
            == claims
                .get("sub")
                .and_then(Value::as_str)
                .unwrap_or_default()
        {
            sqlx::query("DELETE FROM sessions WHERE session_hash = ?")
                .bind(&session.session_hash)
                .execute(&state.database.pool)
                .await
                .map_err(|_| OAuthError::server_error())?;
        }
    }
    let mut response = if let Some(uri) = input.post_logout_redirect_uri {
        let mut url = Url::parse(&uri)
            .map_err(|_| OAuthError::invalid_request("invalid post logout redirect"))?;
        if let Some(state_value) = input.state {
            url.query_pairs_mut().append_pair("state", &state_value);
        }
        redirect(url.as_str())?
    } else {
        (StatusCode::OK, "signed out").into_response()
    };
    crate::security::clear_session_cookies(&mut response, &state.config);
    Ok(response)
}

async fn validate_authorize_request(
    state: &AppState,
    input: &AuthorizeRequest,
) -> Result<Vec<String>, OAuthError> {
    if input.response_type != "code"
        || input.state.is_empty()
        || input.state.len() > 512
        || input
            .nonce
            .as_ref()
            .is_some_and(|nonce| nonce.is_empty() || nonce.len() > 512)
        || input.code_challenge_method != "S256"
        || !valid_s256_challenge(&input.code_challenge)
    {
        return Err(OAuthError::invalid_request(
            "required authorization parameters are invalid",
        ));
    }
    validate_redirect(&state.database, &input.client_id, &input.redirect_uri).await?;
    let _client =
        sqlx::query("SELECT client_id FROM oidc_clients WHERE client_id = ? AND enabled = 1")
            .bind(&input.client_id)
            .fetch_optional(&state.database.pool)
            .await
            .map_err(|_| OAuthError::server_error())?
            .ok_or_else(|| OAuthError::invalid_request("unknown client"))?;
    let scopes = parse_scopes(&input.scope)?;
    ensure_scopes_still_allowed(state, &input.client_id, &scopes).await?;
    Ok(scopes)
}

async fn validate_redirect(
    database: &crate::db::Database,
    client_id: &str,
    uri: &str,
) -> Result<(), OAuthError> {
    if uri.contains('#') || Url::parse(uri).is_err() {
        return Err(OAuthError::invalid_request("redirect_uri is invalid"));
    }
    let allowed = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM client_redirect_uris WHERE client_id = ? AND uri = ?)",
    )
    .bind(client_id)
    .bind(uri)
    .fetch_one(&database.pool)
    .await
    .map_err(|_| OAuthError::server_error())?;
    if allowed {
        Ok(())
    } else {
        Err(OAuthError::invalid_request(
            "redirect_uri is not registered",
        ))
    }
}

async fn parse_scopes_from_client(
    state: &AppState,
    client_id: &str,
) -> Result<Vec<String>, OAuthError> {
    sqlx::query_scalar("SELECT scope FROM client_scopes WHERE client_id = ? ORDER BY scope")
        .bind(client_id)
        .fetch_all(&state.database.pool)
        .await
        .map_err(|_| OAuthError::server_error())
}

async fn ensure_scopes_still_allowed(
    state: &AppState,
    client_id: &str,
    requested: &[String],
) -> Result<(), OAuthError> {
    let allowed = parse_scopes_from_client(state, client_id).await?;
    if requested
        .iter()
        .all(|scope| allowed.iter().any(|candidate| candidate == scope))
    {
        Ok(())
    } else {
        Err(OAuthError::invalid_request(
            "requested scope is not allowed",
        ))
    }
}

fn parse_scopes(scope: &str) -> Result<Vec<String>, OAuthError> {
    let scopes: Vec<String> = scope.split_ascii_whitespace().map(str::to_owned).collect();
    if scopes.is_empty()
        || !scopes.iter().any(|scope| scope == "openid")
        || scopes
            .iter()
            .any(|scope| !matches!(scope.as_str(), "openid" | "profile" | "email" | "groups"))
    {
        return Err(OAuthError::invalid_request(
            "scope must include openid and only supported scopes",
        ));
    }
    let unique: std::collections::HashSet<_> = scopes.iter().collect();
    if unique.len() != scopes.len() {
        return Err(OAuthError::invalid_request("scope values must be unique"));
    }
    Ok(scopes)
}

async fn user_allowed_for_client(
    state: &AppState,
    client_id: &str,
    user_id: &str,
) -> Result<bool, OAuthError> {
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM client_allowed_groups WHERE client_id = ?")
            .bind(client_id)
            .fetch_one(&state.database.pool)
            .await
            .map_err(|_| OAuthError::server_error())?;
    if count == 0 {
        return Ok(true);
    }
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM client_allowed_groups cg JOIN user_groups ug ON ug.group_id = cg.group_id WHERE cg.client_id = ? AND ug.user_id = ?)")
        .bind(client_id)
        .bind(user_id)
        .fetch_one(&state.database.pool)
        .await
        .map_err(|_| OAuthError::server_error())
}

fn callback_with_code(uri: &str, code: &str, state: &str) -> Result<String, OAuthError> {
    let mut url =
        Url::parse(uri).map_err(|_| OAuthError::invalid_request("invalid redirect_uri"))?;
    url.query_pairs_mut()
        .append_pair("code", code)
        .append_pair("state", state);
    Ok(url.into())
}

#[cfg(test)]
fn redirect_with_code(uri: &str, code: &str, state: &str) -> Result<Response, OAuthError> {
    redirect(&callback_with_code(uri, code, state)?)
}

fn redirect(location: &str) -> Result<Response, OAuthError> {
    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, location)
        .header(header::CACHE_CONTROL, "no-store")
        .body(axum::body::Body::empty())
        .map_err(|_| OAuthError::server_error())
}

fn urlencoding(value: &str) -> String {
    use url::form_urlencoded::byte_serialize;
    byte_serialize(value.as_bytes()).collect()
}

fn valid_s256_challenge(challenge: &str) -> bool {
    challenge.len() == 43
        && challenge
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

fn valid_pkce_verifier(verifier: &str) -> bool {
    (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
}

fn s256_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn constant_time_string_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

async fn user_groups(state: &AppState, user_id: &str) -> Result<Vec<String>, OAuthError> {
    sqlx::query_scalar("SELECT g.name FROM groups g JOIN user_groups ug ON ug.group_id = g.id WHERE ug.user_id = ? ORDER BY g.name")
        .bind(user_id)
        .fetch_all(&state.database.pool)
        .await
        .map_err(|_| OAuthError::server_error())
}

async fn custom_claims(
    state: &AppState,
    client_id: &str,
    attributes: &Value,
    scopes: &[String],
) -> Result<Map<String, Value>, OAuthError> {
    let rows = sqlx::query("SELECT claim_name, user_attribute_path, required_scope FROM client_claim_mappings WHERE client_id = ?")
        .bind(client_id)
        .fetch_all(&state.database.pool)
        .await
        .map_err(|_| OAuthError::server_error())?;
    let mut claims = Map::new();
    for row in rows {
        let name: String = row
            .try_get("claim_name")
            .map_err(|_| OAuthError::server_error())?;
        let path: String = row
            .try_get("user_attribute_path")
            .map_err(|_| OAuthError::server_error())?;
        let required_scope: Option<String> = row
            .try_get("required_scope")
            .map_err(|_| OAuthError::server_error())?;
        if required_scope
            .as_ref()
            .is_some_and(|scope| !scopes.contains(scope))
        {
            continue;
        }
        if let Some(value) = attributes.pointer(&path) {
            claims.insert(name, value.clone());
        }
    }
    Ok(claims)
}

fn add_standard_claims(
    claims: &mut Map<String, Value>,
    state: &AppState,
    user_id: &str,
    client_id: &str,
    now: i64,
    exp: i64,
    auth_time: i64,
    token_use: &str,
) {
    claims.insert("iss".into(), Value::String(state.config.issuer()));
    claims.insert("sub".into(), Value::String(user_id.to_owned()));
    claims.insert("aud".into(), Value::String(client_id.to_owned()));
    claims.insert("client_id".into(), Value::String(client_id.to_owned()));
    claims.insert("iat".into(), Value::from(now));
    claims.insert("exp".into(), Value::from(exp));
    claims.insert("auth_time".into(), Value::from(auth_time));
    claims.insert("jti".into(), Value::String(Uuid::new_v4().to_string()));
    claims.insert("token_use".into(), Value::String(token_use.to_owned()));
}

fn add_user_claims(
    claims: &mut Map<String, Value>,
    scopes: &[String],
    username: Option<&str>,
    display_name: Option<&str>,
    email: Option<&str>,
    groups: &[String],
) {
    if scopes.iter().any(|scope| scope == "profile") {
        if let Some(display_name) = display_name {
            claims.insert("name".into(), Value::String(display_name.to_owned()));
        }
        if let Some(username) = username {
            claims.insert(
                "preferred_username".into(),
                Value::String(username.to_owned()),
            );
        }
    }
    if scopes.iter().any(|scope| scope == "email") {
        if let Some(email) = email {
            claims.insert("email".into(), Value::String(email.to_owned()));
        }
    }
    if scopes.iter().any(|scope| scope == "groups") {
        claims.insert(
            "groups".into(),
            serde_json::to_value(groups).unwrap_or(Value::Array(vec![])),
        );
    }
}

async fn verify_access_token(state: &AppState, token: &str) -> Result<AccessClaims, OAuthError> {
    let header = jsonwebtoken::decode_header(token).map_err(|_| OAuthError::invalid_grant())?;
    if header.alg != Algorithm::ES256 {
        return Err(OAuthError::invalid_grant());
    }
    let kid = header.kid.ok_or_else(OAuthError::invalid_grant)?;
    let decoding_key = load_decoding_key(state, &kid, unix_now()).await?;
    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_issuer(&[state.config.issuer()]);
    validation.validate_exp = true;
    // Verify the signature first, then compare the signed audience to its signed client_id below.
    validation.validate_aud = false;
    let claims = jsonwebtoken::decode::<AccessClaims>(token, &decoding_key, &validation)
        .map_err(|_| OAuthError::invalid_grant())?
        .claims;
    if claims.iss != state.config.issuer()
        || claims.token_use != "access"
        || claims.aud != claims.client_id
        || claims.exp <= unix_now()
    {
        return Err(OAuthError::invalid_grant());
    }
    let enabled =
        sqlx::query_scalar::<_, bool>("SELECT enabled FROM oidc_clients WHERE client_id = ?")
            .bind(&claims.client_id)
            .fetch_optional(&state.database.pool)
            .await
            .map_err(|_| OAuthError::server_error())?
            .unwrap_or(false);
    if !enabled {
        return Err(OAuthError::invalid_grant());
    }
    Ok(claims)
}

async fn verify_id_token_hint(
    state: &AppState,
    token: &str,
) -> Result<(Value, String), OAuthError> {
    let header = jsonwebtoken::decode_header(token).map_err(|_| OAuthError::invalid_grant())?;
    if header.alg != Algorithm::ES256 {
        return Err(OAuthError::invalid_grant());
    }
    let kid = header.kid.ok_or_else(OAuthError::invalid_grant)?;
    let decoding_key = load_decoding_key(state, &kid, unix_now()).await?;
    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_issuer(&[state.config.issuer()]);
    validation.validate_exp = false;
    // The signed audience is checked against the active client after decoding.
    validation.validate_aud = false;
    validation.required_spec_claims.remove("exp");
    let claims = jsonwebtoken::decode::<Value>(token, &decoding_key, &validation)
        .map_err(|_| OAuthError::invalid_grant())?
        .claims;
    let client_id = claims
        .get("aud")
        .and_then(Value::as_str)
        .ok_or_else(OAuthError::invalid_grant)?
        .to_owned();
    if claims.get("token_use").and_then(Value::as_str) != Some("id")
        || claims.get("iss").and_then(Value::as_str) != Some(state.config.issuer().as_str())
        || claims.get("aud").and_then(Value::as_str) != Some(client_id.as_str())
    {
        return Err(OAuthError::invalid_grant());
    }
    let enabled =
        sqlx::query_scalar::<_, bool>("SELECT enabled FROM oidc_clients WHERE client_id = ?")
            .bind(&client_id)
            .fetch_optional(&state.database.pool)
            .await
            .map_err(|_| OAuthError::server_error())?
            .unwrap_or(false);
    if !enabled {
        return Err(OAuthError::invalid_grant());
    }
    Ok((claims, client_id))
}

async fn load_decoding_key(
    state: &AppState,
    kid: &str,
    now: i64,
) -> Result<DecodingKey, OAuthError> {
    let row = sqlx::query("SELECT public_jwk FROM signing_keys WHERE kid = ? AND (status = 'active' OR (status = 'retiring' AND retire_after > ?))")
        .bind(kid)
        .bind(now)
        .fetch_optional(&state.database.pool)
        .await
        .map_err(|_| OAuthError::server_error())?
        .ok_or_else(OAuthError::invalid_grant)?;
    let jwk: String = row
        .try_get("public_jwk")
        .map_err(|_| OAuthError::server_error())?;
    let jwk: Value = serde_json::from_str(&jwk).map_err(|_| OAuthError::server_error())?;
    if jwk.get("kty").and_then(Value::as_str) != Some("EC")
        || jwk.get("crv").and_then(Value::as_str) != Some("P-256")
        || jwk.get("alg").and_then(Value::as_str) != Some("ES256")
    {
        return Err(OAuthError::invalid_grant());
    }
    let x = URL_SAFE_NO_PAD
        .decode(
            jwk.get("x")
                .and_then(Value::as_str)
                .ok_or_else(OAuthError::server_error)?,
        )
        .map_err(|_| OAuthError::server_error())?;
    let y = URL_SAFE_NO_PAD
        .decode(
            jwk.get("y")
                .and_then(Value::as_str)
                .ok_or_else(OAuthError::server_error)?,
        )
        .map_err(|_| OAuthError::server_error())?;
    if x.len() != 32 || y.len() != 32 {
        return Err(OAuthError::server_error());
    }
    let point = [vec![4_u8], x, y].concat();
    let verifying_key =
        VerifyingKey::from_sec1_bytes(&point).map_err(|_| OAuthError::server_error())?;
    let pem = verifying_key
        .to_public_key_pem(LineEnding::LF)
        .map_err(|_| OAuthError::server_error())?;
    DecodingKey::from_ec_pem(pem.as_bytes()).map_err(|_| OAuthError::server_error())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        http::{AppState, router as http_router},
        security::create_session,
    };
    use axum::http::Request;
    use std::sync::Arc;
    use tower::ServiceExt;

    #[test]
    fn pkce_uses_s256_and_enforces_rfc_verifier_shape() {
        let verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
        assert!(valid_pkce_verifier(verifier));
        assert_eq!(s256_challenge(verifier).len(), 43);
        assert!(valid_s256_challenge(&s256_challenge(verifier)));
        assert!(!valid_pkce_verifier("short"));
        assert!(!valid_pkce_verifier(&"x".repeat(129)));
        assert!(!valid_s256_challenge(&"a".repeat(44)));
    }

    #[test]
    fn scopes_require_openid_no_duplicates_and_only_supported_values() {
        assert_eq!(
            parse_scopes("openid profile").unwrap(),
            vec!["openid", "profile"]
        );
        assert!(parse_scopes("profile").is_err());
        assert!(parse_scopes("openid openid").is_err());
        assert!(parse_scopes("openid admin").is_err());
    }

    #[test]
    fn profile_claims_are_independently_optional() {
        let scopes = vec!["openid".to_owned(), "profile".to_owned()];
        let mut claims = Map::new();
        add_user_claims(&mut claims, &scopes, None, None, None, &[]);
        assert!(claims.get("name").is_none());
        assert!(claims.get("preferred_username").is_none());

        add_user_claims(&mut claims, &scopes, Some("alice"), None, None, &[]);
        assert_eq!(claims["preferred_username"], "alice");
        assert!(claims.get("name").is_none());
    }

    #[test]
    fn redirect_query_params_are_encoded_and_existing_query_is_preserved() {
        let response =
            redirect_with_code("https://client.example/cb?existing=1", "a b", "state/1").unwrap();
        let location = response
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(location.contains("existing=1"));
        assert!(location.contains("code=a+b"));
        assert!(location.contains("state=state%2F1"));
    }

    async fn oidc_test_state() -> (AppState, String, String) {
        let mut config = crate::config::Config::new(
            "http://localhost:3000",
            "sqlite::memory:".into(),
            "127.0.0.1:0".into(),
        )
        .unwrap();
        config.bootstrap_token = Some("test-bootstrap".into());
        let database = crate::db::Database::connect("sqlite::memory:")
            .await
            .unwrap();
        let signing_keys = crate::keys::SigningKeys::initialize(database.clone(), [31_u8; 32])
            .await
            .unwrap();
        let webauthn = crate::webauthn::WebauthnService::new(
            "localhost",
            &config.public_origin,
            database.clone(),
        )
        .unwrap();
        let state = AppState {
            config: Arc::new(config),
            database,
            signing_keys,
            webauthn,
        };
        let user_id = Uuid::new_v4().to_string();
        let client_id = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO users (id, username, email, display_name, attributes, created_at, updated_at) VALUES (?, 'alice', 'alice@example.test', 'Alice Example', '{\"department\":\"engineering\"}', 1, 1)")
            .bind(&user_id)
            .execute(&state.database.pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO oidc_clients (client_id, client_secret_hash, client_type, name, enabled, created_at) VALUES (?, NULL, 'public', 'Test Client', 1, 1)")
            .bind(&client_id)
            .execute(&state.database.pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO client_redirect_uris (client_id, uri) VALUES (?, 'https://client.example/callback?from=provider')")
            .bind(&client_id)
            .execute(&state.database.pool)
            .await
            .unwrap();
        for scope in ["openid", "profile", "email", "groups"] {
            sqlx::query("INSERT INTO client_scopes (client_id, scope) VALUES (?, ?)")
                .bind(&client_id)
                .bind(scope)
                .execute(&state.database.pool)
                .await
                .unwrap();
        }
        sqlx::query("INSERT INTO client_claim_mappings (client_id, claim_name, user_attribute_path, required_scope) VALUES (?, 'department', '/department', 'profile')")
            .bind(&client_id)
            .execute(&state.database.pool)
            .await
            .unwrap();
        (state, user_id, client_id)
    }

    #[tokio::test]
    async fn authorization_code_flow_binds_state_nonce_pkce_and_consumes_code_once() {
        let (state, user_id, client_id) = oidc_test_state().await;
        let app = http_router(state.clone());
        let verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
        let challenge = s256_challenge(verifier);
        let mut auth_url = Url::parse("http://localhost:3000/authorize").unwrap();
        auth_url
            .query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &client_id)
            .append_pair(
                "redirect_uri",
                "https://client.example/callback?from=provider",
            )
            .append_pair("scope", "openid profile email groups")
            .append_pair("state", "state-value-42")
            .append_pair("nonce", "nonce-value-73")
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(auth_url.as_str())
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FOUND);
        let location = response
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let preauth = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .find_map(|value| {
                value
                    .to_str()
                    .ok()?
                    .strip_prefix("hanko_preauth=")?
                    .split(';')
                    .next()
                    .map(str::to_owned)
            })
            .unwrap();
        let login_page = Url::parse(&location).unwrap();
        let request_id = login_page
            .query_pairs()
            .find(|(key, _)| key == "request_id")
            .unwrap()
            .1
            .to_string();

        let mut info_url = Url::parse("http://localhost:3000/api/authorize/request").unwrap();
        info_url
            .query_pairs_mut()
            .append_pair("request_id", &request_id);
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(info_url.as_str())
                    .header(header::COOKIE, format!("hanko_preauth={preauth}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let info: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(info["client_name"], "Test Client");

        let browser_session = create_session(&state.database, &user_id, false, unix_now())
            .await
            .unwrap();
        let cookie = format!(
            "hanko_session={}; hanko_csrf={}; hanko_preauth={}",
            browser_session.raw_token, browser_session.raw_csrf, preauth,
        );
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(info_url.as_str())
                    .header(header::COOKIE, cookie.clone())
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let info: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(info["client_name"], "Test Client");
        assert_eq!(info["scopes"].as_array().unwrap().len(), 4);

        let continue_body = serde_json::json!({ "request_id": request_id }).to_string();
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/authorize/continue")
                    .header(header::ORIGIN, "http://localhost:3000")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, cookie)
                    .header("x-csrf-token", &browser_session.raw_csrf)
                    .body(axum::body::Body::from(continue_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let approved: Value = serde_json::from_slice(&body).unwrap();
        let callback = Url::parse(approved["redirect_to"].as_str().unwrap()).unwrap();
        let callback_params: std::collections::HashMap<_, _> = callback
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect();
        assert_eq!(
            callback_params.get("from").map(String::as_str),
            Some("provider")
        );
        assert_eq!(
            callback_params.get("state").map(String::as_str),
            Some("state-value-42")
        );
        let code = callback_params.get("code").unwrap().clone();

        let token_request = |code_verifier: &str| {
            let form = url::form_urlencoded::Serializer::new(String::new())
                .append_pair("grant_type", "authorization_code")
                .append_pair("code", &code)
                .append_pair(
                    "redirect_uri",
                    "https://client.example/callback?from=provider",
                )
                .append_pair("client_id", &client_id)
                .append_pair("code_verifier", code_verifier)
                .finish();
            Request::builder()
                .method("POST")
                .uri("/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(axum::body::Body::from(form))
                .unwrap()
        };
        let wrong = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        let response = app.clone().oneshot(token_request(wrong)).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let response = app.clone().oneshot(token_request(verifier)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap();
        let tokens: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(tokens["token_type"], "Bearer");
        assert_eq!(tokens["scope"], "openid profile email groups");
        let (id_claims, id_client) =
            verify_id_token_hint(&state, tokens["id_token"].as_str().unwrap())
                .await
                .unwrap();
        assert_eq!(id_client, client_id);
        assert_eq!(id_claims["nonce"], "nonce-value-73");
        assert_eq!(id_claims["at_hash"].as_str().unwrap().len(), 22);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/userinfo")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {}", tokens["access_token"].as_str().unwrap()),
                    )
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let userinfo: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(userinfo["sub"], user_id);
        assert_eq!(userinfo["name"], "Alice Example");
        assert_eq!(userinfo["preferred_username"], "alice");
        assert_eq!(userinfo["email"], "alice@example.test");
        assert_eq!(userinfo["department"], "engineering");
        assert!(userinfo.get("jti").is_none());

        let replay = app.oneshot(token_request(verifier)).await.unwrap();
        assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn userinfo_rejects_a_tampered_access_token() {
        let (state, _, _) = oidc_test_state().await;
        let app = http_router(state.clone());
        let token = state
            .signing_keys
            .sign(&serde_json::json!({
                "iss": state.config.issuer(), "sub": "missing", "aud": "test", "client_id": "test",
                "token_use": "access", "scope": "openid", "iat": unix_now(), "exp": unix_now()+60
            }))
            .await
            .unwrap();
        let mut tampered = token.clone();
        let last = tampered.pop().unwrap();
        tampered.push(if last == 'a' { 'b' } else { 'a' });
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/userinfo")
                    .header(header::AUTHORIZATION, format!("Bearer {tampered}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
