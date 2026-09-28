use axum::{
    Form, Json, Router,
    extract::{ConnectInfo, Extension, Query, RawQuery, State},
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
use std::collections::HashMap;
use std::net::SocketAddr;
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
const REFRESH_SECONDS: i64 = 30 * 24 * 60 * 60;
const AUTH_REQUEST_SECONDS: i64 = 5 * 60;

struct AuthorizeRequest {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    scope: String,
    state: String,
    state_parameter_present: bool,
    nonce: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    prompt: Option<String>,
    max_age: Option<i64>,
}

struct AuthorizeParameters {
    values: HashMap<String, Vec<String>>,
}

impl AuthorizeParameters {
    fn parse(query: Option<&str>) -> Self {
        let mut values = HashMap::<String, Vec<String>>::new();
        if let Some(query) = query {
            for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
                values
                    .entry(key.into_owned())
                    .or_default()
                    .push(value.into_owned());
            }
        }
        Self { values }
    }

    fn single(&self, key: &str) -> Option<&str> {
        let values = self.values.get(key)?;
        (values.len() == 1).then(|| values[0].as_str())
    }

    fn into_request(self, client_id: String, redirect_uri: String) -> Result<AuthorizeRequest, ()> {
        const REQUEST_PARAMETERS: &[&str] = &[
            "response_type",
            "scope",
            "state",
            "nonce",
            "code_challenge",
            "code_challenge_method",
            "prompt",
            "max_age",
        ];
        if REQUEST_PARAMETERS.iter().any(|key| {
            self.values
                .get(*key)
                .is_some_and(|values| values.len() != 1)
        }) {
            return Err(());
        }
        let max_age = self
            .single("max_age")
            .map(|value| value.parse::<i64>())
            .transpose()
            .map_err(|_| ())?;
        let state = self.single("state").map(str::to_owned);
        Ok(AuthorizeRequest {
            response_type: self.single("response_type").unwrap_or_default().to_owned(),
            client_id,
            redirect_uri,
            scope: self.single("scope").unwrap_or_default().to_owned(),
            state: state.clone().unwrap_or_default(),
            state_parameter_present: state.is_some(),
            nonce: self.single("nonce").map(str::to_owned),
            code_challenge: self.single("code_challenge").map(str::to_owned),
            code_challenge_method: self.single("code_challenge_method").map(str::to_owned),
            prompt: self.single("prompt").map(str::to_owned),
            max_age,
        })
    }
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
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    refresh_token: Option<String>,
    code_verifier: Option<String>,
    client_secret: Option<String>,
}

#[derive(Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: i64,
    id_token: String,
    scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
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
    description: String,
}

impl OAuthError {
    fn invalid_request(description: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            error: "invalid_request",
            description: description.into(),
        }
    }
    fn invalid_client() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            error: "invalid_client",
            description: "client authentication failed".to_owned(),
        }
    }
    fn invalid_scope(description: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            error: "invalid_scope",
            description: description.into(),
        }
    }
    fn access_denied() -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            error: "access_denied",
            description: "Your account is not a member of a group allowed to access this application. Ask an administrator to add your account to an allowed group."
                .to_owned(),
        }
    }
    fn invalid_grant() -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            error: "invalid_grant",
            description: "authorization grant is invalid or expired".to_owned(),
        }
    }
    fn login_required() -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            error: "login_required",
            description: "a fresh user authentication is required".to_owned(),
        }
    }
    fn rate_limited() -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            error: "temporarily_unavailable",
            description: "too many authorization requests; try again shortly".to_owned(),
        }
    }
    fn server_error() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            error: "server_error",
            description: "identity provider error".to_owned(),
        }
    }
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        if self.status.is_server_error() {
            tracing::error!(
                status = %self.status,
                error_code = self.error,
                error_description = %self.description,
                "OIDC request failed"
            );
        } else {
            tracing::warn!(
                status = %self.status,
                error_code = self.error,
                error_description = %self.description,
                "OIDC request returned an error"
            );
        }
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
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
) -> Response {
    match authorize_request(state.clone(), raw_query, headers, peer).await {
        Ok(response) => response,
        Err(error) if error.status.is_server_error() => {
            tracing::error!(error = error.error, "OIDC authorization request failed");
            authorization_page_error(&state, "temporarily_unavailable")
                .unwrap_or_else(|page_error| page_error.into_response())
        }
        Err(error) => error.into_response(),
    }
}

async fn authorize_request(
    state: AppState,
    raw_query: Option<String>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
) -> Result<Response, OAuthError> {
    let Some(_slot) = crate::security::try_anonymous_state_slot() else {
        return authorization_page_error(&state, "temporarily_unavailable");
    };
    let source = crate::security::source_ip(
        peer.map(|Extension(ConnectInfo(address))| address),
        &headers,
        &state.config,
    );
    if !crate::http::allow_anonymous_state_creation(&state, "authorize", source, 30, 600)
        .await
        .map_err(|_| OAuthError::server_error())?
    {
        return authorization_page_error(&state, "temporarily_unavailable");
    }

    let parameters = AuthorizeParameters::parse(raw_query.as_deref());
    let Some(client_id) = parameters.single("client_id").map(str::to_owned) else {
        tracing::warn!(
            endpoint = "/authorize",
            "OIDC request rejected: client_id is missing or repeated"
        );
        return authorization_page_error(&state, "invalid_client");
    };
    let client = match sqlx::query(
        "SELECT client_type, pkce_policy FROM oidc_clients WHERE client_id = ? AND enabled = 1",
    )
    .bind(&client_id)
    .fetch_optional(&state.database.pool)
    .await
    {
        Ok(Some(client)) => client,
        Ok(None) => {
            tracing::warn!(
                endpoint = "/authorize",
                client_id = %client_id,
                "OIDC request rejected: client is unknown or disabled"
            );
            return authorization_page_error(&state, "invalid_client");
        }
        Err(error) => {
            tracing::error!(%error, endpoint = "/authorize", "failed to load OIDC client");
            return authorization_page_error(&state, "temporarily_unavailable");
        }
    };
    let client_type: String = client
        .try_get("client_type")
        .map_err(|_| OAuthError::server_error())?;
    let pkce_policy: String = client
        .try_get("pkce_policy")
        .map_err(|_| OAuthError::server_error())?;
    let Some(redirect_uri) = parameters.single("redirect_uri").map(str::to_owned) else {
        tracing::warn!(
            endpoint = "/authorize",
            client_id = %client_id,
            "OIDC request rejected: redirect_uri is missing or repeated"
        );
        return authorization_page_error(&state, "invalid_redirect_uri");
    };
    match validate_redirect(&state.database, &client_id, &redirect_uri).await {
        Ok(()) => {}
        Err(error) if error.error == "invalid_request" => {
            tracing::warn!(
                endpoint = "/authorize",
                client_id = %client_id,
                "OIDC request rejected: redirect_uri is invalid or not registered"
            );
            return authorization_page_error(&state, "invalid_redirect_uri");
        }
        Err(error) => {
            tracing::error!(
                endpoint = "/authorize",
                client_id = %client_id,
                error = error.error,
                "failed to validate OIDC redirect_uri"
            );
            return authorization_page_error(&state, "temporarily_unavailable");
        }
    }

    let state_value = parameters.single("state").map(str::to_owned);
    let input = match parameters.into_request(client_id.clone(), redirect_uri.clone()) {
        Ok(input) => input,
        Err(()) => {
            let input = AuthorizeRequest {
                response_type: String::new(),
                client_id,
                redirect_uri,
                scope: String::new(),
                state: state_value.clone().unwrap_or_default(),
                state_parameter_present: state_value.is_some(),
                nonce: None,
                code_challenge: None,
                code_challenge_method: None,
                prompt: None,
                max_age: None,
            };
            return authorization_protocol_error(&input, "invalid_request");
        }
    };
    let scopes = match validate_authorize_request(&state, &input, &client_type, &pkce_policy).await
    {
        Ok(scopes) => scopes,
        Err(error) if error.status.is_client_error() => {
            return authorization_protocol_error(&input, error.error);
        }
        Err(error) => {
            tracing::error!(
                endpoint = "/authorize",
                error = error.error,
                "failed to validate OIDC request"
            );
            return authorization_page_error(&state, "temporarily_unavailable");
        }
    };
    let prompts = match authorize_prompts(&input) {
        Ok(prompts) => prompts,
        Err(error) => return authorization_protocol_error(&input, error.error),
    };
    if prompts.iter().any(|prompt| *prompt == "select_account") {
        return authorization_protocol_error(&input, "account_selection_required");
    }
    let now_ms = crate::security::unix_now_millis();
    let now = now_ms / 1000;
    let existing_session = load_session(&headers, &state.database)
        .await
        .map_err(|_| OAuthError::server_error())?;
    let session_auth_time_ms = if let Some(session) = &existing_session {
        sqlx::query_scalar::<_, i64>(
            "SELECT authenticated_at_ms FROM sessions WHERE session_hash = ?",
        )
        .bind(&session.session_hash)
        .fetch_optional(&state.database.pool)
        .await
        .map_err(|_| OAuthError::server_error())?
    } else {
        None
    };
    let max_age_is_stale = input.max_age.is_some_and(|max_age| {
        session_auth_time_ms.is_none_or(|authenticated_at_ms| {
            max_age == 0
                || now_ms.saturating_sub(authenticated_at_ms) > max_age.saturating_mul(1000)
        })
    });
    let force_reauthentication = prompts.contains(&"login") || max_age_is_stale;

    if prompts.contains(&"none") {
        let Some(session) = existing_session
            .as_ref()
            .filter(|session| !session.setup_only)
        else {
            return authorization_protocol_error(&input, "login_required");
        };
        if !user_allowed_for_client(&state, &input.client_id, &session.user_id).await? {
            log_group_access_denial(&input.client_id, &session.user_id);
            return authorization_protocol_error(&input, "access_denied");
        }
        return authorization_protocol_error(
            &input,
            if force_reauthentication {
                "login_required"
            } else {
                // This provider asks for consent on every authorization and has no
                // stored grant that could satisfy prompt=none.
                "consent_required"
            },
        );
    }

    let prior_session_hash = if force_reauthentication {
        existing_session
            .as_ref()
            .map(|session| session.session_hash.clone())
    } else {
        None
    };
    let preauth = crate::security::random_secret();
    let request_id = crate::security::random_secret();
    sqlx::query("DELETE FROM authorization_requests WHERE expires_at <= ?")
        .bind(now)
        .execute(&state.database.pool)
        .await
        .map_err(|_| OAuthError::server_error())?;
    let inserted = sqlx::query("INSERT INTO authorization_requests (request_hash, browser_hash, client_id, redirect_uri, state, nonce, code_challenge, scopes, created_at, expires_at, max_age, force_reauthentication, prior_session_hash, created_at_ms) SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? WHERE (SELECT COUNT(*) FROM authorization_requests WHERE expires_at > ?) < 5000")
        .bind(digest(&request_id))
        .bind(digest(&preauth))
        .bind(&input.client_id)
        .bind(&input.redirect_uri)
        .bind(&input.state)
        // The schema stores an empty string for an omitted optional nonce.
        .bind(input.nonce.as_deref().unwrap_or(""))
        .bind(input.code_challenge.as_deref())
        .bind(serde_json::to_string(&scopes).map_err(|_| OAuthError::server_error())?)
        .bind(now)
        .bind(now + AUTH_REQUEST_SECONDS)
        .bind(input.max_age)
        .bind(force_reauthentication)
        .bind(prior_session_hash)
        .bind(now_ms)
        .bind(now)
        .execute(&state.database.pool)
        .await
        .map_err(|_| OAuthError::server_error())?;
    if inserted.rows_affected() != 1 {
        return authorization_page_error(&state, "temporarily_unavailable");
    }
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
    let scopes_json: String = row
        .try_get("scopes")
        .map_err(|_| OAuthError::server_error())?;
    let scopes: Vec<String> =
        serde_json::from_str(&scopes_json).map_err(|_| OAuthError::server_error())?;
    let max_age: Option<i64> = row
        .try_get("max_age")
        .map_err(|_| OAuthError::server_error())?;
    let force_reauthentication: bool = row
        .try_get("force_reauthentication")
        .map_err(|_| OAuthError::server_error())?;
    let prior_session_hash: Option<Vec<u8>> = row
        .try_get("prior_session_hash")
        .map_err(|_| OAuthError::server_error())?;
    let request_created_at_ms: i64 = row
        .try_get("created_at_ms")
        .map_err(|_| OAuthError::server_error())?;
    let mut requires_fresh_authentication = false;
    let claims = if let Some(session) = session.as_ref() {
        if session.setup_only {
            return Err(OAuthError::invalid_grant());
        }
        let client_id: String = row
            .try_get("client_id")
            .map_err(|_| OAuthError::server_error())?;
        if !user_allowed_for_client(&state, &client_id, &session.user_id).await? {
            log_group_access_denial(&client_id, &session.user_id);
            return Err(OAuthError::access_denied());
        }
        let claims = preview_user_claims(&state, &client_id, &session.user_id, &scopes).await?;
        let authenticated_at_ms = sqlx::query_scalar::<_, i64>(
            "SELECT authenticated_at_ms FROM sessions WHERE session_hash = ?",
        )
        .bind(&session.session_hash)
        .fetch_optional(&state.database.pool)
        .await
        .map_err(|_| OAuthError::server_error())?
        .ok_or_else(OAuthError::invalid_grant)?;
        let same_prior_session = prior_session_hash
            .as_deref()
            .is_some_and(|hash| hash == session.session_hash.as_slice());
        let now_ms = crate::security::unix_now_millis();
        let stale_by_max_age = max_age.is_some_and(|max_age| {
            max_age > 0 && now_ms.saturating_sub(authenticated_at_ms) > max_age.saturating_mul(1000)
        });
        let authenticated_after_request = authenticated_at_ms > request_created_at_ms;
        requires_fresh_authentication = stale_by_max_age
            || (force_reauthentication && (same_prior_session || !authenticated_after_request));
        Some(claims)
    } else {
        None
    };
    Ok(Json(serde_json::json!({
        "client_name": client_name,
        "redirect_uri": row.try_get::<String, _>("redirect_uri").map_err(|_| OAuthError::server_error())?,
        "scopes": scopes,
        "requires_fresh_authentication": requires_fresh_authentication,
        "claims": claims,
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
    let code_challenge: Option<String> = row
        .try_get("code_challenge")
        .map_err(|_| OAuthError::server_error())?;
    let scopes_json: String = row
        .try_get("scopes")
        .map_err(|_| OAuthError::server_error())?;
    let scopes: Vec<String> =
        serde_json::from_str(&scopes_json).map_err(|_| OAuthError::server_error())?;
    let max_age: Option<i64> = row
        .try_get("max_age")
        .map_err(|_| OAuthError::server_error())?;
    let force_reauthentication: bool = row
        .try_get("force_reauthentication")
        .map_err(|_| OAuthError::server_error())?;
    let prior_session_hash: Option<Vec<u8>> = row
        .try_get("prior_session_hash")
        .map_err(|_| OAuthError::server_error())?;
    let request_created_at_ms: i64 = row
        .try_get("created_at_ms")
        .map_err(|_| OAuthError::server_error())?;
    if !user_allowed_for_client(&state, &client_id, &session.user_id).await? {
        log_group_access_denial(&client_id, &session.user_id);
        return Err(OAuthError::access_denied());
    }
    validate_redirect(&state.database, &client_id, &redirect_uri).await?;
    ensure_scopes_still_allowed(&state, &client_id, &scopes).await?;
    let session_auth =
        sqlx::query("SELECT created_at, authenticated_at_ms FROM sessions WHERE session_hash = ?")
            .bind(&session.session_hash)
            .fetch_optional(&state.database.pool)
            .await
            .map_err(|_| OAuthError::server_error())?
            .ok_or_else(OAuthError::invalid_grant)?;
    let auth_time: i64 = session_auth
        .try_get("created_at")
        .map_err(|_| OAuthError::server_error())?;
    let authenticated_at_ms: i64 = session_auth
        .try_get("authenticated_at_ms")
        .map_err(|_| OAuthError::server_error())?;
    let now_ms = crate::security::unix_now_millis();
    let now = now_ms / 1000;
    if max_age.is_some_and(|max_age| {
        max_age > 0 && now_ms.saturating_sub(authenticated_at_ms) > max_age.saturating_mul(1000)
    }) {
        return Err(OAuthError::login_required());
    }
    if force_reauthentication
        && (authenticated_at_ms <= request_created_at_ms
            || prior_session_hash
                .as_deref()
                .is_some_and(|hash| hash == session.session_hash.as_slice()))
    {
        return Err(OAuthError::login_required());
    }
    let code = crate::security::random_secret();
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
        .bind(nonce).bind(code_challenge.as_deref()).bind(now).bind(now + CODE_SECONDS).bind(auth_time)
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
    let row = sqlx::query("SELECT client_id, redirect_uri, state, nonce, code_challenge, scopes, max_age, force_reauthentication, prior_session_hash, created_at_ms FROM authorization_requests WHERE request_hash = ? AND browser_hash = ? AND expires_at > ?")
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
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    Form(input): Form<TokenRequest>,
) -> Result<Json<TokenResponse>, OAuthError> {
    let _slot = crate::security::try_anonymous_state_slot().ok_or_else(OAuthError::rate_limited)?;
    let source = crate::security::source_ip(
        peer.map(|Extension(ConnectInfo(address))| address),
        &headers,
        &state.config,
    );
    if !crate::http::allow_anonymous_state_creation(&state, "token", source, 120, 6000)
        .await
        .map_err(|_| OAuthError::server_error())?
    {
        return Err(OAuthError::rate_limited());
    }
    let authorization_header_present = headers.contains_key(header::AUTHORIZATION);
    let basic_credentials = parse_basic_client_credentials(&headers)?;
    let client_id = match (input.client_id.as_deref(), basic_credentials.as_ref()) {
        (Some(form_client_id), Some((basic_client_id, _))) if form_client_id != basic_client_id => {
            return Err(OAuthError::invalid_client());
        }
        (Some(form_client_id), _) => form_client_id.to_owned(),
        (None, Some((basic_client_id, _))) => basic_client_id.clone(),
        (None, None) => return Err(OAuthError::invalid_client()),
    };
    let client = sqlx::query(
        "SELECT client_type, token_endpoint_auth_method, pkce_policy, client_secret_hash, enabled FROM oidc_clients WHERE client_id = ?",
    )
    .bind(&client_id)
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
    let auth_method: String = client
        .try_get("token_endpoint_auth_method")
        .map_err(|_| OAuthError::server_error())?;
    let pkce_policy: String = client
        .try_get("pkce_policy")
        .map_err(|_| OAuthError::server_error())?;
    let stored_secret: Option<String> = client
        .try_get("client_secret_hash")
        .map_err(|_| OAuthError::server_error())?;
    match (client_type.as_str(), auth_method.as_str()) {
        ("public", "none") if input.client_secret.is_none() && !authorization_header_present => {}
        ("confidential", "client_secret_post") if !authorization_header_present => {
            let Some(secret) = input.client_secret.as_deref() else {
                return Err(OAuthError::invalid_client());
            };
            validate_client_secret(secret, stored_secret.as_deref())?;
        }
        ("confidential", "client_secret_basic")
            if authorization_header_present && input.client_secret.is_none() =>
        {
            let Some((_, secret)) = basic_credentials.as_ref() else {
                return Err(OAuthError::invalid_client());
            };
            validate_client_secret(secret, stored_secret.as_deref())?;
        }
        _ => return Err(OAuthError::invalid_client()),
    }

    match input.grant_type.as_str() {
        "authorization_code" => {
            let code = input
                .code
                .as_deref()
                .ok_or_else(OAuthError::invalid_grant)?;
            let redirect_uri = input
                .redirect_uri
                .as_deref()
                .ok_or_else(OAuthError::invalid_grant)?;
            exchange_authorization_code(
                &state,
                &client_id,
                &pkce_policy,
                code,
                redirect_uri,
                input.code_verifier.as_deref(),
            )
            .await
        }
        "refresh_token" => {
            let refresh_token = input
                .refresh_token
                .as_deref()
                .ok_or_else(OAuthError::invalid_grant)?;
            exchange_refresh_token(&state, &client_id, refresh_token).await
        }
        _ => Err(OAuthError::invalid_grant()),
    }
    .map(Json)
}

fn parse_basic_client_credentials(
    headers: &HeaderMap,
) -> Result<Option<(String, String)>, OAuthError> {
    if headers.get_all(header::AUTHORIZATION).iter().count() > 1 {
        return Err(OAuthError::invalid_client());
    }
    let Some(value) = headers.get(header::AUTHORIZATION) else {
        return Ok(None);
    };
    let value = value.to_str().map_err(|_| OAuthError::invalid_client())?;
    let mut parts = value.split_ascii_whitespace();
    let Some(scheme) = parts.next() else {
        return Err(OAuthError::invalid_client());
    };
    if !scheme.eq_ignore_ascii_case("Basic") {
        return Ok(None);
    }
    let Some(encoded) = parts.next() else {
        return Err(OAuthError::invalid_client());
    };
    if parts.next().is_some() {
        return Err(OAuthError::invalid_client());
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| OAuthError::invalid_client())?;
    let decoded = String::from_utf8(decoded).map_err(|_| OAuthError::invalid_client())?;
    let (raw_client_id, raw_secret) = decoded
        .split_once(':')
        .ok_or_else(OAuthError::invalid_client)?;
    let decode_form_component = |component: &str| {
        let encoded = format!("value={component}");
        url::form_urlencoded::parse(encoded.as_bytes())
            .next()
            .map(|(_, value)| value.into_owned())
            .ok_or_else(OAuthError::invalid_client)
    };
    let client_id = decode_form_component(raw_client_id)?;
    let secret = decode_form_component(raw_secret)?;
    if client_id.is_empty() || secret.is_empty() {
        return Err(OAuthError::invalid_client());
    }
    Ok(Some((client_id, secret)))
}

fn validate_client_secret(secret: &str, stored_secret: Option<&str>) -> Result<(), OAuthError> {
    let Some(stored) = stored_secret else {
        return Err(OAuthError::invalid_client());
    };
    let actual = URL_SAFE_NO_PAD.encode(Sha256::digest(secret.as_bytes()));
    if constant_time_string_eq(&actual, stored) {
        Ok(())
    } else {
        Err(OAuthError::invalid_client())
    }
}

async fn exchange_authorization_code(
    state: &AppState,
    client_id: &str,
    pkce_policy: &str,
    code_value: &str,
    requested_redirect_uri: &str,
    code_verifier: Option<&str>,
) -> Result<TokenResponse, OAuthError> {
    let code_hash = digest(code_value);
    let preview = sqlx::query("SELECT code_challenge, redirect_uri, scopes, user_id FROM authorization_codes WHERE code_hash = ? AND client_id = ? AND consumed_at IS NULL AND expires_at > ?")
        .bind(&code_hash)
        .bind(client_id)
        .bind(unix_now())
        .fetch_optional(&state.database.pool)
        .await
        .map_err(|_| OAuthError::server_error())?
        .ok_or_else(OAuthError::invalid_grant)?;
    let expected_challenge: Option<String> = preview
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
    let pkce_valid = match (expected_challenge.as_deref(), code_verifier) {
        (Some(challenge), Some(verifier)) => {
            valid_pkce_verifier(verifier)
                && constant_time_string_eq(&s256_challenge(verifier), challenge)
        }
        (None, None) if pkce_policy == "optional" => true,
        _ => false,
    };
    if requested_redirect_uri != redirect_uri || !pkce_valid {
        return Err(OAuthError::invalid_grant());
    }
    let scopes: Vec<String> =
        serde_json::from_str(&scopes_json).map_err(|_| OAuthError::server_error())?;
    ensure_scopes_still_allowed(state, client_id, &scopes).await?;
    if !user_allowed_for_client(state, client_id, &preview_user_id).await? {
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
        .bind(client_id)
        .bind(requested_redirect_uri)
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

    issue_tokens(
        state,
        client_id,
        &user_id,
        &consumed_scopes,
        auth_time,
        (!nonce.is_empty()).then_some(nonce.as_str()),
        None,
    )
    .await
}

async fn exchange_refresh_token(
    state: &AppState,
    client_id: &str,
    refresh_token: &str,
) -> Result<TokenResponse, OAuthError> {
    let refresh_hash = digest(refresh_token);
    let now = unix_now();
    let row = sqlx::query("SELECT rt.user_id, rt.scopes, rt.auth_time, rt.family_id, rt.consumed_at, rt.expires_at, f.expires_at AS family_expires_at, f.revoked_at FROM refresh_tokens rt JOIN refresh_token_families f ON f.family_id = rt.family_id WHERE rt.token_hash = ? AND rt.client_id = ?")
        .bind(&refresh_hash)
        .bind(client_id)
        .fetch_optional(&state.database.pool)
        .await
        .map_err(|_| OAuthError::server_error())?
        .ok_or_else(OAuthError::invalid_grant)?;
    let family_id: String = row
        .try_get("family_id")
        .map_err(|_| OAuthError::server_error())?;
    let consumed_at: Option<i64> = row
        .try_get("consumed_at")
        .map_err(|_| OAuthError::server_error())?;
    let expires_at: i64 = row
        .try_get("expires_at")
        .map_err(|_| OAuthError::server_error())?;
    let family_expires_at: i64 = row
        .try_get("family_expires_at")
        .map_err(|_| OAuthError::server_error())?;
    let revoked_at: Option<i64> = row
        .try_get("revoked_at")
        .map_err(|_| OAuthError::server_error())?;
    if consumed_at.is_some() {
        if family_expires_at > now {
            revoke_refresh_family(&state.database, &family_id, now).await?;
        }
        return Err(OAuthError::invalid_grant());
    }
    if expires_at <= now || family_expires_at <= now || revoked_at.is_some() {
        return Err(OAuthError::invalid_grant());
    }
    let user_id: String = row
        .try_get("user_id")
        .map_err(|_| OAuthError::server_error())?;
    let scopes_json: String = row
        .try_get("scopes")
        .map_err(|_| OAuthError::server_error())?;
    let scopes: Vec<String> =
        serde_json::from_str(&scopes_json).map_err(|_| OAuthError::server_error())?;
    let auth_time: i64 = row
        .try_get("auth_time")
        .map_err(|_| OAuthError::server_error())?;
    if !scopes.iter().any(|scope| scope == "offline_access") {
        return Err(OAuthError::invalid_grant());
    }
    ensure_scopes_still_allowed(state, client_id, &scopes).await?;
    if !user_allowed_for_client(state, client_id, &user_id).await? {
        return Err(OAuthError::invalid_grant());
    }

    issue_tokens(
        state,
        client_id,
        &user_id,
        &scopes,
        auth_time,
        None,
        Some(refresh_hash),
    )
    .await
}

async fn revoke_refresh_family(
    database: &crate::db::Database,
    family_id: &str,
    now: i64,
) -> Result<(), OAuthError> {
    let mut transaction = database
        .pool
        .begin()
        .await
        .map_err(|_| OAuthError::server_error())?;
    sqlx::query("UPDATE refresh_token_families SET revoked_at = COALESCE(revoked_at, ?) WHERE family_id = ? AND expires_at > ?")
        .bind(now)
        .bind(family_id)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(|_| OAuthError::server_error())?;
    sqlx::query("DELETE FROM refresh_tokens WHERE family_id = ? AND consumed_at IS NULL")
        .bind(family_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| OAuthError::server_error())?;
    transaction
        .commit()
        .await
        .map_err(|_| OAuthError::server_error())
}

async fn issue_tokens(
    state: &AppState,
    client_id: &str,
    user_id: &str,
    scopes: &[String],
    auth_time: i64,
    nonce: Option<&str>,
    rotate_refresh_hash: Option<Vec<u8>>,
) -> Result<TokenResponse, OAuthError> {
    let now = unix_now();

    let user = sqlx::query(
        "SELECT username, display_name, expose_preferred_username, expose_name, email, attributes FROM users WHERE id = ? AND disabled_at IS NULL",
    )
    .bind(user_id)
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
    let picture = attributes
        .get("picture")
        .and_then(Value::as_str)
        .filter(|picture| !picture.trim().is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| crate::stamp::picture_url(&state.config.issuer(), user_id));
    let phone_number = attributes.get("phone_number").and_then(Value::as_str);
    let address = attributes.get("address");
    let profile_claims = crate::security::oidc_profile_claims(&attributes);
    let groups = user_groups(state, user_id).await?;
    let group_custom_claims = group_custom_claims(state, user_id, scopes).await?;
    let user_custom_claims = user_custom_claims(state, user_id, scopes).await?;
    let custom_claims = custom_claims(state, client_id, &attributes, scopes).await?;

    let scope_string = scopes.join(" ");
    let access_exp = now + ACCESS_SECONDS;
    let id_exp = now + ID_SECONDS;
    let mut access_claims = Map::new();
    add_standard_claims(
        &mut access_claims,
        state,
        user_id,
        client_id,
        now,
        access_exp,
        auth_time,
        "access",
    );
    access_claims.insert("scope".into(), Value::String(scope_string.clone()));
    add_user_claims(
        &mut access_claims,
        scopes,
        expose_preferred_username.then_some(username.as_str()),
        expose_name.then_some(display_name.as_str()),
        &profile_claims,
        email.as_deref(),
        Some(picture.as_str()),
        phone_number,
        address,
        &groups,
    );
    for (claim, value) in &group_custom_claims {
        access_claims.insert(claim.clone(), value.clone());
    }
    for (claim, value) in &user_custom_claims {
        access_claims.insert(claim.clone(), value.clone());
    }
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
        state,
        user_id,
        client_id,
        now,
        id_exp,
        auth_time,
        "id",
    );
    if let Some(nonce) = nonce {
        id_claims.insert("nonce".into(), Value::String(nonce.to_owned()));
    }
    let at_hash = Sha256::digest(access_token.as_bytes());
    id_claims.insert(
        "at_hash".into(),
        Value::String(URL_SAFE_NO_PAD.encode(&at_hash[..16])),
    );
    add_user_claims(
        &mut id_claims,
        scopes,
        expose_preferred_username.then_some(username.as_str()),
        expose_name.then_some(display_name.as_str()),
        &profile_claims,
        email.as_deref(),
        Some(picture.as_str()),
        phone_number,
        address,
        &groups,
    );
    for (claim, value) in group_custom_claims {
        id_claims.insert(claim, value);
    }
    for (claim, value) in user_custom_claims {
        id_claims.insert(claim, value);
    }
    for (claim, value) in custom_claims {
        id_claims.insert(claim, value);
    }
    let id_token = state
        .signing_keys
        .sign(&Value::Object(id_claims))
        .await
        .map_err(|_| OAuthError::server_error())?;

    let refresh_token = if scopes.iter().any(|scope| scope == "offline_access") {
        Some(crate::security::random_secret())
    } else {
        None
    };
    let mut transaction = state
        .database
        .pool
        .begin()
        .await
        .map_err(|_| OAuthError::server_error())?;
    let refresh_family_id = if let Some(refresh_hash) = rotate_refresh_hash {
        // Make this the transaction's first statement: SQLite serializes writers
        // here, so replay checks cannot race a successor insertion.
        let consumed = sqlx::query("UPDATE refresh_tokens SET consumed_at = ? WHERE token_hash = ? AND client_id = ? AND consumed_at IS NULL AND expires_at > ? AND family_id IN (SELECT family_id FROM refresh_token_families WHERE revoked_at IS NULL AND expires_at > ?) RETURNING family_id")
            .bind(now)
            .bind(&refresh_hash)
            .bind(client_id)
            .bind(now)
            .bind(now)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|_| OAuthError::server_error())?;
        if let Some(consumed) = consumed {
            let family_id: String = consumed
                .try_get("family_id")
                .map_err(|_| OAuthError::server_error())?;
            let extended = sqlx::query("UPDATE refresh_token_families SET expires_at = ? WHERE family_id = ? AND revoked_at IS NULL")
                .bind(now + REFRESH_SECONDS)
                .bind(&family_id)
                .execute(&mut *transaction)
                .await
                .map_err(|_| OAuthError::server_error())?;
            if extended.rows_affected() != 1 {
                return Err(OAuthError::invalid_grant());
            }
            Some(family_id)
        } else {
            let replay = sqlx::query("SELECT rt.family_id, rt.consumed_at, f.expires_at AS family_expires_at FROM refresh_tokens rt JOIN refresh_token_families f ON f.family_id = rt.family_id WHERE rt.token_hash = ? AND rt.client_id = ?")
                .bind(&refresh_hash)
                .bind(client_id)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(|_| OAuthError::server_error())?;
            if let Some(replay) = replay {
                let replay_family: String = replay
                    .try_get("family_id")
                    .map_err(|_| OAuthError::server_error())?;
                let replay_consumed: Option<i64> = replay
                    .try_get("consumed_at")
                    .map_err(|_| OAuthError::server_error())?;
                let family_expires_at: i64 = replay
                    .try_get("family_expires_at")
                    .map_err(|_| OAuthError::server_error())?;
                if replay_consumed.is_some() && family_expires_at > now {
                    sqlx::query("UPDATE refresh_token_families SET revoked_at = COALESCE(revoked_at, ?) WHERE family_id = ? AND expires_at > ?")
                        .bind(now)
                        .bind(&replay_family)
                        .bind(now)
                        .execute(&mut *transaction)
                        .await
                        .map_err(|_| OAuthError::server_error())?;
                    sqlx::query(
                        "DELETE FROM refresh_tokens WHERE family_id = ? AND consumed_at IS NULL",
                    )
                    .bind(&replay_family)
                    .execute(&mut *transaction)
                    .await
                    .map_err(|_| OAuthError::server_error())?;
                }
            }
            transaction
                .commit()
                .await
                .map_err(|_| OAuthError::server_error())?;
            return Err(OAuthError::invalid_grant());
        }
    } else if refresh_token.is_some() {
        let family_id = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO refresh_token_families (family_id, client_id, user_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?)")
            .bind(&family_id)
            .bind(client_id)
            .bind(user_id)
            .bind(now)
            .bind(now + REFRESH_SECONDS)
            .execute(&mut *transaction)
            .await
            .map_err(|_| OAuthError::server_error())?;
        Some(family_id)
    } else {
        None
    };
    if let Some(refresh_token) = &refresh_token {
        sqlx::query("INSERT INTO refresh_tokens (token_hash, client_id, user_id, scopes, auth_time, created_at, expires_at, family_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(digest(refresh_token))
            .bind(client_id)
            .bind(user_id)
            .bind(serde_json::to_string(scopes).map_err(|_| OAuthError::server_error())?)
            .bind(auth_time)
            .bind(now)
            .bind(now + REFRESH_SECONDS)
            .bind(refresh_family_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| OAuthError::server_error())?;
    }
    sqlx::query("INSERT OR IGNORE INTO client_users (client_id, user_id) VALUES (?, ?)")
        .bind(client_id)
        .bind(user_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| OAuthError::server_error())?;
    transaction
        .commit()
        .await
        .map_err(|_| OAuthError::server_error())?;

    Ok(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: ACCESS_SECONDS,
        id_token,
        scope: scope_string,
        refresh_token,
    })
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
        for claim in [
            "profile",
            "given_name",
            "family_name",
            "nickname",
            "website",
            "locale",
            "zoneinfo",
        ] {
            if let Some(value) = claims.additional.get(claim) {
                result.insert(claim.to_owned(), value.clone());
            }
        }
    }
    if scopes
        .iter()
        .any(|scope| matches!(*scope, "profile" | "picture"))
    {
        if let Some(picture) = claims.additional.get("picture") {
            result.insert("picture".into(), picture.clone());
        }
    }
    if scopes.contains(&"email") {
        if let Some(email) = email {
            result.insert("email".into(), Value::String(email));
            result.insert("email_verified".into(), Value::Bool(false));
        }
    }
    if scopes.contains(&"address") {
        if let Some(address) = claims.additional.get("address") {
            result.insert("address".into(), address.clone());
        }
    }
    if scopes.contains(&"phone") {
        if let Some(phone_number) = claims.additional.get("phone_number") {
            result.insert("phone_number".into(), phone_number.clone());
            result.insert("phone_number_verified".into(), Value::Bool(false));
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
                | "profile"
                | "given_name"
                | "family_name"
                | "nickname"
                | "website"
                | "locale"
                | "zoneinfo"
                | "email"
                | "email_verified"
                | "picture"
                | "address"
                | "phone_number"
                | "phone_number_verified"
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
    let mut matched_session = false;
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
            matched_session = true;
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
    if matched_session {
        crate::security::clear_session_cookies(&mut response, &state.config);
    }
    Ok(response)
}

async fn validate_authorize_request(
    state: &AppState,
    input: &AuthorizeRequest,
    client_type: &str,
    pkce_policy: &str,
) -> Result<Vec<String>, OAuthError> {
    if input.response_type != "code"
        || input.state.is_empty()
        || input.state.len() > 512
        || input.max_age.is_some_and(|max_age| max_age < 0)
        || input
            .nonce
            .as_ref()
            .is_some_and(|nonce| nonce.is_empty() || nonce.len() > 512)
    {
        return Err(OAuthError::invalid_request(
            "required authorization parameters are invalid",
        ));
    }
    let pkce_present = match (
        input.code_challenge.as_deref(),
        input.code_challenge_method.as_deref(),
    ) {
        (Some(challenge), Some("S256")) => valid_s256_challenge(challenge),
        (None, None) => false,
        // This provider supports only S256. A method without a challenge or an
        // omitted method alongside a challenge cannot silently downgrade it.
        _ => false,
    };
    if !matches!(pkce_policy, "required" | "optional")
        || (client_type == "public" && pkce_policy != "required")
        || (pkce_policy == "required" && !pkce_present)
        || (input.code_challenge.is_some() && !pkce_present)
        || (input.code_challenge.is_none() && input.code_challenge_method.is_some())
    {
        return Err(OAuthError::invalid_request(
            "public clients require PKCE S256; confidential clients follow their configured PKCE policy",
        ));
    }
    let scopes = parse_scopes(&input.scope)?;
    ensure_scopes_still_allowed(state, &input.client_id, &scopes).await?;
    Ok(scopes)
}

fn authorize_prompts(input: &AuthorizeRequest) -> Result<Vec<&str>, OAuthError> {
    let Some(prompt) = input.prompt.as_deref() else {
        return Ok(Vec::new());
    };
    let prompts: Vec<&str> = prompt.split_ascii_whitespace().collect();
    if prompts.is_empty()
        || prompts.iter().enumerate().any(|(index, prompt)| {
            prompts[..index].contains(prompt)
                || !matches!(*prompt, "none" | "login" | "consent" | "select_account")
        })
        || (prompts.contains(&"none") && prompts.len() != 1)
    {
        return Err(OAuthError::invalid_request("prompt parameter is invalid"));
    }
    Ok(prompts)
}

fn authorization_protocol_error(
    input: &AuthorizeRequest,
    error: &str,
) -> Result<Response, OAuthError> {
    tracing::warn!(
        endpoint = "/authorize",
        client_id = %input.client_id,
        error_code = error,
        "OIDC authorization could not continue"
    );
    let mut url = Url::parse(&input.redirect_uri)
        .map_err(|_| OAuthError::invalid_request("redirect_uri is invalid"))?;
    url.query_pairs_mut().append_pair("error", error);
    if input.state_parameter_present {
        url.query_pairs_mut().append_pair("state", &input.state);
    }
    redirect(url.as_str())
}

fn authorization_page_error(state: &AppState, error: &str) -> Result<Response, OAuthError> {
    if error == "temporarily_unavailable" {
        tracing::error!(
            endpoint = "/authorize",
            error_code = error,
            "OIDC authorization could not start"
        );
    } else {
        tracing::warn!(
            endpoint = "/authorize",
            error_code = error,
            "OIDC authorization request was rejected"
        );
    }
    redirect(&format!("{}/?hanko_error={error}", state.config.issuer()))
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
        Err(OAuthError::invalid_scope("requested scope is not allowed"))
    }
}

fn parse_scopes(scope: &str) -> Result<Vec<String>, OAuthError> {
    let scopes: Vec<String> = scope.split_ascii_whitespace().map(str::to_owned).collect();
    let missing_openid = !scopes.iter().any(|scope| scope == "openid");
    let unsupported: Vec<&str> = scopes
        .iter()
        .filter(|scope| {
            !matches!(
                scope.as_str(),
                "openid"
                    | "profile"
                    | "email"
                    | "picture"
                    | "address"
                    | "phone"
                    | "groups"
                    | "offline_access"
            )
        })
        .map(String::as_str)
        .collect();
    if scopes.is_empty() || missing_openid || !unsupported.is_empty() {
        let mut reasons = Vec::new();
        if missing_openid {
            reasons.push("missing required scope \"openid\"".to_owned());
        }
        if unsupported.is_empty() {
            reasons.push("unsupported scopes: none".to_owned());
        } else {
            reasons.push(format!("unsupported scopes: {}", unsupported.join(", ")));
        }
        return Err(OAuthError::invalid_scope(format!(
            "requested scope \"{scope}\" is invalid: {}",
            reasons.join("; ")
        )));
    }
    let unique: std::collections::HashSet<_> = scopes.iter().collect();
    if unique.len() != scopes.len() {
        return Err(OAuthError::invalid_scope("scope values must be unique"));
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

fn log_group_access_denial(client_id: &str, user_id: &str) {
    tracing::warn!(
        event = "authorization_denied",
        reason = "group_policy",
        client_id = %client_id,
        user_id = %user_id,
        "OIDC authorization denied by client group policy"
    );
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

async fn preview_user_claims(
    state: &AppState,
    client_id: &str,
    user_id: &str,
    scopes: &[String],
) -> Result<Map<String, Value>, OAuthError> {
    let user = sqlx::query(
        "SELECT username, display_name, expose_preferred_username, expose_name, email, attributes FROM users WHERE id = ? AND disabled_at IS NULL",
    )
    .bind(user_id)
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
    let picture = attributes
        .get("picture")
        .and_then(Value::as_str)
        .filter(|picture| !picture.trim().is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| crate::stamp::picture_url(&state.config.issuer(), user_id));
    let phone_number = attributes.get("phone_number").and_then(Value::as_str);
    let address = attributes.get("address");
    let profile_claims = crate::security::oidc_profile_claims(&attributes);
    let groups = user_groups(state, user_id).await?;
    let group_custom_claims = group_custom_claims(state, user_id, scopes).await?;
    let user_custom_claims = user_custom_claims(state, user_id, scopes).await?;

    let mut claims = Map::new();
    add_user_claims(
        &mut claims,
        scopes,
        expose_preferred_username.then_some(username.as_str()),
        expose_name.then_some(display_name.as_str()),
        &profile_claims,
        email.as_deref(),
        Some(picture.as_str()),
        phone_number,
        address,
        &groups,
    );
    for (claim, value) in group_custom_claims {
        claims.insert(claim, value);
    }
    for (claim, value) in user_custom_claims {
        claims.insert(claim, value);
    }
    for (claim, value) in custom_claims(state, client_id, &attributes, scopes).await? {
        claims.insert(claim, value);
    }
    Ok(claims)
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
        if matches!(
            name.as_str(),
            "name"
                | "preferred_username"
                | "profile"
                | "given_name"
                | "family_name"
                | "nickname"
                | "website"
                | "locale"
                | "zoneinfo"
                | "picture"
                | "address"
                | "email_verified"
                | "phone_number"
                | "phone_number_verified"
        ) {
            continue;
        }
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

async fn group_custom_claims(
    state: &AppState,
    user_id: &str,
    scopes: &[String],
) -> Result<Map<String, Value>, OAuthError> {
    let rows = sqlx::query("SELECT mappings.claim_name, mappings.claim_value, mappings.required_scope FROM group_claim_mappings mappings JOIN groups ON groups.id = mappings.group_id JOIN user_groups ON user_groups.group_id = mappings.group_id WHERE user_groups.user_id = ? ORDER BY mappings.claim_name, groups.name")
        .bind(user_id)
        .fetch_all(&state.database.pool)
        .await
        .map_err(|_| OAuthError::server_error())?;
    let mut contributions = std::collections::BTreeMap::<String, Vec<Value>>::new();
    for row in rows {
        let required_scope: String = row
            .try_get("required_scope")
            .map_err(|_| OAuthError::server_error())?;
        if !scopes.iter().any(|scope| scope == &required_scope) {
            continue;
        }
        let claim_name: String = row
            .try_get("claim_name")
            .map_err(|_| OAuthError::server_error())?;
        let encoded_value: String = row
            .try_get("claim_value")
            .map_err(|_| OAuthError::server_error())?;
        let value: Value =
            serde_json::from_str(&encoded_value).map_err(|_| OAuthError::server_error())?;
        contributions.entry(claim_name).or_default().push(value);
    }

    let mut claims = Map::new();
    for (name, mut values) in contributions {
        match values.len() {
            0 => {}
            1 => {
                claims.insert(name, values.remove(0));
            }
            _ => {
                let mut merged = Vec::new();
                for value in values {
                    let items = match value {
                        Value::Array(items) => items,
                        value => vec![value],
                    };
                    for item in items {
                        if !merged.contains(&item) {
                            merged.push(item);
                        }
                    }
                }
                claims.insert(name, Value::Array(merged));
            }
        }
    }
    Ok(claims)
}

async fn user_custom_claims(
    state: &AppState,
    user_id: &str,
    scopes: &[String],
) -> Result<Map<String, Value>, OAuthError> {
    let rows = sqlx::query("SELECT claim_name, claim_value, required_scope FROM user_claim_mappings WHERE user_id = ? ORDER BY claim_name")
        .bind(user_id)
        .fetch_all(&state.database.pool)
        .await
        .map_err(|_| OAuthError::server_error())?;
    let mut claims = Map::new();
    for row in rows {
        let required_scope: Option<String> = row
            .try_get("required_scope")
            .map_err(|_| OAuthError::server_error())?;
        if required_scope
            .as_ref()
            .is_some_and(|scope| !scopes.contains(scope))
        {
            continue;
        }
        let claim_name: String = row
            .try_get("claim_name")
            .map_err(|_| OAuthError::server_error())?;
        let encoded_value: String = row
            .try_get("claim_value")
            .map_err(|_| OAuthError::server_error())?;
        let value: Value =
            serde_json::from_str(&encoded_value).map_err(|_| OAuthError::server_error())?;
        claims.insert(claim_name, value);
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
    profile_claims: &Value,
    email: Option<&str>,
    picture: Option<&str>,
    phone_number: Option<&str>,
    address: Option<&Value>,
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
        for claim in [
            "profile",
            "given_name",
            "family_name",
            "nickname",
            "website",
            "locale",
            "zoneinfo",
        ] {
            if let Some(value) = profile_claims.get(claim) {
                claims.insert(claim.to_owned(), value.clone());
            }
        }
    }
    if scopes.iter().any(|scope| scope == "email") {
        if let Some(email) = email {
            claims.insert("email".into(), Value::String(email.to_owned()));
            claims.insert("email_verified".into(), Value::Bool(false));
        }
    }
    if scopes
        .iter()
        .any(|scope| matches!(scope.as_str(), "profile" | "picture"))
    {
        if let Some(picture) = picture {
            claims.insert("picture".into(), Value::String(picture.to_owned()));
        }
    }
    if scopes.iter().any(|scope| scope == "groups") {
        claims.insert(
            "groups".into(),
            serde_json::to_value(groups).unwrap_or(Value::Array(vec![])),
        );
    }
    if scopes.iter().any(|scope| scope == "address") {
        if let Some(address) = address.filter(|address| {
            address
                .as_object()
                .is_some_and(|address| !address.is_empty())
        }) {
            claims.insert("address".into(), address.clone());
        }
    }
    if scopes.iter().any(|scope| scope == "phone") {
        if let Some(phone_number) = phone_number {
            claims.insert(
                "phone_number".into(),
                Value::String(phone_number.to_owned()),
            );
            claims.insert("phone_number_verified".into(), Value::Bool(false));
        }
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
        assert_eq!(
            parse_scopes("openid offline_access").unwrap(),
            vec!["openid", "offline_access"]
        );
        assert!(parse_scopes("profile").is_err());
        assert!(parse_scopes("openid openid").is_err());
        assert!(parse_scopes("openid admin").is_err());
    }

    #[test]
    fn profile_claims_are_independently_optional() {
        let scopes = vec!["openid".to_owned(), "profile".to_owned()];
        let mut claims = Map::new();
        add_user_claims(
            &mut claims,
            &scopes,
            None,
            None,
            &Value::Null,
            None,
            None,
            None,
            None,
            &[],
        );
        assert!(claims.get("name").is_none());
        assert!(claims.get("preferred_username").is_none());

        add_user_claims(
            &mut claims,
            &scopes,
            Some("alice"),
            None,
            &Value::Null,
            None,
            None,
            None,
            None,
            &[],
        );
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
            anonymous_request_limiter: crate::security::AnonymousRequestLimiter::default(),
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

    async fn add_confidential_client(state: &AppState) -> (String, String) {
        let client_id = Uuid::new_v4().to_string();
        let secret = "test-confidential-secret".to_owned();
        let secret_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(secret.as_bytes()));
        sqlx::query("INSERT INTO oidc_clients (client_id, client_secret_hash, client_type, token_endpoint_auth_method, pkce_policy, name, enabled, created_at) VALUES (?, ?, 'confidential', 'client_secret_post', 'optional', 'Confidential Test Client', 1, 1)")
            .bind(&client_id)
            .bind(secret_hash)
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
        (client_id, secret)
    }

    async fn issue_test_refresh_token(state: &AppState, user_id: &str, client_id: &str) -> String {
        sqlx::query(
            "INSERT OR IGNORE INTO client_scopes (client_id, scope) VALUES (?, 'offline_access')",
        )
        .bind(client_id)
        .execute(&state.database.pool)
        .await
        .unwrap();
        issue_tokens(
            state,
            client_id,
            user_id,
            &["openid".to_owned(), "offline_access".to_owned()],
            unix_now(),
            None,
            None,
        )
        .await
        .unwrap()
        .refresh_token
        .unwrap()
    }

    async fn issue_test_authorization_code(
        state: &AppState,
        user_id: &str,
        client_id: &str,
        challenge: Option<&str>,
        challenge_method: Option<&str>,
    ) -> Result<String, StatusCode> {
        let app = http_router(state.clone());
        let mut auth_url = Url::parse("http://localhost:3000/authorize").unwrap();
        {
            let mut query = auth_url.query_pairs_mut();
            query
                .append_pair("response_type", "code")
                .append_pair("client_id", client_id)
                .append_pair(
                    "redirect_uri",
                    "https://client.example/callback?from=provider",
                )
                .append_pair("scope", "openid profile email groups")
                .append_pair("state", "test-state");
            if let Some(challenge) = challenge {
                query.append_pair("code_challenge", challenge);
            }
            if let Some(method) = challenge_method {
                query.append_pair("code_challenge_method", method);
            }
        }
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
        if response.status() != StatusCode::FOUND {
            let status = response.status();
            let body = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            let error: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(error["error"], "invalid_request");
            return Err(status);
        }
        let location = response.headers()[header::LOCATION]
            .to_str()
            .unwrap()
            .to_owned();
        let redirect_url = Url::parse(&location).unwrap();
        if redirect_url
            .query_pairs()
            .any(|(key, value)| key == "error" && value == "invalid_request")
        {
            return Err(StatusCode::BAD_REQUEST);
        }
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
        let request_id = redirect_url
            .query_pairs()
            .find(|(key, _)| key == "request_id")
            .unwrap()
            .1
            .to_string();
        let session = create_session(&state.database, user_id, false, unix_now())
            .await
            .unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/authorize/continue")
                    .header(header::ORIGIN, "http://localhost:3000")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(
                        header::COOKIE,
                        format!(
                            "hanko_session={}; hanko_csrf={}; hanko_preauth={}",
                            session.raw_token, session.raw_csrf, preauth
                        ),
                    )
                    .header("x-csrf-token", &session.raw_csrf)
                    .body(axum::body::Body::from(
                        serde_json::json!({ "request_id": request_id }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        if response.status() != StatusCode::OK {
            return Err(response.status());
        }
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let approved: Value = serde_json::from_slice(&body).unwrap();
        let callback = Url::parse(approved["redirect_to"].as_str().unwrap()).unwrap();
        Ok(callback
            .query_pairs()
            .find(|(key, _)| key == "code")
            .unwrap()
            .1
            .to_string())
    }

    fn test_token_request(
        client_id: &str,
        code: &str,
        secret: Option<&str>,
        verifier: Option<&str>,
    ) -> Request<axum::body::Body> {
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        form.append_pair("grant_type", "authorization_code")
            .append_pair("code", code)
            .append_pair(
                "redirect_uri",
                "https://client.example/callback?from=provider",
            )
            .append_pair("client_id", client_id);
        if let Some(secret) = secret {
            form.append_pair("client_secret", secret);
        }
        if let Some(verifier) = verifier {
            form.append_pair("code_verifier", verifier);
        }
        Request::builder()
            .method("POST")
            .uri("/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(axum::body::Body::from(form.finish()))
            .unwrap()
    }

    #[tokio::test]
    async fn public_clients_require_pkce_and_cannot_authenticate_with_a_secret() {
        let (state, user_id, client_id) = oidc_test_state().await;
        assert_eq!(
            issue_test_authorization_code(&state, &user_id, &client_id, None, None).await,
            Err(StatusCode::BAD_REQUEST)
        );

        let verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
        let challenge = s256_challenge(verifier);
        let code = issue_test_authorization_code(
            &state,
            &user_id,
            &client_id,
            Some(&challenge),
            Some("S256"),
        )
        .await
        .unwrap();
        let response = http_router(state)
            .oneshot(test_token_request(
                &client_id,
                &code,
                Some("unexpected-secret"),
                Some(verifier),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn confidential_clients_can_exchange_codes_with_or_without_pkce() {
        let (state, user_id, _) = oidc_test_state().await;
        let (client_id, secret) = add_confidential_client(&state).await;

        let code = issue_test_authorization_code(&state, &user_id, &client_id, None, None)
            .await
            .unwrap();
        let app = http_router(state.clone());
        let missing_client_secret = app
            .clone()
            .oneshot(test_token_request(&client_id, &code, None, None))
            .await
            .unwrap();
        assert_eq!(missing_client_secret.status(), StatusCode::UNAUTHORIZED);
        let unexpected_verifier = app
            .clone()
            .oneshot(test_token_request(
                &client_id,
                &code,
                Some(&secret),
                Some("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"),
            ))
            .await
            .unwrap();
        assert_eq!(unexpected_verifier.status(), StatusCode::BAD_REQUEST);
        let response = app
            .oneshot(test_token_request(&client_id, &code, Some(&secret), None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
        let challenge = s256_challenge(verifier);
        let code = issue_test_authorization_code(
            &state,
            &user_id,
            &client_id,
            Some(&challenge),
            Some("S256"),
        )
        .await
        .unwrap();
        let app = http_router(state);
        let missing_client_secret = app
            .clone()
            .oneshot(test_token_request(&client_id, &code, None, Some(verifier)))
            .await
            .unwrap();
        assert_eq!(missing_client_secret.status(), StatusCode::UNAUTHORIZED);
        let missing = app
            .clone()
            .oneshot(test_token_request(&client_id, &code, Some(&secret), None))
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::BAD_REQUEST);
        let missing_body = axum::body::to_bytes(missing.into_body(), 4096)
            .await
            .unwrap();
        let missing_error: Value = serde_json::from_slice(&missing_body).unwrap();
        assert_eq!(missing_error["error"], "invalid_grant");
        let wrong = app
            .clone()
            .oneshot(test_token_request(
                &client_id,
                &code,
                Some(&secret),
                Some("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
            ))
            .await
            .unwrap();
        assert_eq!(wrong.status(), StatusCode::BAD_REQUEST);
        let invalid_client = app
            .clone()
            .oneshot(test_token_request(
                &client_id,
                &code,
                Some("wrong-secret"),
                Some(verifier),
            ))
            .await
            .unwrap();
        assert_eq!(invalid_client.status(), StatusCode::UNAUTHORIZED);
        let valid = app
            .oneshot(test_token_request(
                &client_id,
                &code,
                Some(&secret),
                Some(verifier),
            ))
            .await
            .unwrap();
        assert_eq!(valid.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn confidential_pkce_parameters_cannot_be_silently_downgraded() {
        let (state, user_id, _) = oidc_test_state().await;
        let (client_id, _) = add_confidential_client(&state).await;
        let verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
        let challenge = s256_challenge(verifier);
        assert_eq!(
            issue_test_authorization_code(&state, &user_id, &client_id, Some(&challenge), None,)
                .await,
            Err(StatusCode::BAD_REQUEST)
        );
        assert_eq!(
            issue_test_authorization_code(&state, &user_id, &client_id, None, Some("S256"),).await,
            Err(StatusCode::BAD_REQUEST)
        );
        assert_eq!(
            issue_test_authorization_code(
                &state,
                &user_id,
                &client_id,
                Some(&challenge),
                Some("plain"),
            )
            .await,
            Err(StatusCode::BAD_REQUEST)
        );
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
    async fn refresh_token_reuse_revokes_the_active_successor_and_family() {
        let (state, user_id, client_id) = oidc_test_state().await;
        let original = issue_test_refresh_token(&state, &user_id, &client_id).await;
        let family_id: String =
            sqlx::query_scalar("SELECT family_id FROM refresh_tokens WHERE token_hash = ?")
                .bind(digest(&original))
                .fetch_one(&state.database.pool)
                .await
                .unwrap();

        // Whether the legitimate client or a thief redeems the bearer token first,
        // a subsequent use of the consumed value must revoke the entire family.
        let thief = exchange_refresh_token(&state, &client_id, &original)
            .await
            .unwrap();
        let successor = thief.refresh_token.unwrap();
        let replay = exchange_refresh_token(&state, &client_id, &original)
            .await
            .err()
            .unwrap();
        assert_eq!(replay.error, "invalid_grant");

        let active: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM refresh_tokens WHERE family_id = ? AND consumed_at IS NULL",
        )
        .bind(&family_id)
        .fetch_one(&state.database.pool)
        .await
        .unwrap();
        let revoked_at: Option<i64> =
            sqlx::query_scalar("SELECT revoked_at FROM refresh_token_families WHERE family_id = ?")
                .bind(&family_id)
                .fetch_one(&state.database.pool)
                .await
                .unwrap();
        assert_eq!(active, 0);
        assert!(revoked_at.is_some());
        assert_eq!(
            exchange_refresh_token(&state, &client_id, &successor)
                .await
                .err()
                .unwrap()
                .error,
            "invalid_grant"
        );
        assert_eq!(
            exchange_refresh_token(&state, &client_id, &original)
                .await
                .err()
                .unwrap()
                .error,
            "invalid_grant"
        );
    }

    #[tokio::test]
    async fn refresh_token_cross_client_attempt_does_not_revoke_owner_family() {
        let (state, user_id, client_id) = oidc_test_state().await;
        let original = issue_test_refresh_token(&state, &user_id, &client_id).await;
        let other_client = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO oidc_clients (client_id, client_secret_hash, client_type, name, enabled, created_at) VALUES (?, NULL, 'public', 'Other Client', 1, 1)")
            .bind(&other_client)
            .execute(&state.database.pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO client_scopes (client_id, scope) VALUES (?, 'openid'), (?, 'offline_access')")
            .bind(&other_client)
            .bind(&other_client)
            .execute(&state.database.pool)
            .await
            .unwrap();

        let cross_client = exchange_refresh_token(&state, &other_client, &original)
            .await
            .err()
            .unwrap();
        assert_eq!(cross_client.error, "invalid_grant");
        let owner_rotation = exchange_refresh_token(&state, &client_id, &original)
            .await
            .unwrap();
        let successor = owner_rotation.refresh_token.unwrap();
        let replay = exchange_refresh_token(&state, &client_id, &original)
            .await
            .err()
            .unwrap();
        assert_eq!(replay.error, "invalid_grant");
        assert_eq!(
            exchange_refresh_token(&state, &client_id, &successor)
                .await
                .err()
                .unwrap()
                .error,
            "invalid_grant"
        );
    }

    #[tokio::test]
    async fn simultaneous_refresh_redemptions_revoke_the_winning_successor() {
        let (state, user_id, client_id) = oidc_test_state().await;
        let original = issue_test_refresh_token(&state, &user_id, &client_id).await;
        let (first, second) = tokio::join!(
            exchange_refresh_token(&state, &client_id, &original),
            exchange_refresh_token(&state, &client_id, &original),
        );
        assert_ne!(first.is_ok(), second.is_ok());
        let active: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM refresh_tokens WHERE token_hash = ? AND consumed_at IS NULL",
        )
        .bind(digest(&original))
        .fetch_one(&state.database.pool)
        .await
        .unwrap();
        assert_eq!(active, 0);
        let successors: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM refresh_tokens WHERE family_id = (SELECT family_id FROM refresh_tokens WHERE token_hash = ?) AND consumed_at IS NULL",
        )
        .bind(digest(&original))
        .fetch_one(&state.database.pool)
        .await
        .unwrap();
        assert_eq!(successors, 0);
    }

    #[tokio::test]
    async fn max_age_requires_a_new_passkey_session_before_consent() {
        let (state, user_id, client_id) = oidc_test_state().await;
        let app = http_router(state.clone());
        let previous_session =
            create_session(&state.database, &user_id, false, unix_now() - 60 * 60)
                .await
                .unwrap();
        let verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
        let mut authorization_url = Url::parse("http://localhost:3000/authorize").unwrap();
        authorization_url
            .query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &client_id)
            .append_pair(
                "redirect_uri",
                "https://client.example/callback?from=provider",
            )
            .append_pair("scope", "openid profile")
            .append_pair("state", "fresh-state")
            .append_pair("code_challenge", &s256_challenge(verifier))
            .append_pair("code_challenge_method", "S256")
            .append_pair("max_age", "30");
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(authorization_url.as_str())
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FOUND);
        let location = response.headers()[header::LOCATION]
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
        let request_id = Url::parse(&location)
            .unwrap()
            .query_pairs()
            .find(|(key, _)| key == "request_id")
            .unwrap()
            .1
            .to_string();
        let info_uri = format!("/api/authorize/request?request_id={request_id}");
        let old_cookie = format!(
            "hanko_session={}; hanko_csrf={}; hanko_preauth={preauth}",
            previous_session.raw_token, previous_session.raw_csrf
        );
        let info = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&info_uri)
                    .header(header::COOKIE, &old_cookie)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(info.into_body(), 4096).await.unwrap();
        let info: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(info["requires_fresh_authentication"], true);

        let continue_with = |session: &crate::security::BrowserSession| {
            Request::builder()
                .method("POST")
                .uri("/api/authorize/continue")
                .header(header::ORIGIN, "http://localhost:3000")
                .header(header::CONTENT_TYPE, "application/json")
                .header(
                    header::COOKIE,
                    format!(
                        "hanko_session={}; hanko_csrf={}; hanko_preauth={preauth}",
                        session.raw_token, session.raw_csrf
                    ),
                )
                .header("x-csrf-token", &session.raw_csrf)
                .body(axum::body::Body::from(
                    serde_json::json!({ "request_id": request_id }).to_string(),
                ))
                .unwrap()
        };
        let denied = app
            .clone()
            .oneshot(continue_with(&previous_session))
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(denied.into_body(), 4096)
            .await
            .unwrap();
        let error: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error["error"], "login_required");

        let enrollment_session = create_session(&state.database, &user_id, true, unix_now())
            .await
            .unwrap();
        sqlx::query("UPDATE sessions SET setup_only = 0 WHERE session_hash = ?")
            .bind(&enrollment_session.session_hash)
            .execute(&state.database.pool)
            .await
            .unwrap();
        let enrollment_cookie = format!(
            "hanko_session={}; hanko_csrf={}; hanko_preauth={preauth}",
            enrollment_session.raw_token, enrollment_session.raw_csrf
        );
        let info = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&info_uri)
                    .header(header::COOKIE, &enrollment_cookie)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(info.into_body(), 4096).await.unwrap();
        let info: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(info["requires_fresh_authentication"], true);
        let denied = app
            .clone()
            .oneshot(continue_with(&enrollment_session))
            .await
            .unwrap();
        let body = axum::body::to_bytes(denied.into_body(), 4096)
            .await
            .unwrap();
        let error: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error["error"], "login_required");

        let fresh_session = crate::security::create_passkey_session(&state.database, &user_id)
            .await
            .unwrap();
        let info = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&info_uri)
                    .header(
                        header::COOKIE,
                        format!(
                            "hanko_session={}; hanko_csrf={}; hanko_preauth={preauth}",
                            fresh_session.raw_token, fresh_session.raw_csrf
                        ),
                    )
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(info.into_body(), 4096).await.unwrap();
        let info: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(info["requires_fresh_authentication"], false);

        let approved = app.oneshot(continue_with(&fresh_session)).await.unwrap();
        assert_eq!(approved.status(), StatusCode::OK);
        let body = axum::body::to_bytes(approved.into_body(), 4096)
            .await
            .unwrap();
        let result: Value = serde_json::from_slice(&body).unwrap();
        let callback = Url::parse(result["redirect_to"].as_str().unwrap()).unwrap();
        let code = callback
            .query_pairs()
            .find(|(key, _)| key == "code")
            .unwrap()
            .1
            .to_string();
        let auth_time: i64 =
            sqlx::query_scalar("SELECT auth_time FROM authorization_codes WHERE code_hash = ?")
                .bind(digest(&code))
                .fetch_one(&state.database.pool)
                .await
                .unwrap();
        let fresh_auth_time: i64 =
            sqlx::query_scalar("SELECT created_at FROM sessions WHERE session_hash = ?")
                .bind(fresh_session.session_hash)
                .fetch_one(&state.database.pool)
                .await
                .unwrap();
        assert_eq!(auth_time, fresh_auth_time);
    }

    #[tokio::test]
    async fn prompt_login_requires_a_new_assertion_even_for_a_recent_session() {
        let (state, user_id, client_id) = oidc_test_state().await;
        let app = http_router(state.clone());
        let session = create_session(&state.database, &user_id, false, unix_now())
            .await
            .unwrap();
        let verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
        let mut authorization_url = Url::parse("http://localhost:3000/authorize").unwrap();
        authorization_url
            .query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &client_id)
            .append_pair(
                "redirect_uri",
                "https://client.example/callback?from=provider",
            )
            .append_pair("scope", "openid")
            .append_pair("state", "prompt-login-state")
            .append_pair("code_challenge", &s256_challenge(verifier))
            .append_pair("code_challenge_method", "S256")
            .append_pair("prompt", "login");
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(authorization_url.as_str())
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FOUND);
        let location = response.headers()[header::LOCATION]
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
        let request_id = Url::parse(&location)
            .unwrap()
            .query_pairs()
            .find(|(key, _)| key == "request_id")
            .unwrap()
            .1
            .to_string();
        let info = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/authorize/request?request_id={request_id}"))
                    .header(
                        header::COOKIE,
                        format!(
                            "hanko_session={}; hanko_csrf={}; hanko_preauth={preauth}",
                            session.raw_token, session.raw_csrf
                        ),
                    )
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(info.into_body(), 4096).await.unwrap();
        let info: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(info["requires_fresh_authentication"], true);
    }

    #[tokio::test]
    async fn prompt_none_returns_an_interaction_error_without_creating_a_pending_request() {
        let (state, user_id, client_id) = oidc_test_state().await;
        let app = http_router(state.clone());
        let verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
        let mut authorization_url = Url::parse("http://localhost:3000/authorize").unwrap();
        authorization_url
            .query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &client_id)
            .append_pair(
                "redirect_uri",
                "https://client.example/callback?from=provider",
            )
            .append_pair("scope", "openid")
            .append_pair("state", "silent-state")
            .append_pair("code_challenge", &s256_challenge(verifier))
            .append_pair("code_challenge_method", "S256")
            .append_pair("prompt", "none");
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(authorization_url.as_str())
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let location = Url::parse(response.headers()[header::LOCATION].to_str().unwrap()).unwrap();
        assert_eq!(
            location
                .query_pairs()
                .find(|(key, _)| key == "error")
                .unwrap()
                .1,
            "login_required"
        );
        assert_eq!(
            location
                .query_pairs()
                .find(|(key, _)| key == "state")
                .unwrap()
                .1,
            "silent-state"
        );
        let pending: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM authorization_requests")
            .fetch_one(&state.database.pool)
            .await
            .unwrap();
        assert_eq!(pending, 0);

        let session = create_session(&state.database, &user_id, false, unix_now())
            .await
            .unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .uri(authorization_url.as_str())
                    .header(
                        header::COOKIE,
                        format!(
                            "hanko_session={}; hanko_csrf={}",
                            session.raw_token, session.raw_csrf
                        ),
                    )
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let location = Url::parse(response.headers()[header::LOCATION].to_str().unwrap()).unwrap();
        assert_eq!(
            location
                .query_pairs()
                .find(|(key, _)| key == "error")
                .unwrap()
                .1,
            "consent_required"
        );
    }

    #[tokio::test]
    async fn logout_only_clears_cookies_for_a_matching_id_token_subject() {
        let (state, victim_id, client_id) = oidc_test_state().await;
        let app = http_router(state.clone());
        let other_id = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO users (id, username, email, display_name, attributes, created_at, updated_at) VALUES (?, 'bob', 'bob@example.test', 'Bob Example', '{}', 1, 1)")
            .bind(&other_id)
            .execute(&state.database.pool)
            .await
            .unwrap();
        let victim_session = create_session(&state.database, &victim_id, false, unix_now())
            .await
            .unwrap();
        let other_tokens = issue_tokens(
            &state,
            &client_id,
            &other_id,
            &["openid".to_owned()],
            unix_now(),
            None,
            None,
        )
        .await
        .unwrap();
        let logout_uri = |hint: &str| {
            let mut url = Url::parse("http://localhost:3000/logout").unwrap();
            url.query_pairs_mut().append_pair("id_token_hint", hint);
            url.to_string()
        };
        let victim_cookie = format!(
            "hanko_session={}; hanko_csrf={}",
            victim_session.raw_token, victim_session.raw_csrf
        );
        let mismatched = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(logout_uri(&other_tokens.id_token))
                    .header(header::COOKIE, &victim_cookie)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(mismatched.status(), StatusCode::OK);
        assert!(
            mismatched
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .next()
                .is_none()
        );
        let victim_still_exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sessions WHERE session_hash = ?)")
                .bind(&victim_session.session_hash)
                .fetch_one(&state.database.pool)
                .await
                .unwrap();
        assert!(victim_still_exists);

        let absent = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/logout")
                    .header(header::COOKIE, &victim_cookie)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(absent.status(), StatusCode::BAD_REQUEST);
        assert!(
            absent
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .next()
                .is_none()
        );

        let invalid = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/logout?id_token_hint=invalid")
                    .header(header::COOKIE, &victim_cookie)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
        assert!(
            invalid
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .next()
                .is_none()
        );

        let matching_tokens = issue_tokens(
            &state,
            &client_id,
            &victim_id,
            &["openid".to_owned()],
            unix_now(),
            None,
            None,
        )
        .await
        .unwrap();
        let matching = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(logout_uri(&matching_tokens.id_token))
                    .header(header::COOKIE, &victim_cookie)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(matching.status(), StatusCode::OK);
        let cleared: Vec<String> = matching
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|value| value.to_str().unwrap().to_owned())
            .collect();
        assert_eq!(cleared.len(), 5);
        assert!(
            cleared
                .iter()
                .any(|cookie| cookie.starts_with("hanko_session="))
        );
        for cookie_name in ["hanko_csrf", "hanko_crf", "hanko_preauth", "AUTHP"] {
            assert!(
                cleared
                    .iter()
                    .any(|cookie| cookie.starts_with(&format!("{cookie_name}="))),
                "logout should clear the {cookie_name} cookie"
            );
        }
        let victim_still_exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sessions WHERE session_hash = ?)")
                .bind(&victim_session.session_hash)
                .fetch_one(&state.database.pool)
                .await
                .unwrap();
        assert!(!victim_still_exists);

        let expired_session = create_session(&state.database, &other_id, false, unix_now())
            .await
            .unwrap();
        let expired_at = unix_now() - 600;
        let expired_hint = state
            .signing_keys
            .sign(&serde_json::json!({
                "iss": state.config.issuer(),
                "sub": other_id,
                "aud": client_id,
                "token_use": "id",
                "iat": expired_at - 300,
                "exp": expired_at,
            }))
            .await
            .unwrap();
        let expired_logout = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(logout_uri(&expired_hint))
                    .header(
                        header::COOKIE,
                        format!(
                            "hanko_session={}; hanko_csrf={}",
                            expired_session.raw_token, expired_session.raw_csrf
                        ),
                    )
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(expired_logout.status(), StatusCode::OK);
        assert_eq!(
            expired_logout
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .count(),
            5
        );
        let expired_session_remains: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sessions WHERE session_hash = ?)")
                .bind(expired_session.session_hash)
                .fetch_one(&state.database.pool)
                .await
                .unwrap();
        assert!(!expired_session_remains);

        let no_session = app
            .oneshot(
                Request::builder()
                    .uri(logout_uri(&matching_tokens.id_token))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            no_session
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .next()
                .is_none()
        );
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
