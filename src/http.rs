use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{OriginalUri, State},
    http::{HeaderMap, HeaderValue, Request, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
    routing::{get, get_service, post},
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use tower_http::{
    limit::RequestBodyLimitLayer,
    services::{ServeDir, ServeFile},
    set_header::SetResponseHeaderLayer,
    trace::TraceLayer,
};
use uuid::Uuid;

use crate::{
    config::Config,
    db::Database,
    keys::SigningKeys,
    security::{
        BrowserSession, PREAUTH_COOKIE, clear_session_cookies, cookie_header, cookie_value,
        create_session, csrf_header_matches, digest, load_identity, load_session, origin_is_valid,
        set_session_cookies, unix_now,
    },
    webauthn::WebauthnService,
};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub database: Database,
    pub signing_keys: SigningKeys,
    pub webauthn: WebauthnService,
}

#[derive(Serialize)]
struct DiscoveryDocument {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    jwks_uri: String,
    end_session_endpoint: String,
    response_types_supported: [&'static str; 1],
    subject_types_supported: [&'static str; 1],
    id_token_signing_alg_values_supported: [&'static str; 1],
    token_endpoint_auth_methods_supported: [&'static str; 2],
    code_challenge_methods_supported: [&'static str; 1],
    scopes_supported: [&'static str; 4],
}

#[derive(Deserialize)]
struct BootstrapInput {
    token: String,
    username: Option<String>,
    display_name: Option<String>,
    #[serde(default = "default_hanko_color")]
    hanko_color: String,
    #[serde(default = "default_hanko_seed")]
    hanko_seed: String,
}

#[derive(Deserialize)]
struct HankoStyleInput {
    color: String,
    seed: String,
}

#[derive(Deserialize)]
struct OidcProfileInput {
    username: Option<String>,
    display_name: Option<String>,
}

#[derive(Deserialize)]
struct CeremonyInput<T> {
    ceremony_id: String,
    credential: T,
    #[serde(default)]
    label: String,
}

#[derive(Serialize)]
struct SessionResponse {
    authenticated: bool,
    username: Option<String>,
    display_name: Option<String>,
    oidc_username: Option<String>,
    oidc_name: Option<String>,
    hanko_color: Option<String>,
    hanko_seed: Option<String>,
    is_admin: bool,
    setup_only: bool,
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
}

struct ApiError {
    status: StatusCode,
    message: &'static str,
}

impl ApiError {
    fn bad_request(message: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message,
        }
    }

    fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: "authentication required",
        }
    }

    fn forbidden() -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: "request rejected",
        }
    }

    fn conflict(message: &'static str) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message,
        }
    }

    fn internal() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "internal server error",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorBody {
                error: self.message,
            }),
        )
            .into_response()
    }
}

pub fn router(state: AppState) -> Router {
    let base_path = state.config.base_path().to_owned();
    let app = Router::new()
        .merge(crate::oidc::router())
        .merge(crate::admin::router())
        .route("/healthz", get(health))
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/jwks", get(jwks))
        .route("/api/session", get(session_info))
        .route("/api/account/profile", axum::routing::put(update_profile))
        .route("/api/account/hanko", axum::routing::put(update_hanko))
        .route("/api/setup-status", get(setup_status))
        .route("/api/bootstrap", post(bootstrap))
        .route("/api/passkeys/login/options", post(login_options))
        .route("/api/passkeys/login/verify", post(login_verify))
        .route("/api/passkeys/register/options", post(register_options))
        .route("/api/passkeys/register/verify", post(register_verify))
        .route("/logout", post(logout))
        .route_service("/", get_service(ServeFile::new("web/dist/index.html")))
        .route_service(
            "/admin/clients",
            get_service(ServeFile::new("web/dist/index.html")),
        )
        .fallback_service(ServeDir::new("web/dist").append_index_html_on_directories(true).not_found_service(ServeFile::new("web/dist/index.html")))
        .layer(RequestBodyLimitLayer::new(1024 * 1024))
        .layer(TraceLayer::new_for_http().make_span_with(|request: &Request<_>| {
            tracing::info_span!("http_request", method = %request.method(), path = %request.uri().path())
        }))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
        .with_state(state);

    if base_path.is_empty() {
        app
    } else {
        let slashless_path = base_path.clone();
        Router::new()
            .route(
                &format!("{base_path}/"),
                get(move |OriginalUri(uri): OriginalUri| {
                    let path = slashless_path.clone();
                    async move {
                        let location = uri
                            .query()
                            .map(|query| format!("{path}?{query}"))
                            .unwrap_or(path);
                        Redirect::permanent(&location)
                    }
                }),
            )
            // Tailscale Serve strips the matched mount point before proxying.
            // Keep the internal router available as the fallback at `/`, while
            // retaining the explicit nested routes for proxies that preserve
            // the prefix.
            .nest(&base_path, app.clone())
            .fallback_service(app)
    }
}

async fn health() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

async fn discovery(State(state): State<AppState>) -> Json<DiscoveryDocument> {
    let issuer = state.config.issuer();
    Json(DiscoveryDocument {
        authorization_endpoint: format!("{issuer}/authorize"),
        token_endpoint: format!("{issuer}/token"),
        userinfo_endpoint: format!("{issuer}/userinfo"),
        jwks_uri: format!("{issuer}/jwks"),
        end_session_endpoint: format!("{issuer}/logout"),
        issuer,
        response_types_supported: ["code"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["ES256"],
        token_endpoint_auth_methods_supported: ["none", "client_secret_post"],
        code_challenge_methods_supported: ["S256"],
        scopes_supported: ["openid", "profile", "email", "groups"],
    })
}

async fn jwks(State(state): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let keys = state.signing_keys.public_jwks().await.map_err(|error| {
        tracing::error!(%error, "failed to load signing keys");
        ApiError::internal()
    })?;
    Ok(Json(serde_json::json!({ "keys": keys })))
}

async fn bootstrap(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<BootstrapInput>,
) -> Result<Response, ApiError> {
    require_origin(&headers, &state.config)?;
    let expected_token = state.config.bootstrap_token.as_deref().ok_or(ApiError {
        status: StatusCode::NOT_FOUND,
        message: "bootstrap is disabled",
    })?;
    let expected_hash = digest(expected_token);
    let supplied_hash = digest(&input.token);
    if expected_hash.len() != supplied_hash.len()
        || !bool::from(subtle::ConstantTimeEq::ct_eq(
            expected_hash.as_slice(),
            supplied_hash.as_slice(),
        ))
    {
        return Err(ApiError::unauthorized());
    }
    let user_id = Uuid::new_v4().to_string();
    let raw_username = input
        .username
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let username = match raw_username {
        Some(value) => {
            normalize_username(value).ok_or(ApiError::bad_request("invalid username"))?
        }
        None => format!("user-{}", Uuid::new_v4().simple()),
    };
    let raw_display_name = input
        .display_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if raw_display_name.is_some_and(|value| value.len() > 120) {
        return Err(ApiError::bad_request("invalid display name"));
    }
    let display_name = raw_display_name.unwrap_or(&username);
    validate_hanko_style(&input.hanko_color, &input.hanko_seed)?;
    let now = unix_now();
    let inserted = sqlx::query("INSERT INTO users (id, username, display_name, hanko_color, hanko_seed, expose_preferred_username, expose_name, is_admin, created_at, updated_at) SELECT ?, ?, ?, ?, ?, ?, ?, 1, ?, ? WHERE NOT EXISTS (SELECT 1 FROM users)")
        .bind(&user_id)
        .bind(&username)
        .bind(display_name)
        .bind(&input.hanko_color)
        .bind(&input.hanko_seed)
        .bind(raw_username.is_some())
        .bind(raw_display_name.is_some())
        .bind(now)
        .bind(now)
        .execute(&state.database.pool)
        .await
        .map_err(|error| {
            tracing::error!(%error, "failed to create initial administrator");
            ApiError::internal()
        })?;
    if inserted.rows_affected() != 1 {
        return Err(ApiError::conflict(
            "identity provider has already been initialized",
        ));
    }
    let session = create_session(&state.database, &user_id, true, now)
        .await
        .map_err(|error| {
            tracing::error!(%error, "failed to create initial session");
            ApiError::internal()
        })?;
    let mut response = Json(serde_json::json!({ "ok": true, "setup_only": true })).into_response();
    set_session_cookies(&mut response, &session, &state.config);
    Ok(response)
}

async fn session_info(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SessionResponse>, ApiError> {
    let identity = load_identity(&headers, &state.database)
        .await
        .map_err(|error| {
            tracing::error!(%error, "failed to load session");
            ApiError::internal()
        })?;
    Ok(match identity {
        Some(identity) => Json(SessionResponse {
            authenticated: true,
            username: Some(identity.username),
            display_name: Some(identity.display_name),
            oidc_username: identity.oidc_username,
            oidc_name: identity.oidc_name,
            hanko_color: Some(identity.hanko_color),
            hanko_seed: Some(identity.hanko_seed),
            is_admin: identity.is_admin,
            setup_only: identity.setup_only,
        }),
        None => Json(SessionResponse {
            authenticated: false,
            username: None,
            display_name: None,
            oidc_username: None,
            oidc_name: None,
            hanko_color: None,
            hanko_seed: None,
            is_admin: false,
            setup_only: false,
        }),
    })
}

async fn update_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<OidcProfileInput>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_origin(&headers, &state.config)?;
    let session = require_session(&headers, &state.database).await?;
    require_csrf(&headers, &session)?;

    let current = sqlx::query(
        "SELECT username, display_name FROM users WHERE id = ? AND disabled_at IS NULL",
    )
    .bind(&session.user_id)
    .fetch_optional(&state.database.pool)
    .await
    .map_err(|_| ApiError::internal())?
    .ok_or_else(ApiError::unauthorized)?;
    let current_username: String = current
        .try_get("username")
        .map_err(|_| ApiError::internal())?;
    let current_display_name: String = current
        .try_get("display_name")
        .map_err(|_| ApiError::internal())?;

    let raw_username = input
        .username
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let oidc_username = match raw_username {
        Some(value) => {
            Some(normalize_username(value).ok_or(ApiError::bad_request("invalid username"))?)
        }
        None => None,
    };
    let username = oidc_username.as_deref().unwrap_or(&current_username);

    let raw_name = input
        .display_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if raw_name.is_some_and(|value| value.len() > 120) {
        return Err(ApiError::bad_request("invalid name"));
    }
    let display_name = raw_name.unwrap_or(&current_display_name);
    let updated = sqlx::query("UPDATE users SET username = ?, display_name = ?, expose_preferred_username = ?, expose_name = ?, updated_at = ? WHERE id = ? AND disabled_at IS NULL")
        .bind(username)
        .bind(display_name)
        .bind(oidc_username.is_some())
        .bind(raw_name.is_some())
        .bind(unix_now())
        .bind(&session.user_id)
        .execute(&state.database.pool)
        .await;
    if let Err(error) = updated {
        if error
            .as_database_error()
            .and_then(|database| database.code())
            .as_deref()
            == Some("2067")
        {
            return Err(ApiError::conflict("username already exists"));
        }
        tracing::error!(%error, "failed to update OIDC profile");
        return Err(ApiError::internal());
    }

    Ok(Json(serde_json::json!({
        "username": oidc_username,
        "display_name": raw_name,
    })))
}

async fn update_hanko(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<HankoStyleInput>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_origin(&headers, &state.config)?;
    let session = require_session(&headers, &state.database).await?;
    require_csrf(&headers, &session)?;
    validate_hanko_style(&input.color, &input.seed)?;
    sqlx::query("UPDATE users SET hanko_color = ?, hanko_seed = ?, updated_at = ? WHERE id = ? AND disabled_at IS NULL")
        .bind(&input.color)
        .bind(&input.seed)
        .bind(unix_now())
        .bind(&session.user_id)
        .execute(&state.database.pool)
        .await
        .map_err(|_| ApiError::internal())?;
    Ok(Json(
        serde_json::json!({ "color": input.color, "seed": input.seed }),
    ))
}

fn default_hanko_color() -> String {
    "#d64135".to_owned()
}

fn default_hanko_seed() -> String {
    "hanko".to_owned()
}

fn validate_hanko_style(color: &str, seed: &str) -> Result<(), ApiError> {
    let valid_hex = |value: &str| {
        value.len() == 7
            && value.starts_with('#')
            && value[1..].bytes().all(|byte| byte.is_ascii_hexdigit())
    };
    let valid_color = if let Some(stops) = color
        .strip_prefix("linear(")
        .and_then(|value| value.strip_suffix(')'))
    {
        stops
            .split_once(',')
            .is_some_and(|(first, second)| valid_hex(first) && valid_hex(second))
    } else {
        valid_hex(color)
    };
    let valid_seed = (1..=128).contains(&seed.len())
        && seed
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'));
    if valid_color && valid_seed {
        Ok(())
    } else {
        Err(ApiError::bad_request("invalid hanko style"))
    }
}

async fn setup_status(State(state): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let initialized = sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM users)")
        .fetch_one(&state.database.pool)
        .await
        .map_err(|_| ApiError::internal())?;
    Ok(Json(
        serde_json::json!({ "initialized": initialized, "bootstrap_enabled": state.config.bootstrap_token.is_some() }),
    ))
}

async fn login_options(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    require_origin(&headers, &state.config)?;
    let preauth =
        cookie_value(&headers, PREAUTH_COOKIE).unwrap_or_else(crate::security::random_secret);
    let browser_hash = digest(&preauth);
    let now = unix_now();
    let attempts: i64 = sqlx::query_scalar("INSERT INTO login_rate_limits (username_hash, window_started_at, attempts) VALUES (?, ?, 1) ON CONFLICT(username_hash) DO UPDATE SET attempts = CASE WHEN login_rate_limits.window_started_at <= ? THEN 1 ELSE login_rate_limits.attempts + 1 END, window_started_at = CASE WHEN login_rate_limits.window_started_at <= ? THEN excluded.window_started_at ELSE login_rate_limits.window_started_at END RETURNING attempts")
        .bind(&browser_hash)
        .bind(now)
        .bind(now - 60)
        .bind(now - 60)
        .fetch_one(&state.database.pool)
        .await
        .map_err(|_| ApiError::internal())?;
    if attempts > 12 {
        return Err(ApiError {
            status: StatusCode::TOO_MANY_REQUESTS,
            message: "too many sign-in attempts; try again shortly",
        });
    }
    let (ceremony_id, public_key) = state
        .webauthn
        .start_authentication(&browser_hash)
        .await
        .map_err(|_| ApiError::unauthorized())?;
    let mut response =
        Json(serde_json::json!({ "ceremony_id": ceremony_id, "publicKey": public_key }))
            .into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        cookie_header(PREAUTH_COOKIE, &preauth, &state.config, true, 5 * 60)
            .parse()
            .expect("valid pre-auth cookie"),
    );
    Ok(response)
}

async fn login_verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CeremonyInput<webauthn_rs::prelude::PublicKeyCredential>>,
) -> Result<Response, ApiError> {
    require_origin(&headers, &state.config)?;
    let preauth = cookie_value(&headers, PREAUTH_COOKIE).ok_or_else(ApiError::unauthorized)?;
    let browser_hash = digest(&preauth);
    let user_id = state
        .webauthn
        .finish_authentication(&input.ceremony_id, &browser_hash, input.credential)
        .await
        .map_err(|_| ApiError::unauthorized())?;
    let session = create_session(&state.database, &user_id, false, unix_now())
        .await
        .map_err(|error| {
            tracing::error!(%error, "failed to create browser session");
            ApiError::internal()
        })?;
    let mut response = Json(serde_json::json!({ "ok": true })).into_response();
    set_session_cookies(&mut response, &session, &state.config);
    Ok(response)
}

async fn register_options(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_origin(&headers, &state.config)?;
    let session = require_session(&headers, &state.database).await?;
    require_csrf(&headers, &session)?;
    let row = sqlx::query(
        "SELECT username, display_name FROM users WHERE id = ? AND disabled_at IS NULL",
    )
    .bind(&session.user_id)
    .fetch_optional(&state.database.pool)
    .await
    .map_err(|_| ApiError::internal())?
    .ok_or_else(ApiError::unauthorized)?;
    let username: String = row.try_get("username").map_err(|_| ApiError::internal())?;
    let display_name: String = row
        .try_get("display_name")
        .map_err(|_| ApiError::internal())?;
    let (ceremony_id, public_key) = state
        .webauthn
        .start_registration(
            &session.user_id,
            &username,
            &display_name,
            &session.session_hash,
        )
        .await
        .map_err(|error| {
            tracing::error!(%error, "failed to start passkey registration");
            ApiError::bad_request("could not start passkey registration")
        })?;
    Ok(Json(
        serde_json::json!({ "ceremony_id": ceremony_id, "publicKey": public_key }),
    ))
}

async fn register_verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CeremonyInput<webauthn_rs::prelude::RegisterPublicKeyCredential>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_origin(&headers, &state.config)?;
    let session = require_session(&headers, &state.database).await?;
    require_csrf(&headers, &session)?;
    state
        .webauthn
        .finish_registration(
            &input.ceremony_id,
            &session.user_id,
            &session.session_hash,
            input.credential,
            &input.label,
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "passkey registration failed");
            ApiError::bad_request("passkey registration failed")
        })?;
    // Bootstrap and invitation sessions are deliberately limited to enrolling a passkey.
    // Promote the session only after the credential has been committed successfully.
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Result<Response, ApiError> {
    require_origin(&headers, &state.config)?;
    let session = require_session(&headers, &state.database).await?;
    require_csrf(&headers, &session)?;
    sqlx::query("DELETE FROM sessions WHERE session_hash = ?")
        .bind(&session.session_hash)
        .execute(&state.database.pool)
        .await
        .map_err(|_| ApiError::internal())?;
    let mut response = Json(serde_json::json!({ "ok": true })).into_response();
    clear_session_cookies(&mut response, &state.config);
    Ok(response)
}

async fn require_session(
    headers: &HeaderMap,
    database: &Database,
) -> Result<BrowserSession, ApiError> {
    load_session(headers, database)
        .await
        .map_err(|_| ApiError::internal())?
        .ok_or_else(ApiError::unauthorized)
}

fn require_origin(headers: &HeaderMap, config: &Config) -> Result<(), ApiError> {
    if origin_is_valid(headers, config) {
        Ok(())
    } else {
        Err(ApiError::forbidden())
    }
}

fn require_csrf(headers: &HeaderMap, session: &BrowserSession) -> Result<(), ApiError> {
    if csrf_header_matches(headers, session) {
        Ok(())
    } else {
        Err(ApiError::forbidden())
    }
}

fn normalize_username(username: &str) -> Option<String> {
    let username = username.trim().to_ascii_lowercase();
    if username.is_empty()
        || username.len() > 64
        || !username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        None
    } else {
        Some(username)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{security::create_session, webauthn::WebauthnService};
    use tower::ServiceExt;
    use url::Url;

    async fn test_app(config: Config) -> Router {
        let database = Database::connect("sqlite::memory:").await.unwrap();
        let signing_keys = SigningKeys::initialize(database.clone(), [5_u8; 32])
            .await
            .unwrap();
        let rp_id = config.public_origin.host_str().unwrap().to_owned();
        let webauthn =
            WebauthnService::new(&rp_id, &config.webauthn_origin(), database.clone()).unwrap();
        router(AppState {
            config: Arc::new(config),
            database,
            signing_keys,
            webauthn,
        })
    }

    #[tokio::test]
    async fn discovery_uses_configured_issuer_and_advertises_pkce_s256() {
        let config = Config::new(
            "https://login.example",
            "sqlite::memory:".into(),
            "127.0.0.1:0".into(),
        )
        .unwrap();
        let app = test_app(config).await;
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/.well-known/openid-configuration")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let document: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(document["issuer"], "https://login.example");
        assert_eq!(document["code_challenge_methods_supported"][0], "S256");
        assert_eq!(
            document["id_token_signing_alg_values_supported"][0],
            "ES256"
        );
    }

    #[tokio::test]
    async fn base_path_serves_the_ui_and_discovery_document() {
        let config = Config::new(
            "https://login.example/hanko",
            "sqlite::memory:".into(),
            "127.0.0.1:0".into(),
        )
        .unwrap();
        let app = test_app(config).await;

        let slash = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/hanko/?request_id=abc")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(slash.status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(slash.headers()[header::LOCATION], "/hanko?request_id=abc");

        let page = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/hanko")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(page.status(), StatusCode::OK);
        assert!(
            page.headers()[header::CONTENT_TYPE]
                .to_str()
                .unwrap()
                .starts_with("text/html")
        );

        let client_admin_page = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/hanko/admin/clients")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(client_admin_page.status(), StatusCode::OK);

        // Tailscale Serve strips its `/hanko` mount prefix before forwarding.
        let upstream_client_admin_page = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/admin/clients")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(upstream_client_admin_page.status(), StatusCode::OK);

        let discovery = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/hanko/.well-known/openid-configuration")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(discovery.status(), StatusCode::OK);
        let body = axum::body::to_bytes(discovery.into_body(), usize::MAX)
            .await
            .unwrap();
        let document: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(document["issuer"], "https://login.example/hanko");

        // Tailscale Serve removes the `/hanko` mount prefix before forwarding
        // the request, so the same application must also answer at its root.
        let upstream_discovery = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/.well-known/openid-configuration")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(upstream_discovery.status(), StatusCode::OK);

        let upstream_setup_status = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/setup-status")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(upstream_setup_status.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn bootstrap_is_one_time_and_returns_setup_only_secure_session_cookie() {
        let mut config = Config::new(
            "http://localhost:3000",
            "sqlite::memory:".into(),
            "127.0.0.1:0".into(),
        )
        .unwrap();
        config.bootstrap_token = Some("bootstrap-secret".into());
        let app = test_app(config).await;
        let request = || {
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/bootstrap")
                .header(header::ORIGIN, "http://localhost:3000")
                .header(header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(
                    r#"{"token":"bootstrap-secret","username":"admin","hanko_seed":"setup-seed-0123456789"}"#,
                ))
                .unwrap()
        };
        let response = app.clone().oneshot(request()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let cookies: Vec<_> = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_owned())
            .collect();
        assert!(
            cookies
                .iter()
                .any(|v| v.starts_with("hanko_session=") && v.contains("HttpOnly"))
        );
        assert!(
            cookies
                .iter()
                .any(|v| v.starts_with("hanko_csrf=") && !v.contains("HttpOnly"))
        );
        assert_eq!(
            app.oneshot(request()).await.unwrap().status(),
            StatusCode::CONFLICT
        );
    }

    #[tokio::test]
    async fn setup_profile_step_saves_optional_oidc_claims_with_csrf_protection() {
        let mut config = Config::new(
            "http://localhost:3000",
            "sqlite::memory:".into(),
            "127.0.0.1:0".into(),
        )
        .unwrap();
        config.bootstrap_token = Some("bootstrap-secret".into());
        let app = test_app(config).await;
        let bootstrap = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/api/bootstrap")
                    .header(header::ORIGIN, "http://localhost:3000")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(r#"{"token":"bootstrap-secret"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bootstrap.status(), StatusCode::OK);
        let cookies: Vec<_> = bootstrap
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|value| {
                value
                    .to_str()
                    .unwrap()
                    .split(';')
                    .next()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        let cookie_header = cookies.join("; ");
        let csrf = cookies
            .iter()
            .find_map(|cookie| cookie.strip_prefix("hanko_csrf="))
            .unwrap();

        let rejected = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("PUT")
                    .uri("/api/account/profile")
                    .header(header::ORIGIN, "http://localhost:3000")
                    .header(header::COOKIE, &cookie_header)
                    .header("x-csrf-token", "incorrect")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(
                        r#"{"username":"Admin.1","display_name":""}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rejected.status(), StatusCode::FORBIDDEN);

        let saved = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("PUT")
                    .uri("/api/account/profile")
                    .header(header::ORIGIN, "http://localhost:3000")
                    .header(header::COOKIE, &cookie_header)
                    .header("x-csrf-token", csrf)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(
                        r#"{"username":"Admin.1","display_name":""}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(saved.status(), StatusCode::OK);
        let profile: serde_json::Value =
            serde_json::from_slice(&axum::body::to_bytes(saved.into_body(), 4096).await.unwrap())
                .unwrap();
        assert_eq!(profile["username"], "admin.1");
        assert!(profile["display_name"].is_null());

        let session = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/session")
                    .header(header::COOKIE, cookie_header)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(session.into_body(), 4096)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["oidc_username"], "admin.1");
        assert!(body["oidc_name"].is_null());
    }

    #[tokio::test]
    async fn passkey_login_options_are_usernameless_and_bind_a_server_side_ceremony() {
        let config = Config::new(
            "http://localhost:3000",
            "sqlite::memory:".into(),
            "127.0.0.1:0".into(),
        )
        .unwrap();
        let app = test_app(config).await;
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/api/passkeys/login/options")
                    .header(header::ORIGIN, "http://localhost:3000")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get(header::SET_COOKIE).is_some());
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let options: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(options["publicKey"]["challenge"].is_string());
        assert!(
            options["publicKey"]["allowCredentials"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn jwks_contains_the_active_public_key() {
        let config = Config::new(
            "http://localhost:3000",
            "sqlite::memory:".into(),
            "127.0.0.1:0".into(),
        )
        .unwrap();
        let app = test_app(config).await;
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/jwks")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let jwks: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(jwks["keys"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn session_and_webauthn_config_can_be_created_for_local_issuer() {
        let config = Config::new(
            "http://localhost:3000",
            "sqlite::memory:".into(),
            "127.0.0.1:0".into(),
        )
        .unwrap();
        let origin = Url::parse("http://localhost:3000").unwrap();
        assert!(
            WebauthnService::new(
                "localhost",
                &origin,
                Database::connect("sqlite::memory:").await.unwrap()
            )
            .is_ok()
        );
        assert!(normalize_username(" Alice.1 ").is_some());
        assert!(normalize_username("alice@example.com").is_none());
        assert!(validate_hanko_style("#d64135", "0123456789abcdef").is_ok());
        assert!(validate_hanko_style("linear(#d64135,#336699)", "0123456789abcdef").is_ok());
        assert_eq!(
            validate_hanko_style("url(javascript:alert(1))", "0123456789abcdef")
                .unwrap_err()
                .status,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(config.issuer(), "http://localhost:3000");
    }

    #[tokio::test]
    async fn session_cookies_are_unusable_without_the_csrf_cookie() {
        let database = Database::connect("sqlite::memory:").await.unwrap();
        sqlx::query("INSERT INTO users (id, username, display_name, created_at, updated_at) VALUES ('u1', 'alice', 'Alice', 1, 1)")
            .execute(&database.pool)
            .await
            .unwrap();
        let session = create_session(&database, "u1", false, unix_now())
            .await
            .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("hanko_session={}", session.raw_token)).unwrap(),
        );
        assert!(load_session(&headers, &database).await.unwrap().is_none());
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!(
                "hanko_session={}; hanko_csrf={}",
                session.raw_token, session.raw_csrf
            ))
            .unwrap(),
        );
        assert!(load_session(&headers, &database).await.unwrap().is_some());
    }
}
