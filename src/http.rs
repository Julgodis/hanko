use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{ConnectInfo, Extension, OriginalUri, Path, State},
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
        AnonymousRequestLimiter, BrowserSession, PREAUTH_COOKIE, SESSION_COOKIE,
        anonymous_request_allowed, clear_session_cookies, cookie_header, cookie_value,
        create_passkey_session, csrf_header_matches, digest, load_identity, load_session,
        origin_is_valid, set_session_cookies, source_ip, try_anonymous_state_slot, unix_now,
    },
    webauthn::WebauthnService,
};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub database: Database,
    pub signing_keys: SigningKeys,
    pub webauthn: WebauthnService,
    pub anonymous_request_limiter: AnonymousRequestLimiter,
}

pub(crate) async fn allow_anonymous_state_creation(
    state: &AppState,
    endpoint: &str,
    source: IpAddr,
    source_limit: i64,
    global_limit: i64,
) -> Result<bool, sqlx::Error> {
    let now = unix_now();
    if !state
        .anonymous_request_limiter
        .allow(endpoint, source, now, source_limit, global_limit)
    {
        return Ok(false);
    }
    anonymous_request_allowed(
        &state.database,
        endpoint,
        source,
        now,
        source_limit,
        global_limit,
    )
    .await
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
    token_endpoint_auth_methods_supported: [&'static str; 3],
    code_challenge_methods_supported: [&'static str; 1],
    grant_types_supported: [&'static str; 2],
    scopes_supported: [&'static str; 8],
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
    picture: Option<String>,
    phone_number: Option<String>,
    address: Option<AddressInput>,
    profile_claims: Option<OidcProfileClaimsInput>,
}

#[derive(Deserialize)]
struct AddressInput {
    street_address: Option<String>,
    locality: Option<String>,
    region: Option<String>,
    postal_code: Option<String>,
    country: Option<String>,
}

#[derive(Deserialize)]
struct OidcProfileClaimsInput {
    profile: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
    nickname: Option<String>,
    website: Option<String>,
    locale: Option<String>,
    zoneinfo: Option<String>,
    // Kept in the request type so self-service attempts to set or clear roles
    // are rejected explicitly instead of being silently ignored.
    app_roles: Option<BTreeMap<String, Vec<String>>>,
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
    oidc_picture: Option<String>,
    oidc_phone: Option<String>,
    oidc_address: Option<serde_json::Value>,
    oidc_profile_claims: serde_json::Value,
    hanko_color: Option<String>,
    hanko_seed: Option<String>,
    is_admin: bool,
    setup_only: bool,
    required_user_claims: Vec<String>,
    allow_multiple_passkeys_per_authenticator: bool,
}

#[derive(Serialize)]
struct AccountPasskey {
    id: String,
    label: String,
    created_at: i64,
    last_used_at: Option<i64>,
}

#[derive(Deserialize)]
struct RenamePasskeyInput {
    label: String,
}

#[derive(Deserialize)]
struct RemovePasskeyInput {
    confirmation: String,
    approval_token: String,
}

#[derive(Default, Deserialize)]
struct RegistrationOptionsInput {
    approval_token: Option<String>,
}

#[derive(Default, Deserialize)]
struct LoginOptionsInput {
    account: Option<String>,
}

#[derive(Deserialize)]
struct CredentialChangeOptionsInput {
    action: String,
    passkey_id: Option<String>,
}

#[derive(Deserialize)]
struct CredentialChangeVerifyInput {
    ceremony_id: String,
    credential: webauthn_rs::prelude::PublicKeyCredential,
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
}

struct ApiError {
    status: StatusCode,
    message: &'static str,
    retry_after_seconds: Option<u64>,
}

impl ApiError {
    fn bad_request(message: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message,
            retry_after_seconds: None,
        }
    }

    fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: "authentication required",
            retry_after_seconds: None,
        }
    }

    fn forbidden() -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: "request rejected",
            retry_after_seconds: None,
        }
    }

    fn conflict(message: &'static str) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message,
            retry_after_seconds: None,
        }
    }

    fn not_found() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: "passkey not found",
            retry_after_seconds: None,
        }
    }

    fn internal() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "internal server error",
            retry_after_seconds: None,
        }
    }

    fn capacity(message: &'static str, retry_after_seconds: u64) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            message,
            retry_after_seconds: Some(retry_after_seconds),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if self.status.is_server_error() {
            tracing::error!(
                status = %self.status,
                error = self.message,
                retry_after_seconds = ?self.retry_after_seconds,
                "HTTP request failed"
            );
        } else {
            tracing::warn!(
                status = %self.status,
                error = self.message,
                retry_after_seconds = ?self.retry_after_seconds,
                "HTTP request returned an error"
            );
        }
        let retry_after_seconds = self.retry_after_seconds;
        let mut response = (
            self.status,
            Json(ErrorBody {
                error: self.message,
            }),
        )
            .into_response();
        if let Some(seconds) = retry_after_seconds {
            if let Ok(value) = HeaderValue::from_str(&seconds.to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
        }
        response
    }
}

pub fn router(state: AppState) -> Router {
    let base_path = state.config.base_path().to_owned();
    let app = Router::new()
        .merge(crate::oidc::router())
        .merge(crate::admin::router())
        .route("/healthz", get(health))
        .route("/.well-known/openid-configuration", get(discovery).layer(crate::oidc::cors_layer()))
        .route("/jwks", get(jwks).layer(crate::oidc::cors_layer()))
        .route("/api/users/{user_id}/picture.svg", get(generated_user_picture))
        .route("/api/session", get(session_info))
        .route("/api/account/profile", axum::routing::put(update_profile))
        .route("/api/account/hanko", axum::routing::put(update_hanko))
        .route("/api/account/consents", get(list_account_consents))
        .route(
            "/api/account/consents/{client_id}",
            axum::routing::delete(revoke_account_consent),
        )
        .route("/api/setup-status", get(setup_status))
        .route("/api/bootstrap", post(bootstrap))
        .route("/api/passkeys/login/options", post(login_options))
        .route("/api/passkeys/login/verify", post(login_verify))
        .route("/api/passkeys/change/options", post(credential_change_options))
        .route("/api/passkeys/change/verify", post(credential_change_verify))
        .route("/api/passkeys/register/options", post(register_options))
        .route("/api/passkeys/register/verify", post(register_verify))
        .route("/api/passkeys", get(list_passkeys))
        .route(
            "/api/passkeys/{passkey_id}",
            axum::routing::put(rename_passkey).delete(remove_passkey),
        )
        .route("/logout", post(logout))
        .route_service("/", get_service(ServeFile::new("web/dist/index.html")))
        .route_service(
            "/admin/clients",
            get_service(ServeFile::new("web/dist/index.html")),
        )
        .route_service(
            "/account",
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
        token_endpoint_auth_methods_supported: [
            "none",
            "client_secret_basic",
            "client_secret_post",
        ],
        code_challenge_methods_supported: ["S256"],
        grant_types_supported: ["authorization_code", "refresh_token"],
        scopes_supported: [
            "openid",
            "profile",
            "email",
            "groups",
            "offline_access",
            "picture",
            "address",
            "phone",
        ],
    })
}

async fn jwks(State(state): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let keys = state.signing_keys.public_jwks().await.map_err(|error| {
        tracing::error!(%error, "failed to load signing keys");
        ApiError::internal()
    })?;
    Ok(Json(serde_json::json!({ "keys": keys })))
}

async fn generated_user_picture(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> Result<Response, ApiError> {
    let user = sqlx::query(
        "SELECT hanko_color, hanko_seed FROM users WHERE id = ? AND disabled_at IS NULL",
    )
    .bind(&user_id)
    .fetch_optional(&state.database.pool)
    .await
    .map_err(|_| ApiError::internal())?
    .ok_or(ApiError {
        status: StatusCode::NOT_FOUND,
        message: "user not found",
        retry_after_seconds: None,
    })?;
    let color: String = user
        .try_get("hanko_color")
        .map_err(|_| ApiError::internal())?;
    let seed: String = user
        .try_get("hanko_seed")
        .map_err(|_| ApiError::internal())?;
    Response::builder()
        .status(StatusCode::OK)
        .header(
            header::CONTENT_TYPE,
            HeaderValue::from_static("image/svg+xml; charset=utf-8"),
        )
        .header(
            header::CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=300"),
        )
        .body(axum::body::Body::from(crate::stamp::render_picture(
            &color, &seed,
        )))
        .map_err(|_| ApiError::internal())
}

// Only an installation whose sole account is an unfinished administrator may
// resume bootstrap. Completed installations and invited accounts are excluded.
const PENDING_BOOTSTRAP_USER: &str = "SELECT u.id FROM users u WHERE u.is_admin = 1 AND u.disabled_at IS NULL AND u.invitation_link_id IS NULL AND NOT EXISTS (SELECT 1 FROM users other WHERE other.id != u.id) AND NOT EXISTS (SELECT 1 FROM passkeys WHERE user_id = u.id) AND NOT EXISTS (SELECT 1 FROM sessions WHERE user_id = u.id AND setup_only = 0)";

async fn bootstrap(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    Json(input): Json<BootstrapInput>,
) -> Result<Response, ApiError> {
    require_origin(&headers, &state.config)?;
    let _slot = try_anonymous_state_slot().ok_or(ApiError {
        status: StatusCode::TOO_MANY_REQUESTS,
        message: "too many setup requests; try again shortly",
        retry_after_seconds: None,
    })?;
    let source = source_ip(
        peer.map(|Extension(ConnectInfo(address))| address),
        &headers,
        &state.config,
    );
    if !allow_anonymous_state_creation(&state, "bootstrap", source, 5, 100)
        .await
        .map_err(|_| ApiError::internal())?
    {
        return Err(ApiError {
            status: StatusCode::TOO_MANY_REQUESTS,
            message: "too many setup requests; try again shortly",
            retry_after_seconds: None,
        });
    }
    let expected_token = state.config.bootstrap_token.as_deref().ok_or(ApiError {
        status: StatusCode::NOT_FOUND,
        message: "bootstrap is disabled",
        retry_after_seconds: None,
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
    let mut transaction = state
        .database
        .pool
        .begin()
        .await
        .map_err(|_| ApiError::internal())?;
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
        .execute(&mut *transaction)
        .await
        .map_err(|error| {
            tracing::error!(%error, "failed to create initial administrator");
            ApiError::internal()
        })?;
    let user_id = if inserted.rows_affected() == 1 {
        user_id
    } else {
        let user_id: String = sqlx::query_scalar(PENDING_BOOTSTRAP_USER)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|_| ApiError::internal())?
            .ok_or_else(|| ApiError::conflict("identity provider has already been initialized"))?;
        // Rotate the setup capability and discard ceremonies from the old session.
        sqlx::query("DELETE FROM sessions WHERE user_id = ?")
            .bind(&user_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ApiError::internal())?;
        sqlx::query("DELETE FROM webauthn_ceremonies WHERE user_id = ?")
            .bind(&user_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ApiError::internal())?;
        user_id
    };
    let session =
        crate::security::create_session_on_connection(&mut transaction, &user_id, true, now, 0)
            .await
            .map_err(|_| ApiError::internal())?;
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal())?;
    let mut response = Json(serde_json::json!({ "ok": true, "setup_only": true })).into_response();
    set_session_cookies(&mut response, &session, &state.config);
    Ok(response)
}

async fn session_info(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let has_session_cookie = cookie_value(&headers, SESSION_COOKIE).is_some();
    let identity = load_identity(&headers, &state.database)
        .await
        .map_err(|error| {
            tracing::error!(%error, "failed to load session");
            ApiError::internal()
        })?;
    let authenticated = identity.is_some();
    let mut response = match identity {
        Some(identity) => Json(SessionResponse {
            authenticated: true,
            username: Some(identity.username),
            display_name: Some(identity.display_name),
            oidc_username: identity.oidc_username,
            oidc_name: identity.oidc_name,
            oidc_picture: identity.oidc_picture,
            oidc_phone: identity.oidc_phone,
            oidc_address: identity.oidc_address,
            oidc_profile_claims: identity.oidc_profile_claims,
            hanko_color: Some(identity.hanko_color),
            hanko_seed: Some(identity.hanko_seed),
            is_admin: identity.is_admin,
            setup_only: identity.setup_only,
            required_user_claims: state.config.required_user_claims.clone(),
            allow_multiple_passkeys_per_authenticator: state
                .config
                .allow_multiple_passkeys_per_authenticator,
        }),
        None => Json(SessionResponse {
            authenticated: false,
            username: None,
            display_name: None,
            oidc_username: None,
            oidc_name: None,
            oidc_picture: None,
            oidc_phone: None,
            oidc_address: None,
            oidc_profile_claims: serde_json::json!({}),
            hanko_color: None,
            hanko_seed: None,
            is_admin: false,
            setup_only: false,
            required_user_claims: state.config.required_user_claims.clone(),
            allow_multiple_passkeys_per_authenticator: state
                .config
                .allow_multiple_passkeys_per_authenticator,
        }),
    }
    .into_response();
    if has_session_cookie && !authenticated {
        clear_session_cookies(&mut response, &state.config);
    }
    Ok(response)
}

async fn update_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<OidcProfileInput>,
) -> Result<Response, ApiError> {
    require_origin(&headers, &state.config)?;
    let session = require_session(&headers, &state.database).await?;
    require_csrf(&headers, &session)?;
    if input
        .profile_claims
        .as_ref()
        .is_some_and(|claims| claims.app_roles.is_some())
    {
        return Err(ApiError::forbidden());
    }

    let current = sqlx::query(
        "SELECT username, display_name, expose_preferred_username, expose_name, attributes FROM users WHERE id = ? AND disabled_at IS NULL",
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
    let current_exposes_username: bool = current
        .try_get("expose_preferred_username")
        .map_err(|_| ApiError::internal())?;
    let current_exposes_name: bool = current
        .try_get("expose_name")
        .map_err(|_| ApiError::internal())?;
    let attributes_json: String = current
        .try_get("attributes")
        .map_err(|_| ApiError::internal())?;
    let mut attributes: serde_json::Value =
        serde_json::from_str(&attributes_json).map_err(|_| ApiError::internal())?;
    let original_attributes = attributes.clone();

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
    if let Some(raw_picture) = input.picture.as_deref() {
        let raw_picture = raw_picture.trim();
        if raw_picture.is_empty() {
            attributes
                .as_object_mut()
                .ok_or_else(ApiError::internal)?
                .remove("picture");
        } else {
            if !valid_picture_url(raw_picture) {
                return Err(ApiError::bad_request(
                    "picture must be a valid HTTPS image URL (HTTP is allowed for localhost)",
                ));
            }
            attributes
                .as_object_mut()
                .ok_or_else(ApiError::internal)?
                .insert(
                    "picture".to_owned(),
                    serde_json::Value::String(raw_picture.to_owned()),
                );
        }
    }
    if let Some(raw_phone) = input.phone_number.as_deref() {
        let phone = raw_phone.trim();
        let digits = phone.bytes().filter(|byte| byte.is_ascii_digit()).count();
        if !phone.is_empty()
            && (phone.len() > 64
                || !(3..=20).contains(&digits)
                || !phone.bytes().all(|byte| {
                    byte.is_ascii_digit() || matches!(byte, b'+' | b'(' | b')' | b'-' | b'.' | b' ')
                }))
        {
            return Err(ApiError::bad_request(
                "phone number must contain 3 to 20 digits and use common phone number characters",
            ));
        }
        let attributes = attributes.as_object_mut().ok_or_else(ApiError::internal)?;
        if phone.is_empty() {
            attributes.remove("phone_number");
        } else {
            attributes.insert(
                "phone_number".to_owned(),
                serde_json::Value::String(phone.to_owned()),
            );
        }
    }
    if let Some(address) = input.address {
        update_address(&mut attributes, address)?;
    }
    if let Some(profile_claims) = input.profile_claims {
        for (claim, value, max_len, is_url) in [
            ("profile", profile_claims.profile, 2048, true),
            ("given_name", profile_claims.given_name, 120, false),
            ("family_name", profile_claims.family_name, 120, false),
            ("nickname", profile_claims.nickname, 120, false),
            ("website", profile_claims.website, 2048, true),
            ("locale", profile_claims.locale, 128, false),
            ("zoneinfo", profile_claims.zoneinfo, 128, false),
        ] {
            update_profile_attribute(&mut attributes, claim, value, max_len, is_url)?;
        }
    }
    if !required_user_claims_present(
        &state.config.required_user_claims,
        oidc_username.as_deref(),
        raw_name,
        &attributes,
    ) {
        return Err(ApiError::bad_request("a required profile field is missing"));
    }
    let identity_changed = username != current_username
        || display_name != current_display_name
        || oidc_username.is_some() != current_exposes_username
        || raw_name.is_some() != current_exposes_name
        || attributes != original_attributes;
    // Setup has no passkey yet; its session is the only way to finish enrollment.
    let sessions_revoked =
        identity_changed && state.config.revoke_sessions_on_identity_change && !session.setup_only;
    let serialized_attributes =
        serde_json::to_string(&attributes).map_err(|_| ApiError::internal())?;
    let mut transaction = state
        .database
        .pool
        .begin()
        .await
        .map_err(|_| ApiError::internal())?;
    let updated = sqlx::query("UPDATE users SET username = ?, display_name = ?, attributes = ?, expose_preferred_username = ?, expose_name = ?, updated_at = ? WHERE id = ? AND disabled_at IS NULL")
        .bind(username)
        .bind(display_name)
        .bind(serialized_attributes)
        .bind(oidc_username.is_some())
        .bind(raw_name.is_some())
        .bind(unix_now())
        .bind(&session.user_id)
        .execute(&mut *transaction)
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

    if identity_changed && state.config.revoke_consents_on_identity_change {
        let now = unix_now();
        sqlx::query("UPDATE refresh_token_families SET revoked_at = COALESCE(revoked_at, ?) WHERE user_id = ? AND revoked_at IS NULL")
            .bind(now)
            .bind(&session.user_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ApiError::internal())?;
        sqlx::query("DELETE FROM refresh_tokens WHERE user_id = ? AND consumed_at IS NULL")
            .bind(&session.user_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ApiError::internal())?;
        sqlx::query("DELETE FROM authorization_codes WHERE user_id = ?")
            .bind(&session.user_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ApiError::internal())?;
        sqlx::query("DELETE FROM oidc_consents WHERE user_id = ?")
            .bind(&session.user_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ApiError::internal())?;
    }
    if sessions_revoked {
        sqlx::query("DELETE FROM sessions WHERE user_id = ?")
            .bind(&session.user_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ApiError::internal())?;
    }
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal())?;

    let mut response = Json(serde_json::json!({
        "sessions_revoked": sessions_revoked,
        "username": oidc_username,
        "display_name": raw_name,
        "picture": attributes.get("picture").and_then(serde_json::Value::as_str),
        "phone_number": attributes.get("phone_number").and_then(serde_json::Value::as_str),
        "address": attributes.get("address"),
        "profile_claims": crate::security::oidc_profile_claims(&attributes),
    }))
    .into_response();
    if sessions_revoked {
        clear_session_cookies(&mut response, &state.config);
    }
    Ok(response)
}

fn required_user_claims_present(
    required_claims: &[String],
    preferred_username: Option<&str>,
    name: Option<&str>,
    attributes: &serde_json::Value,
) -> bool {
    required_claims.iter().all(|claim| match claim.as_str() {
        "preferred_username" => preferred_username.is_some_and(|value| !value.trim().is_empty()),
        "name" => name.is_some_and(|value| !value.trim().is_empty()),
        "address" => attributes
            .get("address")
            .and_then(serde_json::Value::as_object)
            .is_some_and(|address| {
                address
                    .values()
                    .any(|value| value.as_str().is_some_and(|field| !field.trim().is_empty()))
            }),
        claim if crate::config::is_address_user_claim(claim) => attributes
            .get("address")
            .and_then(|address| address.get(claim))
            .and_then(serde_json::Value::as_str)
            .is_some_and(|value| !value.trim().is_empty()),
        _ => attributes
            .get(claim)
            .and_then(serde_json::Value::as_str)
            .is_some_and(|value| !value.trim().is_empty()),
    })
}

fn update_profile_attribute(
    attributes: &mut serde_json::Value,
    claim: &str,
    value: Option<String>,
    max_len: usize,
    is_url: bool,
) -> Result<(), ApiError> {
    let Some(value) = value else {
        return Ok(());
    };
    let value = value.trim();
    if value.len() > max_len || value.chars().any(char::is_control) {
        return Err(ApiError::bad_request("profile claim has an invalid value"));
    }
    if is_url && !value.is_empty() && !valid_picture_url(value) {
        return Err(ApiError::bad_request(
            "profile and website URLs must be HTTPS (HTTP is allowed for localhost)",
        ));
    }
    let attributes = attributes.as_object_mut().ok_or_else(ApiError::internal)?;
    if value.is_empty() {
        attributes.remove(claim);
    } else {
        attributes.insert(
            claim.to_owned(),
            serde_json::Value::String(value.to_owned()),
        );
    }
    Ok(())
}

fn update_address(attributes: &mut serde_json::Value, input: AddressInput) -> Result<(), ApiError> {
    let mut address = attributes
        .get("address")
        .and_then(serde_json::Value::as_object)
        .cloned()
        .unwrap_or_default();
    for (key, value) in [
        ("street_address", input.street_address),
        ("locality", input.locality),
        ("region", input.region),
        ("postal_code", input.postal_code),
        ("country", input.country),
    ] {
        let Some(value) = value else {
            continue;
        };
        let value = value.trim();
        if value.len() > 500
            || value.chars().any(|character| {
                character.is_control()
                    && !(key == "street_address" && matches!(character, '\n' | '\r'))
            })
        {
            return Err(ApiError::bad_request(
                "address fields must be 500 characters or fewer",
            ));
        }
        if value.is_empty() {
            address.remove(key);
        } else {
            address.insert(key.to_owned(), serde_json::Value::String(value.to_owned()));
        }
    }
    let attributes = attributes.as_object_mut().ok_or_else(ApiError::internal)?;
    if address.is_empty() {
        attributes.remove("address");
    } else {
        attributes.insert("address".to_owned(), serde_json::Value::Object(address));
    }
    Ok(())
}

fn valid_picture_url(value: &str) -> bool {
    if value.len() > 2048 {
        return false;
    }
    let Ok(url) = url::Url::parse(value) else {
        return false;
    };
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return false;
    }
    match url.scheme() {
        "https" => url.host_str().is_some(),
        "http" => matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")),
        _ => false,
    }
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
    let updated = sqlx::query("UPDATE users SET hanko_color = ?, hanko_seed = ?, updated_at = ? WHERE id = ? AND disabled_at IS NULL")
        .bind(&input.color)
        .bind(&input.seed)
        .bind(unix_now())
        .bind(&session.user_id)
        .execute(&state.database.pool)
        .await;
    if let Err(error) = updated {
        tracing::error!(
            user_id = %session.user_id,
            error = %error,
            error_details = ?error,
            "failed to update Hanko style"
        );
        return Err(ApiError::internal());
    }
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
    let incomplete = sqlx::query_scalar::<_, String>(PENDING_BOOTSTRAP_USER)
        .fetch_optional(&state.database.pool)
        .await
        .map_err(|_| ApiError::internal())?
        .is_some();
    let initialized = initialized && !incomplete;
    Ok(Json(
        serde_json::json!({ "initialized": initialized, "bootstrap_enabled": state.config.bootstrap_token.is_some() }),
    ))
}

async fn login_options(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    input: Option<Json<LoginOptionsInput>>,
) -> Result<Response, ApiError> {
    require_origin(&headers, &state.config)?;
    let _slot = try_anonymous_state_slot().ok_or(ApiError {
        status: StatusCode::TOO_MANY_REQUESTS,
        message: "too many sign-in requests; try again shortly",
        retry_after_seconds: None,
    })?;
    let source = source_ip(
        peer.map(|Extension(ConnectInfo(address))| address),
        &headers,
        &state.config,
    );
    if !allow_anonymous_state_creation(&state, "login_options", source, 12, 600)
        .await
        .map_err(|_| ApiError::internal())?
    {
        return Err(ApiError {
            status: StatusCode::TOO_MANY_REQUESTS,
            message: "too many sign-in requests; try again shortly",
            retry_after_seconds: None,
        });
    }
    let supplied_preauth = cookie_value(&headers, PREAUTH_COOKIE);
    let preauth = supplied_preauth
        .clone()
        .unwrap_or_else(crate::security::random_secret);
    let browser_hash = digest(&preauth);
    let now = unix_now();
    if supplied_preauth.is_some() {
        sqlx::query("DELETE FROM login_rate_limits WHERE window_started_at <= ?")
            .bind(now - 60)
            .execute(&state.database.pool)
            .await
            .map_err(|_| ApiError::internal())?;
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
                retry_after_seconds: None,
            });
        }
    }
    let account = input.and_then(|Json(input)| input.account);
    let account = account
        .as_deref()
        .map(|account| account.trim().to_ascii_lowercase());
    if account.as_ref().is_some_and(|account| {
        account.is_empty() || account.len() > 254 || account.chars().any(char::is_control)
    }) {
        return Err(ApiError::bad_request("invalid account name"));
    }
    let authentication = match account.as_deref() {
        Some(account) => {
            state
                .webauthn
                .start_account_authentication(account, &browser_hash)
                .await
        }
        None => state.webauthn.start_authentication(&browser_hash).await,
    };
    let (ceremony_id, public_key) = authentication.map_err(|error| match error {
        crate::webauthn::WebauthnError::Capacity => ApiError {
            status: StatusCode::TOO_MANY_REQUESTS,
            message: "too many active sign-in requests; try again shortly",
            retry_after_seconds: None,
        },
        _ => ApiError::unauthorized(),
    })?;
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
    let session = create_passkey_session(&state.database, &user_id)
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
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    input: Option<Json<RegistrationOptionsInput>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_origin(&headers, &state.config)?;
    let session = require_session(&headers, &state.database).await?;
    require_csrf(&headers, &session)?;
    if session.setup_only && !required_profile_is_complete(&state, &session.user_id).await? {
        return Err(ApiError::bad_request(
            "complete required profile fields before registering a passkey",
        ));
    }
    let _slot = try_anonymous_state_slot().ok_or(ApiError {
        status: StatusCode::TOO_MANY_REQUESTS,
        message: "too many passkey registration requests; try again shortly",
        retry_after_seconds: None,
    })?;
    let source = source_ip(
        peer.map(|Extension(ConnectInfo(address))| address),
        &headers,
        &state.config,
    );
    if !allow_anonymous_state_creation(&state, "registration_options", source, 10, 300)
        .await
        .map_err(|_| ApiError::internal())?
    {
        return Err(ApiError {
            status: StatusCode::TOO_MANY_REQUESTS,
            message: "too many passkey registration requests; try again shortly",
            retry_after_seconds: None,
        });
    }
    let input = input.map(|Json(input)| input).unwrap_or_default();
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
    let registration = state
        .webauthn
        .start_registration(
            &session.user_id,
            &username,
            &display_name,
            &session.session_hash,
            input.approval_token.as_deref(),
        )
        .await;
    let (ceremony_id, public_key) = match registration {
        Ok(registration) => registration,
        Err(error @ crate::webauthn::WebauthnError::Capacity) => {
            tracing::error!(%error, "failed to start passkey registration");
            let retry_after = state
                .webauthn
                .registration_retry_after_seconds(&session.user_id, &session.session_hash)
                .await
                .unwrap_or(300);
            return Err(ApiError::capacity(
                "too many active registration requests; try again shortly",
                retry_after,
            ));
        }
        Err(error) => {
            tracing::error!(%error, "failed to start passkey registration");
            if matches!(error, crate::webauthn::WebauthnError::Authentication) {
                return Err(ApiError::forbidden());
            }
            return Err(ApiError::bad_request(
                "could not start passkey registration",
            ));
        }
    };
    Ok(Json(
        serde_json::json!({ "ceremony_id": ceremony_id, "publicKey": public_key }),
    ))
}

async fn credential_change_options(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    Json(input): Json<CredentialChangeOptionsInput>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_origin(&headers, &state.config)?;
    let session = require_session(&headers, &state.database).await?;
    require_csrf(&headers, &session)?;
    if session.setup_only {
        return Err(ApiError::forbidden());
    }
    let _slot = try_anonymous_state_slot().ok_or(ApiError {
        status: StatusCode::TOO_MANY_REQUESTS,
        message: "too many passkey confirmation requests; try again shortly",
        retry_after_seconds: None,
    })?;
    let source = source_ip(
        peer.map(|Extension(ConnectInfo(address))| address),
        &headers,
        &state.config,
    );
    if !allow_anonymous_state_creation(&state, "credential_change_options", source, 10, 300)
        .await
        .map_err(|_| ApiError::internal())?
    {
        return Err(ApiError {
            status: StatusCode::TOO_MANY_REQUESTS,
            message: "too many passkey confirmation requests; try again shortly",
            retry_after_seconds: None,
        });
    }
    let (ceremony_id, public_key) = state
        .webauthn
        .start_credential_change(
            &session.user_id,
            &session.session_hash,
            &input.action,
            input.passkey_id.as_deref(),
        )
        .await
        .map_err(|error| match error {
            crate::webauthn::WebauthnError::Capacity => ApiError {
                status: StatusCode::TOO_MANY_REQUESTS,
                message: "too many active passkey confirmation requests; try again shortly",
                retry_after_seconds: None,
            },
            crate::webauthn::WebauthnError::User => ApiError::not_found(),
            _ => ApiError::bad_request("could not start passkey confirmation"),
        })?;
    Ok(Json(
        serde_json::json!({ "ceremony_id": ceremony_id, "publicKey": public_key }),
    ))
}

async fn credential_change_verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CredentialChangeVerifyInput>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_origin(&headers, &state.config)?;
    let session = require_session(&headers, &state.database).await?;
    require_csrf(&headers, &session)?;
    if session.setup_only {
        return Err(ApiError::forbidden());
    }
    let approval_token = state
        .webauthn
        .finish_credential_change(
            &input.ceremony_id,
            &session.user_id,
            &session.session_hash,
            input.credential,
        )
        .await
        .map_err(|error| {
            tracing::warn!(
                %error,
                user_id = %session.user_id,
                "passkey change confirmation failed"
            );
            ApiError::bad_request("passkey confirmation failed")
        })?;
    Ok(Json(
        serde_json::json!({ "approval_token": approval_token }),
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
    if session.setup_only && !required_profile_is_complete(&state, &session.user_id).await? {
        return Err(ApiError::bad_request(
            "complete required profile fields before registering a passkey",
        ));
    }
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
            tracing::warn!(
                %error,
                user_id = %session.user_id,
                "passkey registration failed"
            );
            match error {
                crate::webauthn::WebauthnError::NonDiscoverable => ApiError::bad_request(
                    "passkey was not saved as discoverable; choose another passkey provider",
                ),
                _ => ApiError::bad_request("passkey registration failed"),
            }
        })?;
    // Setup and invitation sessions leave setup mode only after the first passkey commits.
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn required_profile_is_complete(state: &AppState, user_id: &str) -> Result<bool, ApiError> {
    if state.config.required_user_claims.is_empty() {
        return Ok(true);
    }
    let row = sqlx::query(
        "SELECT username, display_name, expose_preferred_username, expose_name, attributes FROM users WHERE id = ? AND disabled_at IS NULL",
    )
    .bind(user_id)
    .fetch_optional(&state.database.pool)
    .await
    .map_err(|_| ApiError::internal())?
    .ok_or_else(ApiError::unauthorized)?;
    let username: String = row.try_get("username").map_err(|_| ApiError::internal())?;
    let display_name: String = row
        .try_get("display_name")
        .map_err(|_| ApiError::internal())?;
    let exposes_username: bool = row
        .try_get("expose_preferred_username")
        .map_err(|_| ApiError::internal())?;
    let exposes_name: bool = row
        .try_get("expose_name")
        .map_err(|_| ApiError::internal())?;
    let attributes_json: String = row
        .try_get("attributes")
        .map_err(|_| ApiError::internal())?;
    let attributes: serde_json::Value =
        serde_json::from_str(&attributes_json).map_err(|_| ApiError::internal())?;
    Ok(required_user_claims_present(
        &state.config.required_user_claims,
        exposes_username.then_some(username.as_str()),
        exposes_name.then_some(display_name.as_str()),
        &attributes,
    ))
}

async fn list_passkeys(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<AccountPasskey>>, ApiError> {
    let session = require_session(&headers, &state.database).await?;
    let rows = sqlx::query(
        "SELECT id, label, created_at, last_used_at FROM passkeys WHERE user_id = ? ORDER BY created_at, id",
    )
    .bind(&session.user_id)
    .fetch_all(&state.database.pool)
    .await
    .map_err(|_| ApiError::internal())?;
    let passkeys = rows
        .into_iter()
        .map(|row| {
            Ok(AccountPasskey {
                id: row.try_get("id").map_err(|_| ApiError::internal())?,
                label: row.try_get("label").map_err(|_| ApiError::internal())?,
                created_at: row
                    .try_get("created_at")
                    .map_err(|_| ApiError::internal())?,
                last_used_at: row
                    .try_get("last_used_at")
                    .map_err(|_| ApiError::internal())?,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    Ok(Json(passkeys))
}

async fn list_account_consents(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<serde_json::Value>>, ApiError> {
    let session = require_session(&headers, &state.database).await?;
    if session.setup_only {
        return Err(ApiError::forbidden());
    }
    let rows = sqlx::query("SELECT c.client_id, c.name AS client_name, g.scopes, g.granted_at, g.expires_at FROM oidc_consents g JOIN oidc_clients c ON c.client_id = g.client_id WHERE g.user_id = ? ORDER BY c.name COLLATE NOCASE, c.client_id")
        .bind(&session.user_id)
        .fetch_all(&state.database.pool)
        .await
        .map_err(|_| ApiError::internal())?;
    rows.into_iter()
        .map(|row| {
            let scopes_json: String = row.try_get("scopes").map_err(|_| ApiError::internal())?;
            let scopes: Vec<String> =
                serde_json::from_str(&scopes_json).map_err(|_| ApiError::internal())?;
            Ok(serde_json::json!({
                "client_id": row.try_get::<String, _>("client_id").map_err(|_| ApiError::internal())?,
                "client_name": row.try_get::<String, _>("client_name").map_err(|_| ApiError::internal())?,
                "scopes": scopes,
                "granted_at": row.try_get::<i64, _>("granted_at").map_err(|_| ApiError::internal())?,
                "expires_at": row.try_get::<Option<i64>, _>("expires_at").map_err(|_| ApiError::internal())?,
            }))
        })
        .collect::<Result<Vec<_>, ApiError>>()
        .map(Json)
}

async fn revoke_account_consent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(client_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    require_origin(&headers, &state.config)?;
    let session = require_session(&headers, &state.database).await?;
    require_csrf(&headers, &session)?;
    if session.setup_only {
        return Err(ApiError::forbidden());
    }
    let now = unix_now();
    let mut transaction = state
        .database
        .pool
        .begin()
        .await
        .map_err(|_| ApiError::internal())?;
    sqlx::query("UPDATE refresh_token_families SET revoked_at = COALESCE(revoked_at, ?) WHERE user_id = ? AND client_id = ? AND revoked_at IS NULL")
        .bind(now)
        .bind(&session.user_id)
        .bind(&client_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ApiError::internal())?;
    sqlx::query(
        "DELETE FROM refresh_tokens WHERE user_id = ? AND client_id = ? AND consumed_at IS NULL",
    )
    .bind(&session.user_id)
    .bind(&client_id)
    .execute(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal())?;
    sqlx::query("DELETE FROM authorization_codes WHERE user_id = ? AND client_id = ?")
        .bind(&session.user_id)
        .bind(&client_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ApiError::internal())?;
    sqlx::query("DELETE FROM oidc_consents WHERE user_id = ? AND client_id = ?")
        .bind(&session.user_id)
        .bind(&client_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ApiError::internal())?;
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal())?;
    Ok(StatusCode::NO_CONTENT)
}

async fn rename_passkey(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(passkey_id): Path<String>,
    Json(input): Json<RenamePasskeyInput>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_origin(&headers, &state.config)?;
    let session = require_session(&headers, &state.database).await?;
    require_csrf(&headers, &session)?;
    if session.setup_only {
        return Err(ApiError::forbidden());
    }

    let label = input.label.trim();
    if label.is_empty() || label.chars().count() > 100 {
        return Err(ApiError::bad_request(
            "passkey name must be 1 to 100 characters",
        ));
    }
    let updated = sqlx::query("UPDATE passkeys SET label = ? WHERE id = ? AND user_id = ?")
        .bind(label)
        .bind(passkey_id)
        .bind(&session.user_id)
        .execute(&state.database.pool)
        .await
        .map_err(|_| ApiError::internal())?;
    if updated.rows_affected() == 0 {
        return Err(ApiError::not_found());
    }
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn remove_passkey(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(passkey_id): Path<String>,
    Json(input): Json<RemovePasskeyInput>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_origin(&headers, &state.config)?;
    let session = require_session(&headers, &state.database).await?;
    require_csrf(&headers, &session)?;
    if session.setup_only {
        return Err(ApiError::forbidden());
    }
    if input.confirmation != "REMOVE" {
        return Err(ApiError::bad_request(
            "type REMOVE to confirm passkey removal",
        ));
    }

    let now = unix_now();
    let mut transaction = state
        .database
        .pool
        .begin()
        .await
        .map_err(|_| ApiError::internal())?;
    let approved = sqlx::query("UPDATE credential_change_approvals SET consumed_at = ? WHERE approval_hash = ? AND user_id = ? AND session_hash = ? AND action = 'remove' AND target_passkey_id = ? AND consumed_at IS NULL AND expires_at > ? AND EXISTS (SELECT 1 FROM sessions WHERE session_hash = ? AND user_id = ? AND setup_only = 0 AND expires_at > ?) AND EXISTS (SELECT 1 FROM users WHERE id = ? AND disabled_at IS NULL) RETURNING approval_hash")
        .bind(now)
        .bind(digest(&input.approval_token))
        .bind(&session.user_id)
        .bind(&session.session_hash)
        .bind(&passkey_id)
        .bind(now)
        .bind(&session.session_hash)
        .bind(&session.user_id)
        .bind(now)
        .bind(&session.user_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ApiError::internal())?;
    if approved.is_none() {
        return Err(ApiError::forbidden());
    }

    // Keep this count check in the DELETE itself so concurrent removals cannot
    // leave an account without a credential.
    let deleted = sqlx::query(
        "DELETE FROM passkeys WHERE id = ? AND user_id = ? AND (SELECT COUNT(*) FROM passkeys WHERE user_id = ?) > 1",
    )
    .bind(&passkey_id)
    .bind(&session.user_id)
    .bind(&session.user_id)
    .execute(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal())?;
    if deleted.rows_affected() == 0 {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM passkeys WHERE id = ? AND user_id = ?)",
        )
        .bind(passkey_id)
        .bind(&session.user_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ApiError::internal())?;
        if !exists {
            return Err(ApiError::not_found());
        }
        return Err(ApiError::conflict("at least one passkey must remain"));
    }
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal())?;
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
        test_app_with_database(config).await.0
    }

    async fn test_app_with_database(config: Config) -> (Router, Database) {
        let database = Database::connect("sqlite::memory:").await.unwrap();
        let signing_keys = SigningKeys::initialize(database.clone(), [5_u8; 32])
            .await
            .unwrap();
        let webauthn = WebauthnService::new(
            &config.webauthn_rp_id,
            &config.webauthn_origin(),
            database.clone(),
            config.allow_multiple_passkeys_per_authenticator,
        )
        .unwrap();
        let app = router(AppState {
            config: Arc::new(config),
            database: database.clone(),
            signing_keys,
            webauthn,
            anonymous_request_limiter: crate::security::AnonymousRequestLimiter::default(),
        });
        (app, database)
    }

    #[tokio::test]
    async fn cors_is_available_only_on_public_oidc_endpoints() {
        let app = test_app(local_config()).await;
        for (path, method) in [
            ("/.well-known/openid-configuration", "GET"),
            ("/jwks", "GET"),
            ("/token", "POST"),
            ("/userinfo", "GET"),
        ] {
            let response = app
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .method(method)
                        .uri(path)
                        .header(header::ORIGIN, "https://client.example")
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
            assert!(
                !response
                    .headers()
                    .contains_key(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
            );
            let preflight = app
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .method("OPTIONS")
                        .uri(path)
                        .header(header::ORIGIN, "https://client.example")
                        .header(header::ACCESS_CONTROL_REQUEST_METHOD, method)
                        .header(
                            header::ACCESS_CONTROL_REQUEST_HEADERS,
                            "authorization,content-type",
                        )
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert!(preflight.status().is_success());
            assert_eq!(
                preflight.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
                "*"
            );
            assert!(
                preflight.headers()[header::ACCESS_CONTROL_ALLOW_HEADERS]
                    .to_str()
                    .unwrap()
                    .contains("authorization")
            );
        }
        for path in [
            "/api/session",
            "/api/admin/users",
            "/api/authorize/continue",
            "/logout",
        ] {
            let response = app
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .method("OPTIONS")
                        .uri(path)
                        .header(header::ORIGIN, "https://client.example")
                        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert!(
                !response
                    .headers()
                    .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN),
                "{path}"
            );
        }
    }

    fn local_config() -> Config {
        Config::new(
            "http://localhost:3000",
            "sqlite::memory:".into(),
            "127.0.0.1:0".into(),
        )
        .unwrap()
    }

    async fn browser_request(
        app: &Router,
        method: &str,
        uri: &str,
        cookies: &str,
        body: serde_json::Value,
    ) -> Response {
        let csrf = cookies
            .split("; ")
            .find_map(|cookie| cookie.strip_prefix("hanko_csrf="))
            .unwrap_or("");
        app.clone()
            .oneshot(
                axum::http::Request::builder()
                    .method(method)
                    .uri(uri)
                    .header(header::ORIGIN, "http://localhost:3000")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, cookies)
                    .header("x-csrf-token", csrf)
                    .body(axum::body::Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    fn response_cookies(response: &Response) -> String {
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|value| value.to_str().unwrap().split(';').next().unwrap())
            .collect::<Vec<_>>()
            .join("; ")
    }

    async fn response_json(response: Response) -> serde_json::Value {
        serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap(),
        )
        .unwrap()
    }

    async fn admin_cookies(database: &Database) -> String {
        sqlx::query("INSERT INTO users (id, username, display_name, is_admin, created_at, updated_at) VALUES ('admin', 'admin', 'Admin', 1, 0, 0)")
            .execute(&database.pool).await.unwrap();
        let session = create_session(database, "admin", false, unix_now())
            .await
            .unwrap();
        format!(
            "hanko_session={}; hanko_csrf={}",
            session.raw_token, session.raw_csrf
        )
    }

    #[tokio::test]
    async fn client_listing_keeps_batched_relationships_separate_and_sorted() {
        let (app, database) = test_app_with_database(local_config()).await;
        let cookies = admin_cookies(&database).await;
        sqlx::query("INSERT INTO groups (id, name, display_name, created_at) VALUES ('g', 'staff', 'Staff', 0)").execute(&database.pool).await.unwrap();
        let first = browser_request(&app, "POST", "/api/admin/clients", &cookies, serde_json::json!({
            "name":"A", "client_type":"public", "redirect_uris":["https://a.test/z", "https://a.test/a"],
            "post_logout_redirect_uris":["https://a.test/logout"], "scopes":["openid","profile"],
            "allowed_groups":["staff"], "claims":[{"claim_name":"department", "user_attribute_path":"/department", "required_scope":"profile"}]
        })).await;
        assert_eq!(first.status(), StatusCode::OK);
        let first = response_json(first).await;
        let second = browser_request(&app, "POST", "/api/admin/clients", &cookies, serde_json::json!({
            "name":"B", "client_type":"public", "redirect_uris":["https://b.test/callback"], "scopes":["openid"]
        })).await;
        assert_eq!(second.status(), StatusCode::OK);
        sqlx::query("INSERT INTO client_users (client_id, user_id) VALUES (?, 'admin')")
            .bind(first["client_id"].as_str().unwrap())
            .execute(&database.pool)
            .await
            .unwrap();
        let list = browser_request(
            &app,
            "GET",
            "/api/admin/clients",
            &cookies,
            serde_json::json!({}),
        )
        .await;
        assert_eq!(list.status(), StatusCode::OK);
        let clients = response_json(list).await;
        assert_eq!(clients.as_array().unwrap().len(), 2);
        assert_eq!(clients[0]["name"], "A");
        assert_eq!(
            clients[0]["redirect_uris"],
            serde_json::json!(["https://a.test/a", "https://a.test/z"])
        );
        assert_eq!(
            clients[0]["post_logout_redirect_uris"],
            serde_json::json!(["https://a.test/logout"])
        );
        assert_eq!(clients[0]["allowed_groups"], serde_json::json!(["staff"]));
        assert_eq!(clients[0]["claims"][0]["claim_name"], "department");
        assert_eq!(clients[0]["user_count"], 1);
        assert_eq!(
            clients[1]["redirect_uris"],
            serde_json::json!(["https://b.test/callback"])
        );
        assert_eq!(clients[1]["scopes"], serde_json::json!(["openid"]));
        assert_eq!(clients[1]["allowed_groups"], serde_json::json!([]));
        assert_eq!(clients[1]["claims"], serde_json::json!([]));
        assert_eq!(clients[1]["user_count"], 0);
    }

    #[tokio::test]
    async fn invalid_invitation_requests_preserve_existing_login_cookies() {
        let (app, database) = test_app_with_database(local_config()).await;
        let cookies = admin_cookies(&database).await;
        for token in ["invalid".to_owned(), "x".repeat(43)] {
            for endpoint in ["validate", "consume"] {
                let response = browser_request(
                    &app,
                    "POST",
                    &format!("/api/invitations/{endpoint}"),
                    &cookies,
                    serde_json::json!({"token":token}),
                )
                .await;
                assert_eq!(
                    response.status(),
                    if endpoint == "validate" {
                        StatusCode::OK
                    } else {
                        StatusCode::UNAUTHORIZED
                    }
                );
                assert!(!response.headers().contains_key(header::SET_COOKIE));
            }
        }
        let session = response_json(
            browser_request(&app, "GET", "/api/session", &cookies, serde_json::json!({})).await,
        )
        .await;
        assert_eq!(session["authenticated"], true);
        assert_eq!(session["is_admin"], true);
    }

    #[tokio::test]
    async fn deleting_an_invitation_invalidates_pending_setup_but_preserves_completed_users() {
        let (app, database) = test_app_with_database(local_config()).await;
        let admin = admin_cookies(&database).await;
        let invite = browser_request(&app, "POST", "/api/admin/invitations", &admin,
            serde_json::json!({"label":"Test", "max_uses":2, "expires_in":1, "expires_unit":"hours"})).await;
        assert_eq!(invite.status(), StatusCode::OK);
        let invite = response_json(invite).await;
        let token = invite["enrollment_url"]
            .as_str()
            .unwrap()
            .split("enroll=")
            .nth(1)
            .unwrap();
        let pending = browser_request(
            &app,
            "POST",
            "/api/invitations/consume",
            "",
            serde_json::json!({"token":token}),
        )
        .await;
        assert_eq!(pending.status(), StatusCode::OK);
        let pending_cookies = response_cookies(&pending);
        let completed = browser_request(
            &app,
            "POST",
            "/api/invitations/consume",
            "",
            serde_json::json!({"token":token}),
        )
        .await;
        let completed_cookies = response_cookies(&completed);
        let identity = response_json(
            browser_request(
                &app,
                "GET",
                "/api/session",
                &completed_cookies,
                serde_json::json!({}),
            )
            .await,
        )
        .await;
        let completed_username = identity["username"].as_str().unwrap();
        // Model successful enrollment, which releases the invitation association.
        sqlx::query("UPDATE users SET invitation_link_id = NULL, invitation_reserved_until = NULL WHERE username = ?")
            .bind(completed_username).execute(&database.pool).await.unwrap();
        sqlx::query("UPDATE invitation_links SET revoked_at = ? WHERE id = ?")
            .bind(unix_now())
            .bind(invite["id"].as_str().unwrap())
            .execute(&database.pool)
            .await
            .unwrap();
        let deleted = browser_request(
            &app,
            "DELETE",
            &format!("/api/admin/invitations/{}", invite["id"].as_str().unwrap()),
            &admin,
            serde_json::json!({}),
        )
        .await;
        assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
        let registration = browser_request(
            &app,
            "POST",
            "/api/passkeys/register/options",
            &pending_cookies,
            serde_json::json!({}),
        )
        .await;
        assert_eq!(registration.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users")
                .fetch_one(&database.pool)
                .await
                .unwrap(),
            2
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM sessions")
                .fetch_one(&database.pool)
                .await
                .unwrap(),
            2
        );
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
        assert_eq!(document["scopes_supported"][4], "offline_access");
        assert_eq!(document["grant_types_supported"][1], "refresh_token");
        assert_eq!(document["token_endpoint_auth_methods_supported"][0], "none");
        assert_eq!(
            document["token_endpoint_auth_methods_supported"][1],
            "client_secret_basic"
        );
        assert_eq!(
            document["token_endpoint_auth_methods_supported"][2],
            "client_secret_post"
        );
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

        let account_page = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/hanko/account")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(account_page.status(), StatusCode::OK);

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
        let (app, database) = test_app_with_database(config).await;
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
        sqlx::query("INSERT INTO passkeys (id, user_id, credential_id, passkey_json, label, created_at) SELECT 'key', id, X'01', '{}', 'Test', 0 FROM users")
            .execute(&database.pool).await.unwrap();
        assert_eq!(
            app.oneshot(request()).await.unwrap().status(),
            StatusCode::CONFLICT
        );
    }

    #[tokio::test]
    async fn abandoned_bootstrap_can_resume_with_token_and_rotates_setup_session() {
        let mut config = local_config();
        config.bootstrap_token = Some("bootstrap-secret".into());
        let (app, database) = test_app_with_database(config).await;
        let body = serde_json::json!({"token":"bootstrap-secret"});
        let first = browser_request(&app, "POST", "/api/bootstrap", "", body.clone()).await;
        let old_cookies = response_cookies(&first);
        let user_id: String = sqlx::query_scalar("SELECT id FROM users")
            .fetch_one(&database.pool)
            .await
            .unwrap();
        let status = response_json(
            browser_request(&app, "GET", "/api/setup-status", "", serde_json::json!({})).await,
        )
        .await;
        assert_eq!(status["initialized"], false);
        let rejected = browser_request(
            &app,
            "POST",
            "/api/bootstrap",
            "",
            serde_json::json!({"token":"wrong"}),
        )
        .await;
        assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
        let resumed = browser_request(&app, "POST", "/api/bootstrap", "", body.clone()).await;
        assert_eq!(resumed.status(), StatusCode::OK);
        let cookies = response_cookies(&resumed);
        assert_ne!(old_cookies, cookies);
        assert_eq!(
            sqlx::query_scalar::<_, String>("SELECT id FROM users")
                .fetch_one(&database.pool)
                .await
                .unwrap(),
            user_id
        );
        assert_eq!(
            browser_request(
                &app,
                "POST",
                "/api/passkeys/register/options",
                &old_cookies,
                serde_json::json!({})
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            browser_request(
                &app,
                "POST",
                "/api/passkeys/register/options",
                &cookies,
                serde_json::json!({})
            )
            .await
            .status(),
            StatusCode::OK
        );
        // Resumption must also work after expired sessions have been cleaned up.
        sqlx::query("DELETE FROM sessions")
            .execute(&database.pool)
            .await
            .unwrap();
        assert_eq!(
            browser_request(&app, "POST", "/api/bootstrap", "", body.clone())
                .await
                .status(),
            StatusCode::OK
        );
        sqlx::query("INSERT INTO users(id,username,display_name,created_at,updated_at) VALUES('other','other','Other',0,0)").execute(&database.pool).await.unwrap();
        assert_eq!(
            browser_request(&app, "POST", "/api/bootstrap", "", body)
                .await
                .status(),
            StatusCode::CONFLICT
        );
    }

    #[tokio::test]
    async fn profile_revocation_preserves_setup_and_reports_normal_session_logout() {
        let mut config = local_config();
        config.revoke_sessions_on_identity_change = true;
        config.bootstrap_token = Some("bootstrap-secret".into());
        let (app, database) = test_app_with_database(config).await;
        let bootstrap = browser_request(
            &app,
            "POST",
            "/api/bootstrap",
            "",
            serde_json::json!({"token":"bootstrap-secret"}),
        )
        .await;
        let cookies = response_cookies(&bootstrap);
        let saved = browser_request(
            &app,
            "PUT",
            "/api/account/profile",
            &cookies,
            serde_json::json!({"username":"alice"}),
        )
        .await;
        assert_eq!(saved.status(), StatusCode::OK);
        assert!(!saved.headers().contains_key(header::SET_COOKIE));
        assert_eq!(response_json(saved).await["sessions_revoked"], false);
        let options = browser_request(
            &app,
            "POST",
            "/api/passkeys/register/options",
            &cookies,
            serde_json::json!({}),
        )
        .await;
        assert_eq!(options.status(), StatusCode::OK);
        sqlx::query("UPDATE sessions SET setup_only = 0")
            .execute(&database.pool)
            .await
            .unwrap();
        let saved = browser_request(
            &app,
            "PUT",
            "/api/account/profile",
            &cookies,
            serde_json::json!({"username":"alice", "display_name":"Alice"}),
        )
        .await;
        assert_eq!(saved.status(), StatusCode::OK);
        assert!(response_cookies(&saved).contains("hanko_session="));
        assert_eq!(response_json(saved).await["sessions_revoked"], true);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM sessions")
                .fetch_one(&database.pool)
                .await
                .unwrap(),
            0
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
    async fn login_options_remain_limited_when_preauth_cookies_are_omitted_or_rotated() {
        for rotate_cookie in [false, true] {
            let config = Config::new(
                "http://localhost:3000",
                "sqlite::memory:".into(),
                "127.0.0.1:0".into(),
            )
            .unwrap();
            let app = test_app(config).await;
            for attempt in 0..20 {
                let mut request = axum::http::Request::builder()
                    .method("POST")
                    .uri("/api/passkeys/login/options")
                    .header(header::ORIGIN, "http://localhost:3000");
                if rotate_cookie {
                    request =
                        request.header(header::COOKIE, format!("hanko_preauth=rotated-{attempt}"));
                }
                let response = app
                    .clone()
                    .oneshot(request.body(axum::body::Body::empty()).unwrap())
                    .await
                    .unwrap();
                if attempt < 12 {
                    assert_eq!(response.status(), StatusCode::OK);
                } else {
                    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
                }
            }
        }
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
                &config.webauthn_rp_id,
                &origin,
                Database::connect("sqlite::memory:").await.unwrap(),
                config.allow_multiple_passkeys_per_authenticator,
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

    #[tokio::test]
    async fn registration_ceremonies_are_limited_per_session_and_do_not_block_login() {
        let config = Config::new(
            "http://localhost:3000",
            "sqlite::memory:".into(),
            "127.0.0.1:0".into(),
        )
        .unwrap();
        let (app, database) = test_app_with_database(config).await;
        sqlx::query("INSERT INTO users (id, username, display_name, created_at, updated_at) VALUES ('00000000-0000-4000-8000-000000000001', 'setup-user', 'Setup User', 1, 1)")
            .execute(&database.pool)
            .await
            .unwrap();
        let session = create_session(
            &database,
            "00000000-0000-4000-8000-000000000001",
            true,
            unix_now(),
        )
        .await
        .unwrap();
        let registration_request = || {
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/passkeys/register/options")
                .header(header::ORIGIN, "http://localhost:3000")
                .header(
                    header::COOKIE,
                    format!(
                        "hanko_session={}; hanko_csrf={}",
                        session.raw_token, session.raw_csrf
                    ),
                )
                .header("x-csrf-token", &session.raw_csrf)
                .body(axum::body::Body::empty())
                .unwrap()
        };

        for _ in 0..2 {
            let response = app.clone().oneshot(registration_request()).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
        let over_quota = app.clone().oneshot(registration_request()).await.unwrap();
        assert_eq!(over_quota.status(), StatusCode::TOO_MANY_REQUESTS);

        let registration_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM webauthn_ceremonies WHERE kind = 'registration' AND consumed_at IS NULL",
        )
        .fetch_one(&database.pool)
        .await
        .unwrap();
        assert_eq!(registration_count, 2);

        let login = app
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
        assert_eq!(login.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn normal_session_without_an_existing_factor_cannot_use_setup_registration() {
        let config = Config::new(
            "http://localhost:3000",
            "sqlite::memory:".into(),
            "127.0.0.1:0".into(),
        )
        .unwrap();
        let (app, database) = test_app_with_database(config).await;
        sqlx::query("INSERT INTO users (id, username, display_name, created_at, updated_at) VALUES ('normal-user', 'normal-user', 'Normal User', 1, 1)")
            .execute(&database.pool)
            .await
            .unwrap();
        let session = create_session(&database, "normal-user", false, unix_now())
            .await
            .unwrap();
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/api/passkeys/register/options")
                    .header(header::ORIGIN, "http://localhost:3000")
                    .header(
                        header::COOKIE,
                        format!(
                            "hanko_session={}; hanko_csrf={}",
                            session.raw_token, session.raw_csrf
                        ),
                    )
                    .header("x-csrf-token", &session.raw_csrf)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let ceremonies: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM webauthn_ceremonies WHERE kind = 'registration'",
        )
        .fetch_one(&database.pool)
        .await
        .unwrap();
        assert_eq!(ceremonies, 0);
    }

    #[tokio::test]
    async fn passkey_removal_requires_a_matching_one_use_approval() {
        let config = Config::new(
            "http://localhost:3000",
            "sqlite::memory:".into(),
            "127.0.0.1:0".into(),
        )
        .unwrap();
        let (app, database) = test_app_with_database(config).await;
        let user_id = "00000000-0000-4000-8000-000000000002";
        sqlx::query("INSERT INTO users (id, username, display_name, created_at, updated_at) VALUES (?, 'passkey-user', 'Passkey User', 1, 1)")
            .bind(user_id)
            .execute(&database.pool)
            .await
            .unwrap();
        for (id, credential_id) in [("key-1", vec![1_u8]), ("key-2", vec![2_u8])] {
            sqlx::query("INSERT INTO passkeys (id, user_id, credential_id, passkey_json, label, created_at) VALUES (?, ?, ?, '{}', ?, 1)")
                .bind(id)
                .bind(user_id)
                .bind(credential_id)
                .bind(id)
                .execute(&database.pool)
                .await
                .unwrap();
        }
        let session = create_session(&database, user_id, false, unix_now())
            .await
            .unwrap();
        let wrong_action_token = "approval-for-add-action";
        let wrong_target_token = "approval-for-other-key";
        let valid_token = "approval-for-key-one";
        for (token, action, target) in [
            (wrong_action_token, "add", None),
            (wrong_target_token, "remove", Some("key-2")),
            (valid_token, "remove", Some("key-1")),
        ] {
            sqlx::query("INSERT INTO credential_change_approvals (approval_hash, user_id, session_hash, action, target_passkey_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
                .bind(digest(token))
                .bind(user_id)
                .bind(&session.session_hash)
                .bind(action)
                .bind(target)
                .bind(unix_now())
                .bind(unix_now() + 300)
                .execute(&database.pool)
                .await
                .unwrap();
        }

        let remove_request = |token: &str| {
            axum::http::Request::builder()
                .method("DELETE")
                .uri("/api/passkeys/key-1")
                .header(header::ORIGIN, "http://localhost:3000")
                .header(header::CONTENT_TYPE, "application/json")
                .header(
                    header::COOKIE,
                    format!(
                        "hanko_session={}; hanko_csrf={}",
                        session.raw_token, session.raw_csrf
                    ),
                )
                .header("x-csrf-token", &session.raw_csrf)
                .body(axum::body::Body::from(format!(
                    "{{\"confirmation\":\"REMOVE\",\"approval_token\":\"{token}\"}}"
                )))
                .unwrap()
        };

        for token in [wrong_action_token, wrong_target_token] {
            let response = app.clone().oneshot(remove_request(token)).await.unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            let still_present: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM passkeys WHERE id = 'key-1')")
                    .fetch_one(&database.pool)
                    .await
                    .unwrap();
            assert!(still_present);
        }

        let removed = app
            .clone()
            .oneshot(remove_request(valid_token))
            .await
            .unwrap();
        assert_eq!(removed.status(), StatusCode::OK);
        let replay = app.oneshot(remove_request(valid_token)).await.unwrap();
        assert_eq!(replay.status(), StatusCode::FORBIDDEN);
        let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM passkeys WHERE user_id = ?")
            .bind(user_id)
            .fetch_one(&database.pool)
            .await
            .unwrap();
        assert_eq!(remaining, 1);
    }
}
