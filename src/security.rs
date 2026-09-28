use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::atomic::{AtomicUsize, Ordering},
    sync::{Arc, Mutex},
};

use axum::{
    http::{HeaderMap, header},
    response::Response,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use sqlx::Row;

use crate::{config::Config, db::Database};

pub const SESSION_COOKIE: &str = "hanko_session";
pub const CSRF_COOKIE: &str = "hanko_csrf";
pub const PREAUTH_COOKIE: &str = "hanko_preauth";
pub const SESSION_SECONDS: i64 = 12 * 60 * 60;
const ANONYMOUS_STATE_CREATION_SLOTS: usize = 128;
const ANONYMOUS_RATE_WINDOW_SECONDS: i64 = 60;
const MAX_ACTIVE_SOURCE_BUCKETS: i64 = 4096;
static ACTIVE_ANONYMOUS_STATE_CREATIONS: AtomicUsize = AtomicUsize::new(0);

pub struct AnonymousStateSlot;

#[derive(Clone, Default)]
pub struct AnonymousRequestLimiter {
    windows: Arc<Mutex<AnonymousRateWindows>>,
}

#[derive(Default)]
struct AnonymousRateWindows {
    global: HashMap<String, RateWindow>,
    sources: HashMap<(String, IpAddr), RateWindow>,
}

struct RateWindow {
    started_at: i64,
    attempts: i64,
}

impl AnonymousRequestLimiter {
    pub fn allow(
        &self,
        endpoint: &str,
        source: IpAddr,
        now: i64,
        source_limit: i64,
        global_limit: i64,
    ) -> bool {
        let cutoff = now - ANONYMOUS_RATE_WINDOW_SECONDS;
        let mut windows = self
            .windows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        windows
            .global
            .retain(|_, window| window.started_at > cutoff);
        windows
            .sources
            .retain(|_, window| window.started_at > cutoff);
        let source_key = (endpoint.to_owned(), source);
        if !windows.sources.contains_key(&source_key)
            && windows.sources.len() >= MAX_ACTIVE_SOURCE_BUCKETS as usize
        {
            return false;
        }
        if windows
            .sources
            .get(&source_key)
            .is_some_and(|window| window.attempts >= source_limit)
        {
            return false;
        }
        if !windows.global.contains_key(endpoint) {
            windows.global.insert(
                endpoint.to_owned(),
                RateWindow {
                    started_at: now,
                    attempts: 0,
                },
            );
        }
        let global = windows.global.get_mut(endpoint).expect("inserted above");
        if global.attempts >= global_limit {
            return false;
        }
        global.attempts += 1;
        let source_window = windows.sources.entry(source_key).or_insert(RateWindow {
            started_at: now,
            attempts: 0,
        });
        if source_window.attempts >= source_limit {
            return false;
        }
        source_window.attempts += 1;
        true
    }
}

impl Drop for AnonymousStateSlot {
    fn drop(&mut self) {
        ACTIVE_ANONYMOUS_STATE_CREATIONS.fetch_sub(1, Ordering::Release);
    }
}

pub fn try_anonymous_state_slot() -> Option<AnonymousStateSlot> {
    ACTIVE_ANONYMOUS_STATE_CREATIONS
        .fetch_update(Ordering::Acquire, Ordering::Relaxed, |current| {
            (current < ANONYMOUS_STATE_CREATION_SLOTS).then_some(current + 1)
        })
        .ok()
        .map(|_| AnonymousStateSlot)
}

pub fn source_ip(peer: Option<SocketAddr>, headers: &HeaderMap, config: &Config) -> IpAddr {
    let Some(peer_ip) = peer.map(|address| address.ip()) else {
        return IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    };
    if !config.trusted_proxy_addresses.contains(&peer_ip) {
        return peer_ip;
    }
    let Some(forwarded) = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
    else {
        return peer_ip;
    };
    let mut chain = forwarded
        .split(',')
        .map(str::trim)
        .map(str::parse::<IpAddr>)
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_default();
    chain.push(peer_ip);
    for address in chain.into_iter().rev() {
        if !config.trusted_proxy_addresses.contains(&address) {
            return address;
        }
    }
    peer_ip
}

pub async fn anonymous_request_allowed(
    database: &Database,
    endpoint: &str,
    source: IpAddr,
    now: i64,
    source_limit: i64,
    global_limit: i64,
) -> Result<bool, sqlx::Error> {
    let source_hash = digest(&format!("source:{source}"));
    let global_hash = digest(&format!("global:{endpoint}"));
    let cutoff = now - ANONYMOUS_RATE_WINDOW_SECONDS;
    let mut transaction = database.pool.begin().await?;
    sqlx::query("DELETE FROM anonymous_rate_limits WHERE endpoint = ? AND window_started_at <= ?")
        .bind(endpoint)
        .bind(cutoff)
        .execute(&mut *transaction)
        .await?;
    let source_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM anonymous_rate_limits WHERE endpoint = ? AND source_hash = ?)",
    )
    .bind(endpoint)
    .bind(&source_hash)
    .fetch_one(&mut *transaction)
    .await?;
    if source_exists {
        let source_attempts: i64 = sqlx::query_scalar(
            "SELECT attempts FROM anonymous_rate_limits WHERE endpoint = ? AND source_hash = ?",
        )
        .bind(endpoint)
        .bind(&source_hash)
        .fetch_one(&mut *transaction)
        .await?;
        if source_attempts >= source_limit {
            transaction.commit().await?;
            return Ok(false);
        }
    } else {
        let active_sources: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM anonymous_rate_limits WHERE endpoint = ? AND source_hash != ? AND window_started_at > ?")
            .bind(endpoint)
            .bind(&global_hash)
            .bind(cutoff)
            .fetch_one(&mut *transaction)
            .await?;
        if active_sources >= MAX_ACTIVE_SOURCE_BUCKETS {
            transaction.commit().await?;
            return Ok(false);
        }
    }
    let global_attempts: i64 = sqlx::query_scalar("INSERT INTO anonymous_rate_limits (endpoint, source_hash, window_started_at, attempts) VALUES (?, ?, ?, 1) ON CONFLICT(endpoint, source_hash) DO UPDATE SET attempts = CASE WHEN anonymous_rate_limits.window_started_at <= ? THEN 1 ELSE anonymous_rate_limits.attempts + 1 END, window_started_at = CASE WHEN anonymous_rate_limits.window_started_at <= ? THEN excluded.window_started_at ELSE anonymous_rate_limits.window_started_at END RETURNING attempts")
        .bind(endpoint)
        .bind(&global_hash)
        .bind(now)
        .bind(cutoff)
        .bind(cutoff)
        .fetch_one(&mut *transaction)
        .await?;
    if global_attempts > global_limit {
        transaction.commit().await?;
        return Ok(false);
    }
    let source_attempts: i64 = sqlx::query_scalar("INSERT INTO anonymous_rate_limits (endpoint, source_hash, window_started_at, attempts) VALUES (?, ?, ?, 1) ON CONFLICT(endpoint, source_hash) DO UPDATE SET attempts = CASE WHEN anonymous_rate_limits.window_started_at <= ? THEN 1 ELSE anonymous_rate_limits.attempts + 1 END, window_started_at = CASE WHEN anonymous_rate_limits.window_started_at <= ? THEN excluded.window_started_at ELSE anonymous_rate_limits.window_started_at END RETURNING attempts")
        .bind(endpoint)
        .bind(source_hash)
        .bind(now)
        .bind(cutoff)
        .bind(cutoff)
        .fetch_one(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(source_attempts <= source_limit)
}

#[derive(Clone, Debug)]
pub struct BrowserSession {
    pub raw_token: String,
    pub raw_csrf: String,
    pub session_hash: Vec<u8>,
    pub user_id: String,
    pub setup_only: bool,
    pub is_admin: bool,
}

#[derive(Clone, Debug)]
pub struct SessionIdentity {
    pub username: String,
    pub display_name: String,
    pub oidc_username: Option<String>,
    pub oidc_name: Option<String>,
    pub oidc_picture: Option<String>,
    pub oidc_phone: Option<String>,
    pub oidc_address: Option<serde_json::Value>,
    pub hanko_color: String,
    pub hanko_seed: String,
    pub is_admin: bool,
    pub setup_only: bool,
}

pub fn random_secret() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn digest(value: &str) -> Vec<u8> {
    Sha256::digest(value.as_bytes()).to_vec()
}

pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

pub fn unix_now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

pub fn cookie_value(headers: &HeaderMap, cookie_name: &str) -> Option<String> {
    let value = headers.get(header::COOKIE)?.to_str().ok()?;
    value.split(';').find_map(|pair| {
        let (name, value) = pair.trim().split_once('=')?;
        (name == cookie_name).then(|| value.to_owned())
    })
}

pub fn origin_is_valid(headers: &HeaderMap, config: &Config) -> bool {
    let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    origin == config.public_origin.origin().ascii_serialization()
}

pub fn cookie_header(
    name: &str,
    value: &str,
    config: &Config,
    http_only: bool,
    max_age: i64,
) -> String {
    let secure = if config.public_origin.scheme() == "https" {
        "; Secure"
    } else {
        ""
    };
    let http_only = if http_only { "; HttpOnly" } else { "" };
    let path = if config.base_path().is_empty() {
        "/"
    } else {
        config.base_path()
    };
    format!("{name}={value}; Path={path}; SameSite=Lax; Max-Age={max_age}{http_only}{secure}")
}

pub fn set_session_cookies(response: &mut Response, session: &BrowserSession, config: &Config) {
    response.headers_mut().append(
        header::SET_COOKIE,
        cookie_header(
            SESSION_COOKIE,
            &session.raw_token,
            config,
            true,
            SESSION_SECONDS,
        )
        .parse()
        .expect("valid session cookie header"),
    );
    response.headers_mut().append(
        header::SET_COOKIE,
        cookie_header(
            CSRF_COOKIE,
            &session.raw_csrf,
            config,
            false,
            SESSION_SECONDS,
        )
        .parse()
        .expect("valid CSRF cookie header"),
    );
}

pub fn clear_session_cookies(response: &mut Response, config: &Config) {
    for name in [SESSION_COOKIE, CSRF_COOKIE, PREAUTH_COOKIE] {
        response.headers_mut().append(
            header::SET_COOKIE,
            cookie_header(name, "", config, name != CSRF_COOKIE, 0)
                .parse()
                .expect("valid clearing cookie header"),
        );
    }
}

pub async fn create_session(
    database: &Database,
    user_id: &str,
    setup_only: bool,
    now: i64,
) -> Result<BrowserSession, sqlx::Error> {
    let authenticated_at_ms = if setup_only {
        0
    } else {
        now.saturating_mul(1000)
    };
    create_session_with_auth_time(database, user_id, setup_only, now, authenticated_at_ms).await
}

pub async fn create_passkey_session(
    database: &Database,
    user_id: &str,
) -> Result<BrowserSession, sqlx::Error> {
    let authenticated_at_ms = unix_now_millis();
    create_session_with_auth_time(
        database,
        user_id,
        false,
        authenticated_at_ms / 1000,
        authenticated_at_ms,
    )
    .await
}

async fn create_session_with_auth_time(
    database: &Database,
    user_id: &str,
    setup_only: bool,
    now: i64,
    authenticated_at_ms: i64,
) -> Result<BrowserSession, sqlx::Error> {
    let raw_token = random_secret();
    let raw_csrf = random_secret();
    let session_hash = digest(&raw_token);
    let csrf_hash = digest(&raw_csrf);
    sqlx::query("INSERT INTO sessions (session_hash, user_id, csrf_hash, setup_only, created_at, expires_at, authenticated_at_ms) VALUES (?, ?, ?, ?, ?, ?, ?)")
        .bind(&session_hash)
        .bind(user_id)
        .bind(csrf_hash)
        .bind(setup_only)
        .bind(now)
        .bind(now + SESSION_SECONDS)
        .bind(authenticated_at_ms)
        .execute(&database.pool)
        .await?;
    Ok(BrowserSession {
        raw_token,
        raw_csrf,
        session_hash,
        user_id: user_id.to_owned(),
        setup_only,
        is_admin: false,
    })
}

pub async fn load_session(
    headers: &HeaderMap,
    database: &Database,
) -> Result<Option<BrowserSession>, sqlx::Error> {
    let Some(raw_token) = cookie_value(headers, SESSION_COOKIE) else {
        return Ok(None);
    };
    let session_hash = digest(&raw_token);
    let row = sqlx::query(
        "SELECT s.user_id, s.csrf_hash, s.setup_only, u.is_admin FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.session_hash = ? AND s.expires_at > ? AND u.disabled_at IS NULL",
    )
    .bind(&session_hash)
    .bind(unix_now())
    .fetch_optional(&database.pool)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let stored_csrf: Vec<u8> = row.try_get("csrf_hash")?;
    let raw_csrf = cookie_value(headers, CSRF_COOKIE).unwrap_or_default();
    let supplied_csrf = digest(&raw_csrf);
    let csrf_valid = stored_csrf.len() == supplied_csrf.len()
        && subtle::ConstantTimeEq::ct_eq(stored_csrf.as_slice(), supplied_csrf.as_slice()).into();
    if !csrf_valid {
        return Ok(None);
    }
    Ok(Some(BrowserSession {
        raw_token,
        raw_csrf,
        session_hash,
        user_id: row.try_get("user_id")?,
        setup_only: row.try_get("setup_only")?,
        is_admin: row.try_get("is_admin")?,
    }))
}

pub async fn load_identity(
    headers: &HeaderMap,
    database: &Database,
) -> Result<Option<SessionIdentity>, sqlx::Error> {
    let Some(session) = load_session(headers, database).await? else {
        return Ok(None);
    };
    let row = sqlx::query(
        "SELECT username, display_name, CASE WHEN expose_preferred_username = 1 THEN username ELSE NULL END AS oidc_username, CASE WHEN expose_name = 1 THEN display_name ELSE NULL END AS oidc_name, attributes, hanko_color, hanko_seed FROM users WHERE id = ?",
    )
    .bind(&session.user_id)
    .fetch_one(&database.pool)
    .await?;
    let attributes: String = row.try_get("attributes")?;
    let attributes = serde_json::from_str::<serde_json::Value>(&attributes).ok();
    let oidc_picture = attributes
        .as_ref()
        .and_then(|attributes| attributes.get("picture"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let oidc_phone = attributes
        .as_ref()
        .and_then(|attributes| attributes.get("phone_number"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let oidc_address = attributes
        .as_ref()
        .and_then(|attributes| attributes.get("address"))
        .filter(|address| {
            address.is_object()
                && !address
                    .as_object()
                    .is_some_and(|address| address.is_empty())
        })
        .cloned();
    Ok(Some(SessionIdentity {
        username: row.try_get("username")?,
        display_name: row.try_get("display_name")?,
        oidc_username: row.try_get("oidc_username")?,
        oidc_name: row.try_get("oidc_name")?,
        oidc_picture,
        oidc_phone,
        oidc_address,
        hanko_color: row.try_get("hanko_color")?,
        hanko_seed: row.try_get("hanko_seed")?,
        is_admin: session.is_admin,
        setup_only: session.setup_only,
    }))
}

pub fn csrf_header_matches(headers: &HeaderMap, session: &BrowserSession) -> bool {
    let Some(token) = headers.get("x-csrf-token").and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let supplied = digest(token);
    let expected = digest(&session.raw_csrf);
    supplied.len() == expected.len()
        && subtle::ConstantTimeEq::ct_eq(supplied.as_slice(), expected.as_slice()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn hashes_random_session_tokens_and_checks_exact_origin() {
        let config = Config::new(
            "https://login.example",
            "sqlite::memory:".into(),
            "127.0.0.1:0".into(),
        )
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://login.example"),
        );
        assert!(origin_is_valid(&headers, &config));
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://login.example.attacker.invalid"),
        );
        assert!(!origin_is_valid(&headers, &config));

        let first = random_secret();
        let second = random_secret();
        assert_ne!(first, second);
        assert_ne!(digest(&first), first.as_bytes());
    }

    #[test]
    fn cookies_are_scoped_to_the_configured_application_path() {
        let config = Config::new(
            "https://login.example/hanko",
            "sqlite::memory:".into(),
            "127.0.0.1:0".into(),
        )
        .unwrap();
        let cookie = cookie_header("hanko_session", "secret", &config, true, 60);
        assert!(cookie.contains("Path=/hanko;"));
        assert!(cookie.contains("; Secure"));
    }

    #[test]
    fn forwarded_addresses_are_used_only_for_configured_proxies() {
        let mut config = Config::new(
            "https://login.example",
            "sqlite::memory:".into(),
            "127.0.0.1:0".into(),
        )
        .unwrap();
        let peer = SocketAddr::from(([192, 0, 2, 10], 8080));
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("198.51.100.42"));
        assert_eq!(source_ip(Some(peer), &headers, &config), peer.ip());

        config.trusted_proxy_addresses =
            vec!["192.0.2.10".parse().unwrap(), "192.0.2.11".parse().unwrap()];
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("198.51.100.42, 192.0.2.11"),
        );
        assert_eq!(
            source_ip(Some(peer), &headers, &config),
            "198.51.100.42".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn anonymous_limits_are_independent_of_browser_cookies_and_have_a_global_cap() {
        let limiter = AnonymousRequestLimiter::default();
        let source_a = "198.51.100.10".parse().unwrap();
        let source_b = "198.51.100.11".parse().unwrap();
        for _ in 0..3 {
            assert!(limiter.allow("login", source_a, 1_000, 3, 4));
        }
        assert!(!limiter.allow("login", source_a, 1_000, 3, 4));
        assert!(limiter.allow("login", source_b, 1_000, 3, 4));
        assert!(!limiter.allow("login", source_b, 1_000, 3, 4));
        assert!(limiter.allow("login", source_a, 1_061, 3, 4));
    }

    #[tokio::test]
    async fn persisted_anonymous_limits_enforce_source_and_global_buckets() {
        let database = Database::connect("sqlite::memory:").await.unwrap();
        let source_a = "198.51.100.20".parse().unwrap();
        let source_b = "198.51.100.21".parse().unwrap();
        let source_c = "198.51.100.22".parse().unwrap();
        assert!(
            anonymous_request_allowed(&database, "test", source_a, 1_000, 1, 2)
                .await
                .unwrap()
        );
        assert!(
            !anonymous_request_allowed(&database, "test", source_a, 1_001, 1, 2)
                .await
                .unwrap()
        );
        assert!(
            anonymous_request_allowed(&database, "test", source_b, 1_002, 1, 2)
                .await
                .unwrap()
        );
        assert!(
            !anonymous_request_allowed(&database, "test", source_c, 1_003, 1, 2)
                .await
                .unwrap()
        );
    }
}
