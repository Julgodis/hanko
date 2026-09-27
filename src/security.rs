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
    let raw_token = random_secret();
    let raw_csrf = random_secret();
    let session_hash = digest(&raw_token);
    let csrf_hash = digest(&raw_csrf);
    sqlx::query("INSERT INTO sessions (session_hash, user_id, csrf_hash, setup_only, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)")
        .bind(&session_hash)
        .bind(user_id)
        .bind(csrf_hash)
        .bind(setup_only)
        .bind(now)
        .bind(now + SESSION_SECONDS)
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
        "SELECT username, display_name, CASE WHEN expose_preferred_username = 1 THEN username ELSE NULL END AS oidc_username, CASE WHEN expose_name = 1 THEN display_name ELSE NULL END AS oidc_name, hanko_color, hanko_seed FROM users WHERE id = ?",
    )
    .bind(&session.user_id)
    .fetch_one(&database.pool)
    .await?;
    Ok(Some(SessionIdentity {
        username: row.try_get("username")?,
        display_name: row.try_get("display_name")?,
        oidc_username: row.try_get("oidc_username")?,
        oidc_name: row.try_get("oidc_name")?,
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
}
