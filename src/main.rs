mod admin;
mod config;
mod db;
mod http;
mod keys;
mod oidc;
mod security;
mod stamp;
mod webauthn;

use std::{net::SocketAddr, sync::Arc, time::Duration};

use config::Config;
use db::Database;
use http::AppState;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config = Config::from_env()?;
    let database = Database::connect(&config.database_url).await?;
    let webauthn = webauthn::WebauthnService::new(
        &config.webauthn_rp_id,
        &config.webauthn_origin(),
        database.clone(),
        config.allow_multiple_passkeys_per_authenticator,
    )?;
    let master_key = config.master_key.ok_or("missing identity master key")?;
    database.bind_webauthn_rp_id(&config.webauthn_rp_id).await?;
    let signing_keys = keys::SigningKeys::initialize(database.clone(), master_key).await?;
    spawn_cleanup(database.clone(), signing_keys.clone());
    let app = http::router(AppState {
        config: Arc::new(config.clone()),
        database,
        signing_keys,
        webauthn,
        anonymous_request_limiter: security::AnonymousRequestLimiter::default(),
    });

    let address: SocketAddr = config.bind_address.parse()?;
    let listener = tokio::net::TcpListener::bind(address).await?;
    tracing::info!(%address, issuer = %config.public_origin, "identity provider listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

fn spawn_cleanup(database: Database, signing_keys: keys::SigningKeys) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60 * 60));
        loop {
            interval.tick().await;
            let now = security::unix_now();
            for (job, query, cutoff) in [
                (
                    "authorization request cleanup",
                    "DELETE FROM authorization_requests WHERE expires_at <= ?",
                    now,
                ),
                (
                    "authorization code cleanup",
                    "DELETE FROM authorization_codes WHERE expires_at <= ?",
                    now,
                ),
                (
                    "WebAuthn ceremony cleanup",
                    "DELETE FROM webauthn_ceremonies WHERE expires_at <= ?",
                    now,
                ),
                (
                    "session cleanup",
                    "DELETE FROM sessions WHERE expires_at <= ?",
                    now,
                ),
                (
                    "invitation pending count refresh",
                    "UPDATE invitation_links SET pending_count = (SELECT COUNT(*) FROM users WHERE users.invitation_link_id = invitation_links.id AND users.invitation_reserved_until > ?)",
                    now,
                ),
                (
                    "invitation reservation cleanup",
                    "DELETE FROM users WHERE invitation_link_id IS NOT NULL AND invitation_reserved_until <= ? AND NOT EXISTS (SELECT 1 FROM passkeys WHERE passkeys.user_id = users.id)",
                    now,
                ),
                (
                    "refresh token family cleanup",
                    "DELETE FROM refresh_token_families WHERE expires_at <= ?",
                    now,
                ),
                (
                    "enrollment invitation cleanup",
                    "DELETE FROM enrollment_invitations WHERE expires_at <= ? OR consumed_at IS NOT NULL",
                    now,
                ),
                (
                    "login rate limit cleanup",
                    "DELETE FROM login_rate_limits WHERE window_started_at <= ?",
                    now - 3600,
                ),
                (
                    "anonymous rate limit cleanup",
                    "DELETE FROM anonymous_rate_limits WHERE window_started_at <= ?",
                    now - 60,
                ),
            ] {
                if let Err(error) = sqlx::query(query)
                    .bind(cutoff)
                    .execute(&database.pool)
                    .await
                {
                    tracing::warn!(%error, job = job, "periodic identity data cleanup failed");
                }
            }
            if let Err(error) = signing_keys.prune_retired(now).await {
                tracing::warn!(%error, "retired signing key cleanup failed");
            }
        }
    });
}
