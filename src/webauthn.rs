use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::Row;
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::{
    Credential, DiscoverableAuthentication, DiscoverableKey, Passkey, PasskeyAuthentication,
    PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential, Webauthn,
    WebauthnBuilder,
};

use crate::{
    db::Database,
    security::{digest, random_secret, unix_now},
};

const CEREMONY_SECONDS: i64 = 5 * 60;
const APPROVAL_SECONDS: i64 = 5 * 60;
const MAX_ACTIVE_REGISTRATION_CEREMONIES: i64 = 500;
const MAX_ACTIVE_REGISTRATIONS_PER_USER: i64 = 5;
const MAX_ACTIVE_REGISTRATIONS_PER_SESSION: i64 = 2;
const MAX_ACTIVE_AUTHENTICATION_CEREMONIES: i64 = 5000;
const MAX_ACTIVE_ACCOUNT_AUTH_CEREMONIES_PER_SESSION: i64 = 5;

fn credential_options(value: Value) -> Result<Value, WebauthnError> {
    value
        .get("publicKey")
        .cloned()
        .ok_or(WebauthnError::Protocol)
}

#[derive(Clone)]
pub struct WebauthnService {
    webauthn: Webauthn,
    database: Database,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", content = "state")]
enum CeremonyState {
    Registration {
        state: PasskeyRegistration,
        approval_hash: Option<Vec<u8>>,
        bootstrap_session: bool,
    },
    Authentication(DiscoverableAuthentication),
    CredentialChange {
        state: PasskeyAuthentication,
        action: String,
        target_passkey_id: Option<String>,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum WebauthnError {
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("invalid WebAuthn ceremony")]
    Ceremony,
    #[error("unknown or disabled user")]
    User,
    #[error("passkey authentication failed")]
    Authentication,
    #[error("WebAuthn protocol validation failed")]
    Protocol,
    #[error("invalid WebAuthn configuration")]
    Configuration,
    #[error("too many active WebAuthn ceremonies")]
    Capacity,
}

impl WebauthnService {
    pub fn new(rp_id: &str, origin: &Url, database: Database) -> Result<Self, WebauthnError> {
        let webauthn = WebauthnBuilder::new(rp_id, origin)
            .map_err(|_| WebauthnError::Configuration)?
            .rp_name("Hanko")
            .build()
            .map_err(|_| WebauthnError::Configuration)?;
        Ok(Self { webauthn, database })
    }

    pub async fn start_registration(
        &self,
        user_id: &str,
        username: &str,
        display_name: &str,
        session_hash: &[u8],
        approval_token: Option<&str>,
    ) -> Result<(String, Value), WebauthnError> {
        let passkeys = self.load_passkeys(user_id).await?;
        let now = unix_now();
        let session_setup_only: Option<bool> = sqlx::query_scalar(
            "SELECT setup_only FROM sessions WHERE session_hash = ? AND user_id = ? AND expires_at > ? AND EXISTS (SELECT 1 FROM users WHERE id = ? AND disabled_at IS NULL)",
        )
        .bind(session_hash)
        .bind(user_id)
        .bind(now)
        .bind(user_id)
        .fetch_optional(&self.database.pool)
        .await?;
        let session_setup_only = session_setup_only.ok_or(WebauthnError::User)?;
        let (approval_hash, bootstrap_session) = if session_setup_only {
            if !passkeys.is_empty() || approval_token.is_some() {
                return Err(WebauthnError::Ceremony);
            }
            (None, true)
        } else {
            if passkeys.is_empty() {
                return Err(WebauthnError::Ceremony);
            }
            let approval_token = approval_token.ok_or(WebauthnError::Authentication)?;
            let approval_hash = digest(approval_token);
            let valid: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM credential_change_approvals WHERE approval_hash = ? AND user_id = ? AND session_hash = ? AND action = 'add' AND target_passkey_id IS NULL AND consumed_at IS NULL AND expires_at > ?)",
            )
            .bind(&approval_hash)
            .bind(user_id)
            .bind(session_hash)
            .bind(now)
            .fetch_one(&self.database.pool)
            .await?;
            if !valid {
                return Err(WebauthnError::Authentication);
            }
            (Some(approval_hash), false)
        };
        let excluded = passkeys
            .iter()
            .map(|passkey| passkey.cred_id().clone())
            .collect();
        let user_uuid = Uuid::parse_str(user_id).map_err(|_| WebauthnError::User)?;
        let (options, state) = self
            .webauthn
            .start_passkey_registration(user_uuid, username, display_name, Some(excluded))
            .map_err(|_| WebauthnError::Protocol)?;
        let state = CeremonyState::Registration {
            state,
            approval_hash,
            bootstrap_session,
        };
        let options = credential_options(serde_json::to_value(options)?)?;
        let ceremony_id = self
            .store_ceremony("registration", Some(user_id), Some(session_hash), &state)
            .await?;
        Ok((ceremony_id, options))
    }

    pub async fn registration_retry_after_seconds(
        &self,
        user_id: &str,
        session_hash: &[u8],
    ) -> Result<u64, WebauthnError> {
        let now = unix_now();
        let retry_at: Option<i64> = sqlx::query_scalar(
            "SELECT MAX(next_free_at) FROM (
                SELECT CASE WHEN COUNT(*) >= ? THEN MIN(expires_at) END AS next_free_at
                FROM webauthn_ceremonies
                WHERE kind = 'registration' AND consumed_at IS NULL AND expires_at > ?
                UNION ALL
                SELECT CASE WHEN COUNT(*) >= ? THEN MIN(expires_at) END AS next_free_at
                FROM webauthn_ceremonies
                WHERE kind = 'registration' AND user_id = ? AND consumed_at IS NULL AND expires_at > ?
                UNION ALL
                SELECT CASE WHEN COUNT(*) >= ? THEN MIN(expires_at) END AS next_free_at
                FROM webauthn_ceremonies
                WHERE kind = 'registration' AND user_id = ? AND browser_hash = ? AND consumed_at IS NULL AND expires_at > ?
            )",
        )
        .bind(MAX_ACTIVE_REGISTRATION_CEREMONIES)
        .bind(now)
        .bind(MAX_ACTIVE_REGISTRATIONS_PER_USER)
        .bind(user_id)
        .bind(now)
        .bind(MAX_ACTIVE_REGISTRATIONS_PER_SESSION)
        .bind(user_id)
        .bind(session_hash)
        .bind(now)
        .fetch_one(&self.database.pool)
        .await?;
        Ok(retry_at
            .unwrap_or(now + CEREMONY_SECONDS)
            .saturating_sub(now)
            .max(1) as u64)
    }

    pub async fn finish_registration(
        &self,
        ceremony_id: &str,
        user_id: &str,
        session_hash: &[u8],
        credential: RegisterPublicKeyCredential,
        label: &str,
    ) -> Result<(), WebauthnError> {
        let state = self
            .consume_ceremony(ceremony_id, "registration", Some(user_id), session_hash)
            .await?;
        let CeremonyState::Registration {
            state,
            approval_hash,
            bootstrap_session,
        } = state
        else {
            return Err(WebauthnError::Ceremony);
        };
        let passkey = self
            .webauthn
            .finish_passkey_registration(&credential, &state)
            .map_err(|_| WebauthnError::Protocol)?;
        let credential_id = passkey.cred_id().as_ref().to_vec();
        let now = unix_now();
        let mut transaction = self.database.pool.begin().await?;
        let mut invitation_link_id: Option<String> = None;
        if let Some(approval_hash) = approval_hash {
            let consumed = sqlx::query("UPDATE credential_change_approvals SET consumed_at = ? WHERE approval_hash = ? AND user_id = ? AND session_hash = ? AND action = 'add' AND target_passkey_id IS NULL AND consumed_at IS NULL AND expires_at > ? AND EXISTS (SELECT 1 FROM sessions WHERE session_hash = ? AND user_id = ? AND setup_only = 0 AND expires_at > ?) AND EXISTS (SELECT 1 FROM users WHERE id = ? AND disabled_at IS NULL) RETURNING approval_hash")
                .bind(now)
                .bind(approval_hash)
                .bind(user_id)
                .bind(session_hash)
                .bind(now)
                .bind(session_hash)
                .bind(user_id)
                .bind(now)
                .bind(user_id)
                .fetch_optional(&mut *transaction)
                .await?;
            if consumed.is_none() {
                return Err(WebauthnError::Authentication);
            }
        } else {
            let bootstrap_still_valid: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sessions WHERE session_hash = ? AND user_id = ? AND setup_only = 1 AND expires_at > ?) AND NOT EXISTS(SELECT 1 FROM passkeys WHERE user_id = ?) AND EXISTS(SELECT 1 FROM users WHERE id = ? AND disabled_at IS NULL AND (invitation_link_id IS NULL OR invitation_reserved_until > ?))")
                .bind(session_hash)
                .bind(user_id)
                .bind(now)
                .bind(user_id)
                .bind(user_id)
                .bind(now)
                .fetch_one(&mut *transaction)
                .await?;
            if !bootstrap_session || !bootstrap_still_valid {
                return Err(WebauthnError::Ceremony);
            }
            let user = sqlx::query("SELECT invitation_link_id FROM users WHERE id = ? AND disabled_at IS NULL AND (invitation_link_id IS NULL OR invitation_reserved_until > ?)")
                .bind(user_id)
                .bind(now)
                .fetch_optional(&mut *transaction)
                .await?
                .ok_or(WebauthnError::Ceremony)?;
            invitation_link_id = user.try_get("invitation_link_id")?;
        }
        sqlx::query("INSERT INTO passkeys (id, user_id, credential_id, passkey_json, label, created_at) VALUES (?, ?, ?, ?, ?, ?)")
            .bind(Uuid::new_v4().to_string())
            .bind(user_id)
            .bind(credential_id)
            .bind(serde_json::to_string(&passkey)?)
            .bind(normalize_label(label))
            .bind(now)
            .execute(&mut *transaction)
            .await?;
        if bootstrap_session {
            if let Some(invitation_link_id) = invitation_link_id {
                let finalized = sqlx::query("UPDATE invitation_links SET use_count = use_count + 1, pending_count = pending_count - 1 WHERE id = ? AND pending_count > 0 AND use_count < max_uses AND use_count + pending_count <= max_uses RETURNING id")
                    .bind(&invitation_link_id)
                    .fetch_optional(&mut *transaction)
                    .await?;
                if finalized.is_none() {
                    return Err(WebauthnError::Ceremony);
                }
                let released = sqlx::query("UPDATE users SET invitation_link_id = NULL, invitation_reserved_until = NULL WHERE id = ? AND invitation_link_id = ? AND invitation_reserved_until > ?")
                    .bind(user_id)
                    .bind(invitation_link_id)
                    .bind(now)
                    .execute(&mut *transaction)
                    .await?;
                if released.rows_affected() != 1 {
                    return Err(WebauthnError::Ceremony);
                }
            }
            let promoted = sqlx::query("UPDATE sessions SET setup_only = 0 WHERE session_hash = ? AND user_id = ? AND setup_only = 1 AND expires_at > ? AND EXISTS (SELECT 1 FROM users WHERE id = ? AND disabled_at IS NULL)")
                .bind(session_hash)
                .bind(user_id)
                .bind(now)
                .bind(user_id)
                .execute(&mut *transaction)
                .await?;
            if promoted.rows_affected() != 1 {
                return Err(WebauthnError::Ceremony);
            }
        }
        transaction.commit().await?;
        Ok(())
    }

    pub async fn start_credential_change(
        &self,
        user_id: &str,
        session_hash: &[u8],
        action: &str,
        target_passkey_id: Option<&str>,
    ) -> Result<(String, Value), WebauthnError> {
        let now = unix_now();
        let active_session: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sessions WHERE session_hash = ? AND user_id = ? AND setup_only = 0 AND expires_at > ?) AND EXISTS(SELECT 1 FROM users WHERE id = ? AND disabled_at IS NULL)")
            .bind(session_hash)
            .bind(user_id)
            .bind(now)
            .bind(user_id)
            .fetch_one(&self.database.pool)
            .await?;
        if !active_session {
            return Err(WebauthnError::User);
        }
        match (action, target_passkey_id) {
            ("add", None) => {}
            ("remove", Some(passkey_id)) => {
                let exists: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM passkeys WHERE id = ? AND user_id = ?)",
                )
                .bind(passkey_id)
                .bind(user_id)
                .fetch_one(&self.database.pool)
                .await?;
                if !exists {
                    return Err(WebauthnError::User);
                }
            }
            _ => return Err(WebauthnError::Protocol),
        }
        let passkeys = self.load_passkeys(user_id).await?;
        if passkeys.is_empty() {
            return Err(WebauthnError::Authentication);
        }
        let (options, state) = self
            .webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(|_| WebauthnError::Protocol)?;
        let options = credential_options(serde_json::to_value(options)?)?;
        let ceremony_id = self
            .store_ceremony(
                "authentication",
                Some(user_id),
                Some(session_hash),
                &CeremonyState::CredentialChange {
                    state,
                    action: action.to_owned(),
                    target_passkey_id: target_passkey_id.map(str::to_owned),
                },
            )
            .await?;
        Ok((ceremony_id, options))
    }

    pub async fn finish_credential_change(
        &self,
        ceremony_id: &str,
        user_id: &str,
        session_hash: &[u8],
        credential: PublicKeyCredential,
    ) -> Result<String, WebauthnError> {
        let state = self
            .consume_ceremony(ceremony_id, "authentication", Some(user_id), session_hash)
            .await?;
        let CeremonyState::CredentialChange {
            state,
            action,
            target_passkey_id,
        } = state
        else {
            return Err(WebauthnError::Ceremony);
        };
        let rows = sqlx::query("SELECT id, passkey_json FROM passkeys WHERE user_id = ?")
            .bind(user_id)
            .fetch_all(&self.database.pool)
            .await?;
        let mut passkeys = rows
            .into_iter()
            .map(|row| {
                let id: String = row.try_get("id")?;
                let value: String = row.try_get("passkey_json")?;
                Ok::<_, WebauthnError>((id, serde_json::from_str::<Passkey>(&value)?))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if passkeys.is_empty()
            || (action == "remove"
                && !target_passkey_id
                    .as_ref()
                    .is_some_and(|target| passkeys.iter().any(|(id, _)| id == target)))
        {
            return Err(WebauthnError::Authentication);
        }
        let result = self
            .webauthn
            .finish_passkey_authentication(&credential, &state)
            .map_err(|_| WebauthnError::Authentication)?;
        if !result.user_verified() {
            return Err(WebauthnError::Authentication);
        }
        let credential_id = result.cred_id().as_ref().to_vec();
        let (passkey_id, passkey) = passkeys
            .iter_mut()
            .find(|(_, passkey)| passkey.cred_id().as_ref() == credential_id)
            .ok_or(WebauthnError::Authentication)?;
        let stored_credential: Credential = passkey.clone().into();
        if result.counter() > 0 && result.counter() <= stored_credential.counter {
            return Err(WebauthnError::Authentication);
        }
        passkey
            .update_credential(&result)
            .ok_or(WebauthnError::Authentication)?;

        let approval_token = random_secret();
        let now = unix_now();
        let mut transaction = self.database.pool.begin().await?;
        let active_session: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sessions WHERE session_hash = ? AND user_id = ? AND setup_only = 0 AND expires_at > ?) AND EXISTS(SELECT 1 FROM users WHERE id = ? AND disabled_at IS NULL)")
            .bind(session_hash)
            .bind(user_id)
            .bind(now)
            .bind(user_id)
            .fetch_one(&mut *transaction)
            .await?;
        if !active_session {
            return Err(WebauthnError::User);
        }
        let updated = sqlx::query(
            "UPDATE passkeys SET passkey_json = ?, last_used_at = ? WHERE id = ? AND user_id = ?",
        )
        .bind(serde_json::to_string(passkey)?)
        .bind(now)
        .bind(passkey_id.as_str())
        .bind(user_id)
        .execute(&mut *transaction)
        .await?;
        if updated.rows_affected() != 1 {
            return Err(WebauthnError::Authentication);
        }
        sqlx::query("DELETE FROM credential_change_approvals WHERE expires_at <= ? OR consumed_at IS NOT NULL OR (user_id = ? AND session_hash = ? AND action = ? AND target_passkey_id IS ?)")
            .bind(now)
            .bind(user_id)
            .bind(session_hash)
            .bind(&action)
            .bind(&target_passkey_id)
            .execute(&mut *transaction)
            .await?;
        sqlx::query("INSERT INTO credential_change_approvals (approval_hash, user_id, session_hash, action, target_passkey_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
            .bind(digest(&approval_token))
            .bind(user_id)
            .bind(session_hash)
            .bind(action)
            .bind(target_passkey_id)
            .bind(now)
            .bind(now + APPROVAL_SECONDS)
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        Ok(approval_token)
    }

    pub async fn start_authentication(
        &self,
        browser_hash: &[u8],
    ) -> Result<(String, Value), WebauthnError> {
        let (options, state) = self
            .webauthn
            .start_discoverable_authentication()
            .map_err(|_| WebauthnError::Protocol)?;
        let ceremony_id = self
            .store_ceremony(
                "authentication",
                None,
                Some(browser_hash),
                &CeremonyState::Authentication(state),
            )
            .await?;
        let options = credential_options(serde_json::to_value(options)?)?;
        Ok((ceremony_id, options))
    }

    pub async fn finish_authentication(
        &self,
        ceremony_id: &str,
        browser_hash: &[u8],
        credential: PublicKeyCredential,
    ) -> Result<String, WebauthnError> {
        let state = self
            .consume_ceremony(ceremony_id, "authentication", None, browser_hash)
            .await?;
        let CeremonyState::Authentication(state) = state else {
            return Err(WebauthnError::Ceremony);
        };
        let (user_uuid, _) = self
            .webauthn
            .identify_discoverable_authentication(&credential)
            .map_err(|_| WebauthnError::Authentication)?;
        let user_id = user_uuid.to_string();
        let rows = sqlx::query(
            "SELECT p.id, p.passkey_json FROM passkeys p JOIN users u ON u.id = p.user_id WHERE u.id = ? AND u.disabled_at IS NULL",
        )
        .bind(&user_id)
        .fetch_all(&self.database.pool)
        .await?;
        let passkeys = rows
            .into_iter()
            .map(|row| {
                let id: String = row.try_get("id")?;
                let value: String = row.try_get("passkey_json")?;
                Ok::<_, WebauthnError>((id, serde_json::from_str::<Passkey>(&value)?))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if passkeys.is_empty() {
            return Err(WebauthnError::Authentication);
        }
        let discoverable_keys = passkeys
            .iter()
            .map(|(_, passkey)| DiscoverableKey::from(passkey))
            .collect::<Vec<_>>();
        let result = self
            .webauthn
            .finish_discoverable_authentication(&credential, state, &discoverable_keys)
            .map_err(|_| WebauthnError::Authentication)?;
        if !result.user_verified() {
            return Err(WebauthnError::Authentication);
        }

        let credential_id = result.cred_id().as_ref().to_vec();
        let (passkey_id, mut passkey) = passkeys
            .into_iter()
            .find(|(_, passkey)| passkey.cred_id().as_ref() == credential_id)
            .ok_or(WebauthnError::Authentication)?;
        let stored_credential: Credential = passkey.clone().into();
        if result.counter() > 0 && result.counter() <= stored_credential.counter {
            return Err(WebauthnError::Authentication);
        }
        passkey
            .update_credential(&result)
            .ok_or(WebauthnError::Authentication)?;
        sqlx::query("UPDATE passkeys SET passkey_json = ?, last_used_at = ? WHERE id = ?")
            .bind(serde_json::to_string(&passkey)?)
            .bind(unix_now())
            .bind(passkey_id)
            .execute(&self.database.pool)
            .await?;
        sqlx::query("DELETE FROM login_rate_limits WHERE username_hash = ?")
            .bind(browser_hash)
            .execute(&self.database.pool)
            .await?;
        Ok(user_id)
    }

    async fn load_passkeys(&self, user_id: &str) -> Result<Vec<Passkey>, WebauthnError> {
        let rows = sqlx::query("SELECT passkey_json FROM passkeys WHERE user_id = ?")
            .bind(user_id)
            .fetch_all(&self.database.pool)
            .await?;
        rows.into_iter()
            .map(|row| {
                let value: String = row.try_get("passkey_json")?;
                serde_json::from_str(&value).map_err(WebauthnError::Json)
            })
            .collect()
    }

    async fn store_ceremony<T: Serialize>(
        &self,
        kind: &str,
        user_id: Option<&str>,
        browser_hash: Option<&[u8]>,
        state: &T,
    ) -> Result<String, WebauthnError> {
        let raw_id = random_secret();
        let now = unix_now();
        sqlx::query("DELETE FROM webauthn_ceremonies WHERE expires_at <= ?")
            .bind(now)
            .execute(&self.database.pool)
            .await?;
        let state_json = serde_json::to_string(state)?;
        let inserted = if kind == "registration" {
            sqlx::query("INSERT INTO webauthn_ceremonies (ceremony_hash, kind, user_id, browser_hash, state_json, created_at, expires_at) SELECT ?, ?, ?, ?, ?, ?, ? WHERE (SELECT COUNT(*) FROM webauthn_ceremonies WHERE kind = 'registration' AND consumed_at IS NULL AND expires_at > ?) < ? AND (SELECT COUNT(*) FROM webauthn_ceremonies WHERE kind = 'registration' AND user_id = ? AND consumed_at IS NULL AND expires_at > ?) < ? AND (SELECT COUNT(*) FROM webauthn_ceremonies WHERE kind = 'registration' AND user_id = ? AND browser_hash = ? AND consumed_at IS NULL AND expires_at > ?) < ?")
                .bind(digest(&raw_id))
                .bind(kind)
                .bind(user_id)
                .bind(browser_hash)
                .bind(state_json)
                .bind(now)
                .bind(now + CEREMONY_SECONDS)
                .bind(now)
                .bind(MAX_ACTIVE_REGISTRATION_CEREMONIES)
                .bind(user_id)
                .bind(now)
                .bind(MAX_ACTIVE_REGISTRATIONS_PER_USER)
                .bind(user_id)
                .bind(browser_hash)
                .bind(now)
                .bind(MAX_ACTIVE_REGISTRATIONS_PER_SESSION)
                .execute(&self.database.pool)
                .await?
        } else if let Some(user_id) = user_id {
            sqlx::query("INSERT INTO webauthn_ceremonies (ceremony_hash, kind, user_id, browser_hash, state_json, created_at, expires_at) SELECT ?, ?, ?, ?, ?, ?, ? WHERE (SELECT COUNT(*) FROM webauthn_ceremonies WHERE kind = 'authentication' AND consumed_at IS NULL AND expires_at > ?) < ? AND (SELECT COUNT(*) FROM webauthn_ceremonies WHERE kind = 'authentication' AND user_id = ? AND browser_hash = ? AND consumed_at IS NULL AND expires_at > ?) < ?")
                .bind(digest(&raw_id))
                .bind(kind)
                .bind(Some(user_id))
                .bind(browser_hash)
                .bind(state_json)
                .bind(now)
                .bind(now + CEREMONY_SECONDS)
                .bind(now)
                .bind(MAX_ACTIVE_AUTHENTICATION_CEREMONIES)
                .bind(user_id)
                .bind(browser_hash)
                .bind(now)
                .bind(MAX_ACTIVE_ACCOUNT_AUTH_CEREMONIES_PER_SESSION)
                .execute(&self.database.pool)
                .await?
        } else {
            sqlx::query("INSERT INTO webauthn_ceremonies (ceremony_hash, kind, user_id, browser_hash, state_json, created_at, expires_at) SELECT ?, ?, ?, ?, ?, ?, ? WHERE (SELECT COUNT(*) FROM webauthn_ceremonies WHERE kind = 'authentication' AND consumed_at IS NULL AND expires_at > ?) < ?")
                .bind(digest(&raw_id))
                .bind(kind)
                .bind(user_id)
                .bind(browser_hash)
                .bind(state_json)
                .bind(now)
                .bind(now + CEREMONY_SECONDS)
                .bind(now)
                .bind(MAX_ACTIVE_AUTHENTICATION_CEREMONIES)
                .execute(&self.database.pool)
                .await?
        };
        if inserted.rows_affected() != 1 {
            return Err(WebauthnError::Capacity);
        }
        Ok(raw_id)
    }

    async fn consume_ceremony(
        &self,
        raw_id: &str,
        kind: &str,
        user_id: Option<&str>,
        browser_hash: &[u8],
    ) -> Result<CeremonyState, WebauthnError> {
        let now = unix_now();
        let row = sqlx::query("UPDATE webauthn_ceremonies SET consumed_at = ? WHERE ceremony_hash = ? AND kind = ? AND user_id IS ? AND browser_hash = ? AND consumed_at IS NULL AND expires_at > ? RETURNING state_json")
            .bind(now)
            .bind(digest(raw_id))
            .bind(kind)
            .bind(user_id)
            .bind(browser_hash)
            .bind(now)
            .fetch_optional(&self.database.pool)
            .await?
            .ok_or(WebauthnError::Ceremony)?;
        let state_json: String = row.try_get("state_json")?;
        serde_json::from_str(&state_json).map_err(WebauthnError::Json)
    }
}

fn normalize_label(label: &str) -> String {
    let label = label.trim();
    if label.is_empty() || label.len() > 100 {
        "Passkey".to_owned()
    } else {
        label.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::{create_session, digest, unix_now};

    #[test]
    fn webauthn_public_key_options_are_flattened_for_browser_api() {
        let options = serde_json::json!({
            "publicKey": {
                "challenge": "challenge-value",
                "rp": { "name": "Hanko", "id": "localhost" }
            }
        });
        let flattened = credential_options(options).unwrap();
        assert_eq!(flattened["challenge"], "challenge-value");
        assert_eq!(flattened["rp"]["id"], "localhost");
        assert!(flattened.get("publicKey").is_none());
    }

    #[tokio::test]
    async fn ceremony_state_is_stored_as_server_side_state_and_consumed_once() {
        let database = Database::connect("sqlite::memory:").await.unwrap();
        let service = WebauthnService::new(
            "localhost",
            &Url::parse("http://localhost:3000").unwrap(),
            database.clone(),
        )
        .unwrap();
        let browser_hash = digest("browser");
        let (ceremony_id, options) = service.start_authentication(&browser_hash).await.unwrap();
        assert!(options["allowCredentials"].as_array().unwrap().is_empty());

        let row = sqlx::query(
            "SELECT user_id, state_json FROM webauthn_ceremonies WHERE ceremony_hash = ?",
        )
        .bind(digest(&ceremony_id))
        .fetch_one(&database.pool)
        .await
        .unwrap();
        assert!(
            row.try_get::<Option<String>, _>("user_id")
                .unwrap()
                .is_none()
        );
        assert!(
            row.try_get::<String, _>("state_json")
                .unwrap()
                .contains("Authentication")
        );

        assert!(matches!(
            service
                .consume_ceremony(&ceremony_id, "authentication", None, &browser_hash)
                .await
                .unwrap(),
            CeremonyState::Authentication(_)
        ));
        let replay = service
            .consume_ceremony(&ceremony_id, "authentication", None, &browser_hash)
            .await;
        assert!(matches!(replay, Err(WebauthnError::Ceremony)));
    }

    #[tokio::test]
    async fn registration_quota_is_per_user_and_separate_from_authentication_capacity() {
        let database = Database::connect("sqlite::memory:").await.unwrap();
        let service = WebauthnService::new(
            "localhost",
            &Url::parse("http://localhost:3000").unwrap(),
            database.clone(),
        )
        .unwrap();
        let user_id = "00000000-0000-4000-8000-000000000003";
        sqlx::query("INSERT INTO users (id, username, display_name, created_at, updated_at) VALUES (?, 'registration-user', 'Registration User', 1, 1)")
            .bind(user_id)
            .execute(&database.pool)
            .await
            .unwrap();
        let sessions = [
            create_session(&database, user_id, true, unix_now())
                .await
                .unwrap(),
            create_session(&database, user_id, true, unix_now())
                .await
                .unwrap(),
            create_session(&database, user_id, true, unix_now())
                .await
                .unwrap(),
            create_session(&database, user_id, true, unix_now())
                .await
                .unwrap(),
        ];
        for session in &sessions[..2] {
            for _ in 0..2 {
                service
                    .start_registration(
                        user_id,
                        "registration-user",
                        "Registration User",
                        &session.session_hash,
                        None,
                    )
                    .await
                    .unwrap();
            }
        }
        service
            .start_registration(
                user_id,
                "registration-user",
                "Registration User",
                &sessions[2].session_hash,
                None,
            )
            .await
            .unwrap();
        let over_user_quota = service
            .start_registration(
                user_id,
                "registration-user",
                "Registration User",
                &sessions[3].session_hash,
                None,
            )
            .await;
        assert!(matches!(over_user_quota, Err(WebauthnError::Capacity)));

        let registration_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM webauthn_ceremonies WHERE kind = 'registration' AND user_id = ? AND consumed_at IS NULL",
        )
        .bind(user_id)
        .fetch_one(&database.pool)
        .await
        .unwrap();
        assert_eq!(registration_count, 5);

        let now = unix_now();
        sqlx::query("WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM seq WHERE n < 495) INSERT INTO webauthn_ceremonies (ceremony_hash, kind, state_json, created_at, expires_at) SELECT randomblob(32), 'registration', '{}', ?, ? FROM seq")
            .bind(now)
            .bind(now + CEREMONY_SECONDS)
            .execute(&database.pool)
            .await
            .unwrap();
        let login = service.start_authentication(&digest("login-browser")).await;
        assert!(login.is_ok());
    }
}
