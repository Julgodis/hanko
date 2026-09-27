use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::Row;
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::{
    Credential, DiscoverableAuthentication, DiscoverableKey, Passkey, PasskeyRegistration,
    PublicKeyCredential, RegisterPublicKeyCredential, Webauthn, WebauthnBuilder,
};

use crate::{
    db::Database,
    security::{digest, random_secret, unix_now},
};

const CEREMONY_SECONDS: i64 = 5 * 60;

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
    Registration(PasskeyRegistration),
    Authentication(DiscoverableAuthentication),
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
    ) -> Result<(String, Value), WebauthnError> {
        let passkeys = self.load_passkeys(user_id).await?;
        let excluded = passkeys
            .iter()
            .map(|passkey| passkey.cred_id().clone())
            .collect();
        let user_uuid = Uuid::parse_str(user_id).map_err(|_| WebauthnError::User)?;
        let (options, state) = self
            .webauthn
            .start_passkey_registration(user_uuid, username, display_name, Some(excluded))
            .map_err(|_| WebauthnError::Protocol)?;
        let state = CeremonyState::Registration(state);
        let options = credential_options(serde_json::to_value(options)?)?;
        let ceremony_id = self
            .store_ceremony("registration", Some(user_id), Some(session_hash), &state)
            .await?;
        Ok((ceremony_id, options))
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
        let CeremonyState::Registration(state) = state else {
            return Err(WebauthnError::Ceremony);
        };
        let passkey = self
            .webauthn
            .finish_passkey_registration(&credential, &state)
            .map_err(|_| WebauthnError::Protocol)?;
        let credential_id = passkey.cred_id().as_ref().to_vec();
        let now = unix_now();
        let mut transaction = self.database.pool.begin().await?;
        sqlx::query("INSERT INTO passkeys (id, user_id, credential_id, passkey_json, label, created_at) VALUES (?, ?, ?, ?, ?, ?)")
            .bind(Uuid::new_v4().to_string())
            .bind(user_id)
            .bind(credential_id)
            .bind(serde_json::to_string(&passkey)?)
            .bind(normalize_label(label))
            .bind(now)
            .execute(&mut *transaction)
            .await?;
        sqlx::query("UPDATE sessions SET setup_only = 0 WHERE session_hash = ? AND user_id = ?")
            .bind(session_hash)
            .bind(user_id)
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        Ok(())
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
        sqlx::query("INSERT INTO webauthn_ceremonies (ceremony_hash, kind, user_id, browser_hash, state_json, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
            .bind(digest(&raw_id))
            .bind(kind)
            .bind(user_id)
            .bind(browser_hash)
            .bind(serde_json::to_string(state)?)
            .bind(now)
            .bind(now + CEREMONY_SECONDS)
            .execute(&self.database.pool)
            .await?;
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
    use crate::security::digest;

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
}
