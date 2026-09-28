use std::sync::Arc;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use p256::{
    ecdsa::SigningKey,
    elliptic_curve::Generate,
    pkcs8::{EncodePrivateKey, LineEnding},
};
use serde::Serialize;
use serde_json::Value;
use sqlx::Row;
use uuid::Uuid;

use crate::db::Database;

const RETAINED_TOKEN_SECONDS: i64 = 15 * 60;

#[derive(Clone)]
pub struct SigningKeys {
    database: Database,
    master_key: Arc<[u8; 32]>,
}

impl SigningKeys {
    pub async fn initialize(database: Database, master_key: [u8; 32]) -> Result<Self, KeyError> {
        let store = Self {
            database,
            master_key: Arc::new(master_key),
        };
        let active = sqlx::query(
            "SELECT kid, encrypted_private_key FROM signing_keys WHERE status = 'active'",
        )
        .fetch_optional(&store.database.pool)
        .await?;
        if let Some(row) = active {
            let kid: String = row.try_get("kid")?;
            let encrypted: Vec<u8> = row.try_get("encrypted_private_key")?;
            let pem = store.decrypt(&kid, &encrypted)?;
            EncodingKey::from_ec_pem(&pem).map_err(|_| KeyError::InvalidStoredKey)?;
        } else {
            store.rotate(unix_now()).await?;
        }
        Ok(store)
    }

    pub async fn public_jwks(&self) -> Result<Vec<Value>, KeyError> {
        let rows = sqlx::query(
            "SELECT public_jwk FROM signing_keys WHERE status = 'active' OR (status = 'retiring' AND retire_after > ?)",
        )
        .bind(unix_now())
        .fetch_all(&self.database.pool)
        .await?;
        rows.into_iter()
            .map(|row| {
                let jwk: String = row.try_get("public_jwk")?;
                serde_json::from_str(&jwk).map_err(KeyError::Json)
            })
            .collect()
    }

    #[cfg(test)]
    pub async fn active_kid(&self) -> Result<String, KeyError> {
        let kid =
            sqlx::query_scalar::<_, String>("SELECT kid FROM signing_keys WHERE status = 'active'")
                .fetch_one(&self.database.pool)
                .await?;
        Ok(kid)
    }

    pub async fn sign<T: Serialize>(&self, claims: &T) -> Result<String, KeyError> {
        let row = sqlx::query(
            "SELECT kid, encrypted_private_key FROM signing_keys WHERE status = 'active'",
        )
        .fetch_one(&self.database.pool)
        .await?;
        let kid: String = row.try_get("kid")?;
        let encrypted: Vec<u8> = row.try_get("encrypted_private_key")?;
        let pem = self.decrypt(&kid, &encrypted)?;
        let encoding_key =
            EncodingKey::from_ec_pem(&pem).map_err(|_| KeyError::InvalidStoredKey)?;
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(kid);
        jsonwebtoken::encode(&header, claims, &encoding_key).map_err(KeyError::Jwt)
    }

    /// Creates a new ES256 key and retires the previous one after the maximum token lifetime.
    pub async fn rotate(&self, now: i64) -> Result<String, KeyError> {
        let mut rng = getrandom::SysRng;
        let signing_key =
            SigningKey::try_generate_from_rng(&mut rng).map_err(|_| KeyError::KeyGeneration)?;
        let pem = signing_key
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|_| KeyError::KeyGeneration)?;
        let kid = Uuid::new_v4().to_string();
        let encrypted = self.encrypt(&kid, pem.as_bytes())?;
        let public_key = signing_key.verifying_key().to_sec1_point(false);
        let x = public_key.x().ok_or(KeyError::KeyGeneration)?;
        let y = public_key.y().ok_or(KeyError::KeyGeneration)?;
        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "use": "sig",
            "alg": "ES256",
            "kid": kid,
            "x": URL_SAFE_NO_PAD.encode(x),
            "y": URL_SAFE_NO_PAD.encode(y),
        });

        let mut transaction = self.database.pool.begin().await?;
        sqlx::query(
            "UPDATE signing_keys SET status = 'retiring', retire_after = ? WHERE status = 'active'",
        )
        .bind(now + RETAINED_TOKEN_SECONDS)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO signing_keys (kid, algorithm, encrypted_private_key, public_jwk, status, created_at) VALUES (?, 'ES256', ?, ?, 'active', ?)",
        )
        .bind(&kid)
        .bind(encrypted)
        .bind(jwk.to_string())
        .bind(now)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(kid)
    }

    pub async fn prune_retired(&self, now: i64) -> Result<u64, KeyError> {
        let result =
            sqlx::query("DELETE FROM signing_keys WHERE status = 'retiring' AND retire_after <= ?")
                .bind(now)
                .execute(&self.database.pool)
                .await?;
        Ok(result.rows_affected())
    }

    fn encrypt(&self, kid: &str, plaintext: &[u8]) -> Result<Vec<u8>, KeyError> {
        let cipher = XChaCha20Poly1305::new_from_slice(self.master_key.as_ref())
            .map_err(|_| KeyError::InvalidMasterKey)?;
        let mut nonce = [0_u8; 24];
        getrandom::fill(&mut nonce).map_err(|_| KeyError::Encryption)?;
        let encrypted = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: kid.as_bytes(),
                },
            )
            .map_err(|_| KeyError::Encryption)?;
        Ok([nonce.as_slice(), encrypted.as_slice()].concat())
    }

    fn decrypt(&self, kid: &str, encrypted: &[u8]) -> Result<Vec<u8>, KeyError> {
        if encrypted.len() < 24 {
            return Err(KeyError::InvalidStoredKey);
        }
        let cipher = XChaCha20Poly1305::new_from_slice(self.master_key.as_ref())
            .map_err(|_| KeyError::InvalidMasterKey)?;
        cipher
            .decrypt(
                XNonce::from_slice(&encrypted[..24]),
                Payload {
                    msg: &encrypted[24..],
                    aad: kid.as_bytes(),
                },
            )
            .map_err(|_| KeyError::Decryption)
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("signing key generation failed")]
    KeyGeneration,
    #[error("invalid master key")]
    InvalidMasterKey,
    #[error("signing key encryption failed")]
    Encryption,
    #[error("signing key could not be decrypted; check IDENTITY_MASTER_KEY")]
    Decryption,
    #[error("stored signing key is malformed")]
    InvalidStoredKey,
    #[error(transparent)]
    Jwt(#[from] jsonwebtoken::errors::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{DecodingKey, Validation, decode};
    use p256::pkcs8::EncodePublicKey;

    async fn store() -> SigningKeys {
        let database = Database::connect("sqlite::memory:").await.unwrap();
        SigningKeys::initialize(database, [42_u8; 32])
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn creates_encrypted_es256_key_and_publishes_its_public_jwk() {
        let store = store().await;
        let kid = store.active_kid().await.unwrap();
        let jwks = store.public_jwks().await.unwrap();
        assert_eq!(jwks.len(), 1);
        assert_eq!(jwks[0]["kid"], kid);
        assert_eq!(jwks[0]["alg"], "ES256");
        assert_eq!(jwks[0]["kty"], "EC");

        let token = store
            .sign(&serde_json::json!({ "sub": "user-1" }))
            .await
            .unwrap();
        let row = sqlx::query("SELECT public_jwk FROM signing_keys WHERE kid = ?")
            .bind(&kid)
            .fetch_one(&store.database.pool)
            .await
            .unwrap();
        let public_jwk: Value = serde_json::from_str(&row.get::<String, _>("public_jwk")).unwrap();
        let x = URL_SAFE_NO_PAD
            .decode(public_jwk["x"].as_str().unwrap())
            .unwrap();
        let y = URL_SAFE_NO_PAD
            .decode(public_jwk["y"].as_str().unwrap())
            .unwrap();
        let point = [vec![4_u8], x, y].concat();
        let verifying_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&point).unwrap();
        let public_pem = verifying_key.to_public_key_pem(LineEnding::LF).unwrap();
        let mut validation = Validation::new(Algorithm::ES256);
        validation.validate_exp = false;
        validation.required_spec_claims.remove("exp");
        let decoded = decode::<Value>(
            &token,
            &DecodingKey::from_ec_pem(public_pem.as_bytes()).unwrap(),
            &validation,
        )
        .unwrap();
        assert_eq!(decoded.header.kid.as_deref(), Some(kid.as_str()));
        assert_eq!(decoded.claims["sub"], "user-1");
    }

    #[tokio::test]
    async fn rotation_retains_old_public_key_until_its_tokens_expire() {
        let store = store().await;
        let now = unix_now();
        let previous_kid = store.active_kid().await.unwrap();
        let next_kid = store.rotate(now).await.unwrap();
        assert_ne!(previous_kid, next_kid);
        let jwks = store.public_jwks().await.unwrap();
        assert_eq!(jwks.len(), 2);
        assert_eq!(
            store
                .prune_retired(now + RETAINED_TOKEN_SECONDS - 1)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            store
                .prune_retired(now + RETAINED_TOKEN_SECONDS)
                .await
                .unwrap(),
            1
        );
        assert_eq!(store.public_jwks().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn wrong_master_key_fails_closed() {
        let store = store().await;
        let result = SigningKeys::initialize(store.database.clone(), [43_u8; 32]).await;
        assert!(matches!(result, Err(KeyError::Decryption)));
    }
}
