use std::{str::FromStr, time::Duration};

use sqlx::{
    SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
};

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate::Migrator {
    ignore_missing: true,
    ..sqlx::migrate!("./migrations")
};

#[derive(Clone)]
pub struct Database {
    pub pool: SqlitePool,
}

#[derive(Debug, thiserror::Error)]
pub enum RpIdError {
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    #[error(
        "WebAuthn RP ID changed from {stored} to {configured}; restore the original RP ID to preserve existing passkeys"
    )]
    Changed { stored: String, configured: String },
}

impl Database {
    pub async fn connect(database_url: &str) -> Result<Self, sqlx::Error> {
        let options = SqliteConnectOptions::from_str(database_url)?
            .create_if_missing(true)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(5))
            .journal_mode(SqliteJournalMode::Wal);
        let max_connections = if database_url == "sqlite::memory:" {
            1
        } else {
            8
        };
        let pool = SqlitePoolOptions::new()
            .max_connections(max_connections)
            .connect_with(options)
            .await?;
        validate_migration_history(&pool).await?;
        MIGRATOR.run(&pool).await?;
        Ok(Self { pool })
    }

    pub async fn bind_webauthn_rp_id(&self, rp_id: &str) -> Result<(), RpIdError> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("INSERT INTO webauthn_rp_binding (singleton, rp_id) VALUES (1, ?) ON CONFLICT(singleton) DO NOTHING")
            .bind(rp_id)
            .execute(&mut *transaction)
            .await?;
        let stored: String =
            sqlx::query_scalar("SELECT rp_id FROM webauthn_rp_binding WHERE singleton = 1")
                .fetch_one(&mut *transaction)
                .await?;
        if stored != rp_id {
            return Err(RpIdError::Changed {
                stored,
                configured: rp_id.to_owned(),
            });
        }
        transaction.commit().await?;
        Ok(())
    }
}

async fn validate_migration_history(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    let has_migrations_table: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = '_sqlx_migrations')",
    )
    .fetch_one(pool)
    .await?;
    if !has_migrations_table {
        return Ok(());
    }

    let latest_known_version = MIGRATOR.iter().map(|migration| migration.version).max();
    let Some(latest_known_version) = latest_known_version else {
        return Ok(());
    };
    let applied_versions: Vec<i64> =
        sqlx::query_scalar("SELECT version FROM _sqlx_migrations WHERE success = 1")
            .fetch_all(pool)
            .await?;

    if let Some(missing_version) = applied_versions
        .into_iter()
        .find(|version| *version <= latest_known_version && !MIGRATOR.version_exists(*version))
    {
        return Err(sqlx::migrate::MigrateError::VersionMissing(missing_version).into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn webauthn_rp_id_binding_rejects_changes() {
        let database = Database::connect("sqlite::memory:").await.unwrap();
        database
            .bind_webauthn_rp_id("hanko.example.com")
            .await
            .unwrap();
        database
            .bind_webauthn_rp_id("hanko.example.com")
            .await
            .unwrap();
        assert!(matches!(
            database.bind_webauthn_rp_id("other.example.com").await,
            Err(RpIdError::Changed { .. })
        ));
        let stored: String = sqlx::query_scalar("SELECT rp_id FROM webauthn_rp_binding")
            .fetch_one(&database.pool)
            .await
            .unwrap();
        assert_eq!(stored, "hanko.example.com");
    }

    #[tokio::test]
    async fn migration_creates_core_tables_and_relationship_constraints() {
        let database = Database::connect("sqlite::memory:").await.unwrap();
        let migration_versions: Vec<i64> =
            sqlx::query_scalar("SELECT version FROM _sqlx_migrations ORDER BY version")
                .fetch_all(&database.pool)
                .await
                .unwrap();
        assert_eq!(
            migration_versions,
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17]
        );

        let tables: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name IN ('users', 'passkeys', 'groups', 'group_claim_mappings', 'user_claim_mappings', 'oidc_clients', 'oidc_consents', 'authorization_codes', 'refresh_tokens', 'webauthn_ceremonies', 'signing_keys')",
        )
        .fetch_one(&database.pool)
        .await
        .unwrap();
        assert_eq!(tables, 11);

        let security_tables: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name IN ('refresh_token_families', 'anonymous_rate_limits')",
        )
        .fetch_one(&database.pool)
        .await
        .unwrap();
        assert_eq!(security_tables, 2);

        let credential_change_table: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'credential_change_approvals'",
        )
        .fetch_one(&database.pool)
        .await
        .unwrap();
        assert_eq!(credential_change_table, 1);

        let freshness_columns: i64 = sqlx::query_scalar(
            "SELECT (SELECT COUNT(*) FROM pragma_table_info('sessions') WHERE name = 'authenticated_at_ms') + (SELECT COUNT(*) FROM pragma_table_info('authorization_requests') WHERE name = 'created_at_ms')",
        )
        .fetch_one(&database.pool)
        .await
        .unwrap();
        assert_eq!(freshness_columns, 2);

        let foreign_keys: Vec<(i64, i64, String, String, String, String, String, String)> =
            sqlx::query_as("PRAGMA foreign_key_list(user_groups)")
                .fetch_all(&database.pool)
                .await
                .unwrap();
        assert_eq!(foreign_keys.len(), 2);

        let hanko_style_columns: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pragma_table_info('users') WHERE name IN ('hanko_color', 'hanko_seed', 'expose_preferred_username', 'expose_name')",
        )
        .fetch_one(&database.pool)
        .await
        .unwrap();
        assert_eq!(hanko_style_columns, 4);

        let mainline_tables: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name IN ('client_users', 'invitation_links')",
        )
        .fetch_one(&database.pool)
        .await
        .unwrap();
        assert_eq!(mainline_tables, 2);

        let auth_method_column: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pragma_table_info('oidc_clients') WHERE name = 'token_endpoint_auth_method'",
        )
        .fetch_one(&database.pool)
        .await
        .unwrap();
        assert_eq!(auth_method_column, 1);

        let client_auth_policy_columns: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pragma_table_info('oidc_clients') WHERE name IN ('token_endpoint_auth_method', 'pkce_policy')",
        )
        .fetch_one(&database.pool)
        .await
        .unwrap();
        assert_eq!(client_auth_policy_columns, 2);

        for table in ["authorization_requests", "authorization_codes"] {
            let challenge_required: i64 = sqlx::query_scalar(&format!(
                "SELECT \"notnull\" FROM pragma_table_info('{table}') WHERE name = 'code_challenge'"
            ))
            .fetch_one(&database.pool)
            .await
            .unwrap();
            assert_eq!(
                challenge_required, 0,
                "{table}.code_challenge must be optional"
            );
        }
    }
}
