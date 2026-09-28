use std::{str::FromStr, time::Duration};

use sqlx::{
    SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
};

#[derive(Clone)]
pub struct Database {
    pub pool: SqlitePool,
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
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Self { pool })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
        );

        let tables: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name IN ('users', 'passkeys', 'groups', 'group_claim_mappings', 'oidc_clients', 'authorization_codes', 'refresh_tokens', 'webauthn_ceremonies', 'signing_keys')",
        )
        .fetch_one(&database.pool)
        .await
        .unwrap();
        assert_eq!(tables, 9);

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
