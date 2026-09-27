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
        let tables: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name IN ('users', 'passkeys', 'groups', 'oidc_clients', 'authorization_codes', 'webauthn_ceremonies', 'signing_keys')",
        )
        .fetch_one(&database.pool)
        .await
        .unwrap();
        assert_eq!(tables, 7);

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
    }
}
