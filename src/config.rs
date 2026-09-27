use base64::{Engine, engine::general_purpose::STANDARD};
use url::Url;

#[derive(Clone, Debug)]
pub struct Config {
    pub public_origin: Url,
    pub database_url: String,
    pub bind_address: String,
    pub master_key: Option<[u8; 32]>,
    pub bootstrap_token: Option<String>,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let public_origin =
            std::env::var("PUBLIC_ORIGIN").map_err(|_| ConfigError::Missing("PUBLIC_ORIGIN"))?;
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "sqlite://./hanko.sqlite?mode=rwc".to_owned());
        let bind_address =
            std::env::var("BIND_ADDRESS").unwrap_or_else(|_| "127.0.0.1:3000".to_owned());

        let mut config = Self::new(&public_origin, database_url, bind_address)?;
        let encoded_key = std::env::var("IDENTITY_MASTER_KEY")
            .map_err(|_| ConfigError::Missing("IDENTITY_MASTER_KEY"))?;
        config.master_key = Some(parse_master_key(&encoded_key)?);
        config.bootstrap_token = std::env::var("BOOTSTRAP_TOKEN")
            .ok()
            .filter(|value| !value.is_empty());
        Ok(config)
    }

    pub fn new(
        public_origin: &str,
        database_url: String,
        bind_address: String,
    ) -> Result<Self, ConfigError> {
        let mut public_origin =
            Url::parse(public_origin).map_err(|_| ConfigError::InvalidOrigin)?;
        let local_http = matches!(
            public_origin.host_str(),
            Some("localhost" | "127.0.0.1" | "::1")
        );
        let path = public_origin.path();
        let valid_base_path = path == "/"
            || path.is_empty()
            || (!path.ends_with('/')
                && !path.contains("//")
                && path
                    .split('/')
                    .skip(1)
                    .all(|segment| !segment.is_empty() && segment != "." && segment != ".."));
        if !matches!(public_origin.scheme(), "http" | "https")
            || (public_origin.scheme() != "https" && !local_http)
            || public_origin.host_str().is_none()
            || !public_origin.username().is_empty()
            || public_origin.password().is_some()
            || public_origin.query().is_some()
            || public_origin.fragment().is_some()
            || !valid_base_path
        {
            return Err(ConfigError::InvalidOrigin);
        }

        if public_origin.path() == "/" {
            public_origin.set_path("");
        }
        Ok(Self {
            public_origin,
            database_url,
            bind_address,
            master_key: None,
            bootstrap_token: None,
        })
    }

    pub fn issuer(&self) -> String {
        self.public_origin.as_str().trim_end_matches('/').to_owned()
    }

    pub fn base_path(&self) -> &str {
        if self.public_origin.path() == "/" {
            ""
        } else {
            self.public_origin.path()
        }
    }

    pub fn webauthn_origin(&self) -> Url {
        let mut origin = self.public_origin.clone();
        origin.set_path("/");
        origin
    }
}

fn parse_master_key(value: &str) -> Result<[u8; 32], ConfigError> {
    let key = STANDARD
        .decode(value)
        .map_err(|_| ConfigError::InvalidMasterKey)?;
    key.try_into().map_err(|_| ConfigError::InvalidMasterKey)
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("missing required environment variable {0}")]
    Missing(&'static str),
    #[error(
        "PUBLIC_ORIGIN must use HTTPS (except on localhost) and may have only a clean path prefix"
    )]
    InvalidOrigin,
    #[error("IDENTITY_MASTER_KEY must be base64 encoding of exactly 32 random bytes")]
    InvalidMasterKey,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_https_origin_and_normalizes_trailing_slash() {
        let config = Config::new(
            "https://id.example/",
            "sqlite::memory:".into(),
            "127.0.0.1:0".into(),
        )
        .unwrap();
        assert_eq!(config.issuer(), "https://id.example");
    }

    #[test]
    fn allows_http_only_for_local_development() {
        assert!(
            Config::new(
                "http://localhost:3000",
                "sqlite::memory:".into(),
                "127.0.0.1:0".into()
            )
            .is_ok()
        );
        assert_eq!(
            Config::new(
                "http://id.example",
                "sqlite::memory:".into(),
                "127.0.0.1:0".into()
            )
            .unwrap_err(),
            ConfigError::InvalidOrigin
        );
    }

    #[test]
    fn allows_a_clean_path_prefix_and_uses_it_as_the_issuer() {
        let config = Config::new(
            "https://id.example/hanko",
            "sqlite::memory:".into(),
            "127.0.0.1:0".into(),
        )
        .unwrap();
        assert_eq!(config.issuer(), "https://id.example/hanko");
        assert_eq!(config.base_path(), "/hanko");
        assert_eq!(config.webauthn_origin().as_str(), "https://id.example/");
    }

    #[test]
    fn rejects_invalid_base_paths_and_origin_extras() {
        for origin in [
            "https://id.example/app/",
            "https://id.example//app",
            "https://id.example?x=1",
            "https://user@id.example",
        ] {
            assert_eq!(
                Config::new(origin, "sqlite::memory:".into(), "127.0.0.1:0".into()).unwrap_err(),
                ConfigError::InvalidOrigin
            );
        }
    }

    #[test]
    fn master_key_must_decode_to_exactly_32_bytes() {
        use base64::Engine;
        let key = STANDARD.encode([9_u8; 32]);
        assert_eq!(parse_master_key(&key).unwrap(), [9_u8; 32]);
        assert_eq!(
            parse_master_key(&STANDARD.encode([9_u8; 31])),
            Err(ConfigError::InvalidMasterKey)
        );
    }
}
