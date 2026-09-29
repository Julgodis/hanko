use std::{collections::BTreeMap, sync::LazyLock};

pub static SUPPORTED: LazyLock<Vec<String>> = LazyLock::new(|| {
    serde_json::from_str::<BTreeMap<String, String>>(include_str!("../shared/oidc_scopes.json"))
        .expect("bundled OIDC scopes are valid")
        .into_keys()
        .collect()
});

pub fn supported(scope: &str) -> bool {
    SUPPORTED.iter().any(|candidate| candidate == scope)
}
