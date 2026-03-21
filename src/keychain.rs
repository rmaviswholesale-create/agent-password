use anyhow::{Context, Result};
use security_framework::passwords::{get_generic_password, set_generic_password};

const KEYCHAIN_SERVICE: &str = "tartavull.agent-password.vault";
const KEYCHAIN_ACCOUNT: &str = "vault-key";

pub fn store_vault_key(key: &[u8]) -> Result<()> {
    set_generic_password(&keychain_service(), &keychain_account(), key)
        .context("failed to store vault key in macOS Keychain")
}

pub fn load_vault_key() -> Result<Vec<u8>> {
    get_generic_password(&keychain_service(), &keychain_account())
        .context("failed to load vault key from macOS Keychain")
}

fn keychain_service() -> String {
    std::env::var("PASSWORD_KEYCHAIN_SERVICE").unwrap_or_else(|_| KEYCHAIN_SERVICE.to_string())
}

fn keychain_account() -> String {
    std::env::var("PASSWORD_KEYCHAIN_ACCOUNT").unwrap_or_else(|_| KEYCHAIN_ACCOUNT.to_string())
}
