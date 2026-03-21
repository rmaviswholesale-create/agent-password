use anyhow::{Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use serde_json::{Map, Value};
use zeroize::Zeroizing;

pub const VAULT_KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;

pub fn encrypt_fields(key_bytes: &[u8], fields: &Map<String, Value>) -> Result<(Vec<u8>, Vec<u8>)> {
    let plaintext = Zeroizing::new(
        serde_json::to_vec(fields).context("failed to serialize encrypted secret fields")?,
    );
    let cipher = cipher(key_bytes)?;
    let nonce_bytes = random_nonce()?;
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce_bytes), plaintext.as_ref())
        .map_err(|_| anyhow::anyhow!("failed to encrypt secret fields"))?;
    Ok((nonce_bytes.to_vec(), ciphertext))
}

pub fn decrypt_fields(
    key_bytes: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Map<String, Value>> {
    let cipher = cipher(key_bytes)?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(XNonce::from_slice(nonce), ciphertext)
            .map_err(|_| anyhow::anyhow!("failed to decrypt secret fields"))?,
    );
    let fields = serde_json::from_slice(plaintext.as_ref())
        .context("failed to parse decrypted secret fields")?;
    Ok(fields)
}

pub fn generate_vault_key() -> Result<[u8; VAULT_KEY_LEN]> {
    let mut key = [0u8; VAULT_KEY_LEN];
    getrandom::getrandom(&mut key).map_err(|_| anyhow::anyhow!("failed to generate vault key"))?;
    Ok(key)
}

fn random_nonce() -> Result<[u8; NONCE_LEN]> {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|_| anyhow::anyhow!("failed to generate nonce"))?;
    Ok(nonce)
}

fn cipher(key_bytes: &[u8]) -> Result<XChaCha20Poly1305> {
    let key = Key::from_slice(key_bytes);
    Ok(XChaCha20Poly1305::new(key))
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Map, Value};

    use super::{decrypt_fields, encrypt_fields, generate_vault_key};

    #[test]
    fn round_trips_encrypted_fields() {
        let key = generate_vault_key().unwrap();
        let mut fields = Map::<String, Value>::new();
        fields.insert("password".into(), json!("hunter2"));
        fields.insert("username".into(), json!("alice"));

        let (nonce, ciphertext) = encrypt_fields(&key, &fields).unwrap();
        let decrypted = decrypt_fields(&key, &nonce, &ciphertext).unwrap();

        assert_eq!(decrypted, fields);
    }
}
