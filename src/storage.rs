use std::path::Path;

use anyhow::{anyhow, Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::crypto;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretMetadata {
    pub id: String,
    pub kind: String,
    pub title: String,
    pub service: String,
    pub username: String,
    pub tags: Vec<String>,
    pub updated_at: String,
}

#[derive(Clone, Debug)]
pub struct SecretInput {
    pub id: String,
    pub kind: String,
    pub title: Option<String>,
    pub service: Option<String>,
    pub username: Option<String>,
    pub tags: Vec<String>,
    pub fields: Map<String, Value>,
}

pub fn initialize(database_path: &Path) -> Result<()> {
    if let Some(parent) = database_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let connection = Connection::open(database_path)
        .with_context(|| format!("failed to open {}", database_path.display()))?;
    create_schema(&connection)
}

pub fn upsert_secret(
    database_path: &Path,
    input: SecretInput,
    key: &[u8],
) -> Result<SecretMetadata> {
    validate_secret_id(&input.id)?;

    let metadata = build_metadata(input)?;
    let (nonce, ciphertext) = crypto::encrypt_fields(key, &metadata.1)?;
    let tags_json =
        serde_json::to_string(&metadata.0.tags).context("failed to serialize secret tags")?;

    let connection = open(database_path)?;
    connection
        .execute(
            r#"
            INSERT INTO secrets (id, kind, title, service, username, tags_json, updated_at, nonce, ciphertext)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            ON CONFLICT(id) DO UPDATE SET
                kind = excluded.kind,
                title = excluded.title,
                service = excluded.service,
                username = excluded.username,
                tags_json = excluded.tags_json,
                updated_at = excluded.updated_at,
                nonce = excluded.nonce,
                ciphertext = excluded.ciphertext
            "#,
            params![
                metadata.0.id,
                metadata.0.kind,
                metadata.0.title,
                metadata.0.service,
                metadata.0.username,
                tags_json,
                metadata.0.updated_at,
                nonce,
                ciphertext
            ],
        )
        .context("failed to write secret to the vault")?;

    Ok(metadata.0)
}

pub fn delete_secret(database_path: &Path, id: &str) -> Result<()> {
    let connection = open(database_path)?;
    let changed = connection
        .execute("DELETE FROM secrets WHERE id = ?1", params![id])
        .context("failed to delete secret")?;
    if changed == 0 {
        return Err(anyhow!("secret `{id}` does not exist"));
    }
    Ok(())
}

pub fn list_secrets(database_path: &Path) -> Result<Vec<SecretMetadata>> {
    let connection = open(database_path)?;
    let mut statement = connection
        .prepare(
            "SELECT id, kind, title, service, username, tags_json, updated_at
             FROM secrets
             ORDER BY title COLLATE NOCASE, id COLLATE NOCASE",
        )
        .context("failed to prepare secret list query")?;

    let rows = statement
        .query_map([], |row| {
            Ok(SecretMetadata {
                id: row.get(0)?,
                kind: row.get(1)?,
                title: row.get(2)?,
                service: row.get(3)?,
                username: row.get(4)?,
                tags: serde_json::from_str::<Vec<String>>(&row.get::<_, String>(5)?)
                    .unwrap_or_default(),
                updated_at: row.get(6)?,
            })
        })
        .context("failed to query secret list")?;

    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("failed to decode secret metadata")
}

pub fn get_secret_metadata(database_path: &Path, id: &str) -> Result<Option<SecretMetadata>> {
    let connection = open(database_path)?;
    connection
        .query_row(
            "SELECT id, kind, title, service, username, tags_json, updated_at FROM secrets WHERE id = ?1",
            params![id],
            |row| {
                Ok(SecretMetadata {
                    id: row.get(0)?,
                    kind: row.get(1)?,
                    title: row.get(2)?,
                    service: row.get(3)?,
                    username: row.get(4)?,
                    tags: serde_json::from_str::<Vec<String>>(&row.get::<_, String>(5)?).unwrap_or_default(),
                    updated_at: row.get(6)?,
                })
            },
        )
        .optional()
        .context("failed to load secret metadata")
}

pub fn read_secret_fields(
    database_path: &Path,
    id: &str,
    key: &[u8],
) -> Result<Map<String, Value>> {
    let connection = open(database_path)?;
    let record = connection
        .query_row(
            "SELECT nonce, ciphertext FROM secrets WHERE id = ?1",
            params![id],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()
        .context("failed to load encrypted secret")?;

    let Some((nonce, ciphertext)) = record else {
        return Err(anyhow!("secret `{id}` does not exist"));
    };

    crypto::decrypt_fields(key, &nonce, &ciphertext)
}

pub fn secret_exists(database_path: &Path, id: &str) -> Result<bool> {
    Ok(get_secret_metadata(database_path, id)?.is_some())
}

fn open(database_path: &Path) -> Result<Connection> {
    let connection = Connection::open(database_path)
        .with_context(|| format!("failed to open {}", database_path.display()))?;
    create_schema(&connection)?;
    Ok(connection)
}

fn create_schema(connection: &Connection) -> Result<()> {
    connection
        .execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS secrets (
                id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                title TEXT NOT NULL,
                service TEXT NOT NULL DEFAULT '',
                username TEXT NOT NULL DEFAULT '',
                tags_json TEXT NOT NULL DEFAULT '[]',
                updated_at TEXT NOT NULL,
                nonce BLOB NOT NULL,
                ciphertext BLOB NOT NULL
            );
            "#,
        )
        .context("failed to initialize vault schema")
}

fn build_metadata(input: SecretInput) -> Result<(SecretMetadata, Map<String, Value>)> {
    let updated_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .context("failed to format timestamp")?;

    let fields = input.fields;
    let title = input.title.unwrap_or_else(|| input.id.clone());
    let service = input
        .service
        .or_else(|| {
            fields
                .get("service")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
        .or_else(|| {
            fields
                .get("url")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
        .unwrap_or_default();
    let username = input
        .username
        .or_else(|| {
            fields
                .get("username")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
        .or_else(|| {
            fields
                .get("account")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
        .unwrap_or_default();

    Ok((
        SecretMetadata {
            id: input.id,
            kind: input.kind,
            title,
            service,
            username,
            tags: dedupe_tags(input.tags),
            updated_at,
        },
        fields,
    ))
}

fn dedupe_tags(tags: Vec<String>) -> Vec<String> {
    let mut tags = tags;
    tags.sort();
    tags.dedup();
    tags
}

fn validate_secret_id(id: &str) -> Result<()> {
    if id.is_empty() {
        return Err(anyhow!("secret id must not be empty"));
    }
    if id
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    {
        Ok(())
    } else {
        Err(anyhow!(
            "secret id `{id}` is invalid; use only ASCII letters, numbers, `-`, and `_`"
        ))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Map, Value};
    use tempfile::tempdir;

    use crate::crypto::generate_vault_key;

    use super::{
        get_secret_metadata, list_secrets, read_secret_fields, upsert_secret, SecretInput,
    };

    #[test]
    fn stores_and_reads_secret() {
        let temp = tempdir().unwrap();
        let db = temp.path().join("vault.db");
        let key = generate_vault_key().unwrap();

        let mut fields = Map::<String, Value>::new();
        fields.insert("password".into(), json!("secret"));
        fields.insert("username".into(), json!("alice"));

        upsert_secret(
            &db,
            SecretInput {
                id: "github".into(),
                kind: "login".into(),
                title: Some("GitHub".into()),
                service: Some("https://github.com".into()),
                username: Some("alice".into()),
                tags: vec!["work".into()],
                fields: fields.clone(),
            },
            &key,
        )
        .unwrap();

        assert_eq!(list_secrets(&db).unwrap().len(), 1);
        assert_eq!(
            get_secret_metadata(&db, "github").unwrap().unwrap().title,
            "GitHub"
        );
        assert_eq!(read_secret_fields(&db, "github", &key).unwrap(), fields);
    }
}
