use std::path::PathBuf;

use anyhow::{Context, Result};

pub const APP_DIR_NAME: &str = ".agent-password";
pub const DATABASE_NAME: &str = "vault.db";
pub const SOCKET_NAME: &str = "daemon.sock";

pub fn app_dir() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("PASSWORD_APP_DIR") {
        return Ok(PathBuf::from(path));
    }
    let home = dirs::home_dir().context("failed to determine home directory")?;
    Ok(home.join(APP_DIR_NAME))
}

pub fn database_path() -> Result<PathBuf> {
    Ok(app_dir()?.join(DATABASE_NAME))
}

/// Unix-only: path of the daemon Unix-domain socket.
#[cfg(unix)]
pub fn socket_path() -> Result<PathBuf> {
    Ok(app_dir()?.join(SOCKET_NAME))
}

/// Windows-only: named-pipe path for the daemon.
///
/// The pipe name is derived from the app-state directory so that the
/// `PASSWORD_APP_DIR` environment variable also isolates the pipe in tests.
/// Format: `\\.\pipe\<dir-stem>`, e.g. `\\.\pipe\.agent-password`.
#[cfg(windows)]
pub fn pipe_name() -> Result<String> {
    // Allow full override for isolated test environments.
    if let Ok(name) = std::env::var("PASSWORD_PIPE_NAME") {
        return Ok(name);
    }
    let dir = app_dir()?;
    let stem = dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("agent-password");
    Ok(format!(r"\\.\pipe\{stem}"))
}
