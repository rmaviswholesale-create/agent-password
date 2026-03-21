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

pub fn socket_path() -> Result<PathBuf> {
    Ok(app_dir()?.join(SOCKET_NAME))
}
