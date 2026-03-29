// Vault key storage — platform-specific implementations below.
//
// The key is a raw 32-byte secret.  Each backend stores and retrieves it as
// binary data without any additional encoding.

const KEYCHAIN_SERVICE: &str = "tartavull.agent-password.vault";
const KEYCHAIN_ACCOUNT: &str = "vault-key";

pub fn store_vault_key(key: &[u8]) -> anyhow::Result<()> {
    platform::store(key, &credential_service(), &credential_account())
}

pub fn load_vault_key() -> anyhow::Result<Vec<u8>> {
    platform::load(&credential_service(), &credential_account())
}

fn credential_service() -> String {
    std::env::var("PASSWORD_KEYCHAIN_SERVICE").unwrap_or_else(|_| KEYCHAIN_SERVICE.to_string())
}

fn credential_account() -> String {
    std::env::var("PASSWORD_KEYCHAIN_ACCOUNT").unwrap_or_else(|_| KEYCHAIN_ACCOUNT.to_string())
}

// ---------------------------------------------------------------------------
// macOS — Security.framework generic password keychain item
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod platform {
    use anyhow::{Context, Result};
    use security_framework::passwords::{get_generic_password, set_generic_password};

    pub fn store(key: &[u8], service: &str, account: &str) -> Result<()> {
        set_generic_password(service, account, key)
            .context("failed to store vault key in macOS Keychain")
    }

    pub fn load(service: &str, account: &str) -> Result<Vec<u8>> {
        get_generic_password(service, account)
            .context("failed to load vault key from macOS Keychain")
    }
}

// ---------------------------------------------------------------------------
// Windows — Credential Manager (generic credential, machine-scoped)
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod platform {
    use anyhow::{anyhow, Context, Result};
    use windows::Win32::Security::Credentials::{
        CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_FLAGS, CRED_PERSIST_LOCAL_MACHINE,
        CRED_TYPE_GENERIC,
    };
    use windows::core::{PCWSTR, PWSTR};

    /// Encode a string as a null-terminated UTF-16 wide string.
    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub fn store(key: &[u8], target: &str, username: &str) -> Result<()> {
        let mut target_wide = to_wide(target);
        let mut username_wide = to_wide(username);
        let mut comment_wide = to_wide("agent-password vault key");

        let cred = CREDENTIALW {
            Flags: CRED_FLAGS(0),
            Type: CRED_TYPE_GENERIC,
            TargetName: PWSTR(target_wide.as_mut_ptr()),
            Comment: PWSTR(comment_wide.as_mut_ptr()),
            LastWritten: Default::default(),
            CredentialBlobSize: key.len() as u32,
            CredentialBlob: key.as_ptr() as *mut u8,
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            AttributeCount: 0,
            Attributes: std::ptr::null_mut(),
            TargetAlias: PWSTR::null(),
            UserName: PWSTR(username_wide.as_mut_ptr()),
        };

        unsafe { CredWriteW(&cred, 0) }
            .context("failed to store vault key in Windows Credential Manager")
    }

    pub fn load(target: &str, _username: &str) -> Result<Vec<u8>> {
        let target_wide = to_wide(target);
        let mut pcred: *mut CREDENTIALW = std::ptr::null_mut();

        unsafe {
            CredReadW(
                PCWSTR(target_wide.as_ptr()),
                CRED_TYPE_GENERIC,
                0,
                &mut pcred,
            )
        }
        .context("failed to load vault key from Windows Credential Manager")?;

        if pcred.is_null() {
            return Err(anyhow!(
                "vault key not found in Windows Credential Manager"
            ));
        }

        let key = unsafe {
            let cred = &*pcred;
            std::slice::from_raw_parts(cred.CredentialBlob, cred.CredentialBlobSize as usize)
                .to_vec()
        };

        unsafe { CredFree(pcred as *const std::ffi::c_void) };
        Ok(key)
    }
}

// ---------------------------------------------------------------------------
// Linux — key file at <app-dir>/vault.key (mode 0600)
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod platform {
    use std::fs;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    use anyhow::{Context, Result};

    fn key_path(service: &str) -> std::path::PathBuf {
        crate::paths::app_dir()
            .unwrap_or_else(|_| std::path::PathBuf::from("/tmp"))
            .join(format!("{}.key", service.replace('/', "_")))
    }

    pub fn store(key: &[u8], service: &str, _account: &str) -> Result<()> {
        let path = key_path(service);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        // Write with mode 0600 so only the owning user can read it.
        fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .and_then(|mut f| {
                use std::io::Write;
                f.write_all(key)
            })
            .with_context(|| format!("failed to write key file {}", path.display()))?;
        // Force 0600 even if the file already existed with looser permissions.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to set permissions on {}", path.display()))?;
        Ok(())
    }

    pub fn load(service: &str, _account: &str) -> Result<Vec<u8>> {
        let path = key_path(service);
        fs::read(&path)
            .with_context(|| format!("failed to read key file {} — run `vault init` first", path.display()))
    }
}

// ---------------------------------------------------------------------------
// Unsupported platforms — compile-time stub
// ---------------------------------------------------------------------------

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
mod platform {
    use anyhow::{anyhow, Result};

    pub fn store(_key: &[u8], _service: &str, _account: &str) -> Result<()> {
        Err(anyhow!("credential storage is not supported on this platform"))
    }

    pub fn load(_service: &str, _account: &str) -> Result<Vec<u8>> {
        Err(anyhow!("credential storage is not supported on this platform"))
    }
}
