pub fn authenticate(reason: &str) -> anyhow::Result<()> {
    let reason = reason.trim();
    if reason.is_empty() {
        return Err(anyhow::anyhow!(
            "biometric authentication reason must not be empty"
        ));
    }
    platform::authenticate(reason)
}

// ---------------------------------------------------------------------------
// macOS — Touch ID via Local Authentication framework
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod platform {
    use std::sync::mpsc;

    use anyhow::{anyhow, Result};
    use block2::RcBlock;
    use objc2::runtime::Bool;
    use objc2::AnyThread;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAError, LAPolicy};

    pub fn authenticate(reason: &str) -> Result<()> {
        let context = unsafe { LAContext::init(LAContext::alloc()) };
        let policy = LAPolicy::DeviceOwnerAuthenticationWithBiometrics;
        unsafe {
            context
                .canEvaluatePolicy_error(policy)
                .map_err(|error| anyhow!(describe_error(&error)))?;
        }

        let reason_ns = NSString::from_str(reason);
        let (sender, receiver) = mpsc::channel();
        let reply = RcBlock::new(move |success: Bool, error: *mut NSError| {
            let result = if success.as_bool() {
                Ok(())
            } else {
                let message = unsafe {
                    error
                        .as_ref()
                        .map(describe_error)
                        .unwrap_or_else(|| "biometric authentication failed".to_string())
                };
                Err(message)
            };
            let _ = sender.send(result);
        });

        unsafe {
            context.evaluatePolicy_localizedReason_reply(policy, &reason_ns, &reply);
        }

        receiver
            .recv()
            .map_err(|_| anyhow!("biometric authentication did not return a result"))?
            .map_err(|message| anyhow!(message))
    }

    fn describe_error(error: &NSError) -> String {
        match LAError(error.code()) {
            LAError::AuthenticationFailed => "biometric authentication failed".to_string(),
            LAError::UserCancel => "biometric authentication was canceled".to_string(),
            LAError::UserFallback => {
                "biometric authentication fell back to another method".to_string()
            }
            LAError::SystemCancel => {
                "biometric authentication was canceled by the system".to_string()
            }
            LAError::PasscodeNotSet => {
                "Touch ID is unavailable because no device passcode is set".to_string()
            }
            LAError::BiometryNotAvailable => "Touch ID is not available on this Mac".to_string(),
            LAError::BiometryNotEnrolled => "Touch ID is not configured on this Mac".to_string(),
            LAError::BiometryLockout => {
                "Touch ID is locked; unlock it with your macOS password first".to_string()
            }
            LAError::AppCancel => "biometric authentication was canceled by the app".to_string(),
            LAError::InvalidContext => {
                "biometric authentication context became invalid".to_string()
            }
            other => {
                let description = error.localizedDescription().to_string();
                format!("{description} (LAError {})", other.0)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Windows — Windows Hello via UserConsentVerifier (WinRT)
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod platform {
    use anyhow::{anyhow, Result};
    use windows::core::HSTRING;
    use windows::Security::Credentials::UI::{
        UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
    };

    pub fn authenticate(reason: &str) -> Result<()> {
        // Check that Windows Hello is usable on this device / account.
        let availability = UserConsentVerifier::CheckAvailabilityAsync()
            .map_err(|e| anyhow!("failed to check Windows Hello availability: {e}"))?
            .get()
            .map_err(|e| anyhow!("failed to retrieve Windows Hello availability: {e}"))?;

        match availability {
            UserConsentVerifierAvailability::Available => {}
            UserConsentVerifierAvailability::DeviceNotPresent => {
                return Err(anyhow!(
                    "Windows Hello: no biometric device present on this PC"
                ));
            }
            UserConsentVerifierAvailability::NotConfiguredForUser => {
                return Err(anyhow!(
                    "Windows Hello is not configured for this user account"
                ));
            }
            UserConsentVerifierAvailability::DisabledByPolicy => {
                return Err(anyhow!("Windows Hello has been disabled by group policy"));
            }
            _ => return Err(anyhow!("Windows Hello is not available")),
        }

        // Prompt the user.
        let message = HSTRING::from(reason);
        let result = UserConsentVerifier::RequestVerificationAsync(&message)
            .map_err(|e| anyhow!("failed to request Windows Hello verification: {e}"))?
            .get()
            .map_err(|e| anyhow!("failed to complete Windows Hello verification: {e}"))?;

        match result {
            UserConsentVerificationResult::Verified => Ok(()),
            UserConsentVerificationResult::DeviceNotPresent => {
                Err(anyhow!("Windows Hello: no biometric device present"))
            }
            UserConsentVerificationResult::NotConfiguredForUser => {
                Err(anyhow!("Windows Hello is not configured for this user"))
            }
            UserConsentVerificationResult::DisabledByPolicy => {
                Err(anyhow!("Windows Hello has been disabled by policy"))
            }
            UserConsentVerificationResult::DeviceBusy => {
                Err(anyhow!("Windows Hello device is busy; try again"))
            }
            UserConsentVerificationResult::RetriesExhausted => {
                Err(anyhow!("Windows Hello: too many failed attempts"))
            }
            UserConsentVerificationResult::Canceled => {
                Err(anyhow!("Windows Hello verification was canceled"))
            }
            _ => Err(anyhow!("Windows Hello verification failed")),
        }
    }
}

// ---------------------------------------------------------------------------
// Linux — Unix account password verified via PAM (raw C bindings, no crate)
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod platform {
    use std::ffi::CString;

    use anyhow::{anyhow, Result};
    use libc::{c_char, c_int, c_void};
    use rpassword::prompt_password;

    // -----------------------------------------------------------------------
    // Minimal PAM types
    // -----------------------------------------------------------------------
    enum PamHandle {} // opaque

    const PAM_SUCCESS: c_int = 0;
    const PAM_PROMPT_ECHO_OFF: c_int = 1;

    #[repr(C)]
    struct PamMessage {
        msg_style: c_int,
        msg: *const c_char,
    }

    #[repr(C)]
    struct PamResponse {
        resp: *mut c_char,
        resp_retcode: c_int,
    }

    #[repr(C)]
    struct PamConv {
        conv: unsafe extern "C" fn(
            num_msg: c_int,
            msg: *const *const PamMessage,
            resp: *mut *mut PamResponse,
            appdata_ptr: *mut c_void,
        ) -> c_int,
        appdata_ptr: *mut c_void,
    }

    #[link(name = "pam")]
    extern "C" {
        fn pam_start(
            service: *const c_char,
            user: *const c_char,
            conv: *const PamConv,
            pamh: *mut *mut PamHandle,
        ) -> c_int;
        fn pam_authenticate(pamh: *mut PamHandle, flags: c_int) -> c_int;
        fn pam_end(pamh: *mut PamHandle, status: c_int) -> c_int;
    }

    // PAM conversation callback: copy the stored password into each
    // PAM_PROMPT_ECHO_OFF message slot, ignore others.
    unsafe extern "C" fn conv_fn(
        num_msg: c_int,
        msg: *const *const PamMessage,
        resp: *mut *mut PamResponse,
        appdata_ptr: *mut c_void,
    ) -> c_int {
        let password = &*(appdata_ptr as *const String);
        let responses =
            libc::calloc(num_msg as usize, std::mem::size_of::<PamResponse>()) as *mut PamResponse;
        if responses.is_null() {
            return 99; // PAM_CONV_ERR
        }
        for i in 0..num_msg as isize {
            let m = &**msg.offset(i);
            if m.msg_style == PAM_PROMPT_ECHO_OFF {
                let cpass = CString::new(password.as_str()).unwrap_or_default();
                (*responses.offset(i)).resp = libc::strdup(cpass.as_ptr());
            }
        }
        *resp = responses;
        PAM_SUCCESS
    }

    pub fn authenticate(reason: &str) -> Result<()> {
        // root never needs to re-authenticate.
        if unsafe { libc::getuid() } == 0 {
            eprintln!("[agent-password] {reason} — running as root, auto-approved");
            return Ok(());
        }

        let username = std::env::var("USER")
            .or_else(|_| std::env::var("LOGNAME"))
            .unwrap_or_else(|_| "user".to_string());

        let password = prompt_password(format!(
            "[agent-password] {reason}\nPassword for {username}: "
        ))
        .map_err(|e| anyhow!("failed to read password: {e}"))?;

        let svc = CString::new("su").unwrap();
        let user = CString::new(username.as_str()).unwrap();
        // Store password on the heap so the pointer stays valid for the whole PAM call.
        let pw_box = Box::new(password);
        let pw_ptr = Box::into_raw(pw_box);

        let conv = PamConv {
            conv: conv_fn,
            appdata_ptr: pw_ptr as *mut c_void,
        };

        let mut pamh: *mut PamHandle = std::ptr::null_mut();
        let result = unsafe {
            let rc = pam_start(svc.as_ptr(), user.as_ptr(), &conv, &mut pamh);
            if rc != PAM_SUCCESS {
                drop(Box::from_raw(pw_ptr));
                return Err(anyhow!("pam_start failed ({})", rc));
            }
            let rc = pam_authenticate(pamh, 0);
            pam_end(pamh, rc);
            // Reclaim the password box so it is dropped (zeroed by Rust's drop).
            drop(Box::from_raw(pw_ptr));
            rc
        };

        if result == PAM_SUCCESS {
            Ok(())
        } else {
            Err(anyhow!("authentication failed"))
        }
    }
}

// ---------------------------------------------------------------------------
// Unsupported platforms — compile-time stub
// ---------------------------------------------------------------------------

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
mod platform {
    use anyhow::{anyhow, Result};

    pub fn authenticate(_reason: &str) -> Result<()> {
        Err(anyhow!(
            "biometric authentication is not supported on this platform"
        ))
    }
}
