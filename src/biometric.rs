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
    use windows::Security::Credentials::UI::{
        UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
    };
    use windows::core::HSTRING;

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
// Unsupported platforms — compile-time stub
// ---------------------------------------------------------------------------

#[cfg(not(any(target_os = "macos", windows)))]
mod platform {
    use anyhow::{anyhow, Result};

    pub fn authenticate(_reason: &str) -> Result<()> {
        Err(anyhow!(
            "biometric authentication is not supported on this platform"
        ))
    }
}
