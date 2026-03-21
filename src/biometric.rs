use std::sync::mpsc;

use anyhow::{anyhow, Result};
use block2::RcBlock;
use objc2::runtime::Bool;
use objc2::AnyThread;
use objc2_foundation::{NSError, NSString};
use objc2_local_authentication::{LAContext, LAError, LAPolicy};

pub fn authenticate(reason: &str) -> Result<()> {
    let reason = reason.trim();
    if reason.is_empty() {
        return Err(anyhow!("biometric authentication reason must not be empty"));
    }

    let context = unsafe { LAContext::init(LAContext::alloc()) };
    let policy = LAPolicy::DeviceOwnerAuthenticationWithBiometrics;
    unsafe {
        context
            .canEvaluatePolicy_error(policy)
            .map_err(|error| anyhow!(describe_error(&error)))?;
    }

    let reason = NSString::from_str(reason);
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
        context.evaluatePolicy_localizedReason_reply(policy, &reason, &reply);
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
        LAError::UserFallback => "biometric authentication fell back to another method".to_string(),
        LAError::SystemCancel => "biometric authentication was canceled by the system".to_string(),
        LAError::PasscodeNotSet => {
            "Touch ID is unavailable because no device passcode is set".to_string()
        }
        LAError::BiometryNotAvailable => "Touch ID is not available on this Mac".to_string(),
        LAError::BiometryNotEnrolled => "Touch ID is not configured on this Mac".to_string(),
        LAError::BiometryLockout => {
            "Touch ID is locked; unlock it with your macOS password first".to_string()
        }
        LAError::AppCancel => "biometric authentication was canceled by the app".to_string(),
        LAError::InvalidContext => "biometric authentication context became invalid".to_string(),
        other => {
            let description = error.localizedDescription().to_string();
            format!("{description} (LAError {})", other.0)
        }
    }
}
