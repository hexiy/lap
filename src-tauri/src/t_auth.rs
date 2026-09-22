//! Session-scoped unlock state for hidden photos.
//!
//! The unlock flag is in-memory only: the app re-locks on every start, and
//! `thumb://`/`preview://` protocol handlers consult `is_unlocked()` before
//! serving media for hidden files.
//!
//! Platform auth order: OS-level verification first (Touch ID / Windows
//! Hello), falling back to an app PIN stored as `hidden_pin.json` inside the
//! fork's own app-data directory. The PIN file never lives in the shared
//! library config so the official build ignores it entirely.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

static HIDDEN_UNLOCKED: AtomicBool = AtomicBool::new(false);

pub fn is_unlocked() -> bool {
    HIDDEN_UNLOCKED.load(Ordering::SeqCst)
}

fn unlock() {
    HIDDEN_UNLOCKED.store(true, Ordering::SeqCst);
}

const PIN_ITERATIONS: u32 = 100_000;
const PIN_SALT_LEN: usize = 16;
const PIN_MIN_LEN: usize = 4;
const PIN_MAX_LEN: usize = 64;

#[derive(Debug, Serialize, Deserialize)]
struct PinRecord {
    salt: String,
    hash: String,
    iterations: u32,
}

fn pin_file_path() -> Result<PathBuf, String> {
    crate::t_config::get_app_data_dir().map(|dir| dir.join("hidden_pin.json"))
}

fn pin_record() -> Result<Option<PinRecord>, String> {
    let path = pin_file_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let raw =
        fs::read_to_string(&path).map_err(|e| format!("Failed to read hidden PIN file: {}", e))?;
    serde_json::from_str(&raw)
        .map(Some)
        .map_err(|e| format!("Failed to parse hidden PIN file: {}", e))
}

fn pin_configured() -> bool {
    matches!(pin_record(), Ok(Some(_)))
}

fn hash_pin(salt: &[u8], pin: &str, iterations: u32) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(pin.as_bytes());
    let mut digest = hasher.finalize().to_vec();
    for _ in 1..iterations {
        let mut hasher = Sha256::new();
        hasher.update(&digest);
        digest = hasher.finalize().to_vec();
    }
    digest
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

enum OsAuth {
    Ok,
    Unavailable,
    Cancelled,
}

#[cfg(target_os = "macos")]
fn try_os_auth() -> Result<OsAuth, String> {
    macos_auth::evaluate()
}

#[cfg(target_os = "windows")]
fn try_os_auth() -> Result<OsAuth, String> {
    use windows::Security::Credentials::UI::{
        UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
    };
    use windows::core::HSTRING;

    let availability = UserConsentVerifier::CheckAvailabilityAsync()
        .and_then(|op| op.get())
        .map_err(|e| format!("Windows Hello availability check failed: {}", e))?;
    if availability != UserConsentVerifierAvailability::Available {
        return Ok(OsAuth::Unavailable);
    }

    let result =
        UserConsentVerifier::RequestVerificationAsync(&HSTRING::from("Unlock hidden photos"))
            .and_then(|op| op.get())
            .map_err(|e| format!("Windows Hello verification failed: {}", e))?;

    Ok(match result {
        UserConsentVerificationResult::Verified => OsAuth::Ok,
        UserConsentVerificationResult::DeviceNotPresent
        | UserConsentVerificationResult::NotConfiguredForUser => OsAuth::Unavailable,
        _ => OsAuth::Cancelled,
    })
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn try_os_auth() -> Result<OsAuth, String> {
    Ok(OsAuth::Unavailable)
}

#[cfg(target_os = "macos")]
mod macos_auth {
    use super::OsAuth;
    use block2::RcBlock;
    use objc2::runtime::{AnyObject, Bool};
    use objc2::{class, msg_send};
    use objc2_foundation::NSString;
    use std::sync::mpsc;

    // class!(LAContext) resolves via the ObjC runtime only when the framework
    // is loaded; linking it here guarantees that.
    #[link(name = "LocalAuthentication", kind = "framework")]
    unsafe extern "C" {}

    // LAPolicyDeviceOwnerAuthentication — biometrics first, automatic
    // fallback to the system password.
    const POLICY_DEVICE_OWNER_AUTHENTICATION: i64 = 2;

    pub fn evaluate() -> Result<OsAuth, String> {
        unsafe {
            let context: *mut AnyObject = msg_send![class!(LAContext), new];
            if context.is_null() {
                return Err("LocalAuthentication is unavailable".to_string());
            }

            let mut error: *mut AnyObject = std::ptr::null_mut();
            let can_evaluate: Bool = msg_send![
                context,
                canEvaluatePolicy: POLICY_DEVICE_OWNER_AUTHENTICATION,
                error: &mut error
            ];
            if !can_evaluate.as_bool() {
                return Ok(OsAuth::Unavailable);
            }

            let reason = NSString::from_str("Unlock hidden photos");
            let (tx, rx) = mpsc::channel();
            let block = RcBlock::new(move |success: Bool, _error: *mut AnyObject| {
                let _ = tx.send(success.as_bool());
            });
            let _: () = msg_send![
                context,
                evaluatePolicy: POLICY_DEVICE_OWNER_AUTHENTICATION,
                localizedReason: &*reason,
                reply: &*block
            ];

            // The reply block fires on LA's private queue, so waiting here is
            // safe on any background thread.
            match rx.recv() {
                Ok(true) => Ok(OsAuth::Ok),
                _ => Ok(OsAuth::Cancelled),
            }
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlockOutcome {
    /// "unlocked" | "pin_required" | "cancelled"
    pub status: &'static str,
    pub pin_configured: bool,
}

#[tauri::command]
pub fn hidden_unlock_state() -> bool {
    is_unlocked()
}

#[tauri::command]
pub fn lock_hidden() {
    HIDDEN_UNLOCKED.store(false, Ordering::SeqCst);
}

#[tauri::command]
pub fn hidden_pin_status() -> bool {
    pin_configured()
}

/// Try OS-level auth first; when unavailable the caller should fall back to
/// the PIN dialog (`hidden_pin_status` / `set_hidden_pin` /
/// `verify_hidden_pin`).
#[tauri::command]
pub async fn unlock_hidden() -> Result<UnlockOutcome, String> {
    if is_unlocked() {
        return Ok(UnlockOutcome {
            status: "unlocked",
            pin_configured: pin_configured(),
        });
    }
    let status = match try_os_auth()? {
        OsAuth::Ok => {
            unlock();
            "unlocked"
        }
        OsAuth::Unavailable => "pin_required",
        OsAuth::Cancelled => "cancelled",
    };
    Ok(UnlockOutcome {
        status,
        pin_configured: pin_configured(),
    })
}

/// Create or replace the app PIN. Once a PIN exists it can only be changed
/// while the session is unlocked.
#[tauri::command]
pub fn set_hidden_pin(pin: String) -> Result<(), String> {
    if pin_configured() && !is_unlocked() {
        return Err("Unlock hidden photos before changing the PIN".to_string());
    }
    if pin.len() < PIN_MIN_LEN || pin.len() > PIN_MAX_LEN {
        return Err(format!(
            "PIN must be between {} and {} characters",
            PIN_MIN_LEN, PIN_MAX_LEN
        ));
    }

    let mut salt = [0u8; PIN_SALT_LEN];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut salt);
    let digest = hash_pin(&salt, &pin, PIN_ITERATIONS);

    let record = PinRecord {
        salt: B64.encode(salt),
        hash: B64.encode(digest),
        iterations: PIN_ITERATIONS,
    };
    let path = pin_file_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create app data directory: {}", e))?;
    }
    let json = serde_json::to_string(&record).map_err(|e| e.to_string())?;
    fs::write(&path, json).map_err(|e| format!("Failed to write hidden PIN file: {}", e))?;
    // Setting the first PIN only happens inside the unlock flow (when OS auth
    // is unavailable), so a successful write also unlocks the session.
    unlock();
    Ok(())
}

#[tauri::command]
pub fn verify_hidden_pin(pin: String) -> Result<bool, String> {
    let Some(record) = pin_record()? else {
        return Err("No hidden-photos PIN is configured".to_string());
    };
    let salt = B64
        .decode(&record.salt)
        .map_err(|e| format!("Corrupt hidden PIN salt: {}", e))?;
    let expected = B64
        .decode(&record.hash)
        .map_err(|e| format!("Corrupt hidden PIN hash: {}", e))?;
    let iterations = record.iterations.max(1);
    let ok = constant_time_eq(&hash_pin(&salt, &pin, iterations), &expected);
    if ok {
        unlock();
    }
    Ok(ok)
}
