//! Windows privilege checking module
//!
//! Provides functionality to check if the current process is running with
//! administrative privileges (high integrity level).

use crate::error::PrivilegeError;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{
    GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Check if the current process is running with administrative privileges
///
/// This function checks if the process token has elevated privileges,
/// which is required for operations like dumping LSASS memory.
///
/// Equivalent to C#'s `WindowsPrincipal.IsInRole(WindowsBuiltInRole.Administrator)`
///
/// # Returns
/// - `Ok(true)` if running as administrator
/// - `Ok(false)` if running as normal user
/// - `Err(PrivilegeError)` if the check fails
///
/// # Example
/// ```no_run
/// use safety_katz_lib::is_high_integrity;
///
/// match is_high_integrity() {
///     Ok(true) => println!("Running as admin"),
///     Ok(false) => println!("Not admin"),
///     Err(e) => eprintln!("Error: {}", e),
/// }
/// ```
pub fn is_high_integrity() -> Result<bool, PrivilegeError> {
    unsafe {
        // Get handle to current process
        let process_handle = GetCurrentProcess();

        // Open process token with query access
        let mut token_handle = HANDLE::default();
        let result = OpenProcessToken(process_handle, TOKEN_QUERY, &mut token_handle);

        if result.is_err() {
            return Err(PrivilegeError::TokenAccessFailed);
        }

        // Ensure token handle is closed on scope exit
        let _token_guard = TokenHandleGuard(token_handle);

        // Query token elevation information
        let mut elevation = TOKEN_ELEVATION::default();
        let mut return_length: u32 = 0;

        let result = GetTokenInformation(
            token_handle,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut return_length,
        );

        if result.is_err() {
            return Err(PrivilegeError::ElevationCheckFailed);
        }

        // TOKEN_ELEVATION.TokenIsElevated is non-zero if elevated
        Ok(elevation.TokenIsElevated != 0)
    }
}

/// RAII guard for token handle cleanup
struct TokenHandleGuard(HANDLE);

impl Drop for TokenHandleGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_high_integrity_returns_result() {
        // This test just verifies the function returns a Result
        // Actual admin status depends on how the test is run
        let result = is_high_integrity();
        assert!(result.is_ok(), "Function should return Ok on Windows");
    }

    #[test]
    fn test_is_high_integrity_returns_bool() {
        // Verify we get a boolean value
        if let Ok(is_elevated) = is_high_integrity() {
            // is_elevated should be true or false
            assert!(is_elevated == true || is_elevated == false);
        }
    }
}
