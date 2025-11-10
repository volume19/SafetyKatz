//! Error types for SafetyKatz

use thiserror::Error;

/// Main error type for SafetyKatz operations
#[derive(Error, Debug)]
pub enum SafetyKatzError {
    #[error("Privilege error: {0}")]
    Privilege(#[from] PrivilegeError),

    #[error("Minidump error: {0}")]
    Minidump(#[from] MinidumpError),

    #[error("PE loader error: {0}")]
    PeLoader(#[from] PeError),

    #[error("Payload error: {0}")]
    Payload(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Errors related to privilege checking
#[derive(Error, Debug)]
pub enum PrivilegeError {
    #[error("Failed to get current token")]
    TokenAccessFailed,

    #[error("Failed to check token elevation")]
    ElevationCheckFailed,

    #[error("Windows API error: {0}")]
    WindowsApi(String),
}

/// Errors related to minidump operations
#[derive(Error, Debug)]
pub enum MinidumpError {
    #[error("Process not found: {0}")]
    ProcessNotFound(String),

    #[error("Access denied - requires administrative privileges")]
    AccessDenied,

    #[error("Failed to create dump file: {0}")]
    FileCreationFailed(String),

    #[error("MiniDumpWriteDump API failed: {0}")]
    ApiError(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Errors related to PE parsing and loading
#[derive(Error, Debug)]
pub enum PeError {
    #[error("Invalid PE format: {0}")]
    InvalidFormat(String),

    #[error("Unsupported architecture (expected x64)")]
    UnsupportedArchitecture,

    #[error("Malformed header: {0}")]
    MalformedHeader(String),

    #[error("Memory allocation failed")]
    AllocationFailed,

    #[error("Relocation processing failed: {0}")]
    RelocationFailed(String),

    #[error("Import resolution failed: {0}")]
    ImportResolutionFailed(String),

    #[error("Execution failed: {0}")]
    ExecutionFailed(String),
}

/// Errors related to payload operations
#[derive(Error, Debug)]
pub enum PayloadError {
    #[error("Decompression failed: {0}")]
    DecompressionFailed(String),

    #[error("Invalid payload size: expected {expected}, got {actual}")]
    InvalidSize { expected: usize, actual: usize },
}
