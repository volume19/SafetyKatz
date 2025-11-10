//! SafetyKatz - Educational tool for authorized security testing
//!
//! This is a Rust port of SafetyKatz for educational lab environments.
//! Original C# version by @harmj0y (Will Schroeder).
//!
//! **WARNING: This tool is for authorized security testing only.**
//! Use only in controlled lab environments with proper authorization.
//!
//! # Components
//! - `privilege`: Windows privilege checking
//! - `minidump`: LSASS process memory dumping
//! - `pe_loader`: PE file parsing and in-memory loading
//! - `payload`: Embedded payload management

#![cfg_attr(target_os = "windows", windows_subsystem = "console")]

pub mod error;

#[cfg(target_os = "windows")]
pub mod privilege;

#[cfg(target_os = "windows")]
pub mod minidump;

#[cfg(target_os = "windows")]
pub mod pe_loader;

pub mod payload;

// Re-export main types
pub use error::*;

#[cfg(target_os = "windows")]
pub use privilege::is_high_integrity;

#[cfg(target_os = "windows")]
pub use minidump::create_minidump;
