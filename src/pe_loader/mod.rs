//! PE (Portable Executable) file parsing and loading module
//!
//! This module handles parsing PE file structures and loading them into
//! memory for execution.

pub mod parser;
pub mod loader;

pub use parser::PeImage;
pub use loader::load_and_execute;
