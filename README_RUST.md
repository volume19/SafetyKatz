# SafetyKatz (Rust Port)

⚠️ **FOR EDUCATIONAL LAB ENVIRONMENTS ONLY** ⚠️

This is a Rust port of [SafetyKatz](https://github.com/GhostPack/SafetyKatz) for educational security testing in controlled lab environments.

## Original Project

SafetyKatz is a combination of:
- [@gentilkiwi](https://twitter.com/gentilkiwi)'s [Mimikatz](https://github.com/gentilkiwi/mimikatz/)
- [@subtee](https://twitter.com/subtee)'s .NET PE Loader

Original C# version by [@harmj0y](https://twitter.com/harmj0y) (Will Schroeder).

## Purpose

This Rust port is designed for:
- **Educational lab environments** teaching offensive security techniques
- **Authorized penetration testing** with documented engagement scope
- **Security research** in controlled environments
- **Red team/blue team exercises** with proper authorization

## What It Does

1. Uses `MiniDumpWriteDump` Win32 API to create a minidump of LSASS process
2. Loads a customized Mimikatz PE from memory
3. Executes credential extraction on the minidump
4. Cleans up artifacts

## Build Instructions

### Prerequisites

- Rust 1.70+ with `x86_64-pc-windows-msvc` target
- Windows 10/11 or Windows Server
- Administrative privileges (for execution)

### Compilation

```bash
# Debug build
cargo build

# Release build (optimized)
cargo build --release --target x86_64-pc-windows-msvc
```

### Testing

```bash
# Unit tests (no admin required)
cargo test --lib

# Integration tests (requires Windows + admin)
# Run in elevated PowerShell/cmd
cargo test --test integration_tests
```

## Usage

⚠️ **Must be run as Administrator (elevated privileges required)**

```bash
# Default: dump lsass.exe and execute
safety_katz.exe

# Specify custom PID
safety_katz.exe --pid 1234

# Custom output path for minidump
safety_katz.exe --output-path C:\Temp\custom.dmp

# Verbose logging
safety_katz.exe --verbose
```

## Security & Ethical Guidelines

### ✅ AUTHORIZED USE ONLY

- Educational lab environments
- Documented penetration testing engagements
- CTF competitions
- Security research with institutional approval

### ❌ PROHIBITED USE

- Unauthorized access to systems
- Malicious credential theft
- Deployment without proper authorization
- Any illegal activity

## Improvements Over C# Version

- **Type safety**: Rust's ownership system prevents memory safety bugs
- **Error handling**: Explicit `Result` types instead of exceptions
- **Auditability**: Structured logging with timestamps
- **Testing**: Comprehensive unit and integration tests
- **Security**: No unsafe code where avoidable, documented safety invariants

## License

BSD 3-Clause License (maintaining original SafetyKatz license)

## Attribution

- Original SafetyKatz: Will Schroeder (@harmj0y)
- PE Loader: @subtee
- Mimikatz: Benjamin Delpy (@gentilkiwi)
- Rust port: [Educational Lab Project]

## Disclaimer

This tool is provided for educational purposes only. Users are solely responsible for ensuring they have proper authorization before use. The authors assume no liability for misuse.
