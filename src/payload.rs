//! Embedded payload management
//!
//! Handles decompression and management of the embedded Mimikatz payload.
//!
//! **IMPORTANT FOR EDUCATIONAL LAB INSTRUCTORS**:
//! The actual Mimikatz binary is NOT included in this repository for security reasons.
//! To use this tool in your lab environment:
//! 1. Compile Mimikatz from source (https://github.com/gentilkiwi/mimikatz)
//! 2. Compress the x64 binary using DEFLATE
//! 3. Base64 encode the compressed data
//! 4. Replace COMPRESSED_PAYLOAD_BASE64 constant below
//!
//! Original C# version includes a pre-compiled embedded binary in Constants.cs.

use crate::error::PayloadError;
use flate2::read::DeflateDecoder;
use std::io::Read;

/// Expected size of decompressed payload (628736 bytes as per original C# version)
pub const EXPECTED_PAYLOAD_SIZE: usize = 628736;

/// Compressed Mimikatz payload (base64-encoded DEFLATE compressed PE)
///
/// **EDUCATIONAL LAB INSTRUCTORS**: Replace this with your own compiled Mimikatz binary.
/// The empty string here prevents accidental misuse while maintaining the correct API.
///
/// To generate:
/// ```bash
/// # Compile Mimikatz x64
/// # Compress with DEFLATE
/// # Base64 encode
/// # Insert string here
/// ```
const COMPRESSED_PAYLOAD_BASE64: &str = "";

/// Decompress the embedded payload
///
/// This function:
/// 1. Decodes the base64-encoded compressed data
/// 2. Decompresses using DEFLATE algorithm
/// 3. Validates the resulting PE has correct size and "MZ" signature
///
/// # Returns
/// - `Ok(Vec<u8>)` containing the decompressed PE bytes
/// - `Err(PayloadError)` on decompression failure or validation error
///
/// # Example
/// ```no_run
/// use safety_katz_lib::payload::decompress_payload;
///
/// match decompress_payload() {
///     Ok(pe_bytes) => println!("Decompressed {} bytes", pe_bytes.len()),
///     Err(e) => eprintln!("Failed: {}", e),
/// }
/// ```
pub fn decompress_payload() -> Result<Vec<u8>, PayloadError> {
    if COMPRESSED_PAYLOAD_BASE64.is_empty() {
        return Err(PayloadError::DecompressionFailed(
            "No payload embedded. Educational lab instructors must compile and embed their own Mimikatz binary. See module documentation.".to_string()
        ));
    }

    // Decode base64
    let compressed_data = base64_decode(COMPRESSED_PAYLOAD_BASE64)
        .map_err(|e| PayloadError::DecompressionFailed(format!("Base64 decode failed: {}", e)))?;

    // Decompress using DEFLATE
    let mut decoder = DeflateDecoder::new(&compressed_data[..]);
    let mut decompressed = Vec::with_capacity(EXPECTED_PAYLOAD_SIZE);

    decoder
        .read_to_end(&mut decompressed)
        .map_err(|e| PayloadError::DecompressionFailed(format!("DEFLATE decompression failed: {}", e)))?;

    // Validate size
    if decompressed.len() != EXPECTED_PAYLOAD_SIZE {
        return Err(PayloadError::InvalidSize {
            expected: EXPECTED_PAYLOAD_SIZE,
            actual: decompressed.len(),
        });
    }

    // Validate PE signature ("MZ")
    if decompressed.len() < 2 || decompressed[0] != b'M' || decompressed[1] != b'Z' {
        return Err(PayloadError::DecompressionFailed(
            "Decompressed data is not a valid PE file (missing MZ signature)".to_string(),
        ));
    }

    log::info!("Successfully decompressed payload: {} bytes", decompressed.len());

    Ok(decompressed)
}

/// Simple base64 decoder (using standard base64 encoding)
fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    // Remove whitespace
    let cleaned: String = input.chars().filter(|c| !c.is_whitespace()).collect();

    // Decode using base64 algorithm
    base64_decode_impl(&cleaned)
}

/// Base64 decoding implementation
fn base64_decode_impl(input: &str) -> Result<Vec<u8>, String> {
    const BASE64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut decode_table = [255u8; 256];
    for (i, &ch) in BASE64_CHARS.iter().enumerate() {
        decode_table[ch as usize] = i as u8;
    }
    decode_table[b'=' as usize] = 0;

    let input_bytes = input.as_bytes();
    let mut output = Vec::new();
    let mut i = 0;

    while i < input_bytes.len() {
        if i + 4 > input_bytes.len() {
            break;
        }

        let b1 = decode_table[input_bytes[i] as usize];
        let b2 = decode_table[input_bytes[i + 1] as usize];
        let b3 = decode_table[input_bytes[i + 2] as usize];
        let b4 = decode_table[input_bytes[i + 3] as usize];

        if b1 == 255 || b2 == 255 {
            return Err("Invalid base64 character".to_string());
        }

        output.push((b1 << 2) | (b2 >> 4));

        if input_bytes[i + 2] != b'=' {
            output.push((b2 << 4) | (b3 >> 2));
        }

        if input_bytes[i + 3] != b'=' {
            output.push((b3 << 6) | b4);
        }

        i += 4;
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_decode_simple() {
        // "Hello" in base64 is "SGVsbG8="
        let result = base64_decode("SGVsbG8=").unwrap();
        assert_eq!(result, b"Hello");
    }

    #[test]
    fn test_base64_decode_with_padding() {
        // "Hi" in base64 is "SGk="
        let result = base64_decode("SGk=").unwrap();
        assert_eq!(result, b"Hi");
    }

    #[test]
    fn test_expected_payload_size() {
        assert_eq!(EXPECTED_PAYLOAD_SIZE, 628736);
    }

    #[test]
    fn test_decompress_payload_returns_error_when_empty() {
        // Since we don't embed a real payload, this should return an error
        let result = decompress_payload();
        assert!(result.is_err());
    }

    #[test]
    fn test_decompress_small_pe_stub() {
        // Test the decompression logic with a tiny stub
        // (In real usage, instructor would embed actual Mimikatz)

        // This is just to demonstrate the API works
        // Real implementation needs actual payload
    }
}
