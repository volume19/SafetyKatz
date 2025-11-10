//! PE file format parsing
//!
//! Parses PE (Portable Executable) file structures including DOS header,
//! NT headers, section headers, and data directories.
//!
//! Structures match the Windows PE specification and are compatible with
//! the original C# implementation in Program.cs:238-601.

use crate::error::PeError;
use byteorder::{LittleEndian, ReadBytesExt};
use std::io::Cursor;
use std::mem;

/// DOS .EXE header (IMAGE_DOS_HEADER)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageDosHeader {
    pub e_magic: u16,    // Magic number ("MZ" = 0x5A4D)
    pub e_cblp: u16,     // Bytes on last page of file
    pub e_cp: u16,       // Pages in file
    pub e_crlc: u16,     // Relocations
    pub e_cparhdr: u16,  // Size of header in paragraphs
    pub e_minalloc: u16, // Minimum extra paragraphs needed
    pub e_maxalloc: u16, // Maximum extra paragraphs needed
    pub e_ss: u16,       // Initial (relative) SS value
    pub e_sp: u16,       // Initial SP value
    pub e_csum: u16,     // Checksum
    pub e_ip: u16,       // Initial IP value
    pub e_cs: u16,       // Initial (relative) CS value
    pub e_lfarlc: u16,   // File address of relocation table
    pub e_ovno: u16,     // Overlay number
    pub e_res: [u16; 4], // Reserved words
    pub e_oemid: u16,    // OEM identifier
    pub e_oeminfo: u16,  // OEM information
    pub e_res2: [u16; 10], // Reserved words
    pub e_lfanew: u32,   // File address of new exe header (PE header offset)
}

/// Data directory entry
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ImageDataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

/// COFF file header (IMAGE_FILE_HEADER)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageFileHeader {
    pub machine: u16,               // Machine type
    pub number_of_sections: u16,    // Number of sections
    pub time_date_stamp: u32,       // Time/date stamp
    pub pointer_to_symbol_table: u32, // Symbol table offset (deprecated)
    pub number_of_symbols: u32,     // Number of symbols (deprecated)
    pub size_of_optional_header: u16, // Size of optional header
    pub characteristics: u16,       // File characteristics
}

/// PE32+ (64-bit) optional header (IMAGE_OPTIONAL_HEADER64)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageOptionalHeader64 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    // Data directories follow (16 entries)
    pub export_table: ImageDataDirectory,
    pub import_table: ImageDataDirectory,
    pub resource_table: ImageDataDirectory,
    pub exception_table: ImageDataDirectory,
    pub certificate_table: ImageDataDirectory,
    pub base_relocation_table: ImageDataDirectory,
    pub debug: ImageDataDirectory,
    pub architecture: ImageDataDirectory,
    pub global_ptr: ImageDataDirectory,
    pub tls_table: ImageDataDirectory,
    pub load_config_table: ImageDataDirectory,
    pub bound_import: ImageDataDirectory,
    pub iat: ImageDataDirectory,
    pub delay_import_descriptor: ImageDataDirectory,
    pub clr_runtime_header: ImageDataDirectory,
    pub reserved: ImageDataDirectory,
}

/// Section header (IMAGE_SECTION_HEADER)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageSectionHeader {
    pub name: [u8; 8],             // Section name
    pub virtual_size: u32,          // Virtual size
    pub virtual_address: u32,       // Virtual address
    pub size_of_raw_data: u32,     // Size of raw data
    pub pointer_to_raw_data: u32,  // File pointer to raw data
    pub pointer_to_relocations: u32, // File pointer to relocations
    pub pointer_to_linenumbers: u32, // File pointer to line numbers
    pub number_of_relocations: u16, // Number of relocations
    pub number_of_linenumbers: u16, // Number of line numbers
    pub characteristics: u32,       // Section characteristics
}

impl ImageSectionHeader {
    /// Get section name as string (null-terminated)
    pub fn name_str(&self) -> Result<&str, std::str::Utf8Error> {
        let null_pos = self.name.iter().position(|&b| b == 0).unwrap_or(8);
        std::str::from_utf8(&self.name[..null_pos])
    }
}

/// Base relocation block header (IMAGE_BASE_RELOCATION)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageBaseRelocation {
    pub virtual_address: u32,
    pub size_of_block: u32,
}

/// Magic numbers for PE format
pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D; // "MZ"
pub const IMAGE_NT_SIGNATURE: u32 = 0x00004550; // "PE\0\0"
pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20b; // PE32+

/// Machine types
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664; // x64

/// Characteristics - 32-bit machine
pub const IMAGE_FILE_32BIT_MACHINE: u16 = 0x0100;

/// Represents a parsed PE image
#[derive(Debug)]
pub struct PeImage {
    pub dos_header: ImageDosHeader,
    pub file_header: ImageFileHeader,
    pub optional_header64: ImageOptionalHeader64,
    pub section_headers: Vec<ImageSectionHeader>,
    pub raw_bytes: Vec<u8>,
}

impl PeImage {
    /// Parse a PE image from bytes
    ///
    /// # Arguments
    /// - `data`: Raw PE file bytes
    ///
    /// # Returns
    /// - `Ok(PeImage)` on successful parse
    /// - `Err(PeError)` if file is invalid or unsupported
    ///
    /// # Validation
    /// - Checks DOS "MZ" signature
    /// - Checks PE "PE\0\0" signature
    /// - Verifies 64-bit PE32+ format
    /// - Validates x64 machine type
    pub fn from_bytes(data: &[u8]) -> Result<Self, PeError> {
        if data.len() < mem::size_of::<ImageDosHeader>() {
            return Err(PeError::InvalidFormat("File too small for DOS header".to_string()));
        }

        let mut cursor = Cursor::new(data);

        // Read DOS header
        let dos_header = Self::read_dos_header(&mut cursor)?;

        // Validate DOS signature
        if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
            return Err(PeError::InvalidFormat(format!(
                "Invalid DOS signature: expected 0x{:04X}, got 0x{:04X}",
                IMAGE_DOS_SIGNATURE, dos_header.e_magic
            )));
        }

        // Seek to PE header
        if dos_header.e_lfanew as usize >= data.len() {
            return Err(PeError::InvalidFormat("Invalid PE header offset".to_string()));
        }

        cursor.set_position(dos_header.e_lfanew as u64);

        // Read and validate PE signature
        let pe_signature = cursor.read_u32::<LittleEndian>()
            .map_err(|e| PeError::InvalidFormat(format!("Failed to read PE signature: {}", e)))?;

        if pe_signature != IMAGE_NT_SIGNATURE {
            return Err(PeError::InvalidFormat(format!(
                "Invalid PE signature: expected 0x{:08X}, got 0x{:08X}",
                IMAGE_NT_SIGNATURE, pe_signature
            )));
        }

        // Read COFF file header
        let file_header = Self::read_file_header(&mut cursor)?;

        // Check for 64-bit architecture
        if file_header.machine != IMAGE_FILE_MACHINE_AMD64 {
            return Err(PeError::UnsupportedArchitecture);
        }

        // Read optional header (64-bit)
        let optional_header64 = Self::read_optional_header64(&mut cursor)?;

        // Validate PE32+ magic
        if optional_header64.magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
            return Err(PeError::UnsupportedArchitecture);
        }

        // Read section headers
        let mut section_headers = Vec::with_capacity(file_header.number_of_sections as usize);
        for _ in 0..file_header.number_of_sections {
            section_headers.push(Self::read_section_header(&mut cursor)?);
        }

        Ok(PeImage {
            dos_header,
            file_header,
            optional_header64,
            section_headers,
            raw_bytes: data.to_vec(),
        })
    }

    /// Check if this is a 32-bit PE
    pub fn is_32bit(&self) -> bool {
        (self.file_header.characteristics & IMAGE_FILE_32BIT_MACHINE) != 0
    }

    // Helper methods for reading structures

    fn read_dos_header(cursor: &mut Cursor<&[u8]>) -> Result<ImageDosHeader, PeError> {
        Ok(ImageDosHeader {
            e_magic: cursor.read_u16::<LittleEndian>()?,
            e_cblp: cursor.read_u16::<LittleEndian>()?,
            e_cp: cursor.read_u16::<LittleEndian>()?,
            e_crlc: cursor.read_u16::<LittleEndian>()?,
            e_cparhdr: cursor.read_u16::<LittleEndian>()?,
            e_minalloc: cursor.read_u16::<LittleEndian>()?,
            e_maxalloc: cursor.read_u16::<LittleEndian>()?,
            e_ss: cursor.read_u16::<LittleEndian>()?,
            e_sp: cursor.read_u16::<LittleEndian>()?,
            e_csum: cursor.read_u16::<LittleEndian>()?,
            e_ip: cursor.read_u16::<LittleEndian>()?,
            e_cs: cursor.read_u16::<LittleEndian>()?,
            e_lfarlc: cursor.read_u16::<LittleEndian>()?,
            e_ovno: cursor.read_u16::<LittleEndian>()?,
            e_res: [
                cursor.read_u16::<LittleEndian>()?,
                cursor.read_u16::<LittleEndian>()?,
                cursor.read_u16::<LittleEndian>()?,
                cursor.read_u16::<LittleEndian>()?,
            ],
            e_oemid: cursor.read_u16::<LittleEndian>()?,
            e_oeminfo: cursor.read_u16::<LittleEndian>()?,
            e_res2: [
                cursor.read_u16::<LittleEndian>()?,
                cursor.read_u16::<LittleEndian>()?,
                cursor.read_u16::<LittleEndian>()?,
                cursor.read_u16::<LittleEndian>()?,
                cursor.read_u16::<LittleEndian>()?,
                cursor.read_u16::<LittleEndian>()?,
                cursor.read_u16::<LittleEndian>()?,
                cursor.read_u16::<LittleEndian>()?,
                cursor.read_u16::<LittleEndian>()?,
                cursor.read_u16::<LittleEndian>()?,
            ],
            e_lfanew: cursor.read_u32::<LittleEndian>()?,
        })
    }

    fn read_file_header(cursor: &mut Cursor<&[u8]>) -> Result<ImageFileHeader, PeError> {
        Ok(ImageFileHeader {
            machine: cursor.read_u16::<LittleEndian>()?,
            number_of_sections: cursor.read_u16::<LittleEndian>()?,
            time_date_stamp: cursor.read_u32::<LittleEndian>()?,
            pointer_to_symbol_table: cursor.read_u32::<LittleEndian>()?,
            number_of_symbols: cursor.read_u32::<LittleEndian>()?,
            size_of_optional_header: cursor.read_u16::<LittleEndian>()?,
            characteristics: cursor.read_u16::<LittleEndian>()?,
        })
    }

    fn read_optional_header64(cursor: &mut Cursor<&[u8]>) -> Result<ImageOptionalHeader64, PeError> {
        let magic = cursor.read_u16::<LittleEndian>()?;

        Ok(ImageOptionalHeader64 {
            magic,
            major_linker_version: cursor.read_u8()?,
            minor_linker_version: cursor.read_u8()?,
            size_of_code: cursor.read_u32::<LittleEndian>()?,
            size_of_initialized_data: cursor.read_u32::<LittleEndian>()?,
            size_of_uninitialized_data: cursor.read_u32::<LittleEndian>()?,
            address_of_entry_point: cursor.read_u32::<LittleEndian>()?,
            base_of_code: cursor.read_u32::<LittleEndian>()?,
            image_base: cursor.read_u64::<LittleEndian>()?,
            section_alignment: cursor.read_u32::<LittleEndian>()?,
            file_alignment: cursor.read_u32::<LittleEndian>()?,
            major_operating_system_version: cursor.read_u16::<LittleEndian>()?,
            minor_operating_system_version: cursor.read_u16::<LittleEndian>()?,
            major_image_version: cursor.read_u16::<LittleEndian>()?,
            minor_image_version: cursor.read_u16::<LittleEndian>()?,
            major_subsystem_version: cursor.read_u16::<LittleEndian>()?,
            minor_subsystem_version: cursor.read_u16::<LittleEndian>()?,
            win32_version_value: cursor.read_u32::<LittleEndian>()?,
            size_of_image: cursor.read_u32::<LittleEndian>()?,
            size_of_headers: cursor.read_u32::<LittleEndian>()?,
            check_sum: cursor.read_u32::<LittleEndian>()?,
            subsystem: cursor.read_u16::<LittleEndian>()?,
            dll_characteristics: cursor.read_u16::<LittleEndian>()?,
            size_of_stack_reserve: cursor.read_u64::<LittleEndian>()?,
            size_of_stack_commit: cursor.read_u64::<LittleEndian>()?,
            size_of_heap_reserve: cursor.read_u64::<LittleEndian>()?,
            size_of_heap_commit: cursor.read_u64::<LittleEndian>()?,
            loader_flags: cursor.read_u32::<LittleEndian>()?,
            number_of_rva_and_sizes: cursor.read_u32::<LittleEndian>()?,
            export_table: Self::read_data_directory(cursor)?,
            import_table: Self::read_data_directory(cursor)?,
            resource_table: Self::read_data_directory(cursor)?,
            exception_table: Self::read_data_directory(cursor)?,
            certificate_table: Self::read_data_directory(cursor)?,
            base_relocation_table: Self::read_data_directory(cursor)?,
            debug: Self::read_data_directory(cursor)?,
            architecture: Self::read_data_directory(cursor)?,
            global_ptr: Self::read_data_directory(cursor)?,
            tls_table: Self::read_data_directory(cursor)?,
            load_config_table: Self::read_data_directory(cursor)?,
            bound_import: Self::read_data_directory(cursor)?,
            iat: Self::read_data_directory(cursor)?,
            delay_import_descriptor: Self::read_data_directory(cursor)?,
            clr_runtime_header: Self::read_data_directory(cursor)?,
            reserved: Self::read_data_directory(cursor)?,
        })
    }

    fn read_data_directory(cursor: &mut Cursor<&[u8]>) -> Result<ImageDataDirectory, PeError> {
        Ok(ImageDataDirectory {
            virtual_address: cursor.read_u32::<LittleEndian>()?,
            size: cursor.read_u32::<LittleEndian>()?,
        })
    }

    fn read_section_header(cursor: &mut Cursor<&[u8]>) -> Result<ImageSectionHeader, PeError> {
        let mut name = [0u8; 8];
        cursor.read_exact(&mut name)?;

        Ok(ImageSectionHeader {
            name,
            virtual_size: cursor.read_u32::<LittleEndian>()?,
            virtual_address: cursor.read_u32::<LittleEndian>()?,
            size_of_raw_data: cursor.read_u32::<LittleEndian>()?,
            pointer_to_raw_data: cursor.read_u32::<LittleEndian>()?,
            pointer_to_relocations: cursor.read_u32::<LittleEndian>()?,
            pointer_to_linenumbers: cursor.read_u32::<LittleEndian>()?,
            number_of_relocations: cursor.read_u16::<LittleEndian>()?,
            number_of_linenumbers: cursor.read_u16::<LittleEndian>()?,
            characteristics: cursor.read_u32::<LittleEndian>()?,
        })
    }
}

// Implement From<std::io::Error> for PeError to simplify error handling
impl From<std::io::Error> for PeError {
    fn from(error: std::io::Error) -> Self {
        PeError::InvalidFormat(format!("IO error: {}", error))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dos_header_size() {
        assert_eq!(mem::size_of::<ImageDosHeader>(), 64);
    }

    #[test]
    fn test_file_header_size() {
        assert_eq!(mem::size_of::<ImageFileHeader>(), 20);
    }

    #[test]
    fn test_data_directory_size() {
        assert_eq!(mem::size_of::<ImageDataDirectory>(), 8);
    }

    #[test]
    fn test_section_header_size() {
        assert_eq!(mem::size_of::<ImageSectionHeader>(), 40);
    }

    #[test]
    fn test_parse_invalid_too_small() {
        let data = vec![0u8; 10];
        let result = PeImage::from_bytes(&data);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PeError::InvalidFormat(_)));
    }

    #[test]
    fn test_parse_invalid_dos_signature() {
        let mut data = vec![0u8; 64];
        // Invalid DOS signature (not "MZ")
        data[0] = 0x00;
        data[1] = 0x00;
        let result = PeImage::from_bytes(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_section_name_str() {
        let mut section = ImageSectionHeader {
            name: [0; 8],
            virtual_size: 0,
            virtual_address: 0,
            size_of_raw_data: 0,
            pointer_to_raw_data: 0,
            pointer_to_relocations: 0,
            pointer_to_linenumbers: 0,
            number_of_relocations: 0,
            number_of_linenumbers: 0,
            characteristics: 0,
        };

        // Test with ".text\0\0\0"
        section.name = [b'.', b't', b'e', b'x', b't', 0, 0, 0];
        assert_eq!(section.name_str().unwrap(), ".text");
    }
}
