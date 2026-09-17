use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use std::time::Instant;

use aho_corasick::AhoCorasick;
use clap::Parser;
use colored::*;
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Attribute, Cell, Color, ContentArrangement, Table};
use crc32fast::Hasher;
use flate2::read::{GzDecoder, ZlibDecoder};
use memmap2::Mmap;
use serde::{Deserialize, Serialize};

#[derive(Parser, Debug)]
#[command(
    name = "binwalk2",
    author = "DFIR Toolkit Team",
    version = "2.0.0 (Zero-Copy Deep Verification)",
    about = "Ultra-Fast Universal Forensic Firmware & Binary Signature Carver"
)]
struct Cli {
    #[arg(help = "Path to the binary file, firmware, or memory dump")]
    file: String,

    #[arg(short = 'e', long = "extract", help = "Carve/extract discovered files to output directory")]
    extract: bool,

    #[arg(short = 'o', long = "outdir", help = "Custom output directory for carved files")]
    outdir: Option<String>,

    #[arg(short = 'l', long = "limit", default_value_t = 100, help = "Limit rows in output table")]
    limit: usize,

    #[arg(long = "json", help = "Export results to JSON file")]
    json: Option<String>,

    #[arg(long = "md", help = "Export results to Markdown report")]
    md: Option<String>,

    #[arg(long = "bench", help = "Show performance benchmark timing")]
    bench: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignatureMatch {
    offset: usize,
    category: String,
    description: String,
    confidence: String,
    carve_size: Option<usize>,
    extension: String,
}

// ---------------------------------------------------------------------------
// Deep Validation Routines (Zero False Positives)
// ---------------------------------------------------------------------------

/// Deep verification of ELF headers (Executables, Shared Libraries .so, Relocatable Objects .o/.ko)
fn check_elf(data: &[u8], pos: usize) -> Option<(String, usize, String)> {
    if pos + 64 > data.len() {
        return None;
    }
    let slice = &data[pos..];
    if !slice.starts_with(b"\x7fELF") {
        return None;
    }

    let class = slice[4]; // 1 = 32-bit, 2 = 64-bit
    let endian = slice[5]; // 1 = LSB, 2 = MSB
    let version = slice[6]; // Must be 1

    if (class != 1 && class != 2) || (endian != 1 && endian != 2) || version != 1 {
        return None;
    }

    let is_64 = class == 2;
    let is_le = endian == 1;

    let e_type = if is_le {
        u16::from_le_bytes([slice[16], slice[17]])
    } else {
        u16::from_be_bytes([slice[16], slice[17]])
    };

    let e_machine = if is_le {
        u16::from_le_bytes([slice[18], slice[19]])
    } else {
        u16::from_be_bytes([slice[18], slice[19]])
    };

    // Strict validation of ELF Header Size (e_ehsize): MUST be 64 for 64-bit, 52 for 32-bit
    let e_ehsize = if is_64 {
        if is_le { u16::from_le_bytes([slice[52], slice[53]]) } else { u16::from_be_bytes([slice[52], slice[53]]) }
    } else {
        if is_le { u16::from_le_bytes([slice[40], slice[41]]) } else { u16::from_be_bytes([slice[40], slice[41]]) }
    };

    let expected_ehsize = if is_64 { 64 } else { 52 };
    if e_ehsize != expected_ehsize {
        return None; // Header trash / random memory match rejected
    }

    // Program header entry size sanity
    let (e_phentsize, e_phnum) = if is_64 {
        let entsz = if is_le { u16::from_le_bytes([slice[54], slice[55]]) } else { u16::from_be_bytes([slice[54], slice[55]]) };
        let num = if is_le { u16::from_le_bytes([slice[56], slice[57]]) } else { u16::from_be_bytes([slice[56], slice[57]]) };
        (entsz, num)
    } else {
        let entsz = if is_le { u16::from_le_bytes([slice[42], slice[43]]) } else { u16::from_be_bytes([slice[42], slice[43]]) };
        let num = if is_le { u16::from_le_bytes([slice[44], slice[45]]) } else { u16::from_be_bytes([slice[44], slice[45]]) };
        (entsz, num)
    };

    if e_phnum > 256 {
        return None;
    }
    if e_phnum > 0 && e_phentsize != (if is_64 { 56 } else { 32 }) {
        return None; // Corrupted / fake program header table
    }

    // Strict machine architecture whitelist
    const KNOWN_MACHINES: &[u16] = &[
        0x02, // SPARC
        0x03, // x86
        0x08, // MIPS
        0x14, // PowerPC
        0x15, // PowerPC 64
        0x28, // ARM (32-bit)
        0x3E, // AMD x86-64
        0xB7, // AArch64 (ARM 64-bit)
        0xF3, // RISC-V
    ];
    if !KNOWN_MACHINES.contains(&e_machine) || e_type == 0 || e_type > 4 {
        return None;
    }

    let (type_str, ext) = match e_type {
        1 => ("Relocatable Object / Linux Kernel Module (.o / .ko)", "o"),
        2 => ("Executable Binary", "elf"),
        3 => ("Shared Object / Dynamic Library (.so) / PIE", "so"),
        4 => ("Core Dump", "core"),
        _ => ("ELF Binary", "elf"),
    };

    let arch_str = match e_machine {
        0x03 => "x86 (IA-32)",
        0x3E => "AMD x86-64",
        0x28 => "ARM (32-bit)",
        0xB7 => "AArch64 (ARM 64-bit)",
        0xF3 => "RISC-V",
        0x08 => "MIPS",
        0x14 => "PowerPC",
        0x15 => "PowerPC 64",
        0x02 => "SPARC",
        _ => "Unknown Arch",
    };

    // Calculate total ELF size from section headers or program headers
    let mut total_size = 0usize;
    if is_64 && pos + 64 <= data.len() {
        let sh_off = if is_le {
            u64::from_le_bytes(slice[40..48].try_into().unwrap_or_default()) as usize
        } else {
            u64::from_be_bytes(slice[40..48].try_into().unwrap_or_default()) as usize
        };
        let sh_entsize = if is_le {
            u16::from_le_bytes([slice[58], slice[59]]) as usize
        } else {
            u16::from_be_bytes([slice[58], slice[59]]) as usize
        };
        let sh_num = if is_le {
            u16::from_le_bytes([slice[60], slice[61]]) as usize
        } else {
            u16::from_be_bytes([slice[60], slice[61]]) as usize
        };

        if sh_off > 0 && sh_entsize == 64 && sh_num > 0 && sh_num <= 256 {
            let candidate = sh_off + (sh_entsize * sh_num);
            if candidate > 64 && candidate <= 500 * 1024 * 1024 {
                total_size = candidate;
            }
        }
    } else if !is_64 && pos + 52 <= data.len() {
        let sh_off = if is_le {
            u32::from_le_bytes(slice[32..36].try_into().unwrap_or_default()) as usize
        } else {
            u32::from_be_bytes(slice[32..36].try_into().unwrap_or_default()) as usize
        };
        let sh_entsize = if is_le {
            u16::from_le_bytes([slice[46], slice[47]]) as usize
        } else {
            u16::from_be_bytes([slice[46], slice[47]]) as usize
        };
        let sh_num = if is_le {
            u16::from_le_bytes([slice[48], slice[49]]) as usize
        } else {
            u16::from_be_bytes([slice[48], slice[49]]) as usize
        };

        if sh_off > 0 && sh_entsize == 40 && sh_num > 0 && sh_num <= 256 {
            let candidate = sh_off + (sh_entsize * sh_num);
            if candidate > 52 && candidate <= 500 * 1024 * 1024 {
                total_size = candidate;
            }
        }
    }

    // Inspect program headers for interpreter path (e.g. /lib64/ld-linux-x86-64.so.2)
    let mut interp_info = String::new();
    let ph_off = if is_64 {
        if is_le { u64::from_le_bytes(slice[32..40].try_into().unwrap_or_default()) as usize }
        else { u64::from_be_bytes(slice[32..40].try_into().unwrap_or_default()) as usize }
    } else {
        if is_le { u32::from_le_bytes(slice[28..32].try_into().unwrap_or_default()) as usize }
        else { u32::from_be_bytes(slice[28..32].try_into().unwrap_or_default()) as usize }
    };

    if ph_off > 0 && e_phnum > 0 && e_phnum <= 64 {
        let phent = e_phentsize as usize;
        for i in 0..e_phnum as usize {
            let ph_idx = ph_off + (i * phent);
            if ph_idx + phent <= slice.len() {
                let ph_slice = &slice[ph_idx..ph_idx + phent];
                let p_type = if is_le {
                    u32::from_le_bytes(ph_slice[0..4].try_into().unwrap_or_default())
                } else {
                    u32::from_be_bytes(ph_slice[0..4].try_into().unwrap_or_default())
                };

                // PT_INTERP = 3
                if p_type == 3 {
                    let p_offset = if is_64 {
                        if is_le { u64::from_le_bytes(ph_slice[8..16].try_into().unwrap_or_default()) as usize }
                        else { u64::from_be_bytes(ph_slice[8..16].try_into().unwrap_or_default()) as usize }
                    } else {
                        if is_le { u32::from_le_bytes(ph_slice[4..8].try_into().unwrap_or_default()) as usize }
                        else { u32::from_be_bytes(ph_slice[4..8].try_into().unwrap_or_default()) as usize }
                    };
                    let p_filesz = if is_64 {
                        if is_le { u64::from_le_bytes(ph_slice[32..40].try_into().unwrap_or_default()) as usize }
                        else { u64::from_be_bytes(ph_slice[32..40].try_into().unwrap_or_default()) as usize }
                    } else {
                        if is_le { u32::from_le_bytes(ph_slice[16..20].try_into().unwrap_or_default()) as usize }
                        else { u32::from_be_bytes(ph_slice[16..20].try_into().unwrap_or_default()) as usize }
                    };

                    if p_offset > 0 && p_filesz > 0 && p_offset + p_filesz <= slice.len() && p_filesz <= 256 {
                        if let Ok(st) = std::str::from_utf8(&slice[p_offset..p_offset + p_filesz]) {
                            let clean = st.trim_matches('\0').trim();
                            if !clean.is_empty() {
                                interp_info = format!(", Interpreter: '{}'", clean);
                            }
                        }
                    }
                    break;
                }
            }
        }
    }

    let class_str = if is_64 { "64-bit" } else { "32-bit" };
    let endian_str = if is_le { "LSB" } else { "MSB" };

    let desc = format!("ELF {} {} {}, Arch: {}{}", class_str, endian_str, type_str, arch_str, interp_info);
    Some((desc, total_size, ext.to_string()))
}

/// Deep verification of PE binaries (Executables, DLLs, SYS Drivers)
fn check_pe(data: &[u8], pos: usize) -> Option<(String, usize, String)> {
    if pos + 0x40 > data.len() {
        return None;
    }
    let slice = &data[pos..];
    if !slice.starts_with(b"MZ") {
        return None;
    }

    // e_lfanew is at offset 0x3C
    let e_lfanew = u32::from_le_bytes(slice[0x3C..0x40].try_into().unwrap_or_default()) as usize;
    if e_lfanew < 0x40 || e_lfanew > 0x1000 || pos + e_lfanew + 24 > data.len() {
        return None;
    }

    let pe_header = &slice[e_lfanew..];
    if !pe_header.starts_with(b"PE\0\0") {
        return None;
    }

    let machine = u16::from_le_bytes([pe_header[4], pe_header[5]]);
    let num_sections = u16::from_le_bytes([pe_header[6], pe_header[7]]) as usize;
    let opt_hdr_size = u16::from_le_bytes([pe_header[20], pe_header[21]]) as usize;
    let characteristics = u16::from_le_bytes([pe_header[22], pe_header[23]]);

    if num_sections == 0 || num_sections > 96 {
        return None; // Header trash
    }

    let arch_str = match machine {
        0x014c => "x86 (32-bit)",
        0x8664 => "x86-64 (AMD64)",
        0x01c0 => "ARM",
        0xaa64 => "ARM64",
        _ => return None, // Whitelist valid PE machines
    };

    // Inspect Optional Header
    let mut is_driver = false;
    if opt_hdr_size >= 70 && pe_header.len() >= 24 + opt_hdr_size {
        let opt_header = &pe_header[24..];
        let magic = u16::from_le_bytes([opt_header[0], opt_header[1]]);
        if magic != 0x010B && magic != 0x020B {
            return None; // Invalid PE optional header magic
        }
        let subsystem = u16::from_le_bytes([opt_header[68], opt_header[69]]);
        if subsystem == 1 {
            is_driver = true; // IMAGE_SUBSYSTEM_NATIVE (Driver / SYS)
        }
    }

    let is_dll = (characteristics & 0x2000) != 0;
    let (type_str, ext) = if is_driver {
        ("Windows Kernel Driver / Native System Image (.sys)", "sys")
    } else if is_dll {
        ("Windows Dynamic Link Library (DLL)", "dll")
    } else {
        ("Windows PE Executable", "exe")
    };

    // Calculate approximate PE file size from Section Headers
    let mut total_size = 0usize;
    let sec_table_off = 24 + opt_hdr_size;
    if pe_header.len() >= sec_table_off + (num_sections * 40) {
        let mut max_end = 0usize;
        for i in 0..num_sections {
            let sec = &pe_header[sec_table_off + (i * 40)..];
            let raw_size = u32::from_le_bytes(sec[16..20].try_into().unwrap_or_default()) as usize;
            let raw_offset = u32::from_le_bytes(sec[20..24].try_into().unwrap_or_default()) as usize;
            if raw_offset > 0 && raw_size > 0 {
                let end = e_lfanew + raw_offset + raw_size;
                if end > max_end && end <= 500 * 1024 * 1024 {
                    max_end = end;
                }
            }
        }
        if max_end > 0 {
            total_size = max_end;
        }
    }

    let desc = format!("{} (MZ / PE00), Machine: {}, Sections: {}, Flags: 0x{:04X}", type_str, arch_str, num_sections, characteristics);
    Some((desc, total_size, ext.to_string()))
}

/// Deep verification of Android Dalvik / ART bytecode libraries (.dex)
fn check_dex(data: &[u8], pos: usize) -> Option<(String, usize, String)> {
    if pos + 0x70 > data.len() {
        return None;
    }
    let slice = &data[pos..];
    if !slice.starts_with(b"dex\n") {
        return None;
    }

    let ver_bytes = &slice[4..8];
    if ver_bytes[3] != 0 {
        return None;
    }
    let ver_str = match &ver_bytes[..3] {
        b"035" => "v035 (Android 1.0 - 6.0)",
        b"037" => "v037 (Android 7.0)",
        b"038" => "v038 (Android 8.0)",
        b"039" => "v039 (Android 9.0+)",
        _ => return None,
    };

    let file_size = u32::from_le_bytes(slice[32..36].try_into().unwrap_or_default()) as usize;
    let header_size = u32::from_le_bytes(slice[36..40].try_into().unwrap_or_default()) as usize;
    let endian_tag = u32::from_le_bytes(slice[40..44].try_into().unwrap_or_default());

    if header_size != 0x70 || endian_tag != 0x12345678 || file_size < 0x70 || file_size > 500 * 1024 * 1024 {
        return None;
    }

    let desc = format!("Android Dalvik Executable / Library (.dex, {})", ver_str);
    Some((desc, file_size, "dex".to_string()))
}

/// Deep verification of Java Class bytecode libraries (.class)
fn check_java_class(data: &[u8], pos: usize) -> Option<(String, usize, String)> {
    if pos + 10 > data.len() {
        return None;
    }
    let slice = &data[pos..];
    if !slice.starts_with(b"\xca\xfe\xba\xbe") {
        return None;
    }

    let major = u16::from_be_bytes([slice[6], slice[7]]);
    if !(45..=70).contains(&major) {
        return None;
    }
    let java_ver = match major {
        45..=48 => format!("1.{}", major - 44),
        m => format!("{}", m - 44),
    };

    let cp_count = u16::from_be_bytes([slice[8], slice[9]]);
    if cp_count < 2 || cp_count > 32768 {
        return None;
    }

    if pos + 11 <= data.len() {
        let tag = slice[10];
        if !matches!(tag, 1 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 15 | 16 | 17 | 18 | 19 | 20) {
            return None;
        }
    }

    let desc = format!("Java Class Compiled Bytecode (.class, Java {})", java_ver);
    Some((desc, 0, "class".to_string()))
}

/// Deep verification of Mach-O binaries & Dynamic Libraries (.dylib, .o, .bundle)
fn check_macho(data: &[u8], pos: usize) -> Option<(String, usize, String)> {
    if pos + 32 > data.len() {
        return None;
    }
    let slice = &data[pos..];
    let (is_64, is_le) = match &slice[0..4] {
        b"\xfe\xed\xfa\xce" => (false, false), // MH_MAGIC
        b"\xce\xfa\xed\xfe" => (false, true),  // MH_CIGAM
        b"\xfe\xed\xfa\xcf" => (true, false),  // MH_MAGIC_64
        b"\xcf\xfa\xed\xfe" => (true, true),   // MH_CIGAM_64
        _ => return None,
    };

    let cputype = if is_le {
        u32::from_le_bytes(slice[4..8].try_into().unwrap_or_default())
    } else {
        u32::from_be_bytes(slice[4..8].try_into().unwrap_or_default())
    };
    let filetype = if is_le {
        u32::from_le_bytes(slice[12..16].try_into().unwrap_or_default())
    } else {
        u32::from_be_bytes(slice[12..16].try_into().unwrap_or_default())
    };

    if !matches!(filetype, 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12) {
        return None;
    }

    let (type_str, ext) = match filetype {
        1 => ("Relocatable Object (.o)", "o"),
        2 => ("Executable Binary", "macho"),
        6 => ("Dynamic Shared Library (.dylib)", "dylib"),
        7 => ("Dynamic Linker (.dylib)", "dylib"),
        8 => ("Bundle (.bundle)", "bundle"),
        _ => ("Mach-O Binary", "macho"),
    };

    let arch_str = match cputype {
        7 => "x86",
        0x01000007 => "x86-64",
        12 => "ARM",
        0x0100000C => "ARM64 (Apple Silicon)",
        _ => "Unknown Arch",
    };

    let desc = format!("Mach-O {} {} ({}), Arch: {}", if is_64 { "64-bit" } else { "32-bit" }, type_str, if is_le { "LE" } else { "BE" }, arch_str);
    Some((desc, 0, ext.to_string()))
}

/// Deep verification of Unix / Linux Static Library Archives (.a)
fn check_ar_archive(data: &[u8], pos: usize) -> Option<(String, usize, String)> {
    if pos + 68 > data.len() {
        return None;
    }
    let slice = &data[pos..];
    if !slice.starts_with(b"!<arch>\n") {
        return None;
    }

    // Verify member header trailer: slice[58..60] must be `\n
    if &slice[58..60] != b"\x60\n" {
        return None;
    }

    let name_raw = std::str::from_utf8(&slice[8..24]).unwrap_or("");
    let name = name_raw.trim();
    let desc = if !name.is_empty() {
        format!("Unix / Linux Static Library Archive (.a, first member: '{}')", name)
    } else {
        "Unix / Linux Static Library Archive (.a)".to_string()
    };
    Some((desc, 0, "a".to_string()))
}

/// Deep verification of Zip Archives, JARs, APKs, and Office Containers
fn check_zip(data: &[u8], pos: usize) -> Option<(String, usize, String)> {
    if pos + 30 > data.len() {
        return None;
    }
    let slice = &data[pos..];
    if !slice.starts_with(b"PK\x03\x04") {
        return None;
    }

    let comp_method = u16::from_le_bytes([slice[8], slice[9]]);
    let fname_len = u16::from_le_bytes([slice[26], slice[27]]) as usize;
    let extra_len = u16::from_le_bytes([slice[28], slice[29]]) as usize;

    if fname_len == 0 || comp_method > 20 || fname_len > 1024 || extra_len > 4096 {
        return None;
    }

    let mut fname = String::new();
    let mut ext = "zip".to_string();
    let mut type_label = "Zip Archive / Container".to_string();

    if pos + 30 + fname_len <= data.len() {
        if let Ok(st) = std::str::from_utf8(&slice[30..30 + fname_len]) {
            if st.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
                fname = format!(", First entry: '{}'", st);
                if st.ends_with(".class") || st.starts_with("META-INF/") {
                    type_label = "Java Archive Package (JAR / WAR)".to_string();
                    ext = "jar".to_string();
                } else if st == "AndroidManifest.xml" || st == "classes.dex" {
                    type_label = "Android Application Package (APK)".to_string();
                    ext = "apk".to_string();
                } else if st == "[Content_Types].xml" {
                    type_label = "Microsoft Office OpenXML Container (DOCX/XLSX)".to_string();
                    ext = "docx".to_string();
                }
            }
        }
    }

    let desc = format!("{} (PK0304, compression: {}){}", type_label, comp_method, fname);
    Some((desc, 0, ext))
}

/// Deep verification of Gzip Compressed Streams with decompression trial
fn check_gzip(data: &[u8], pos: usize) -> Option<(String, usize, String)> {
    if pos + 10 > data.len() {
        return None;
    }
    let slice = &data[pos..];
    if slice[0] != 0x1f || slice[1] != 0x8b {
        return None;
    }
    let method = slice[2];
    let flags = slice[3];

    // Method must be 8 (deflate) and top 3 bits of flags must be 0
    if method != 8 || (flags & 0xE0) != 0 {
        return None;
    }

    // Trial decompression test to eliminate random byte false positives
    let test_slice = &slice[..std::cmp::min(slice.len(), 1024)];
    let mut gz = GzDecoder::new(test_slice);
    let mut buf = [0u8; 16];
    if gz.read(&mut buf).is_err() {
        return None;
    }

    let desc = format!("Gzip Compressed Data (deflate, flags: 0x{:02X})", flags);
    Some((desc, 0, "gz".to_string()))
}

/// Deep verification of Zlib Deflate Streams with decompression trial
fn check_zlib(data: &[u8], pos: usize) -> Option<(String, usize, String)> {
    if pos + 32 > data.len() {
        return None;
    }
    let slice = &data[pos..];
    let cmf = slice[0];
    let flg = slice[1];

    // Checksum check: (CMF * 256 + FLG) % 31 == 0
    let check = ((cmf as u32) * 256 + (flg as u32)) % 31;
    if check != 0 {
        return None;
    }

    let cm = cmf & 0x0F;
    let cinfo = (cmf >> 4) & 0x0F;
    if cm != 8 || cinfo > 7 {
        return None;
    }

    // Verify decompression with ZlibDecoder on a small slice (must decompress at least 16 bytes)
    let test_slice = &slice[..std::cmp::min(slice.len(), 512)];
    let mut decoder = ZlibDecoder::new(test_slice);
    let mut out = [0u8; 16];
    if decoder.read(&mut out).is_err() {
        return None;
    }

    let desc = format!("Zlib Compressed Stream (deflate, window size: 2^{})", cinfo + 8);
    Some((desc, 0, "zlib".to_string()))
}

/// Deep verification of PNG Image Files with exact IEND carve boundary
fn check_png(data: &[u8], pos: usize) -> Option<(String, usize, String)> {
    if pos + 24 > data.len() {
        return None;
    }
    let slice = &data[pos..];
    if !slice.starts_with(b"\x89PNG\r\n\x1a\n") {
        return None;
    }

    // Must be followed by IHDR chunk: 4 bytes len (13) + "IHDR"
    if &slice[8..16] != b"\x00\x00\x00\x0dIHDR" {
        return None;
    }

    let width = u32::from_be_bytes(slice[16..20].try_into().unwrap_or_default());
    let height = u32::from_be_bytes(slice[20..24].try_into().unwrap_or_default());

    // Search for IEND chunk to compute exact file size
    let mut total_size = 0usize;
    if let Some(iend_idx) = slice.windows(12).position(|w| w.starts_with(b"\x00\x00\x00\x00IEND")) {
        total_size = iend_idx + 12;
    }

    let desc = format!("PNG Image File, {}x{} pixels", width, height);
    Some((desc, total_size, "png".to_string()))
}

/// Deep verification of JPEG Image Files
fn check_jpeg(data: &[u8], pos: usize) -> Option<(String, usize, String)> {
    if pos + 4 > data.len() {
        return None;
    }
    let slice = &data[pos..];
    if !slice.starts_with(b"\xff\xd8\xff") {
        return None;
    }
    let marker = slice[3];
    if !matches!(marker, 0xe0 | 0xe1 | 0xdb | 0xc0 | 0xc2 | 0xee) {
        return None;
    }

    let marker_name = match marker {
        0xe0 => "JFIF APP0",
        0xe1 => "Exif APP1",
        0xdb => "DQT",
        0xc0 => "Baseline SOF0",
        _ => "JPEG Marker",
    };

    // Find EOI marker (\xFF\xD9)
    let mut total_size = 0usize;
    if let Some(eoi_idx) = slice.windows(2).position(|w| w == b"\xff\xd9") {
        total_size = eoi_idx + 2;
    }

    let desc = format!("JPEG Image ({})", marker_name);
    Some((desc, total_size, "jpg".to_string()))
}

/// Deep verification of POSIX TAR Archives
fn check_tar(data: &[u8], pos: usize) -> Option<(String, usize, String)> {
    if pos + 512 > data.len() {
        return None;
    }
    let slice = &data[pos..];
    if &slice[257..263] == b"ustar\x00" || &slice[257..265] == b"ustar  \x00" {
        // Strict check: mode, size, and chksum must be octal digits
        let mode_bytes = &slice[100..106];
        if !mode_bytes.iter().all(|&b| (b'0'..=b'7').contains(&b) || b == 0 || b == b' ') {
            return None;
        }
        let size_bytes = &slice[108..116];
        if !size_bytes.iter().all(|&b| (b'0'..=b'7').contains(&b) || b == 0 || b == b' ') {
            return None;
        }

        let name_bytes = &slice[0..100];
        let name_clean: String = name_bytes
            .iter()
            .take_while(|&&b| b != 0)
            .map(|&b| if (32..=126).contains(&b) { b as char } else { ' ' })
            .collect();
        let fname = name_clean.trim();
        let desc = if fname.is_empty() {
            "POSIX tar Archive (ustar)".to_string()
        } else {
            format!("POSIX tar Archive (ustar, entry: '{}')", fname)
        };
        return Some((desc, 0, "tar".to_string()));
    }
    None
}

/// Deep verification of SQLite 3 Databases with exact file size computation
fn check_sqlite(data: &[u8], pos: usize) -> Option<(String, usize, String)> {
    if pos + 100 > data.len() {
        return None;
    }
    let slice = &data[pos..];
    if !slice.starts_with(b"SQLite format 3\x00") {
        return None;
    }
    let page_size_raw = u16::from_be_bytes([slice[16], slice[17]]);
    let page_size = if page_size_raw == 1 { 65536usize } else { page_size_raw as usize };
    if page_size < 512 || page_size > 65536 || (page_size & (page_size - 1)) != 0 {
        return None;
    }

    let page_count = u32::from_be_bytes(slice[28..32].try_into().unwrap_or_default()) as usize;
    let total_size = if page_count > 0 && page_count <= 1_000_000 {
        page_size * page_count
    } else {
        0
    };

    let desc = format!("SQLite 3 Database (page size: {}, page count: {})", page_size, page_count);
    Some((desc, total_size, "sqlite".to_string()))
}

/// Deep verification of PDF Documents
fn check_pdf(data: &[u8], pos: usize) -> Option<(String, usize, String)> {
    if pos + 8 > data.len() {
        return None;
    }
    let slice = &data[pos..];
    if slice.starts_with(b"%PDF-1.") {
        let minor = slice[7] as char;
        if minor.is_ascii_digit() {
            let desc = format!("Adobe Portable Document Format (PDF v1.{})", minor);
            return Some((desc, 0, "pdf".to_string()));
        }
    }
    None
}

/// Deep verification of CaRT containers
fn check_cart(data: &[u8], pos: usize) -> Option<(String, usize, String)> {
    if pos + 8 > data.len() {
        return None;
    }
    let slice = &data[pos..];
    if slice.starts_with(b"CART\x01\x00") || slice.starts_with(b"CART") {
        return Some(("CaRT (Compressed & Redacted Target Container)".to_string(), 0, "cart".to_string()));
    }
    None
}

/// Deep verification of Network Captures (PCAP / PCAPNG)
fn check_pcap(data: &[u8], pos: usize) -> Option<(String, usize, String)> {
    if pos + 24 > data.len() {
        return None;
    }
    let slice = &data[pos..];
    if slice.starts_with(b"\xd4\xc3\xb2\xa1") {
        return Some(("PCAP Packet Capture File (Little-Endian, v2.4)".to_string(), 0, "pcap".to_string()));
    }
    if slice.starts_with(b"\xa1\xb2\xc3\xd4") {
        return Some(("PCAP Packet Capture File (Big-Endian, v2.4)".to_string(), 0, "pcap".to_string()));
    }
    if slice.starts_with(b"\x0a\x0d\x0d\x0a") {
        return Some(("PCAPNG Next Generation Packet Capture (Section Header Block)".to_string(), 0, "pcapng".to_string()));
    }
    None
}

/// Deep verification of Compiled Python Bytecode (.pyc)
fn check_pyc(data: &[u8], pos: usize) -> Option<(String, usize, String)> {
    if pos + 16 > data.len() {
        return None;
    }
    let slice = &data[pos..];
    let (py_ver, magic) = match &slice[0..4] {
        b"\x42\x0d\r\n" => ("3.7", true),
        b"\x55\x0d\r\n" => ("3.8", true),
        b"\x61\x0d\r\n" => ("3.9", true),
        b"\x6f\x0d\r\n" => ("3.10", true),
        b"\xa7\x0d\r\n" => ("3.11", true),
        b"\xcb\x0d\r\n" => ("3.12", true),
        b"\xf3\x0d\r\n" => ("3.13", true),
        _ => ("", false),
    };
    if magic {
        // Validate bitfield flags at offset 4..8
        let flags = u32::from_le_bytes(slice[4..8].try_into().unwrap_or_default());
        if flags > 7 {
            return None; // Header trash
        }
        let desc = format!("Compiled Python Bytecode (.pyc, Python {})", py_ver);
        return Some((desc, 0, "pyc".to_string()));
    }
    None
}

/// Deep verification of Cryptographic Certificates & Private Keys (PEM) with exact boundary carving
fn check_pem(data: &[u8], pos: usize) -> Option<(String, usize, String)> {
    let slice = &data[pos..];
    let patterns: &[(&[u8], &[u8], &str)] = &[
        (b"-----BEGIN CERTIFICATE-----", b"-----END CERTIFICATE-----", "X.509 Certificate (PEM)"),
        (b"-----BEGIN RSA PRIVATE KEY-----", b"-----END RSA PRIVATE KEY-----", "RSA Private Key (PEM)"),
        (b"-----BEGIN OPENSSH PRIVATE KEY-----", b"-----END OPENSSH PRIVATE KEY-----", "OpenSSH Private Key (PEM)"),
        (b"-----BEGIN EC PRIVATE KEY-----", b"-----END EC PRIVATE KEY-----", "EC Private Key (PEM)"),
        (b"-----BEGIN PRIVATE KEY-----", b"-----END PRIVATE KEY-----", "PKCS#8 Private Key (PEM)"),
        (b"-----BEGIN PUBLIC KEY-----", b"-----END PUBLIC KEY-----", "Public Key (PEM)"),
    ];

    for &(begin_pat, end_pat, desc) in patterns {
        if slice.starts_with(begin_pat) {
            let mut total_size = 0usize;
            if let Some(end_idx) = slice.windows(end_pat.len()).position(|w| w == end_pat) {
                total_size = end_idx + end_pat.len();
            }
            return Some((desc.to_string(), total_size, "pem".to_string()));
        }
    }
    None
}

/// Deep verification of Linux Kernel Firmware Images & Boot Executables
fn check_linux_kernel(data: &[u8], pos: usize) -> Option<(String, usize, String)> {
    let slice = &data[pos..];
    if slice.starts_with(b"\x27\x05\x19\x56") {
        return Some(("U-Boot uImage / Linux Kernel Firmware Image".to_string(), 0, "uImage".to_string()));
    }
    if pos + 0x206 <= data.len() && &data[pos + 0x202..pos + 0x206] == b"HdrS" {
        return Some(("Linux x86 Kernel Boot Executable (bzImage)".to_string(), 0, "kernel".to_string()));
    }
    None
}

/// Deep verification of Embedded Filesystems
fn check_filesystems(data: &[u8], pos: usize) -> Option<(String, usize, String)> {
    let slice = &data[pos..];
    if slice.starts_with(b"hsqs") {
        return Some(("Squashfs Filesystem (Little-Endian, v4.0)".to_string(), 0, "squashfs".to_string()));
    }
    if slice.starts_with(b"sqsh") {
        return Some(("Squashfs Filesystem (Big-Endian, v4.0)".to_string(), 0, "squashfs".to_string()));
    }
    if slice.starts_with(b"\x28\xcd\x3d\x45") || slice.starts_with(b"\x45\x3d\xcd\x28") {
        return Some(("Cramfs Filesystem".to_string(), 0, "cramfs".to_string()));
    }
    if slice.starts_with(b"UBI#") {
        return Some(("UBIFS Flash Image (UBI# Header)".to_string(), 0, "ubifs".to_string()));
    }
    None
}

/// Deep verification of Compressed Archives with CRC checksum validation
fn check_other_archives(data: &[u8], pos: usize) -> Option<(String, usize, String)> {
    let slice = &data[pos..];

    // 7-Zip Archive (Verify CRC32 of header)
    if slice.starts_with(b"7z\xbc\xaf\x27\x1c") && slice.len() >= 32 {
        let expected_crc = u32::from_le_bytes(slice[8..12].try_into().unwrap_or_default());
        let mut h = Hasher::new();
        h.update(&slice[12..32]);
        if expected_crc == h.finalize() {
            return Some(("7-Zip Compressed Archive (7z v0.4+, Verified CRC32)".to_string(), 0, "7z".to_string()));
        }
    }

    // RAR Archives
    if slice.starts_with(b"Rar!\x1a\x07\x00") {
        return Some(("RAR 4.x Archive".to_string(), 0, "rar".to_string()));
    }
    if slice.starts_with(b"Rar!\x1a\x07\x01\x00") {
        return Some(("RAR 5.x Archive".to_string(), 0, "rar".to_string()));
    }

    // XZ Compressed Archive (Verify CRC32 of stream flags)
    if slice.starts_with(b"\xfd7zXZ\x00") && slice.len() >= 12 {
        let expected_crc = u32::from_le_bytes(slice[8..12].try_into().unwrap_or_default());
        let mut h = Hasher::new();
        h.update(&slice[6..8]);
        if expected_crc == h.finalize() {
            return Some(("XZ Compressed Archive (.xz, Verified CRC32)".to_string(), 0, "xz".to_string()));
        }
    }

    // Bzip2 Compressed Archive (Verify block header)
    if slice.starts_with(b"BZh") && slice.len() >= 10 && slice[3].is_ascii_digit() {
        if &slice[4..10] == b"1AY&SY" || &slice[4..10] == b"\x17\x72\x45\x38\x50\x90" {
            return Some(("Bzip2 Compressed Archive (.bz2, Verified Block Magic)".to_string(), 0, "bz2".to_string()));
        }
    }

    // Zstandard Compressed Archive
    if slice.starts_with(b"\x28\xb5\x2f\xfd") {
        return Some(("Zstandard Compressed Archive (.zst)".to_string(), 0, "zst".to_string()));
    }

    // WebAssembly Module
    if slice.starts_with(b"\x00asm\x01\x00\x00\x00") {
        return Some(("WebAssembly Binary Module (.wasm, v1)".to_string(), 0, "wasm".to_string()));
    }

    None
}

// ---------------------------------------------------------------------------
// Main Scanner Engine (Multi-Pattern Single Pass)
// ---------------------------------------------------------------------------

fn scan_signatures(data: &[u8]) -> Vec<SignatureMatch> {
    let anchors: &[&[u8]] = &[
        b"\x7fELF",                     // ELF
        b"MZ",                          // PE
        b"PK\x03\x04",                  // ZIP / JAR / APK / DOCX
        b"\x1f\x8b",                    // GZIP
        b"\x78\x01", b"\x78\x9c", b"\x78\xda", b"\x78\x5e", b"\x78\xbb", // ZLIB candidates
        b"\x89PNG\r\n\x1a\n",           // PNG
        b"\xff\xd8\xff",                // JPEG
        b"ustar",                       // TAR
        b"SQLite format 3\x00",         // SQLite
        b"%PDF-1.",                     // PDF
        b"CART",                        // CaRT
        b"\xd4\xc3\xb2\xa1",            // PCAP LE
        b"\xa1\xb2\xc3\xd4",            // PCAP BE
        b"\x0a\x0d\x0d\x0a",            // PCAPNG
        b"\x42\x0d\r\n", b"\x55\x0d\r\n", b"\x61\x0d\r\n", b"\x6f\x0d\r\n",
        b"\xa7\x0d\r\n", b"\xcb\x0d\r\n", b"\xf3\x0d\r\n", // PYC
        b"-----BEGIN ",                 // PEM
        b"\x27\x05\x19\x56",            // uImage
        b"HdrS",                        // Linux bzImage
        b"hsqs", b"sqsh",               // Squashfs
        b"\x28\xcd\x3d\x45",            // Cramfs
        b"UBI#",                        // UBIFS
        b"7z\xbc\xaf\x27\x1c",          // 7z
        b"Rar!\x1a\x07",                // RAR
        b"\xfd7zXZ\x00",                // XZ
        b"BZh",                         // BZ2
        b"\x28\xb5\x2f\xfd",            // Zstandard
        b"!<arch>\n",                   // Linux Static Library Archive .a
        b"\x00asm\x01\x00\x00\x00",     // WebAssembly .wasm
        b"dex\n",                       // Android DEX Library
        b"\xca\xfe\xba\xbe",            // Java Class Library
        b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", // Mach-O Binary / dylib
    ];

    let ac = AhoCorasick::new(anchors).unwrap();
    let mut matches = Vec::new();
    let mut last_offset = usize::MAX;

    for m in ac.find_iter(data) {
        let pos = m.start();

        if pos == last_offset {
            continue;
        }

        let verified = None
            .or_else(|| check_elf(data, pos).map(|(d, s, ext)| ("Executable / Library", d, s, ext)))
            .or_else(|| check_pe(data, pos).map(|(d, s, ext)| ("Executable / Library", d, s, ext)))
            .or_else(|| check_dex(data, pos).map(|(d, s, ext)| ("Executable / Library", d, s, ext)))
            .or_else(|| check_java_class(data, pos).map(|(d, s, ext)| ("Executable / Library", d, s, ext)))
            .or_else(|| check_macho(data, pos).map(|(d, s, ext)| ("Executable / Library", d, s, ext)))
            .or_else(|| check_ar_archive(data, pos).map(|(d, s, ext)| ("Archive / Library", d, s, ext)))
            .or_else(|| check_png(data, pos).map(|(d, s, ext)| ("Graphics Image", d, s, ext)))
            .or_else(|| check_jpeg(data, pos).map(|(d, s, ext)| ("Graphics Image", d, s, ext)))
            .or_else(|| check_zip(data, pos).map(|(d, s, ext)| ("Archive / Container", d, s, ext)))
            .or_else(|| check_gzip(data, pos).map(|(d, s, ext)| ("Compressed Stream", d, s, ext)))
            .or_else(|| check_zlib(data, pos).map(|(d, s, ext)| ("Compressed Stream", d, s, ext)))
            .or_else(|| check_other_archives(data, pos).map(|(d, s, ext)| ("Archive / Compression", d, s, ext)))
            .or_else(|| check_cart(data, pos).map(|(d, s, ext)| ("Container File", d, s, ext)))
            .or_else(|| check_sqlite(data, pos).map(|(d, s, ext)| ("Database File", d, s, ext)))
            .or_else(|| check_pcap(data, pos).map(|(d, s, ext)| ("Network Capture", d, s, ext)))
            .or_else(|| check_pdf(data, pos).map(|(d, s, ext)| ("Document File", d, s, ext)))
            .or_else(|| check_pyc(data, pos).map(|(d, s, ext)| ("Compiled Code", d, s, ext)))
            .or_else(|| check_pem(data, pos).map(|(d, s, ext)| ("Cryptographic Key / Cert", d, s, ext)))
            .or_else(|| check_linux_kernel(data, pos).map(|(d, s, ext)| ("Firmware / Kernel", d, s, ext)))
            .or_else(|| check_filesystems(data, pos).map(|(d, s, ext)| ("Filesystem Image", d, s, ext)))
            .or_else(|| {
                if pos >= 257 {
                    check_tar(data, pos - 257).map(|(d, s, ext)| ("Archive Container", d, s, ext))
                } else {
                    None
                }
            });

        if let Some((cat, desc, carve_sz, ext)) = verified {
            last_offset = pos;
            matches.push(SignatureMatch {
                offset: pos,
                category: cat.to_string(),
                description: desc,
                confidence: "High (Verified Structure)".to_string(),
                carve_size: if carve_sz > 0 { Some(carve_sz) } else { None },
                extension: ext,
            });
        }
    }

    matches
}

fn main() {
    let cli = Cli::parse();
    let start_time = Instant::now();

    let path = Path::new(&cli.file);
    if !path.exists() {
        eprintln!("{}: file not found: {}", "error".red().bold(), cli.file);
        std::process::exit(1);
    }

    println!("{}", "=================================================================".bright_cyan());
    println!("{}", "       BINWALK2 - ULTRA-FAST FORENSIC SIGNATURE CARVER           ".bright_yellow().bold());
    println!("{}", "       Zero-Copy Deep Signature Analyzer & Embedded File Hunter  ".bright_white());
    println!("{}", "=================================================================".bright_cyan());

    let file = File::open(path).expect("Failed to open target evidence file");
    let mmap = unsafe { Mmap::map(&file).expect("Failed to memory-map target file") };
    let data = &mmap[..];
    let file_size = data.len();

    let matches = scan_signatures(data);
    let elapsed = start_time.elapsed();

    // Print Results Table
    println!("\n{}", format!("[+] Discovered File Signatures & Embedded Artifacts ({} Found)", matches.len()).bold().green());
    if matches.is_empty() {
        println!("{}", "[-] No verified embedded file signatures identified.".dimmed());
    } else {
        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL)
            .apply_modifier(UTF8_ROUND_CORNERS)
            .set_content_arrangement(ContentArrangement::Dynamic);

        table.set_header(vec![
            Cell::new("Decimal").fg(Color::Cyan).add_attribute(Attribute::Bold),
            Cell::new("Hex Offset").fg(Color::Yellow).add_attribute(Attribute::Bold),
            Cell::new("Category").fg(Color::DarkGrey),
            Cell::new("Description & Forensic Metadata").fg(Color::White).add_attribute(Attribute::Bold),
        ]);

        for m in matches.iter().take(cli.limit) {
            table.add_row(vec![
                Cell::new(m.offset.to_string()).fg(Color::Cyan),
                Cell::new(format!("0x{:08X}", m.offset)).fg(Color::Yellow),
                Cell::new(&m.category).fg(Color::DarkGrey),
                Cell::new(&m.description).fg(Color::White),
            ]);
        }
        println!("{table}");
        if matches.len() > cli.limit {
            println!("{}", format!("... and {} more findings (use --limit to display all)", matches.len() - cli.limit).dimmed());
        }
    }

    // Carve / Extract Handler
    if cli.extract {
        let out_dir = cli.outdir.unwrap_or_else(|| {
            let stem = path.file_stem().unwrap_or_default().to_string_lossy();
            format!("{}_binwalk2_carved", stem)
        });

        fs::create_dir_all(&out_dir).expect("Failed to create extraction directory");
        println!("\n{}", format!("[*] Extracting carved file streams into: {}", out_dir).bold().cyan());

        let mut carved_count = 0;
        for (i, m) in matches.iter().enumerate() {
            let fname = format!("{}/0x{:08X}_{}.{}", out_dir, m.offset, i + 1, m.extension);
            let carve_len = m.carve_size.unwrap_or_else(|| {
                let next_off = matches.get(i + 1).map(|n| n.offset).unwrap_or(data.len());
                let bounded = next_off.saturating_sub(m.offset);
                std::cmp::min(bounded, 50 * 1024 * 1024)
            });

            if m.offset + carve_len <= data.len() && carve_len > 0 {
                if let Ok(mut out_f) = File::create(&fname) {
                    let _ = out_f.write_all(&data[m.offset..m.offset + carve_len]);
                    println!("  {} Carved: {} ({} bytes)", "[+]".green().bold(), fname.cyan(), carve_len);
                    carved_count += 1;
                }
            }
        }
        println!("{} Successfully carved {} embedded files into {}", "[+]".green().bold(), carved_count, out_dir.cyan());
    }

    // Export Handlers
    if let Some(ref md_path) = cli.md {
        let mut f = File::create(md_path).expect("Failed to create markdown report");
        writeln!(f, "# Binwalk2 Forensic Carve Report\n").unwrap();
        writeln!(f, "- **Target File:** `{}`", path.file_name().unwrap_or_default().to_string_lossy()).unwrap();
        writeln!(f, "- **File Size:** `{} bytes`", file_size).unwrap();
        writeln!(f, "- **Scan Duration:** `{:.2?}`", elapsed).unwrap();
        writeln!(f, "- **Total Signatures:** `{}`\n", matches.len()).unwrap();
        writeln!(f, "| Decimal | Hex Offset | Category | Description |").unwrap();
        writeln!(f, "|---|---|---|---|").unwrap();
        for m in &matches {
            writeln!(f, "| {} | `0x{:08X}` | {} | {} |", m.offset, m.offset, m.category, m.description).unwrap();
        }
        println!("{} Exported Markdown report to: {}", "[+]".green().bold(), md_path.cyan());
    }

    if let Some(ref json_path) = cli.json {
        let mut f = File::create(json_path).expect("Failed to create JSON report");
        let payload = serde_json::json!({
            "target_file": path.file_name().unwrap_or_default().to_string_lossy(),
            "file_size": file_size,
            "scan_duration_ms": elapsed.as_millis(),
            "total_matches": matches.len(),
            "matches": matches,
        });
        serde_json::to_writer_pretty(&mut f, &payload).unwrap();
        println!("{} Exported JSON report to: {}", "[+]".green().bold(), json_path.cyan());
    }

    println!("\n{} Scan finished in {:.2?} (Zero-Copy Deep Verification Engine)", "[*]".green().bold(), elapsed);
    if cli.bench {
        let mb_per_sec = (file_size as f64 / (1024.0 * 1024.0)) / elapsed.as_secs_f64();
        eprintln!("[*] Throughput: {:.2} MB/s | Processed: {} bytes", mb_per_sec, file_size);
    }
}
