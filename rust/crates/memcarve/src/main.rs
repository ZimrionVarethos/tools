use std::collections::HashSet;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::time::Instant;

use clap::{Parser, Subcommand};
use colored::*;
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::{Attribute, Cell, Color, ContentArrangement, Table};
use memchr::memmem;
use memmap2::Mmap;
use sha1::{Digest, Sha1};
use sha2::Sha256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BinaryType {
    Dex,
    Elf,
    Pe,
    Zip,
    SevenZip,
    Pdf,
    Png,
    Jpg,
    Gzip,
    Tar,
    Sqlite,
    Wasm,
    Pcap,
    PcapNg,
    Luac,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AssemblyMode {
    SinglePage,
    ForwardLinear,
    ReverseLifo,
}

#[derive(Debug, Clone)]
pub struct FormatDef {
    pub id: &'static str,
    pub binary_type: BinaryType,
    pub name: &'static str,
    pub aliases: &'static [&'static str],
    pub magic_hex: &'static str,
    pub magic: &'static [u8],
    pub description: &'static str,
    pub extension: &'static str,
}

pub const FORMAT_DICTIONARY: &[FormatDef] = &[
    FormatDef {
        id: "DEX",
        binary_type: BinaryType::Dex,
        name: "Android Dalvik Executable",
        aliases: &["dex", "android", "apk_dex"],
        magic_hex: "64 65 78 0a (dex\\n)",
        magic: b"dex\n",
        description: "Compiled Android bytecode (.dex) with Adler32 & SHA-1 checksums",
        extension: "dex",
    },
    FormatDef {
        id: "ELF",
        binary_type: BinaryType::Elf,
        name: "Linux Executable & Linkable Format",
        aliases: &["elf", "so", "linux"],
        magic_hex: "7f 45 4c 46 (\\x7fELF)",
        magic: b"\x7fELF",
        description: "Linux binary, shared object (.so), or core dump (32/64-bit)",
        extension: "elf",
    },
    FormatDef {
        id: "PE",
        binary_type: BinaryType::Pe,
        name: "Windows Portable Executable",
        aliases: &["pe", "exe", "dll", "sys"],
        magic_hex: "4d 5a (MZ -> PE\\0\\0)",
        magic: b"MZ",
        description: "Windows executable, DLL library, or kernel driver",
        extension: "exe",
    },
    FormatDef {
        id: "ZIP",
        binary_type: BinaryType::Zip,
        name: "ZIP Archive / APK / JAR / Office",
        aliases: &["zip", "apk", "jar", "docx", "xlsx"],
        magic_hex: "50 4b 03 04 (PK\\x03\\x04)",
        magic: b"PK\x03\x04",
        description: "ZIP archive, Android APK package, Java JAR, or OOXML document",
        extension: "zip",
    },
    FormatDef {
        id: "7Z",
        binary_type: BinaryType::SevenZip,
        name: "7-Zip Compressed Archive",
        aliases: &["7z", "7zip"],
        magic_hex: "37 7a bc af 27 1c",
        magic: b"7z\xbc\xaf\x27\x1c",
        description: "7-Zip high-compression archive container",
        extension: "7z",
    },
    FormatDef {
        id: "PDF",
        binary_type: BinaryType::Pdf,
        name: "Adobe Portable Document Format",
        aliases: &["pdf", "document"],
        magic_hex: "25 50 44 46 2d (%PDF-)",
        magic: b"%PDF-",
        description: "Adobe Acrobat / PDF document container",
        extension: "pdf",
    },
    FormatDef {
        id: "PNG",
        binary_type: BinaryType::Png,
        name: "Portable Network Graphics Image",
        aliases: &["png", "image"],
        magic_hex: "89 50 4e 47 0d 0a 1a 0a",
        magic: b"\x89PNG\r\n\x1a\n",
        description: "Lossless bitmap image format with IHDR/IEND chunks",
        extension: "png",
    },
    FormatDef {
        id: "JPG",
        binary_type: BinaryType::Jpg,
        name: "JPEG / JFIF Image",
        aliases: &["jpg", "jpeg"],
        magic_hex: "ff d8 ff",
        magic: b"\xff\xd8\xff",
        description: "Lossy photographic image stream (SOI -> EOI)",
        extension: "jpg",
    },
    FormatDef {
        id: "GZ",
        binary_type: BinaryType::Gzip,
        name: "GZIP Compressed Stream / Tarball",
        aliases: &["gz", "gzip", "tar.gz"],
        magic_hex: "1f 8b",
        magic: b"\x1f\x8b",
        description: "DEFLATE compressed stream or tar.gz archive",
        extension: "gz",
    },
    FormatDef {
        id: "TAR",
        binary_type: BinaryType::Tar,
        name: "POSIX Tar Archive",
        aliases: &["tar"],
        magic_hex: "75 73 74 61 72 (ustar)",
        magic: b"ustar",
        description: "Standard Unix tar tape archive header",
        extension: "tar",
    },
    FormatDef {
        id: "SQLITE",
        binary_type: BinaryType::Sqlite,
        name: "SQLite Database",
        aliases: &["sqlite", "db", "sqlite3"],
        magic_hex: "53 51 4c 69 74 65 20 66 6f 72 6d 61 74 20 33 00",
        magic: b"SQLite format 3\0",
        description: "Embedded relational database file format v3",
        extension: "db",
    },
    FormatDef {
        id: "WASM",
        binary_type: BinaryType::Wasm,
        name: "WebAssembly Binary Module",
        aliases: &["wasm"],
        magic_hex: "00 61 73 6d (\\0asm)",
        magic: b"\x00asm",
        description: "Compiled WebAssembly low-level bytecode module",
        extension: "wasm",
    },
    FormatDef {
        id: "PCAP",
        binary_type: BinaryType::Pcap,
        name: "Libpcap Packet Capture",
        aliases: &["pcap", "cap"],
        magic_hex: "d4 c3 b2 a1 / a1 b2 c3 d4",
        magic: b"\xd4\xc3\xb2\xa1",
        description: "Standard Wireshark / tcpdump network packet capture",
        extension: "pcap",
    },
    FormatDef {
        id: "PCAPNG",
        binary_type: BinaryType::PcapNg,
        name: "PCAP Next Generation Capture",
        aliases: &["pcapng"],
        magic_hex: "0a 0d 0d 0a (Section Header)",
        magic: b"\x0a\x0d\x0d\x0a",
        description: "Modern extensible network capture format",
        extension: "pcapng",
    },
    FormatDef {
        id: "LUAC",
        binary_type: BinaryType::Luac,
        name: "Lua Compiled Bytecode",
        aliases: &["luac", "lua"],
        magic_hex: "1b 4c 75 61 (\\x1bLua)",
        magic: b"\x1bLua",
        description: "Compiled Lua script VM instructions",
        extension: "luac",
    },
];

#[derive(Parser, Debug)]
#[command(
    name = "memcarve",
    author = "DFIR Toolkit Team",
    version = "2.0.0 (SIMD Dictionary & Multi-Page Assembler)",
    about = "Ultra-Fast Raw Memory Carver with Header Dictionary & LIFO Reverse-Page Detection"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    #[arg(help = "Path to the memory dump (.raw, .dmp, .bin, LiME)")]
    file: Option<String>,

    #[arg(short = 's', long = "scan", help = "Anchor pattern / keyword to search")]
    scan: Option<String>,

    #[arg(short = 'c', long = "context", help = "Display surrounding page context (hexdump & strings preview)")]
    context: bool,

    #[arg(short = 'e', long = "extract", help = "Directory to save carved binaries")]
    extract: Option<String>,

    #[arg(short = 'o', long = "output", help = "Alias for --extract")]
    output: Option<String>,

    #[arg(short = 'a', long = "all", help = "Scan across all headers in the dictionary")]
    all: bool,

    #[arg(long = "dict", help = "Display supported file header dictionary")]
    show_dict: bool,

    #[arg(long = "offset", help = "Target physical offset of header")]
    offset: Option<String>,

    #[arg(long = "radius", default_value_t = 64, help = "Search radius in 4KB pages around anchor (default: 64 pages / 256KB)")]
    radius: usize,

    #[arg(short = 'l', long = "limit", default_value_t = 25, help = "Maximum search matches to process")]
    limit: usize,
}

#[derive(Subcommand, Debug)]
enum Commands {
    #[command(about = "Scan memory dump for binaries of specific type (or -a for all) containing an anchor string")]
    Scan {
        #[arg(help = "Path to the memory dump")]
        file: String,

        #[arg(help = "Target header type from dictionary (e.g. 'DEX', 'ELF', 'PE', 'ZIP') or pattern if -a")]
        arg1: String,

        #[arg(help = "Anchor string / keyword if target type was specified in arg1")]
        arg2: Option<String>,

        #[arg(short = 'a', long = "all", help = "Search across ALL headers in the dictionary")]
        all: bool,

        #[arg(short = 'c', long = "context", help = "Show surrounding memory page context (hexdump & strings)")]
        context: bool,

        #[arg(short = 'e', long = "extract", help = "Directory to extract/save assembled binaries")]
        extract: Option<String>,

        #[arg(short = 'o', long = "output", help = "Alias for --extract")]
        output: Option<String>,

        #[arg(long = "radius", default_value_t = 64, help = "Search radius in 4KB pages around anchor")]
        radius: usize,

        #[arg(short = 'l', long = "limit", default_value_t = 25, help = "Maximum matches to report")]
        limit: usize,
    },
    #[command(about = "Display the built-in dictionary of file headers and signatures")]
    Dict,
    #[command(about = "Inspect memory page context around a physical offset")]
    Context {
        #[arg(help = "Path to the memory dump")]
        file: String,
        #[arg(help = "Physical offset (Hex e.g. 0x65f85000 or Dec)")]
        offset: String,
        #[arg(short = 'r', long = "range", default_value_t = 4096, help = "Bytes to inspect")]
        range: usize,
    },
    #[command(about = "Carve and assemble binary from a known physical header offset")]
    Carve {
        #[arg(help = "Path to the memory dump")]
        file: String,
        #[arg(help = "Physical offset of binary header (Hex e.g. 0x65f86000)")]
        offset: String,
        #[arg(short = 'e', long = "extract", help = "Directory to save carved binary")]
        extract: Option<String>,
        #[arg(short = 'o', long = "output", help = "Alias for --extract")]
        output: Option<String>,
    },
}

#[derive(Debug, Clone)]
struct CarveCandidate {
    binary_type: BinaryType,
    header_offset: usize,
    file_size: usize,
    mode: AssemblyMode,
    is_valid: bool,
    checksum_info: String,
    assembled_data: Vec<u8>,
}

fn print_banner() {
    println!("{}", "================================================================================".cyan());
    println!("{}", "   🔬 MEMCARVE - Universal Raw Memory Carver & Heuristic Multi-Page Assembler   ".bold().bright_green());
    println!("{}", "   DFIR Unified Suite | SIMD Header Dictionary | LIFO Reverse-Page Detection   ".bright_yellow());
    println!("{}", "================================================================================".cyan());
}

fn print_dictionary() {
    println!("\n{}", "[+] BUILT-IN HEADER & MAGIC DICTIONARY:".bold().bright_green());
    let mut table = Table::new();
    table.load_preset(UTF8_ROUND_CORNERS);
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec![
        Cell::new("#").fg(Color::Yellow),
        Cell::new("Format / ID").fg(Color::Cyan),
        Cell::new("Magic Signature (Hex / ASCII)").fg(Color::Green),
        Cell::new("Aliases").fg(Color::White),
        Cell::new("Description & Integrity Validation").fg(Color::Yellow),
    ]);

    for (i, def) in FORMAT_DICTIONARY.iter().enumerate() {
        table.add_row(vec![
            Cell::new((i + 1).to_string()),
            Cell::new(def.id).fg(Color::Cyan).add_attribute(Attribute::Bold),
            Cell::new(def.magic_hex).fg(Color::Green),
            Cell::new(def.aliases.join(", ")).fg(Color::White),
            Cell::new(def.description),
        ]);
    }
    println!("{table}");
    println!("{}", "\nContoh Penggunaan dengan Dictionary:".bold().white());
    println!("  {} memcarve scan chall.raw DEX \"api/v1\" --context --extract ./out", "$".bright_yellow());
    println!("  {} memcarve scan chall.raw ELF \"botnet\" --extract ./out", "$".bright_yellow());
    println!("  {} memcarve scan chall.raw -a \"api/v1\" --extract ./out", "$".bright_yellow());
}

fn parse_offset(s: &str) -> Option<usize> {
    let s = s.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        usize::from_str_radix(&s[2..], 16).ok()
    } else {
        s.parse::<usize>().ok()
    }
}

fn compute_adler32(data: &[u8]) -> u32 {
    let mut s1: u32 = 1;
    let mut s2: u32 = 0;
    for &byte in data {
        s1 = (s1 + byte as u32) % 65521;
        s2 = (s2 + s1) % 65521;
    }
    (s2 << 16) | s1
}

fn extract_printable_strings(data: &[u8], min_len: usize) -> Vec<String> {
    let mut results = Vec::new();
    let mut current = Vec::new();

    for &b in data {
        if b >= 32 && b <= 126 {
            current.push(b);
        } else {
            if current.len() >= min_len {
                if let Ok(s) = String::from_utf8(current.clone()) {
                    results.push(s);
                }
            }
            current.clear();
        }
    }
    if current.len() >= min_len {
        if let Ok(s) = String::from_utf8(current) {
            results.push(s);
        }
    }
    results
}

fn print_hexdump(data: &[u8], base_offset: usize, max_len: usize) {
    let len = data.len().min(max_len);
    for chunk_start in (0..len).step_by(16) {
        let chunk_end = (chunk_start + 16).min(len);
        let chunk = &data[chunk_start..chunk_end];
        let addr = base_offset + chunk_start;

        let mut hex_part = String::new();
        for (i, &b) in chunk.iter().enumerate() {
            if i == 8 {
                hex_part.push(' ');
            }
            hex_part.push_str(&format!("{:02x} ", b));
        }
        while hex_part.len() < 50 {
            hex_part.push(' ');
        }

        let ascii_part: String = chunk
            .iter()
            .map(|&b| if b >= 32 && b <= 126 { b as char } else { '.' })
            .collect();

        println!(
            "  {}  {}  |{}|",
            format!("0x{:08x}", addr).bright_black(),
            hex_part.bright_cyan(),
            ascii_part.bright_white()
        );
    }
}

fn inspect_page_context(mmap: &[u8], offset: usize, range: usize) {
    let file_len = mmap.len();
    if offset >= file_len {
        println!("{}", "[!] Offset out of bounds.".red());
        return;
    }

    let page_base = offset & !0xFFF;
    let end = (page_base + range).min(file_len);
    let page_slice = &mmap[page_base..end];

    println!(
        "\n{} Anchor Match Offset: {} | Page Base: {} | Range: {} bytes",
        "[+] CONTEXT INSPECTION:".bold().bright_green(),
        format!("0x{:x} ({})", offset, offset).bold().yellow(),
        format!("0x{:x}", page_base).bold().cyan(),
        range.to_string().bold().white()
    );

    println!("\n{}", "--- Hex Dump Preview (First 512 bytes) ---".bright_black());
    print_hexdump(page_slice, page_base, 512);

    println!("\n{}", "--- Harvester: Strings of Interest in Page ---".bright_black());
    let strings = extract_printable_strings(page_slice, 4);
    let mut interesting = Vec::new();

    for s in strings {
        let s_lower = s.to_lowercase();
        if s_lower.contains("http://")
            || s_lower.contains("https://")
            || s_lower.contains("api/")
            || s_lower.contains("updater")
            || s_lower.contains("aes")
            || s_lower.contains("gcm")
            || s_lower.contains("com.")
            || s_lower.contains("dalvik")
            || s_lower.contains("dex")
            || s_lower.contains("apk")
            || s_lower.contains("elf")
            || s_lower.contains("exfil")
            || s_lower.contains("token")
            || s_lower.contains("secret")
            || s_lower.contains("seed")
            || s_lower.contains("sig")
            || s_lower.contains("blob")
            || s_lower.contains("/sdcard/")
            || s_lower.contains("/data/")
        {
            interesting.push(s);
        }
    }

    if interesting.is_empty() {
        println!("  {}", "No suspicious keywords detected in this page.".bright_black());
    } else {
        let mut table = Table::new();
        table.load_preset(UTF8_ROUND_CORNERS);
        table.set_content_arrangement(ContentArrangement::Dynamic);
        table.set_header(vec![
            Cell::new("#").fg(Color::Yellow),
            Cell::new("Category").fg(Color::Cyan),
            Cell::new("Detected String Artefact").fg(Color::Green),
        ]);

        let mut seen = HashSet::new();
        let mut count = 0;
        for item in interesting {
            if !seen.insert(item.clone()) {
                continue;
            }
            count += 1;
            let category = if item.contains("http") || item.contains("api") {
                "C2 / Network"
            } else if item.contains("AES") || item.contains("GCM") || item.contains("seed") || item.contains("sig") {
                "Crypto / Cipher"
            } else if item.contains("com.") || item.contains("dalvik") || item.contains("dex") {
                "Runtime / Class"
            } else {
                "Artifact"
            };

            table.add_row(vec![
                Cell::new(count.to_string()),
                Cell::new(category).fg(Color::Magenta),
                Cell::new(item),
            ]);
            if count >= 35 {
                break;
            }
        }
        println!("{table}");
    }
}

fn assemble_pages(mmap: &[u8], base_offset: usize, file_size: usize, mode: AssemblyMode) -> Option<Vec<u8>> {
    let file_len = mmap.len();
    if base_offset >= file_len || file_size == 0 {
        return None;
    }

    // SinglePage and ForwardLinear are physically contiguous
    if mode == AssemblyMode::SinglePage || mode == AssemblyMode::ForwardLinear || file_size <= 4096 {
        let end = (base_offset + file_size).min(file_len);
        return Some(mmap[base_offset..end].to_vec());
    }

    // Only ReverseLifo requires non-contiguous page reordering
    let num_pages = (file_size + 4095) / 4096;
    if num_pages > 4096 {
        return None; // Limit reverse reassembly to 16MB max
    }

    let page_base = base_offset & !0xFFF;
    let page_offset = base_offset % 4096;

    let mut assembled = Vec::with_capacity(num_pages * 4096);

    for p in 0..num_pages {
        if page_base < p * 4096 {
            return None;
        }
        let target_page = page_base - (p * 4096);
        if target_page + 4096 > file_len {
            return None;
        }

        let page_slice = &mmap[target_page..target_page + 4096];
        if p == 0 {
            assembled.extend_from_slice(&page_slice[page_offset..]);
        } else {
            assembled.extend_from_slice(page_slice);
        }
    }

    if assembled.len() > file_size {
        assembled.truncate(file_size);
    }
    Some(assembled)
}

fn try_carve_dex(mmap: &[u8], offset: usize) -> Option<CarveCandidate> {
    if offset + 112 > mmap.len() || !mmap[offset..].starts_with(b"dex\n") {
        return None;
    }

    let header = &mmap[offset..offset + 112];
    let file_size = u32::from_le_bytes(header[32..36].try_into().ok()?) as usize;
    let header_size = u32::from_le_bytes(header[36..40].try_into().ok()?) as usize;
    let endian_tag = u32::from_le_bytes(header[40..44].try_into().ok()?);

    if file_size < 112 || file_size > 50 * 1024 * 1024 || header_size != 112 || endian_tag != 0x12345678 {
        return None;
    }

    let expected_adler = u32::from_le_bytes(header[8..12].try_into().ok()?);
    let expected_sha1 = &header[12..32];

    // Try Forward Mode first (fast contiguous slice)
    let mut forward_cand = None;
    if let Some(f_data) = assemble_pages(mmap, offset, file_size, AssemblyMode::ForwardLinear) {
        if f_data.len() == file_size {
            let calc_adler = compute_adler32(&f_data[12..]);
            let is_valid = if calc_adler == expected_adler {
                let mut hasher = Sha1::new();
                hasher.update(&f_data[32..]);
                let calc_sha1 = hasher.finalize();
                calc_sha1.as_slice() == expected_sha1
            } else {
                false
            };

            let mode = if file_size <= 4096 { AssemblyMode::SinglePage } else { AssemblyMode::ForwardLinear };
            forward_cand = Some(CarveCandidate {
                binary_type: BinaryType::Dex,
                header_offset: offset,
                file_size,
                mode,
                is_valid,
                checksum_info: format!("{} | Adler32: 0x{:08x} (Valid: {})", if file_size <= 4096 { "Single Page" } else { "Forward Linear" }, calc_adler, is_valid),
                assembled_data: f_data,
            });
        }
    }

    if let Some(ref cand) = forward_cand {
        if cand.is_valid {
            return forward_cand;
        }
    }

    // Try Reverse LIFO Mode (for in-memory allocated multi-page binaries)
    if file_size <= 16 * 1024 * 1024 {
        if let Some(r_data) = assemble_pages(mmap, offset, file_size, AssemblyMode::ReverseLifo) {
            if r_data.len() == file_size {
                let calc_adler = compute_adler32(&r_data[12..]);
                if calc_adler == expected_adler {
                    let mut hasher = Sha1::new();
                    hasher.update(&r_data[32..]);
                    let calc_sha1 = hasher.finalize();
                    let is_valid = calc_sha1.as_slice() == expected_sha1;

                    if is_valid {
                        return Some(CarveCandidate {
                            binary_type: BinaryType::Dex,
                            header_offset: offset,
                            file_size,
                            mode: AssemblyMode::ReverseLifo,
                            is_valid: true,
                            checksum_info: format!("LIFO Reverse | Adler32: 0x{:08x} (MATCH 100%!)", calc_adler),
                            assembled_data: r_data,
                        });
                    }
                }
            }
        }
    }

    forward_cand
}

fn try_carve_elf(mmap: &[u8], offset: usize) -> Option<CarveCandidate> {
    if offset + 64 > mmap.len() || !mmap[offset..].starts_with(b"\x7fELF") {
        return None;
    }

    let header = &mmap[offset..offset + 64];
    let is_64 = header[4] == 2;
    let is_little = header[5] == 1;
    if !is_little {
        return None;
    }

    let (e_phoff, phnum, e_phentsize) = if is_64 {
        let phoff = u64::from_le_bytes(header[32..40].try_into().ok()?) as usize;
        let phentsize = u16::from_le_bytes(header[54..56].try_into().ok()?) as usize;
        let phnum = u16::from_le_bytes(header[56..58].try_into().ok()?) as usize;
        (phoff, phnum, phentsize)
    } else {
        let phoff = u32::from_le_bytes(header[28..32].try_into().ok()?) as usize;
        let phentsize = u16::from_le_bytes(header[42..44].try_into().ok()?) as usize;
        let phnum = u16::from_le_bytes(header[44..46].try_into().ok()?) as usize;
        (phoff, phnum, phentsize)
    };

    if phnum == 0 || phnum > 128 || e_phentsize == 0 {
        return None;
    }

    let mut max_span = e_phoff + (phnum * e_phentsize);
    let ph_end = offset + max_span;
    if ph_end > mmap.len() {
        return None;
    }

    for i in 0..phnum {
        let ph_offset = offset + e_phoff + (i * e_phentsize);
        if ph_offset + (if is_64 { 32 } else { 20 }) > mmap.len() {
            break;
        }
        let (p_offset, p_filesz) = if is_64 {
            let poff = u64::from_le_bytes(mmap[ph_offset + 8..ph_offset + 16].try_into().ok()?) as usize;
            let pfsz = u64::from_le_bytes(mmap[ph_offset + 32..ph_offset + 40].try_into().ok()?) as usize;
            (poff, pfsz)
        } else {
            let poff = u32::from_le_bytes(mmap[ph_offset + 4..ph_offset + 8].try_into().ok()?) as usize;
            let pfsz = u32::from_le_bytes(mmap[ph_offset + 16..ph_offset + 20].try_into().ok()?) as usize;
            (poff, pfsz)
        };
        let end_span = p_offset + p_filesz;
        if end_span > max_span && end_span < 50 * 1024 * 1024 {
            max_span = end_span;
        }
    }

    if max_span < 64 || max_span > 50 * 1024 * 1024 {
        return None;
    }

    let forward_data = assemble_pages(mmap, offset, max_span, AssemblyMode::ForwardLinear)?;
    Some(CarveCandidate {
        binary_type: BinaryType::Elf,
        header_offset: offset,
        file_size: max_span,
        mode: AssemblyMode::ForwardLinear,
        is_valid: true,
        checksum_info: format!("ELF ({}) | Headers: {} | Size: {} B", if is_64 { "64-bit" } else { "32-bit" }, phnum, max_span),
        assembled_data: forward_data,
    })
}

fn try_carve_pe(mmap: &[u8], offset: usize) -> Option<CarveCandidate> {
    if offset + 0x40 > mmap.len() || !mmap[offset..].starts_with(b"MZ") {
        return None;
    }

    let e_lfanew = u32::from_le_bytes(mmap[offset + 0x3C..offset + 0x40].try_into().ok()?) as usize;
    if e_lfanew < 0x40 || e_lfanew > 0x1000 || offset + e_lfanew + 4 > mmap.len() {
        return None;
    }

    if &mmap[offset + e_lfanew..offset + e_lfanew + 4] != b"PE\x00\x00" {
        return None;
    }

    let opt_hdr_offset = offset + e_lfanew + 24;
    if opt_hdr_offset + 60 > mmap.len() {
        return None;
    }

    let magic = u16::from_le_bytes(mmap[opt_hdr_offset..opt_hdr_offset + 2].try_into().ok()?);
    let size_of_image = if magic == 0x20b || magic == 0x10b {
        u32::from_le_bytes(mmap[opt_hdr_offset + 56..opt_hdr_offset + 60].try_into().ok()?) as usize
    } else {
        return None;
    };

    if size_of_image < 0x200 || size_of_image > 100 * 1024 * 1024 {
        return None;
    }

    let forward_data = assemble_pages(mmap, offset, size_of_image, AssemblyMode::ForwardLinear)?;
    Some(CarveCandidate {
        binary_type: BinaryType::Pe,
        header_offset: offset,
        file_size: size_of_image,
        mode: AssemblyMode::ForwardLinear,
        is_valid: true,
        checksum_info: format!("PE Binary | SizeOfImage: 0x{:x} ({} B)", size_of_image, size_of_image),
        assembled_data: forward_data,
    })
}

fn try_carve_zip(mmap: &[u8], offset: usize) -> Option<CarveCandidate> {
    if offset + 30 > mmap.len() || !mmap[offset..].starts_with(b"PK\x03\x04") {
        return None;
    }
    let search_limit = (offset + 100 * 1024 * 1024).min(mmap.len());
    let eocd_finder = memmem::Finder::new(b"PK\x05\x06");
    if let Some(eocd_rel) = eocd_finder.find(&mmap[offset..search_limit]) {
        let eocd_pos = offset + eocd_rel;
        if eocd_pos + 22 <= mmap.len() {
            let comment_len = u16::from_le_bytes(mmap[eocd_pos + 20..eocd_pos + 22].try_into().ok()?) as usize;
            let total_len = (eocd_pos + 22 + comment_len) - offset;
            if total_len > 30 && total_len <= 100 * 1024 * 1024 {
                let forward_data = assemble_pages(mmap, offset, total_len, AssemblyMode::ForwardLinear)?;
                return Some(CarveCandidate {
                    binary_type: BinaryType::Zip,
                    header_offset: offset,
                    file_size: total_len,
                    mode: AssemblyMode::ForwardLinear,
                    is_valid: true,
                    checksum_info: format!("ZIP / APK Archive | Size: {} B", total_len),
                    assembled_data: forward_data,
                });
            }
        }
    }
    None
}

fn try_carve_generic(mmap: &[u8], offset: usize, def: &FormatDef) -> Option<CarveCandidate> {
    if offset + def.magic.len() > mmap.len() || !mmap[offset..].starts_with(def.magic) {
        return None;
    }
    let default_len = 64 * 1024; // 64KB inspection window
    let end = (offset + default_len).min(mmap.len());
    let data = mmap[offset..end].to_vec();

    Some(CarveCandidate {
        binary_type: def.binary_type,
        header_offset: offset,
        file_size: data.len(),
        mode: AssemblyMode::SinglePage,
        is_valid: true,
        checksum_info: format!("{} Header | Magic: {}", def.name, def.magic_hex),
        assembled_data: data,
    })
}

fn try_carve_any_format(mmap: &[u8], offset: usize, target_type: BinaryType) -> Option<CarveCandidate> {
    match target_type {
        BinaryType::Dex => try_carve_dex(mmap, offset),
        BinaryType::Elf => try_carve_elf(mmap, offset),
        BinaryType::Pe => try_carve_pe(mmap, offset),
        BinaryType::Zip => try_carve_zip(mmap, offset),
        _ => {
            if let Some(def) = FORMAT_DICTIONARY.iter().find(|d| d.binary_type == target_type) {
                try_carve_generic(mmap, offset, def)
            } else {
                None
            }
        }
    }
}

fn resolve_format_filter(filter_str: &str, is_all: bool) -> Vec<&'static FormatDef> {
    if is_all || filter_str.eq_ignore_ascii_case("all") || filter_str.eq_ignore_ascii_case("-a") {
        return FORMAT_DICTIONARY.iter().collect();
    }

    let filter_clean = filter_str.trim().to_lowercase();
    let mut matches = Vec::new();

    for def in FORMAT_DICTIONARY {
        if def.id.eq_ignore_ascii_case(&filter_clean)
            || def.name.to_lowercase().contains(&filter_clean)
            || def.aliases.iter().any(|&a| a.eq_ignore_ascii_case(&filter_clean))
        {
            matches.push(def);
        }
    }
    matches
}

fn execute_carve_action(candidates: &[CarveCandidate], extract_dir: Option<&str>) {
    if candidates.is_empty() {
        println!("{}", "[!] No valid binary headers detected in the specified range.".yellow());
        return;
    }

    let mut table = Table::new();
    table.load_preset(UTF8_ROUND_CORNERS);
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec![
        Cell::new("#").fg(Color::Yellow),
        Cell::new("Format Type").fg(Color::Cyan),
        Cell::new("Header Offset").fg(Color::Green),
        Cell::new("File Size").fg(Color::White),
        Cell::new("Assembly Mode").fg(Color::Magenta),
        Cell::new("Integrity / Status").fg(Color::Green),
    ]);

    for (idx, cand) in candidates.iter().enumerate() {
        let mode_str = match cand.mode {
            AssemblyMode::SinglePage => "Single Frame",
            AssemblyMode::ForwardLinear => "Forward Linear (P0, P1..)",
            AssemblyMode::ReverseLifo => "REVERSE LIFO (P0, P-1..)",
        };

        let type_str = match cand.binary_type {
            BinaryType::Dex => "Android DEX",
            BinaryType::Elf => "Linux ELF",
            BinaryType::Pe => "Windows PE",
            BinaryType::Zip => "ZIP / APK",
            BinaryType::SevenZip => "7-Zip Archive",
            BinaryType::Pdf => "PDF Document",
            BinaryType::Png => "PNG Image",
            BinaryType::Jpg => "JPEG Image",
            BinaryType::Gzip => "GZIP Stream",
            BinaryType::Tar => "POSIX Tar",
            BinaryType::Sqlite => "SQLite DB",
            BinaryType::Wasm => "WebAssembly",
            BinaryType::Pcap => "PCAP Capture",
            BinaryType::PcapNg => "PCAPNG Capture",
            BinaryType::Luac => "Lua Bytecode",
        };

        let status_cell = if cand.is_valid {
            Cell::new(format!("✓ VALID ({})", cand.checksum_info)).fg(Color::Green)
        } else {
            Cell::new(format!("? UNVERIFIED ({})", cand.checksum_info)).fg(Color::Yellow)
        };

        table.add_row(vec![
            Cell::new((idx + 1).to_string()),
            Cell::new(type_str).add_attribute(Attribute::Bold),
            Cell::new(format!("0x{:08x}", cand.header_offset)).fg(Color::Green),
            Cell::new(format!("{} B", cand.file_size)),
            Cell::new(mode_str).fg(Color::Magenta).add_attribute(Attribute::Bold),
            status_cell,
        ]);
    }

    println!("\n{}", "[+] HEURISTIC MULTI-PAGE BINARY RECONSTRUCTION:".bold().bright_green());
    println!("{table}");

    if let Some(out_dir_str) = extract_dir {
        let out_dir = Path::new(out_dir_str);
        if let Err(e) = fs::create_dir_all(out_dir) {
            eprintln!("{} Failed to create output directory {}: {}", "[!]".red(), out_dir_str, e);
            return;
        }

        println!("\n{}", "[+] EXTRACTING CARVED ARTIFACTS:".bold().bright_green());
        for (_idx, cand) in candidates.iter().enumerate() {
            let ext = match cand.binary_type {
                BinaryType::Dex => "dex",
                BinaryType::Elf => "elf",
                BinaryType::Pe => "exe",
                BinaryType::Zip => "zip",
                BinaryType::SevenZip => "7z",
                BinaryType::Pdf => "pdf",
                BinaryType::Png => "png",
                BinaryType::Jpg => "jpg",
                BinaryType::Gzip => "gz",
                BinaryType::Tar => "tar",
                BinaryType::Sqlite => "db",
                BinaryType::Wasm => "wasm",
                BinaryType::Pcap => "pcap",
                BinaryType::PcapNg => "pcapng",
                BinaryType::Luac => "luac",
            };
            let mode_tag = match cand.mode {
                AssemblyMode::SinglePage => "single",
                AssemblyMode::ForwardLinear => "forward",
                AssemblyMode::ReverseLifo => "reverse",
            };
            let filename = format!("carved_0x{:08x}_{}_{}.{}", cand.header_offset, ext, mode_tag, ext);
            let out_path = out_dir.join(&filename);

            match File::create(&out_path) {
                Ok(mut file) => {
                    if let Err(e) = file.write_all(&cand.assembled_data) {
                        eprintln!("  {} Failed to write {}: {}", "[!]".red(), out_path.display(), e);
                    } else {
                        let mut sha256_hasher = Sha256::new();
                        sha256_hasher.update(&cand.assembled_data);
                        let sha256_hex = hex::encode(sha256_hasher.finalize());

                        println!(
                            "  {} Saved: {} ({}) | SHA256: {}",
                            "✓".bold().green(),
                            out_path.display().to_string().bold().bright_white(),
                            format!("{} bytes", cand.file_size).cyan(),
                            sha256_hex.bright_black()
                        );
                    }
                }
                Err(e) => eprintln!("  {} Failed to create file {}: {}", "[!]".red(), out_path.display(), e),
            }
        }
    } else {
        println!(
            "\n{} To save reconstructed binaries to disk, pass: {} or {}",
            "[*]".yellow(),
            "-e <DIR>".bold().white(),
            "--extract <DIR>".bold().white()
        );
    }
}

fn search_binaries_with_string(
    mmap: &[u8],
    formats: &[&FormatDef],
    needle: &str,
    show_context: bool,
    extract_dir: Option<&str>,
    radius_pages: usize,
    limit: usize,
) {
    let start_time = Instant::now();
    let format_names: Vec<&str> = formats.iter().map(|f| f.id).collect();
    println!(
        "\n{} Searching for binaries [{}] containing string '{}' across {} ...",
        "[+] DICTIONARY-DRIVEN SCAN:".bold().bright_green(),
        format_names.join(", ").bold().cyan(),
        needle.bold().yellow(),
        format!("{:.2} GB", mmap.len() as f64 / (1024.0 * 1024.0 * 1024.0)).cyan()
    );

    let needle_bytes = needle.as_bytes();
    let needle_finder = memmem::Finder::new(needle_bytes);
    let mut needle_matches = Vec::new();

    for pos in needle_finder.find_iter(mmap) {
        needle_matches.push(pos);
        if needle_matches.len() >= 10000 {
            break;
        }
    }

    let elapsed = start_time.elapsed();
    println!(
        "{} Found {} string occurrences of '{}' across RAM in {:.3} seconds.",
        "[✓]".bold().green(),
        needle_matches.len().to_string().bold().yellow(),
        needle.cyan(),
        elapsed.as_secs_f64()
    );
    let _ = std::io::stdout().flush();

    if needle_matches.is_empty() {
        println!("{}", "[!] String not found in physical memory dump.".yellow());
        return;
    }

    // Deduplicate needle matches by 4KB page to prevent redundant radius searches
    let mut unique_pages = Vec::new();
    let mut seen_pages = HashSet::new();
    for &pos in &needle_matches {
        let p = pos & !0xFFF;
        if seen_pages.insert(p) {
            unique_pages.push((p, pos));
        }
    }

    let mut confirmed_candidates = Vec::new();
    let mut seen_headers = HashSet::new();
    let mut matched_needle_positions = Vec::new();

    let radius_bytes = radius_pages * 4096;

    for &(page_base, needle_pos) in &unique_pages {
        let start = page_base.saturating_sub(radius_bytes);
        let end = (page_base + radius_bytes + 4096).min(mmap.len());
        let slice = &mmap[start..end];

        for format in formats {
            let magic_finder = memmem::Finder::new(format.magic);
            for pos in magic_finder.find_iter(slice) {
                let abs_header_pos = start + pos;
                if !seen_headers.insert((format.binary_type, abs_header_pos)) {
                    continue;
                }

                // Quick pre-validation: only invoke full carver if header looks valid
                let quick_valid = match format.binary_type {
                    BinaryType::Dex => {
                        if abs_header_pos + 44 <= mmap.len() {
                            let endian_tag = u32::from_le_bytes(mmap[abs_header_pos + 40..abs_header_pos + 44].try_into().unwrap_or([0; 4]));
                            endian_tag == 0x12345678
                        } else {
                            false
                        }
                    }
                    BinaryType::Elf => {
                        if abs_header_pos + 6 <= mmap.len() {
                            mmap[abs_header_pos + 5] == 1 // Little-endian
                        } else {
                            false
                        }
                    }
                    BinaryType::Pe => {
                        if abs_header_pos + 0x40 <= mmap.len() {
                            let e_lfanew = u32::from_le_bytes(mmap[abs_header_pos + 0x3C..abs_header_pos + 0x40].try_into().unwrap_or([0; 4])) as usize;
                            e_lfanew >= 0x40 && e_lfanew <= 0x1000 && abs_header_pos + e_lfanew + 4 <= mmap.len() && &mmap[abs_header_pos + e_lfanew..abs_header_pos + e_lfanew + 4] == b"PE\x00\x00"
                        } else {
                            false
                        }
                    }
                    _ => true,
                };

                if !quick_valid {
                    continue;
                }

                if let Some(cand) = try_carve_any_format(mmap, abs_header_pos, format.binary_type) {
                    let data = &cand.assembled_data;
                    let contains_needle = data.windows(needle_bytes.len()).any(|w| w == needle_bytes);

                    if contains_needle {
                        println!(
                            "  {} MATCH: [{}] Header at {} contains '{}' ({}, Size: {} B)",
                            "✓".bold().bright_green(),
                            format.id.bold().cyan(),
                            format!("0x{:08x}", abs_header_pos).bold().green(),
                            needle.bold().yellow(),
                            cand.checksum_info.magenta(),
                            cand.file_size.to_string().white()
                        );
                        let _ = std::io::stdout().flush();
                        matched_needle_positions.push(needle_pos);
                        confirmed_candidates.push(cand);
                        if confirmed_candidates.len() >= limit {
                            break;
                        }
                    }
                }
            }
            if confirmed_candidates.len() >= limit {
                break;
            }
        }
        if confirmed_candidates.len() >= limit {
            break;
        }
    }

    // Context Inspection on confirmed matches (or first occurrences if no candidate)
    if show_context {
        if !matched_needle_positions.is_empty() {
            for &pos in matched_needle_positions.iter().take(2) {
                inspect_page_context(mmap, pos, 4096);
            }
        } else {
            for &pos in needle_matches.iter().take(2) {
                inspect_page_context(mmap, pos, 4096);
            }
        }
    }

    if !confirmed_candidates.is_empty() {
        execute_carve_action(&confirmed_candidates, extract_dir);
    } else {
        println!(
            "\n{} String '{}' was found in memory, but no valid [{}] headers encompassed it within {} pages radius.",
            "[!]".yellow(),
            needle,
            format_names.join(", "),
            radius_pages
        );
        println!("  Tip: Coba perbesar radius dengan '--radius 256' atau periksa context memori.");
    }
}

fn normalize_cli_args() -> Vec<String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        return args;
    }

    // Check if user ran: memcarve <FILE> scan ...
    // and normalize to: memcarve scan <FILE> ...
    let first = &args[1];
    let second = &args[2];

    if !first.starts_with('-') && (second == "scan" || second == "context" || second == "carve") {
        let mut new_args = Vec::new();
        new_args.push(args[0].clone());
        new_args.push(second.clone());
        new_args.push(first.clone());
        new_args.extend_from_slice(&args[3..]);
        return new_args;
    }

    args
}

fn main() {
    let normalized = normalize_cli_args();
    let cli = match Cli::try_parse_from(&normalized) {
        Ok(c) => c,
        Err(e) => {
            print_banner();
            e.exit();
        }
    };

    print_banner();

    if cli.show_dict {
        print_dictionary();
        return;
    }

    if let Some(Commands::Dict) = cli.command {
        print_dictionary();
        return;
    }

    let (file_path, target_type_str, pattern_str, is_all, show_ctx, extract_d, radius, limit) = match cli.command {
        Some(Commands::Scan { file, arg1, arg2, all, context, extract, output, radius, limit }) => {
            let out_dir = extract.or(output);
            if all || arg1.eq_ignore_ascii_case("-a") {
                // memcarve scan chall.raw -a "api/v1"
                let pattern = arg2.unwrap_or(arg1);
                (file, "ALL".to_string(), pattern, true, context, out_dir, radius, limit)
            } else if let Some(p) = arg2 {
                // memcarve scan chall.raw DEX "api/v1"
                (file, arg1, p, false, context, out_dir, radius, limit)
            } else {
                // memcarve scan chall.raw "api/v1" (default to ALL)
                (file, "ALL".to_string(), arg1, true, context, out_dir, radius, limit)
            }
        }
        Some(Commands::Context { file, offset, range }) => {
            if let Ok(mmap) = unsafe { Mmap::map(&File::open(Path::new(&file)).expect("Cannot open file")) } {
                if let Some(off) = parse_offset(&offset) {
                    inspect_page_context(&mmap, off, range);
                }
            }
            return;
        }
        Some(Commands::Carve { file, offset, extract, output }) => {
            if let Ok(mmap) = unsafe { Mmap::map(&File::open(Path::new(&file)).expect("Cannot open file")) } {
                if let Some(off) = parse_offset(&offset) {
                    let mut cands = Vec::new();
                    for def in FORMAT_DICTIONARY {
                        if let Some(c) = try_carve_any_format(&mmap, off, def.binary_type) {
                            cands.push(c);
                            break;
                        }
                    }
                    execute_carve_action(&cands, extract.or(output).as_deref());
                }
            }
            return;
        }
        Some(Commands::Dict) => unreachable!(),
        None => {
            if let (Some(f), Some(p)) = (cli.file, cli.scan) {
                (f, if cli.all { "ALL".to_string() } else { "ALL".to_string() }, p, cli.all, cli.context, cli.extract.or(cli.output), cli.radius, cli.limit)
            } else {
                println!("\n{} Silakan gunakan format perintah berikut:", "[*]".yellow());
                println!("  memcarve scan <FILE> <FORMAT> <STRING> [--context] [--extract <DIR>]");
                println!("  memcarve scan <FILE> -a <STRING> [--context] [--extract <DIR>]");
                println!("  memcarve dict");
                println!("\nContoh Nyata:");
                println!("  memcarve scan chall.raw DEX \"api/v1\" --context --extract ./output");
                println!("  memcarve scan chall.raw -a \"api/v1\" --extract ./output");
                return;
            }
        }
    };

    let path = Path::new(&file_path);
    if !path.exists() {
        eprintln!("\n{} File tidak ditemukan: {}", "[!]".red(), file_path);
        return;
    }

    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("\n{} Gagal membuka file {}: {}", "[!]".red(), file_path, e);
            return;
        }
    };

    let mmap = match unsafe { Mmap::map(&file) } {
        Ok(m) => m,
        Err(e) => {
            eprintln!("\n{} Gagal memory mapping: {}", "[!]".red(), e);
            return;
        }
    };

    let resolved_formats = resolve_format_filter(&target_type_str, is_all);
    if resolved_formats.is_empty() {
        eprintln!("\n{} Format '{}' tidak ditemukan di dictionary!", "[!]".red(), target_type_str);
        println!("Jalankan 'memcarve dict' untuk melihat daftar header yang didukung.");
        return;
    }

    search_binaries_with_string(
        &mmap,
        &resolved_formats,
        &pattern_str,
        show_ctx,
        extract_d.as_deref(),
        radius,
        limit,
    );
}
