use std::collections::HashSet;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::time::Instant;

use aho_corasick::AhoCorasick;
use clap::Parser;
use colored::*;
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Attribute, Cell, Color, ContentArrangement, Table};
use memmap2::Mmap;
use md5::Md5;
use md5::Digest;
use rayon::prelude::*;
use regex::bytes::Regex as BytesRegex;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::Sha256;

#[derive(Parser, Debug)]
#[command(
    name = "globalscan2",
    author = "DFIR Toolkit Team",
    version = "2.0.0 (Zero-Copy SIMD)",
    about = "Ultra-Fast Universal Forensic File Scanner & CTF Flag Hunter"
)]
struct Cli {
    #[arg(help = "Path to the evidence/dump/capture file")]
    file: Option<String>,

    #[arg(short = 'f', long = "file", help = "Explicit path to file")]
    file_flag: Option<String>,

    #[arg(short = 'p', long = "prefix", help = "Custom CTF flag prefix (e.g. 'FLAG', 'HTB')")]
    prefix: Option<String>,

    #[arg(long = "flags-only", help = "Display only captured CTF flags")]
    flags_only: bool,

    #[arg(long = "keywords-only", help = "Display only sensitive keywords/tokens")]
    keywords_only: bool,

    #[arg(long = "meta-only", help = "Display only file metadata, hashes & magic")]
    meta_only: bool,

    #[arg(short = 'l', long = "limit", default_value_t = 50, help = "Limit rows in tables")]
    limit: usize,

    #[arg(long = "md", help = "Export report to Markdown (.md)")]
    md: Option<String>,

    #[arg(long = "json", help = "Export report to JSON (.json)")]
    json: Option<String>,

    #[arg(long = "export-all", help = "Auto-export Markdown and JSON reports")]
    export_all: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct FlagMatch {
    flag: String,
    encoding: String,
    offset: String,
    length: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct KeywordMatch {
    category: String,
    matched_value: String,
    context: String,
    offset: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct FileMeta {
    filename: String,
    size_bytes: u64,
    size_human: String,
    entropy: f64,
    file_type: String,
    md5: String,
    sha1: String,
    sha256: String,
}

fn human_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * 1024;
    const GB: u64 = 1024 * 1024 * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0f64;
    for &count in &counts {
        if count > 0 {
            let p = (count as f64) / len;
            entropy -= p * p.log2();
        }
    }
    (entropy * 1000.0).round() / 1000.0
}

fn detect_magic_signature(data: &[u8]) -> &'static str {
    let sigs: &[(&[u8], &'static str)] = &[
        (b"\x7fELF", "Linux ELF Executable / Object"),
        (b"MZ", "Windows PE Executable / DLL (MZ Header)"),
        (b"\x21\x42\x44\x4e\x00\x00\x00\x00", "AccessData Logical Image (AD1)"),
        (b"\xd4\xc3\xb2\xa1", "PCAP Capture File (Little-Endian)"),
        (b"\xa1\xb2\xc3\xd4", "PCAP Capture File (Big-Endian)"),
        (b"\x4d\x3c\x2b\x1a", "PCAP Capture File (Nanosecond LE)"),
        (b"\x0a\x0d\x0d\x0a", "PCAPNG Next Generation Capture"),
        (b"MDMP", "Windows MiniDump Crash Dump (MDMP)"),
        (b"PAGE", "Windows Complete / Kernel Memory Dump (PAGE)"),
        (b"CART\x01\x00", "CaRT (Compressed & Redacted Target)"),
        (b"CART", "CaRT Container File"),
        (b"\x00asm\x01\x00\x00\x00", "WebAssembly Binary Module"),
        (b"PK\x03\x04", "ZIP / Office OpenXML / APK Archive"),
        (b"Rar!\x1a\x07\x00", "RAR 4.x Archive"),
        (b"Rar!\x1a\x07\x01\x00", "RAR 5.x Archive"),
        (b"7z\xbc\xaf\x27\x1c", "7-Zip Archive"),
        (b"\x1f\x8b\x08", "GZIP Compressed File"),
        (b"BZh", "BZIP2 Compressed Archive"),
        (b"\xfd7zXZ\x00", "XZ Compressed Archive"),
        (b"\x28\xb5\x2f\xfd", "Zstandard Compressed Archive"),
        (b"%PDF-", "Adobe Portable Document (PDF)"),
        (b"\x89PNG\r\n\x1a\n", "PNG Image"),
        (b"\xff\xd8\xff", "JPEG Image"),
        (b"GIF87a", "GIF Image (87a)"),
        (b"GIF89a", "GIF Image (89a)"),
        (b"BM", "Bitmap Image (BMP)"),
        (b"SQLite format 3\x00", "SQLite 3 Database"),
        (b"KDBX", "KeePass Password Database"),
    ];

    for &(sig, desc) in sigs {
        if data.starts_with(sig) {
            return desc;
        }
    }
    "Unknown Binary / Raw Data"
}

fn is_valid_flag(s: &str) -> bool {
    if s.len() < 6 || s.len() > 250 {
        return false;
    }
    // Check ASCII printable only
    if !s.bytes().all(|b| (32..=126).contains(&b)) {
        return false;
    }
    // Must contain '{' and end with '}'
    let open_idx = match s.find('{') {
        Some(idx) => idx,
        None => return false,
    };
    if !s.ends_with('}') {
        return false;
    }

    let prefix = &s[..open_idx];
    let inner = &s[open_idx + 1..s.len() - 1];

    // Inner content inside braces must be at least 3 chars
    if inner.trim().len() < 3 {
        return false;
    }

    // Reject placeholder words like {GROUP}, {NAME}, {ID}, {VALUE}, {PYTHON_CODE}
    let inner_lower = inner.to_ascii_lowercase();
    const PLACEHOLDERS: &[&str] = &[
        "group", "name", "id", "value", "values", "key", "param", "arg",
        "args", "item", "path", "fmt", "type", "str", "string", "int", "bool",
        "choice", "choices", "format", "formats", "command", "packages",
        "python_code", "sql_query", "markdown_content", "attrs_str", "import_str",
        "mount_config", "extra_message", "arbitrary_string", "digest_name",
        "sha256", "number_type", "range", "number_color", "number_stroke",
    ];
    if PLACEHOLDERS.contains(&inner_lower.as_str()) {
        return false;
    }

    if !prefix.is_empty() {
        let pref_lower = prefix.to_ascii_lowercase();
        const REJECT_PREFIXES: &[&str] = &[
            "frac", "text", "sqrt", "left", "right", "begin", "end", "mathbf",
            "mathit", "mathrm", "overline", "underline", "mathcal", "download",
            "deprecated", "required", "format", "style", "color", "include",
            "import", "export", "default", "select", "update", "insert",
            "delete", "define", "struct", "class", "enum", "fn", "def", "pub",
            "var", "let", "const", "return", "function", "self", "this",
        ];
        if REJECT_PREFIXES.contains(&pref_lower.as_str()) {
            return false;
        }
        // Flag prefix must start with an ASCII letter
        if !prefix.chars().next().map(|c| c.is_ascii_alphabetic()).unwrap_or(false) {
            return false;
        }
        // Reject prefix ending with '.' or '-'
        if prefix.ends_with('.') || prefix.ends_with('-') {
            return false;
        }
        // LaTeX subscript like y_{t - 1}
        if prefix.ends_with('_') && (inner.contains(' ') || inner.contains('-') || inner.contains('+')) {
            return false;
        }
    } else {
        // Bare braces: {something}
        if inner.len() < 8 {
            return false;
        }
        // Reject python format string modifiers or expressions
        if inner.contains("!r") || inner.contains("!s") || inner.contains("!a")
            || inner.contains('(') || inner.contains(')') || inner.contains('/')
            || inner.contains('.') || inner.contains('\\') || inner.contains(':')
            || inner.contains(' ')
        {
            return false;
        }
        // Must contain numbers, special CTF chars, or underscores
        let has_digit = inner.chars().any(|c| c.is_ascii_digit());
        let has_special = inner.chars().any(|c| matches!(c, '_' | '-' | '@' | '!' | '$' | '%'));
        if !has_digit && !has_special {
            return false;
        }
    }

    true
}

fn is_valid_credential_value(val: &str) -> bool {
    let trimmed = val.trim();
    if trimmed.len() < 4 || trimmed.len() > 100 {
        return false;
    }
    // Must be printable ASCII only
    if !trimmed.bytes().all(|b| (32..=126).contains(&b)) {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();

    // Reject docstring words, documentation keywords, and dummy tokens
    const DOCSTRING_WORDS: &[&str] = &[
        "type", "string", "str", "int", "bool", "float", "dict", "list", "tuple",
        "object", "bytes", "none", "null", "unique", "optional", "available",
        "direct", "default", "required", "expected", "raises", "param", "entity",
        "description", "property", "override", "rride", "returns", "example",
        "unknown", "inherited", "whether", "value", "values", "variable", "true",
        "false", "empty", "undefined", "placeholder", "eof", "the", "an", "a",
        "this", "that", "document", "hash", "path", "file", "message", "stdin",
        "stdout", "stderr", "prompt", "input", "help", "usage", "test", "sample",
        "dummy", "todo", "secret", "password", "token", "admin", "root",
        "invalid", "error", "warning", "info", "debug", "critical", "legacy",
    ];
    if DOCSTRING_WORDS.contains(&lower.as_str()) {
        return false;
    }
    if lower.starts_with("http://") || lower.starts_with("https://") || lower.starts_with("ftp://") {
        return false;
    }
    // Reject if value contains another colon like "type: string"
    if trimmed.contains(':') {
        return false;
    }
    // If quotes are present, strip them and re-check
    let clean_val = trimmed.trim_matches(|c| c == '\'' || c == '"');
    if clean_val.len() < 4 {
        return false;
    }
    if DOCSTRING_WORDS.contains(&clean_val.to_ascii_lowercase().as_str()) {
        return false;
    }

    true
}

/// Zero-Copy Parallel Regex Flag Hunter directly on raw bytes
fn parallel_scan_flags(data: &[u8], custom_prefix: Option<&str>) -> Vec<FlagMatch> {
    let default_regex = BytesRegex::new(
        r"(?i)(?:[A-Za-z][A-Za-z0-9_]{1,30}\{[^}\r\n]{3,200}\})|(?:\{(?:flag|ctf)[A-Za-z0-9_!@#\$%\^&\*\-\+=\.]{3,120}\})|(?:flag\[[A-Za-z0-9_\-\s]{3,100}\])"
    ).unwrap();

    let custom_regex = custom_prefix.map(|p| {
        let esc = regex::escape(p);
        BytesRegex::new(&format!(r"(?i){}\{{[^}}\r\n]{{2,200}}\}}", esc)).unwrap()
    });

    let chunk_size = 4 * 1024 * 1024; // 4MB chunks
    let overlap = 4096;

    let chunks: Vec<(usize, &[u8])> = if data.len() <= chunk_size {
        vec![(0, data)]
    } else {
        let mut list = Vec::new();
        let mut start = 0;
        while start < data.len() {
            let end = std::cmp::min(data.len(), start + chunk_size + overlap);
            list.push((start, &data[start..end]));
            start += chunk_size;
        }
        list
    };

    chunks
        .into_par_iter()
        .flat_map(|(chunk_offset, chunk)| {
            let mut matches = Vec::new();

            if let Some(ref cr) = custom_regex {
                for m in cr.find_iter(chunk) {
                    if let Ok(s) = std::str::from_utf8(m.as_bytes()) {
                        let val = s.trim();
                        if is_valid_flag(val) {
                            matches.push(FlagMatch {
                                flag: val.to_string(),
                                encoding: "ASCII (Custom Prefix)".to_string(),
                                offset: format!("0x{:X}", chunk_offset + m.start()),
                                length: val.len(),
                            });
                        }
                    }
                }
            }

            for m in default_regex.find_iter(chunk) {
                if let Ok(s) = std::str::from_utf8(m.as_bytes()) {
                    let val = s.trim();
                    if is_valid_flag(val) {
                        matches.push(FlagMatch {
                            flag: val.to_string(),
                            encoding: "ASCII".to_string(),
                            offset: format!("0x{:X}", chunk_offset + m.start()),
                            length: val.len(),
                        });
                    }
                }
            }

            matches
        })
        .collect()
}

/// Zero-Copy Parallel Base64 Carving directly on bytes
fn parallel_scan_base64(data: &[u8]) -> Vec<FlagMatch> {
    let b64_re = BytesRegex::new(r"[A-Za-z0-9+/]{16,}={0,2}").unwrap();
    let flag_re = BytesRegex::new(r"(?i)(?:[A-Za-z][A-Za-z0-9_]{1,30}\{[^}\r\n]{3,200}\})|(?:\{(?:flag|ctf)[A-Za-z0-9_!@#\$%\^&\*\-\+=\.]{3,120}\})").unwrap();

    let chunk_size = 4 * 1024 * 1024;
    let overlap = 1024;

    let chunks: Vec<(usize, &[u8])> = if data.len() <= chunk_size {
        vec![(0, data)]
    } else {
        let mut list = Vec::new();
        let mut start = 0;
        while start < data.len() {
            let end = std::cmp::min(data.len(), start + chunk_size + overlap);
            list.push((start, &data[start..end]));
            start += chunk_size;
        }
        list
    };

    chunks
        .into_par_iter()
        .flat_map(|(chunk_offset, chunk)| {
            let mut matches = Vec::new();
            use base64::Engine;

            for m in b64_re.find_iter(chunk) {
                if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(m.as_bytes()) {
                    for fm in flag_re.find_iter(&decoded) {
                        if let Ok(s) = std::str::from_utf8(fm.as_bytes()) {
                            let val = s.trim();
                            if is_valid_flag(val) {
                                matches.push(FlagMatch {
                                    flag: val.to_string(),
                                    encoding: "Base64 Decoded".to_string(),
                                    offset: format!("0x{:X}", chunk_offset + m.start()),
                                    length: val.len(),
                                });
                            }
                        }
                    }
                }
            }
            matches
        })
        .collect()
}

/// Ultra-Fast Single-Pass Aho-Corasick SIMD XOR Scanner
fn scan_xor_flags_simd(data: &[u8]) -> Vec<FlagMatch> {
    let targets = [
        b"flag{" as &[u8],
        b"FLAG{",
        b"ctf{",
        b"CTF{",
        b"htb{",
        b"HTB{",
    ];

    let sample_size = std::cmp::min(data.len(), 16 * 1024 * 1024); // 16MB sample matches Python globalscan
    let sample = &data[..sample_size];

    // Build all 1530 patterns (255 keys * 6 target headers)
    let mut patterns = Vec::with_capacity(255 * targets.len());
    let mut pattern_meta = Vec::with_capacity(255 * targets.len());

    for key in 1u8..=255u8 {
        for &tgt in &targets {
            let x_tgt: Vec<u8> = tgt.iter().map(|&b| b ^ key).collect();
            patterns.push(x_tgt);
            pattern_meta.push(key);
        }
    }

    let ac = match AhoCorasick::new(&patterns) {
        Ok(a) => a,
        Err(_) => return Vec::new(),
    };

    let mut matches = Vec::new();
    let mut seen = HashSet::new();

    for m in ac.find_iter(sample) {
        let pattern_id = m.pattern().as_usize();
        let key = pattern_meta[pattern_id];
        let pos = m.start();

        let mut dec = Vec::new();
        let end = std::cmp::min(sample.len(), pos + 220);
        for &b in &sample[pos..end] {
            let d = b ^ key;
            if d == b'}' {
                dec.push(d);
                break;
            } else if (32..=126).contains(&d) {
                dec.push(d);
            } else {
                break;
            }
        }

        if let Ok(s) = String::from_utf8(dec) {
            if s.ends_with('}') && is_valid_flag(&s) && seen.insert(s.clone()) {
                matches.push(FlagMatch {
                    flag: s.clone(),
                    encoding: format!("XOR 0x{:02X}", key),
                    offset: format!("0x{:X}", pos),
                    length: s.len(),
                });
            }
        }
    }

    matches
}

/// Zero-Copy Parallel Sensitive Keyword Hunter directly on bytes
fn parallel_scan_keywords(data: &[u8]) -> Vec<KeywordMatch> {
    let patterns: &[(&'static str, &'static str)] = &[
        ("Passwords & Credentials", r"(?i)\b(?:password|passwd|pwd|secret|db_pass(?:word)?)[ \t]*[:=][ \t]*['\x22]?([A-Za-z0-9_\-!@#\$%\^&\*\.+=~]{3,64})['\x22]?"),
        ("API Keys & Access Tokens", r"(?i)\b(?:access[_-]?token|api[_-]?key|auth[_-]?token|bearer|token)[ \t]*[:=][ \t]*['\x22]?([A-Za-z0-9_\-!@#\$%\^&\*\.+=~]{3,64})['\x22]?"),
        ("AWS Keys", r"\bAKIA[0-9A-Z]{16}\b"),
        ("GitHub Token", r"\bgh[pousr]_[A-Za-z0-9_]{36,255}\b"),
        ("JWT Access Token", r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
        ("Discord Webhook", r"https?://(?:discord\.com|discordapp\.com)/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+"),
        ("Private Key", r"-----BEGIN\s+[A-Z\s]+PRIVATE\s+KEY-----"),
        ("Forensic Clues & C2", r"(?i)\b(?:mimikatz|base64_decode|eval\(|shell_exec|cmd\.exe|powershell\.exe|/bin/sh|/bin/bash)\b"),
    ];

    let compiled: Vec<(&'static str, BytesRegex)> = patterns
        .iter()
        .map(|&(cat, pat)| (cat, BytesRegex::new(pat).unwrap()))
        .collect();

    let chunk_size = 4 * 1024 * 1024;
    let overlap = 1024;

    let chunks: Vec<(usize, &[u8])> = if data.len() <= chunk_size {
        vec![(0, data)]
    } else {
        let mut list = Vec::new();
        let mut start = 0;
        while start < data.len() {
            let end = std::cmp::min(data.len(), start + chunk_size + overlap);
            list.push((start, &data[start..end]));
            start += chunk_size;
        }
        list
    };

    chunks
        .into_par_iter()
        .flat_map(|(chunk_offset, chunk)| {
            let mut matches = Vec::new();
            for (cat, re) in &compiled {
                for caps in re.captures_iter(chunk) {
                    let m = match caps.get(0) {
                        Some(m) => m,
                        None => continue,
                    };

                    // Check all bytes in full match are printable ASCII
                    if !m.as_bytes().iter().all(|&b| (32..=126).contains(&b)) {
                        continue;
                    }

                    // If pattern has a captured value (group 1), validate it
                    if let Some(c1) = caps.get(1) {
                        if let Ok(val_str) = std::str::from_utf8(c1.as_bytes()) {
                            if !is_valid_credential_value(val_str) {
                                continue;
                            }
                        } else {
                            continue;
                        }
                    }

                    if let Ok(val) = std::str::from_utf8(m.as_bytes()) {
                        let val_trimmed = val.trim();
                        if val_trimmed.len() >= 4 {
                            let start = m.start().saturating_sub(25);
                            let end = std::cmp::min(chunk.len(), m.end() + 35);
                            let ctx_slice = &chunk[start..end];
                            let ctx_clean: String = ctx_slice
                                .iter()
                                .map(|&b| if (32..=126).contains(&b) { b as char } else { ' ' })
                                .collect();
                            let ctx = ctx_clean.split_whitespace().collect::<Vec<&str>>().join(" ");
                            matches.push(KeywordMatch {
                                category: cat.to_string(),
                                matched_value: val_trimmed.to_string(),
                                context: ctx,
                                offset: format!("0x{:X}", chunk_offset + m.start()),
                            });
                        }
                    }
                }
            }
            matches
        })
        .collect()
}

fn main() {
    let cli = Cli::parse();

    let target_file = cli
        .file
        .or(cli.file_flag)
        .unwrap_or_else(|| {
            eprintln!("{}", "Error: No evidence file specified. Run with --help for usage.".red().bold());
            std::process::exit(1);
        });

    let path = Path::new(&target_file);
    if !path.exists() {
        eprintln!("{} File not found: {}", "Error:".red().bold(), target_file);
        std::process::exit(1);
    }

    let start_time = Instant::now();

    println!("{}", "=================================================================".bright_cyan());
    println!("{}", "       GLOBALSCAN2 - ULTRA-FAST FORENSIC FILE SCANNER            ".bright_yellow().bold());
    println!("{}", "       Multi-Core Aho-Corasick SIMD & Memory-Mapped Engine       ".bright_white());
    println!("{}", "=================================================================".bright_cyan());

    let file = File::open(path).expect("Failed to open evidence file");
    let mmap = unsafe { Mmap::map(&file).expect("Failed to memory-map evidence file") };
    let data = &mmap[..];
    let file_size = data.len() as u64;

    // Parallel Hash & Entropy calculation
    let ((md5_str, sha1_str), (sha256_str, entropy_val)) = rayon::join(
        || {
            rayon::join(
                || {
                    let mut hasher = Md5::new();
                    hasher.update(data);
                    format!("{:x}", hasher.finalize())
                },
                || {
                    let mut hasher = Sha1::new();
                    hasher.update(data);
                    format!("{:x}", hasher.finalize())
                },
            )
        },
        || {
            rayon::join(
                || {
                    let mut hasher = Sha256::new();
                    hasher.update(data);
                    format!("{:x}", hasher.finalize())
                },
                || calculate_entropy(data),
            )
        },
    );

    let meta = FileMeta {
        filename: path.file_name().unwrap_or_default().to_string_lossy().to_string(),
        size_bytes: file_size,
        size_human: human_size(file_size),
        entropy: entropy_val,
        file_type: detect_magic_signature(data).to_string(),
        md5: md5_str,
        sha1: sha1_str,
        sha256: sha256_str,
    };

    // Parallel Zero-Copy SIMD Scanning (Flags, Base64, Aho-Corasick XOR, Keywords)
    let (mut all_flags, raw_keywords) = rayon::join(
        || {
            let (mut f1, (f2, f3)) = rayon::join(
                || parallel_scan_flags(data, cli.prefix.as_deref()),
                || rayon::join(
                    || parallel_scan_base64(data),
                    || scan_xor_flags_simd(data),
                ),
            );
            f1.extend(f2);
            f1.extend(f3);
            f1
        },
        || parallel_scan_keywords(data),
    );

    // Dedup all flags
    let mut unique_flags = Vec::new();
    let mut seen_flags = HashSet::new();
    for f in all_flags.drain(..) {
        if seen_flags.insert(f.flag.clone()) {
            unique_flags.push(f);
        }
    }

    // Dedup keywords
    let mut unique_keywords = Vec::new();
    let mut seen_kw = HashSet::new();
    for kw in raw_keywords {
        if seen_kw.insert(kw.matched_value.clone()) {
            unique_keywords.push(kw);
        }
    }

    let elapsed = start_time.elapsed();

    // Print File Metadata Panel
    if !cli.flags_only && !cli.keywords_only {
        let mut meta_table = Table::new();
        meta_table
            .load_preset(UTF8_FULL)
            .apply_modifier(UTF8_ROUND_CORNERS)
            .set_content_arrangement(ContentArrangement::Dynamic);

        meta_table.set_header(vec![
            Cell::new("Property").fg(Color::Cyan).add_attribute(Attribute::Bold),
            Cell::new("Forensic Value").fg(Color::White).add_attribute(Attribute::Bold),
        ]);

        meta_table.add_row(vec![Cell::new("Target File"), Cell::new(&meta.filename).fg(Color::Yellow)]);
        meta_table.add_row(vec![Cell::new("File Size"), Cell::new(format!("{} ({} bytes)", meta.size_human, meta.size_bytes))]);
        meta_table.add_row(vec![Cell::new("Detected Magic"), Cell::new(&meta.file_type).fg(Color::Green).add_attribute(Attribute::Bold)]);
        meta_table.add_row(vec![Cell::new("Shannon Entropy"), Cell::new(format!("{:.3} / 8.000", meta.entropy))]);
        meta_table.add_row(vec![Cell::new("MD5 Hash"), Cell::new(&meta.md5).fg(Color::DarkGrey)]);
        meta_table.add_row(vec![Cell::new("SHA1 Hash"), Cell::new(&meta.sha1).fg(Color::DarkGrey)]);
        meta_table.add_row(vec![Cell::new("SHA256 Hash"), Cell::new(&meta.sha256).fg(Color::DarkGrey)]);
        meta_table.add_row(vec![Cell::new("Analysis Time"), Cell::new(format!("{:.2?}", elapsed)).fg(Color::Cyan).add_attribute(Attribute::Bold)]);

        println!("\n{}", "[+] File Metadata & Cryptographic Hashes".bold());
        println!("{meta_table}");
    }

    if cli.meta_only {
        return;
    }

    // Print Flags Table
    if !cli.keywords_only {
        println!("\n{}", format!("[+] Discovered CTF Flags & Objectives ({} Found)", unique_flags.len()).bold().green());
        if unique_flags.is_empty() {
            println!("{}", "[-] No CTF flags matched across evidence buffers.".yellow());
        } else {
            let mut flag_table = Table::new();
            flag_table
                .load_preset(UTF8_FULL)
                .apply_modifier(UTF8_ROUND_CORNERS)
                .set_content_arrangement(ContentArrangement::Dynamic);

            flag_table.set_header(vec![
                Cell::new("#").fg(Color::DarkGrey),
                Cell::new("Captured Flag / Objective").fg(Color::Green).add_attribute(Attribute::Bold),
                Cell::new("Encoding / Vector").fg(Color::Yellow),
                Cell::new("Offset").fg(Color::Cyan),
            ]);

            for (idx, f) in unique_flags.iter().take(cli.limit).enumerate() {
                flag_table.add_row(vec![
                    Cell::new((idx + 1).to_string()),
                    Cell::new(&f.flag).fg(Color::White).add_attribute(Attribute::Bold),
                    Cell::new(&f.encoding).fg(Color::Yellow),
                    Cell::new(&f.offset).fg(Color::Cyan),
                ]);
            }
            println!("{flag_table}");
        }
    }

    // Print Keywords Table
    if !cli.flags_only {
        println!("\n{}", format!("[+] Sensitive Tokens, Keys & Credentials ({} Findings)", unique_keywords.len()).bold().yellow());
        if unique_keywords.is_empty() {
            println!("{}", "[-] No sensitive credentials or tokens discovered.".dimmed());
        } else {
            let mut kw_table = Table::new();
            kw_table
                .load_preset(UTF8_FULL)
                .apply_modifier(UTF8_ROUND_CORNERS)
                .set_content_arrangement(ContentArrangement::Dynamic);

            kw_table.set_header(vec![
                Cell::new("#").fg(Color::DarkGrey),
                Cell::new("Category").fg(Color::Cyan).add_attribute(Attribute::Bold),
                Cell::new("Extracted Match").fg(Color::Red).add_attribute(Attribute::Bold),
                Cell::new("Context Snippet").fg(Color::White),
                Cell::new("Offset").fg(Color::DarkGrey),
            ]);

            for (idx, kw) in unique_keywords.iter().take(cli.limit).enumerate() {
                kw_table.add_row(vec![
                    Cell::new((idx + 1).to_string()),
                    Cell::new(&kw.category).fg(Color::Cyan),
                    Cell::new(&kw.matched_value).fg(Color::Red).add_attribute(Attribute::Bold),
                    Cell::new(&kw.context),
                    Cell::new(&kw.offset).fg(Color::DarkGrey),
                ]);
            }
            println!("{kw_table}");
        }
    }

    // Export Handlers
    let base_name = path.file_stem().unwrap_or_default().to_string_lossy().to_string();
    let md_path = if cli.export_all && cli.md.is_none() {
        Some(format!("{}_globalscan2.md", base_name))
    } else {
        cli.md
    };

    let json_path = if cli.export_all && cli.json.is_none() {
        Some(format!("{}_globalscan2.json", base_name))
    } else {
        cli.json
    };

    if let Some(ref out_md) = md_path {
        let mut f = File::create(out_md).expect("Failed to create markdown report");
        writeln!(f, "# Globalscan2 Forensic Report\n").unwrap();
        writeln!(f, "- **Target File:** `{}`", meta.filename).unwrap();
        writeln!(f, "- **Size:** `{}`", meta.size_human).unwrap();
        writeln!(f, "- **SHA256:** `{}`", meta.sha256).unwrap();
        writeln!(f, "- **Execution Time:** `{:.2?}`", elapsed).unwrap();
        writeln!(f, "\n## Captured Flags").unwrap();
        writeln!(f, "| # | Flag | Encoding | Offset |").unwrap();
        writeln!(f, "|---|---|---|---|").unwrap();
        for (i, fl) in unique_flags.iter().enumerate() {
            writeln!(f, "| {} | **`{}`** | {} | `{}` |", i + 1, fl.flag, fl.encoding, fl.offset).unwrap();
        }
        println!("{} Exported Markdown report to: {}", "[+]".green().bold(), out_md.cyan());
    }

    if let Some(ref out_json) = json_path {
        let mut f = File::create(out_json).expect("Failed to create json report");
        let payload = serde_json::json!({
            "metadata": meta,
            "flags": unique_flags,
            "keywords": unique_keywords,
            "elapsed_ms": elapsed.as_millis(),
        });
        serde_json::to_writer_pretty(&mut f, &payload).unwrap();
        println!("{} Exported JSON report to: {}", "[+]".green().bold(), out_json.cyan());
    }

    println!("\n{} Scan finished in {:.2?} (Zero-Copy SIMD Engine)", "[*]".green().bold(), elapsed);
}
