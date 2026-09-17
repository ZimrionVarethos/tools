use std::fs::File;
use std::io::{self, BufWriter, IsTerminal, Write};
use std::path::Path;
use std::time::Instant;

use clap::Parser;
use colored::*;
use memmap2::Mmap;
use rayon::prelude::*;
use regex::Regex;

#[derive(Parser, Debug)]
#[command(
    name = "strings2",
    author = "DFIR Toolkit Team",
    version = "2.0.0 (Zero-Copy Multi-Core)",
    about = "Ultra-Fast Universal Forensic Strings Carving & Search Engine"
)]
struct Cli {
    #[arg(help = "Path to the evidence / dump / capture / binary file")]
    file: String,

    #[arg(short = 'n', long = "bytes", default_value_t = 4, help = "Minimum sequence length (default: 4)")]
    min_len: usize,

    #[arg(short = 'o', long = "offset", help = "Print byte offset in hex (0x...)")]
    show_offset: bool,

    #[arg(short = 'E', long = "encoding", help = "Print encoding tag ([ASCII] or [UTF-16LE])")]
    show_encoding: bool,

    #[arg(short = 'a', long = "ascii-only", help = "Scan only 1-byte ASCII strings")]
    ascii_only: bool,

    #[arg(short = 'u', long = "unicode-only", help = "Scan only 2-byte UTF-16LE wide strings")]
    unicode_only: bool,

    #[arg(short = 's', long = "search", help = "Instant in-memory search pattern / regex")]
    search: Option<String>,

    #[arg(short = 'i', long = "ignore-case", help = "Case-insensitive search")]
    ignore_case: bool,

    #[arg(short = 'C', long = "context", default_value_t = 0, help = "Print NUM lines of context around search matches")]
    context: usize,

    #[arg(long = "count", help = "Print only total count of carved or matched strings")]
    count_only: bool,

    #[arg(long = "bench", help = "Show performance benchmark metrics on stderr")]
    bench: bool,
}

#[derive(Clone, Debug)]
struct CarvedString {
    offset: usize,
    val: String,
    encoding: &'static str,
}

/// Zero-copy carve 1-byte ASCII strings from a slice
fn carve_ascii_chunk(chunk: &[u8], base_offset: usize, min_len: usize) -> Vec<CarvedString> {
    let mut results = Vec::new();
    let mut start = None;

    for (i, &b) in chunk.iter().enumerate() {
        if (32..=126).contains(&b) || b == b'\t' {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start.take() {
            let len = i - s;
            if len >= min_len {
                if let Ok(st) = std::str::from_utf8(&chunk[s..i]) {
                    results.push(CarvedString {
                        offset: base_offset + s,
                        val: st.to_string(),
                        encoding: "ASCII",
                    });
                }
            }
        }
    }

    if let Some(s) = start.take() {
        let len = chunk.len() - s;
        if len >= min_len {
            if let Ok(st) = std::str::from_utf8(&chunk[s..]) {
                results.push(CarvedString {
                    offset: base_offset + s,
                    val: st.to_string(),
                    encoding: "ASCII",
                });
            }
        }
    }

    results
}

/// Zero-copy carve 2-byte UTF-16LE wide strings from a slice
fn carve_utf16le_chunk(chunk: &[u8], base_offset: usize, min_len: usize) -> Vec<CarvedString> {
    let mut results = Vec::new();

    // Check both even (0) and odd (1) alignments
    for align in 0..2 {
        let mut start = None;
        let mut idx = align;

        while idx + 1 < chunk.len() {
            let b0 = chunk[idx];
            let b1 = chunk[idx + 1];

            if b1 == 0 && ((32..=126).contains(&b0) || b0 == b'\t') {
                if start.is_none() {
                    start = Some(idx);
                }
            } else if let Some(s) = start.take() {
                let char_count = (idx - s) / 2;
                if char_count >= min_len {
                    let mut s_buf = String::with_capacity(char_count);
                    for k in (s..idx).step_by(2) {
                        s_buf.push(chunk[k] as char);
                    }
                    results.push(CarvedString {
                        offset: base_offset + s,
                        val: s_buf,
                        encoding: "UTF-16LE",
                    });
                }
            }
            idx += 2;
        }

        if let Some(s) = start.take() {
            let char_count = (idx - s) / 2;
            if char_count >= min_len {
                let mut s_buf = String::with_capacity(char_count);
                for k in (s..idx).step_by(2) {
                    s_buf.push(chunk[k] as char);
                }
                results.push(CarvedString {
                    offset: base_offset + s,
                    val: s_buf,
                    encoding: "UTF-16LE",
                });
            }
        }
    }

    results
}

fn main() {
    let cli = Cli::parse();
    let start_time = Instant::now();

    let path = Path::new(&cli.file);
    if !path.exists() {
        eprintln!("{}: file not found: {}", "error".red().bold(), cli.file);
        std::process::exit(1);
    }

    let file = File::open(path).unwrap_or_else(|e| {
        eprintln!("{}: failed to open {}: {}", "error".red().bold(), cli.file, e);
        std::process::exit(1);
    });

    let mmap = unsafe {
        Mmap::map(&file).unwrap_or_else(|e| {
            eprintln!("{}: memory mapping failed: {}", "error".red().bold(), e);
            std::process::exit(1);
        })
    };

    let data = &mmap[..];
    let file_size = data.len();

    // Compile regex if search pattern is provided
    let search_regex = cli.search.as_ref().map(|pat| {
        let re_str = if cli.ignore_case {
            format!("(?i){}", pat)
        } else {
            pat.clone()
        };
        Regex::new(&re_str).unwrap_or_else(|e| {
            eprintln!("{}: invalid regex pattern '{}': {}", "error".red().bold(), pat, e);
            std::process::exit(1);
        })
    });

    // 4MB chunks for parallel multi-core scanning
    let chunk_size = 4 * 1024 * 1024;
    let chunks: Vec<(usize, &[u8])> = if file_size <= chunk_size {
        vec![(0, data)]
    } else {
        let mut list = Vec::new();
        let mut start = 0;
        while start < file_size {
            let end = std::cmp::min(file_size, start + chunk_size);
            list.push((start, &data[start..end]));
            start += chunk_size;
        }
        list
    };

    let scan_ascii = !cli.unicode_only;
    let scan_unicode = !cli.ascii_only;

    // Parallel carving across all available CPU cores
    let mut all_strings: Vec<CarvedString> = chunks
        .into_par_iter()
        .flat_map(|(chunk_offset, chunk)| {
            let mut chunk_res = Vec::new();
            if scan_ascii {
                chunk_res.extend(carve_ascii_chunk(chunk, chunk_offset, cli.min_len));
            }
            if scan_unicode {
                chunk_res.extend(carve_utf16le_chunk(chunk, chunk_offset, cli.min_len));
            }
            chunk_res
        })
        .collect();

    // Sort by offset to preserve chronological file order
    all_strings.par_sort_unstable_by_key(|s| s.offset);

    let carve_elapsed = start_time.elapsed();

    // If --count only
    if cli.count_only {
        if let Some(ref re) = search_regex {
            let matched_cnt = all_strings.par_iter().filter(|s| re.is_match(&s.val)).count();
            println!("{}", matched_cnt);
        } else {
            println!("{}", all_strings.len());
        }
        if cli.bench {
            eprintln!("[*] Carved {} strings in {:.2?}", all_strings.len(), carve_elapsed);
        }
        return;
    }

    let stdout = io::stdout();
    let is_tty = stdout.is_terminal();
    let mut writer = BufWriter::with_capacity(256 * 1024, stdout.lock());

    // Case 1: Built-in Search Mode
    if let Some(ref re) = search_regex {
        let total = all_strings.len();
        let mut match_indices = Vec::new();

        for (i, s) in all_strings.iter().enumerate() {
            if re.is_match(&s.val) {
                match_indices.push(i);
            }
        }

        if cli.context == 0 {
            // Print only matching lines
            for &idx in &match_indices {
                let item = &all_strings[idx];
                print_item(&mut writer, item, cli.show_offset, cli.show_encoding, is_tty, Some(re));
            }
        } else {
            // Print with context (-C num)
            let mut printed = vec![false; total];
            let ctx = cli.context;

            for (m_num, &idx) in match_indices.iter().enumerate() {
                let start_idx = idx.saturating_sub(ctx);
                let end_idx = std::cmp::min(total, idx + ctx + 1);

                if m_num > 0 && start_idx > 0 && !printed[start_idx] {
                    let _ = writeln!(writer, "--");
                }

                for j in start_idx..end_idx {
                    if !printed[j] {
                        printed[j] = true;
                        let item = &all_strings[j];
                        let is_target = j == idx;
                        if is_target {
                            print_item(&mut writer, item, cli.show_offset, cli.show_encoding, is_tty, Some(re));
                        } else {
                            print_item(&mut writer, item, cli.show_offset, cli.show_encoding, is_tty, None);
                        }
                    }
                }
            }
        }
    } else {
        // Case 2: Pure Stream Mode (Piped or raw stdout)
        for item in &all_strings {
            print_item(&mut writer, item, cli.show_offset, cli.show_encoding, is_tty, None);
        }
    }

    let _ = writer.flush();

    if cli.bench {
        let total_elapsed = start_time.elapsed();
        eprintln!(
            "[*] Total Carved: {} strings | File: {} bytes | Carve: {:.2?} | Total: {:.2?}",
            all_strings.len(),
            file_size,
            carve_elapsed,
            total_elapsed
        );
    }
}

fn print_item<W: Write>(
    writer: &mut W,
    item: &CarvedString,
    show_offset: bool,
    show_encoding: bool,
    is_tty: bool,
    highlight_re: Option<&Regex>,
) {
    if show_offset {
        let _ = write!(writer, "0x{:08X} ", item.offset);
    }

    if show_encoding {
        let _ = write!(writer, "[{}] ", item.encoding);
    }

    if let Some(re) = highlight_re {
        if is_tty {
            // Highlight matching parts with bright red / bold
            let val = &item.val;
            let mut last_end = 0;
            for mat in re.find_iter(val) {
                let _ = write!(writer, "{}", &val[last_end..mat.start()]);
                let _ = write!(writer, "{}", mat.as_str().bold().red());
                last_end = mat.end();
            }
            let _ = writeln!(writer, "{}", &val[last_end..]);
            return;
        }
    }

    let _ = writeln!(writer, "{}", item.val);
}
