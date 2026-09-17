"""
Universal Forensic File Scanner & Flag Hunter (core/globalscan.py)
Works on ANY file format (.dmp, .raw, .pcap, .ad1, .e01, .img, .bin, .exe, .zip, .pdf, images, etc.)

Features:
1. Regex Flag Hunter (CTF flag patterns, flexible braces, leet speak, custom prefixes)
2. Sensitive Keywords Carving (passwords, secrets, keys, XOR, c2, tokens, db credentials)
3. Decoders: Base64 carving & verification, Hex ASCII decoding, Single-byte XOR flag brute-forcer
4. File Metadata, Hashes (MD5/SHA1/SHA256), Shannon Entropy & Magic Signature Analyzer
5. AD1 Decompression Engine (automatically carves decompressed logical image payloads)
6. Multi-format Export (Terminal Tables, Markdown, JSON, CSV)
"""
import os
import sys
import re
import math
import struct
import hashlib
import binascii
import base64
import argparse
import json
from typing import List, Dict, Any, Optional, Set, Tuple

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.markup import escape

from core.banner import print_banner
from core.utils import human_size

console = Console(force_terminal=True, legacy_windows=False)

# Standard and flexible flag patterns
DEFAULT_FLAG_REGEX = re.compile(
    r"(?:[A-Za-z0-9_\.\-]{2,40}\{[^}\r\n]{2,200}\})"
    r"|(?:\{[A-Za-z0-9_!@#\$%\^&\*\(\)\-\+=\.\?\/\s]{3,120}\})"
    r"|(?:flag\[[A-Za-z0-9_\-\s]{2,100}\])"
    r"|(?:FLAG\[[A-Za-z0-9_\-\s]{2,100}\])",
    re.IGNORECASE
)

# Known Sensitive Keywords Categories
SENSITIVE_KEYWORD_PATTERNS = {
    "Credentials & Passwords": [
        r"password\s*[:=]\s*['\"]?[^\s'\";]{2,60}",
        r"passwd\s*[:=]\s*['\"]?[^\s'\";]{2,60}",
        r"pwd\s*[:=]\s*['\"]?[^\s'\";]{2,60}",
        r"secret\s*[:=]\s*['\"]?[^\s'\";]{2,60}",
        r"admin\s*[:=]\s*['\"]?[^\s'\";]{2,60}",
        r"root\s*[:=]\s*['\"]?[^\s'\";]{2,60}",
        r"db_pass(?:word)?\s*[:=]\s*['\"]?[^\s'\";]{2,60}",
    ],
    "API Keys & Access Tokens": [
        r"AKIA[0-9A-Z]{16}",                               # AWS Access Key
        r"ghp_[A-Za-z0-9_]{36,255}",                       # GitHub Personal Access Token
        r"gho_[A-Za-z0-9_]{36,255}",                       # GitHub OAuth Token
        r"glpat-[0-9a-zA-Z\-_]{20,}",                      # GitLab Token
        r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", # JWT Token
        r"https?://(?:discord\.com|discordapp\.com)/api/webhooks/[0-9]+/[A-Za-z0-9_-]+", # Discord Webhook
        r"api[_-]?key\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{8,64}",
        r"access[_-]?token\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{8,64}",
        r"bearer\s+[A-Za-z0-9\-_=]{16,128}"
    ],
    "Private Keys & Certificates": [
        r"-----BEGIN\s+[A-Z\s]+PRIVATE\s+KEY-----",
        r"-----BEGIN\s+CERTIFICATE-----",
        r"-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----"
    ],
    "Crypto & Forensic Clues": [
        r"(?:xor|rot13|caesar|cipher|vigenere|hashcat|mimikatz|base64_decode|eval\(|shell_exec|cmd\.exe|powershell\.exe|/bin/sh|/bin/bash)\b"
    ]
}

# Magic Signatures Database
MAGIC_SIGNATURES = [
    (b"\x7fELF", "Linux ELF Executable / Object"),
    (b"MZ", "Windows PE Executable / DLL (MZ Header)"),
    (b"\x21\x42\x44\x4e\x00\x00\x00\x00", "AccessData Logical Image (AD1)"),
    (b"\xd4\xc3\xb2\xa1", "PCAP Capture File (Little-Endian)"),
    (b"\xa1\xb2\xc3\xd4", "PCAP Capture File (Big-Endian)"),
    (b"\x4d\x3c\x2b\x1a", "PCAP Capture File (Nanosecond LE)"),
    (b"\x0a\x0d\x0d\x0a", "PCAPNG Next Generation Capture"),
    (b"MDMP", "Windows MiniDump Crash Dump (MDMP)"),
    (b"PAGE", "Windows Complete / Kernel Memory Dump (PAGE)"),
    (b"PK\x03\x04", "ZIP / DOCX / XLSX / APK / JAR Archive"),
    (b"PK\x05\x06", "ZIP Archive (Empty)"),
    (b"PK\x07\x08", "ZIP Spanned Archive"),
    (b"Rar!\x1a\x07\x00", "RAR 4.x Archive"),
    (b"Rar!\x1a\x07\x01\x00", "RAR 5.x Archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip Archive"),
    (b"\x1f\x8b\x08", "GZIP Compressed File"),
    (b"BZh", "BZIP2 Compressed Archive"),
    (b"\xfd7zXZ\x00", "XZ Compressed Archive"),
    (b"\x89PNG\r\n\x1a\n", "PNG Image File"),
    (b"\xff\xd8\xff", "JPEG / JFIF Image"),
    (b"GIF87a", "GIF Image (87a)"),
    (b"GIF89a", "GIF Image (89a)"),
    (b"BM", "Bitmap Image (BMP)"),
    (b"RIFF", "RIFF Container (WAV / AVI / WebP)"),
    (b"%PDF-", "Adobe Portable Document Format (PDF)"),
    (b"SQLite format 3\x00", "SQLite 3 Database"),
    (b"regf", "Windows NT Registry Hive (regf)"),
    (b"EVTX", "Windows Event Log (EVTX)"),
    (b"NES\x1a", "Nintendo Entertainment System ROM"),
    (b"\x00\x01\x00\x00\x00", "TrueType Font (TTF)"),
    (b"OTTO", "OpenType Font (OTF)")
]


def is_valid_printable_flag(val: str) -> bool:
    """Validate that flag candidate consists only of printable ASCII characters."""
    if not val or len(val) < 4 or len(val) > 250:
        return False
    # Check ASCII printable
    if not all(32 <= ord(c) <= 126 or c in (" ", "\t") for c in val):
        return False
    # Must contain alphanumeric characters
    if not re.search(r"[A-Za-z0-9]{2,}", val):
        return False
    # Check brace structure
    if val.startswith("{") and not val.endswith("}"):
        return False
    return True


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon Entropy (0.0 to 8.0) of a byte sequence."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    for count in counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def get_entropy_classification(entropy: float) -> str:
    """Classify entropy value into human readable context."""
    if entropy < 3.0:
        return "Low (Sparse / Repetitive Text)"
    elif entropy < 5.5:
        return "Medium (Plaintext / Source Code / Structured Config)"
    elif entropy < 7.2:
        return "High (Compiled Binary / Packed Executable)"
    else:
        return "Very High (Encrypted / Heavily Compressed Data)"


def detect_file_type(header_bytes: bytes, filename: str) -> str:
    """Identify file type from magic bytes."""
    for magic, desc in MAGIC_SIGNATURES:
        if header_bytes.startswith(magic):
            return desc
    ext = os.path.splitext(filename)[1].lower()
    if ext in [".txt", ".log", ".csv", ".json", ".md", ".xml", ".html", ".py", ".c", ".cpp", ".sh"]:
        return "Plaintext Text / Script Document"
    return "Raw Binary / Data Blob"


class GlobalScanner:
    """
    Universal File Forensics & Strings Carving Engine.
    """
    def __init__(self, file_path: str, min_string_len: int = 4, custom_prefix: Optional[str] = None):
        self.file_path = file_path
        self.min_string_len = min_string_len
        self.custom_prefix = custom_prefix
        self.file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0

    def analyze_metadata(self) -> Dict[str, Any]:
        """Compute file hashes, magic signature, and entropy."""
        md5_h = hashlib.md5()
        sha1_h = hashlib.sha1()
        sha256_h = hashlib.sha256()

        header_bytes = b""
        sample_entropy_bytes = bytearray()
        sample_limit = 5 * 1024 * 1024 # 5 MB sample for entropy if huge

        with open(self.file_path, "rb") as f:
            header_bytes = f.read(64)
            f.seek(0)
            
            while chunk := f.read(1024 * 1024):
                md5_h.update(chunk)
                sha1_h.update(chunk)
                sha256_h.update(chunk)
                if len(sample_entropy_bytes) < sample_limit:
                    sample_entropy_bytes.extend(chunk[:sample_limit - len(sample_entropy_bytes)])

        entropy = calculate_entropy(bytes(sample_entropy_bytes))
        file_type = detect_file_type(header_bytes, self.file_path)

        return {
            "file_name": os.path.basename(self.file_path),
            "file_path": os.path.abspath(self.file_path),
            "file_size": self.file_size,
            "file_size_human": human_size(self.file_size),
            "file_type": file_type,
            "md5": md5_h.hexdigest(),
            "sha1": sha1_h.hexdigest(),
            "sha256": sha256_h.hexdigest(),
            "entropy": entropy,
            "entropy_class": get_entropy_classification(entropy)
        }

    def scan_all(self, max_records_per_cat: int = 200, enable_xor: bool = True) -> Dict[str, Any]:
        """
        Main execution workflow:
        1. Metadata & Hashes
        2. Fast Multi-Encoding Strings Extraction (ASCII & UTF-16LE)
        3. Flag Pattern Hunter
        4. Sensitive Keywords & Secrets Hunter
        5. Base64 & Hex Decoders
        6. XOR Single-Byte Flag Brute-Forcer
        7. Logical Image Decompression (AD1)
        """
        meta = self.analyze_metadata()

        flags = []
        seen_flags = set()

        sensitive_matches = []
        decoded_payloads = []

        # Compile custom flag regex if provided
        flag_patterns = [DEFAULT_FLAG_REGEX]
        if self.custom_prefix:
            pref_escaped = re.escape(self.custom_prefix)
            custom_re = re.compile(
                rf"{pref_escaped}\{{[^}}\r\n]{{2,200}}\}}",
                re.IGNORECASE
            )
            flag_patterns.insert(0, custom_re)

        # Chunked stream reader with overlap
        chunk_size = 4 * 1024 * 1024 # 4MB
        overlap_size = 1024 * 64     # 64KB overlap to catch flags spanning chunk boundaries

        offset = 0
        with open(self.file_path, "rb") as f:
            prev_overlap = b""
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break

                full_block = prev_overlap + chunk
                current_offset = max(0, offset - len(prev_overlap))

                # 1. Extract ASCII & UTF-16LE text representation
                # Decode printable characters cleanly
                text_ascii = full_block.decode("latin-1", errors="replace")
                
                # Try UTF-16LE decoding (Windows memory / registry / string representations)
                try:
                    text_utf16 = full_block.decode("utf-16le", errors="ignore")
                except Exception:
                    text_utf16 = ""

                # 2. Flag Pattern Matching
                for text_sample, enc_name in [(text_ascii, "ASCII"), (text_utf16, "UTF-16LE")]:
                    for pat in flag_patterns:
                        for m in pat.finditer(text_sample):
                            flag_val = m.group(0).strip()
                            flag_val = re.sub(r"[\r\n\t]", "", flag_val)

                            if is_valid_printable_flag(flag_val) and flag_val not in seen_flags:
                                seen_flags.add(flag_val)
                                rel_pos = m.start()
                                byte_off = current_offset + rel_pos if enc_name == "ASCII" else current_offset + (rel_pos * 2)
                                flags.append({
                                    "flag": flag_val,
                                    "offset_hex": f"0x{byte_off:X}",
                                    "encoding": enc_name,
                                    "length": len(flag_val)
                                })

                # 3. Sensitive Keywords Matching
                for cat_name, patterns in SENSITIVE_KEYWORD_PATTERNS.items():
                    for pat_str in patterns:
                        r_comp = re.compile(pat_str, re.IGNORECASE)
                        for m in r_comp.finditer(text_ascii):
                            match_str = m.group(0).strip()
                            # Clean up match
                            if not all(32 <= ord(c) <= 126 for c in match_str):
                                continue

                            rel_pos = m.start()
                            byte_off = current_offset + rel_pos

                            # Grab surrounding context snippet (up to 80 chars)
                            start_ctx = max(0, rel_pos - 20)
                            end_ctx = min(len(text_ascii), rel_pos + len(match_str) + 40)
                            snippet = text_ascii[start_ctx:end_ctx].replace("\n", " ").replace("\r", "")
                            # Keep snippet printable
                            snippet = "".join(c if 32 <= ord(c) <= 126 else "." for c in snippet)

                            if len(sensitive_matches) < max_records_per_cat * 5:
                                sensitive_matches.append({
                                    "category": cat_name,
                                    "match": match_str,
                                    "snippet": snippet,
                                    "offset_hex": f"0x{byte_off:X}"
                                })

                # 4. Base64 Carving & Decoding
                b64_matches = re.finditer(r"(?:[A-Za-z0-9+/]{16,}={0,2})", text_ascii)
                for b_match in b64_matches:
                    cand = b_match.group(0)
                    if len(cand) % 4 == 0:
                        try:
                            dec_b = base64.b64decode(cand, validate=True)
                            # Check if printable ASCII
                            if dec_b and all(32 <= c <= 126 or c in (10, 13, 9) for c in dec_b):
                                dec_str = dec_b.decode("utf-8", errors="ignore").strip()
                                if len(dec_str) >= 4 and not dec_str.isnumeric():
                                    rel_pos = b_match.start()
                                    byte_off = current_offset + rel_pos
                                    # Check if contains flag inside base64
                                    is_flag = bool(DEFAULT_FLAG_REGEX.search(dec_str))
                                    if len(decoded_payloads) < max_records_per_cat:
                                        decoded_payloads.append({
                                            "type": "Base64",
                                            "encoded": cand[:50] + ("..." if len(cand) > 50 else ""),
                                            "decoded": dec_str,
                                            "is_flag": is_flag,
                                            "offset_hex": f"0x{byte_off:X}"
                                        })
                                        if is_flag and dec_str not in seen_flags and is_valid_printable_flag(dec_str):
                                            seen_flags.add(dec_str)
                                            flags.append({
                                                "flag": dec_str,
                                                "offset_hex": f"0x{byte_off:X} (Base64)",
                                                "encoding": "Base64 Decoded",
                                                "length": len(dec_str)
                                            })
                        except Exception:
                            pass

                # 5. Hex ASCII Carving
                hex_matches = re.finditer(r"\b([0-9a-fA-F]{16,})\b", text_ascii)
                for h_match in hex_matches:
                    hex_str = h_match.group(1)
                    if len(hex_str) % 2 == 0 and len(hex_str) <= 256:
                        try:
                            dec_h = bytes.fromhex(hex_str)
                            if dec_h and all(32 <= c <= 126 for c in dec_h):
                                dec_str = dec_h.decode("utf-8", errors="ignore").strip()
                                if len(dec_str) >= 6 and re.search(r"[A-Za-z]{3,}", dec_str):
                                    is_flag = bool(DEFAULT_FLAG_REGEX.search(dec_str))
                                    if is_flag and dec_str not in seen_flags and is_valid_printable_flag(dec_str):
                                        seen_flags.add(dec_str)
                                        flags.append({
                                            "flag": dec_str,
                                            "offset_hex": f"0x{current_offset + h_match.start():X} (Hex)",
                                            "encoding": "Hex Decoded",
                                            "length": len(dec_str)
                                        })
                        except Exception:
                            pass

                offset += len(chunk)
                prev_overlap = chunk[-overlap_size:] if len(chunk) >= overlap_size else chunk

        # 6. Single-Byte XOR Flag Brute-Forcer
        if enable_xor and self.file_size > 0:
            xor_flags = self._bruteforce_xor_flags()
            for xf in xor_flags:
                if xf["flag"] not in seen_flags and is_valid_printable_flag(xf["flag"]):
                    seen_flags.add(xf["flag"])
                    flags.append(xf)

        # 7. Logical Image Carving (AD1 Decompression)
        if meta["file_type"].startswith("AccessData Logical Image") or self.file_path.lower().endswith(".ad1"):
            try:
                from ad1.parser import AD1Parser
                ad1_p = AD1Parser(self.file_path)
                ad1_p.build_tree()
                for item in ad1_p.items:
                    if item.is_dir or item.decompressed_size == 0 or item.decompressed_size > 10 * 1024 * 1024:
                        continue
                    
                    # Scan item name
                    for pat in flag_patterns:
                        for m in pat.finditer(item.item_name):
                            fv = m.group(0).strip()
                            if is_valid_printable_flag(fv) and fv not in seen_flags:
                                seen_flags.add(fv)
                                flags.append({
                                    "flag": fv,
                                    "offset_hex": f"AD1 File: {item.item_name}",
                                    "encoding": "AD1 Name",
                                    "length": len(fv)
                                })
                    
                    # Scan content of text/script/config files
                    ext = os.path.splitext(item.item_name)[1].lower()
                    if ext in [".txt", ".log", ".json", ".xml", ".csv", ".py", ".sh", ".conf", ".ini", ".env", ".md", ".sql", ".sqlite", ".dat"]:
                        data_bytes = ad1_p.read_file_bytes(item)
                        if data_bytes:
                            text_s = data_bytes.decode("utf-8", errors="ignore")
                            for pat in flag_patterns:
                                for m in pat.finditer(text_s):
                                    fv = m.group(0).strip()
                                    if is_valid_printable_flag(fv) and fv not in seen_flags:
                                        seen_flags.add(fv)
                                        flags.append({
                                            "flag": fv,
                                            "offset_hex": f"AD1 Content: {item.item_name}",
                                            "encoding": "AD1 Decompressed",
                                            "length": len(fv)
                                        })
            except Exception:
                pass

        return {
            "metadata": meta,
            "flags": flags,
            "sensitive_matches": sensitive_matches[:max_records_per_cat],
            "decoded_payloads": decoded_payloads[:max_records_per_cat]
        }

    def _bruteforce_xor_flags(self) -> List[Dict[str, Any]]:
        """
        Fast single-byte XOR (1..255) scanner looking for flag headers ('flag{', 'FLAG{', 'ctf{', 'CTF{').
        """
        xor_results = []
        header_targets = [b"flag{", b"FLAG{", b"ctf{", b"CTF{", b"htb{", b"HTB{"]
        
        # Read initial 10MB sample for XOR brute-force
        sample_size = min(self.file_size, 10 * 1024 * 1024)
        try:
            with open(self.file_path, "rb") as f:
                data = f.read(sample_size)
        except Exception:
            return []

        for key in range(1, 256):
            for target in header_targets:
                # Encrypt the header target with key
                x_target = bytes([b ^ key for b in target])
                idx = data.find(x_target)
                if idx != -1:
                    # Carve XOR decrypted sequence up to closing brace '}'
                    dec_bytes = bytearray()
                    end_idx = min(len(data), idx + 200)
                    for b in data[idx:end_idx]:
                        dec_b = b ^ key
                        if dec_b == ord("}"):
                            dec_bytes.append(dec_b)
                            break
                        elif 32 <= dec_b <= 126:
                            dec_bytes.append(dec_b)
                        else:
                            break

                    try:
                        candidate_flag = dec_bytes.decode("utf-8")
                        if candidate_flag.endswith("}") and is_valid_printable_flag(candidate_flag):
                            xor_results.append({
                                "flag": candidate_flag,
                                "offset_hex": f"0x{idx:X} (XOR Key: 0x{key:02X})",
                                "encoding": f"XOR 0x{key:02X}",
                                "length": len(candidate_flag)
                            })
                    except Exception:
                        pass
        return xor_results


# -------------------------------------------------------------
# Rich Console Rendering & Pretty Print Tables (Fully Escaped)
# -------------------------------------------------------------

def print_metadata_panel(meta: Dict[str, Any]):
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Key", style="bold cyan", width=18)
    table.add_column("Value", style="yellow")

    table.add_row("File Name", f"[bold white]{escape(meta['file_name'])}[/bold white]")
    table.add_row("File Size", f"{meta['file_size_human']} ({meta['file_size']:,} bytes)")
    table.add_row("Detected Type", f"[bold green]{escape(meta['file_type'])}[/bold green]")
    table.add_row("Shannon Entropy", f"{meta['entropy']} / 8.00  ([dim]{escape(meta['entropy_class'])}[/dim])")
    table.add_row("MD5", meta["md5"])
    table.add_row("SHA-1", meta["sha1"])
    table.add_row("SHA-256", meta["sha256"])

    panel = Panel(
        table,
        title=" File Identification & Metadata",
        title_align="left",
        border_style="cyan",
        padding=(1, 2)
    )
    console.print(panel)


def print_flags_table(flags: List[Dict[str, Any]]):
    if not flags:
        console.print("[yellow][i]  No CTF flag patterns matched in this file.[/yellow]")
        return

    table = Table(
        title=f" Discovered CTF Flags & Objectives ({len(flags)} Found)",
        show_header=True,
        header_style="bold magenta",
        border_style="bold green",
        expand=True
    )
    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("Captured Flag / Objective", style="bold white on dark_green", min_width=35, overflow="fold")
    table.add_column("Offset", style="cyan", width=26)
    table.add_column("Encoding / Source", style="yellow", width=18, justify="center")

    for idx, f in enumerate(flags, start=1):
        table.add_row(
            str(idx),
            escape(f" {f['flag']} "),
            escape(f["offset_hex"]),
            escape(f["encoding"])
        )

    console.print(table)


def print_sensitive_table(matches: List[Dict[str, Any]], max_rows: int = 50):
    if not matches:
        console.print("[dim][i]  No sensitive credentials or keywords identified.[/dim]")
        return

    table = Table(
        title=f" Sensitive Keywords & Credentials ({len(matches)} Matches)",
        show_header=True,
        header_style="bold yellow",
        border_style="yellow",
        expand=True
    )
    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("Category", style="bold cyan", width=24)
    table.add_column("Detected Match / Token", style="bold red", width=30, overflow="fold")
    table.add_column("Offset", style="dim cyan", width=14)
    table.add_column("Surrounding Context Snippet", style="white", min_width=30, overflow="fold")

    for idx, m in enumerate(matches[:max_rows], start=1):
        table.add_row(
            str(idx),
            escape(m["category"]),
            escape(m["match"]),
            escape(m["offset_hex"]),
            escape(m["snippet"])
        )

    console.print(table)
    if len(matches) > max_rows:
        console.print(f"[dim]... and {len(matches) - max_rows} more matches (use --limit to expand)[/dim]")


def print_decoded_table(payloads: List[Dict[str, Any]], max_rows: int = 30):
    if not payloads:
        return

    table = Table(
        title=f" Decoded Payloads (Base64 / Hex Strings)",
        show_header=True,
        header_style="bold cyan",
        border_style="cyan",
        expand=True
    )
    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("Type", style="bold green", width=10)
    table.add_column("Encoded Source", style="dim white", width=28, overflow="fold")
    table.add_column("Decoded Plaintext Content", style="bold yellow", min_width=32, overflow="fold")
    table.add_column("Offset", style="cyan", width=14)

    for idx, p in enumerate(payloads[:max_rows], start=1):
        table.add_row(
            str(idx),
            escape(p["type"]),
            escape(p["encoded"]),
            escape(p["decoded"]),
            escape(p["offset_hex"])
        )

    console.print(table)


# -------------------------------------------------------------
# Export Handlers (Markdown, JSON, CSV)
# -------------------------------------------------------------

def export_to_markdown(results: Dict[str, Any], output_path: str):
    meta = results["metadata"]
    flags = results["flags"]
    sensitive = results["sensitive_matches"]
    decoded = results["decoded_payloads"]

    lines = [
        f"# Universal Forensic Scan Report - `{meta['file_name']}`",
        f"- **File Path:** `{meta['file_path']}`",
        f"- **File Size:** `{meta['file_size_human']}` ({meta['file_size']:,} bytes)",
        f"- **Detected Signature:** `{meta['file_type']}`",
        f"- **Entropy:** `{meta['entropy']} / 8.00` ({meta['entropy_class']})",
        f"- **MD5:** `{meta['md5']}`",
        f"- **SHA-1:** `{meta['sha1']}`",
        f"- **SHA-256:** `{meta['sha256']}`",
        "",
        "##  Captured CTF Flags & Objectives",
        f"Total Flags Found: `{len(flags)}`",
        ""
    ]

    if flags:
        lines.append("| # | Captured Flag | Offset | Encoding / Source |")
        lines.append("|---|---|---|---|")
        for idx, f in enumerate(flags, start=1):
            flag_esc = f['flag'].replace("|", "\\|")
            lines.append(f"| {idx} | **`{flag_esc}`** | `{f['offset_hex']}` | {f['encoding']} |")
        lines.append("")
    else:
        lines.append("*No flag patterns identified.*  \n")

    if sensitive:
        lines.append("##  Sensitive Keywords & Credentials")
        lines.append("| # | Category | Detected Token | Offset | Context Snippet |")
        lines.append("|---|---|---|---|---|")
        for idx, m in enumerate(sensitive, start=1):
            m_esc = m['match'].replace("|", "\\|")
            c_esc = m['snippet'].replace("|", "\\|")
            lines.append(f"| {idx} | **{m['category']}** | `{m_esc}` | `{m['offset_hex']}` | `{c_esc}` |")
        lines.append("")

    if decoded:
        lines.append("##  Decoded Payloads (Base64 / Hex)")
        lines.append("| # | Type | Encoded Source | Decoded Plaintext Content | Offset |")
        lines.append("|---|---|---|---|---|")
        for idx, p in enumerate(decoded, start=1):
            e_esc = p['encoded'].replace("|", "\\|")
            d_esc = p['decoded'].replace("|", "\\|")
            lines.append(f"| {idx} | {p['type']} | `{e_esc}` | **`{d_esc}`** | `{p['offset_hex']}` |")
        lines.append("")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    console.print(f"[bold green][/bold green] Exported report to Markdown: [cyan]{output_path}[/cyan]")


def export_to_json(results: Dict[str, Any], output_path: str):
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    console.print(f"[bold green][/bold green] Exported report to JSON: [cyan]{output_path}[/cyan]")


def export_to_csv(results: Dict[str, Any], output_path: str):
    import csv
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Type", "Category/Encoding", "Content/Flag", "Offset", "Extra Context"])
        for f_item in results["flags"]:
            writer.writerow(["FLAG", f_item["encoding"], f_item["flag"], f_item["offset_hex"], ""])
        for s_item in results["sensitive_matches"]:
            writer.writerow(["SENSITIVE", s_item["category"], s_item["match"], s_item["offset_hex"], s_item["snippet"]])
        for d_item in results["decoded_payloads"]:
            writer.writerow(["DECODED", d_item["type"], d_item["decoded"], d_item["offset_hex"], d_item["encoded"]])

    console.print(f"[bold green][/bold green] Exported report to CSV: [cyan]{output_path}[/cyan]")


# -------------------------------------------------------------
# Main CLI Entrypoint
# -------------------------------------------------------------

def main(args_list=None):
    if args_list is None:
        args_list = sys.argv[1:]

    # Normalize -file to -f
    cleaned_args = []
    for a in args_list:
        if a == "-file":
            cleaned_args.append("-f")
        else:
            cleaned_args.append(a)

    parser = argparse.ArgumentParser(
        prog="globalscan",
        description=" Universal Forensic File Scanner & Flag Hunter (.DMP, .RAW, .PCAP, .AD1, .E01, .BIN, .ZIP, etc.)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  globalscan memory.DMP
  globalscan -file cute.DMP
  globalscan -f capture.pcap --flags-only
  globalscan disk.raw -p "CTF{" --xor-scan
  globalscan evidence.bin --md report.md --json report.json
  globalscan suspicious.exe --export-all
        """
    )

    parser.add_argument("file_pos", nargs="?", help="Target file path to scan")
    parser.add_argument("-f", "--file", dest="file_opt", help="Target file path (alternative syntax)")
    parser.add_argument("-p", "--prefix", help="Custom flag prefix (e.g. 'FLAG', 'HTB', 'cyber', 'chall')")
    parser.add_argument("-n", "--min-len", type=int, default=4, help="Minimum string length (default: 4)")
    parser.add_argument("-l", "--limit", type=int, default=100, help="Row display limit in tables (default: 100)")
    
    # Filter Flags
    parser.add_argument("--flags-only", action="store_true", help="Display only discovered CTF flags")
    parser.add_argument("--keywords-only", action="store_true", help="Display only sensitive keywords/tokens")
    parser.add_argument("--meta-only", action="store_true", help="Display only file metadata, hashes, and entropy")
    parser.add_argument("--no-xor", action="store_true", help="Disable single-byte XOR brute-force scanner")

    # Export Formats
    parser.add_argument("--md", "--markdown", dest="md", help="Export to Markdown report (.md)")
    parser.add_argument("--json", help="Export to JSON file")
    parser.add_argument("--csv", help="Export to CSV file")
    parser.add_argument("--export-all", action="store_true", help="Generate MD, JSON, and CSV reports automatically")

    args = parser.parse_args(cleaned_args)

    target_file = args.file_opt or args.file_pos
    if not target_file:
        parser.print_help()
        sys.exit(1)

    if not os.path.exists(target_file):
        console.print(f"[bold red]Error:[/bold red] File not found: {target_file}")
        sys.exit(1)

    if os.path.isdir(target_file):
        console.print(f"[bold red]Error:[/bold red] Target is a directory. Use on files (.DMP, .PCAP, .AD1, .RAW, etc.).")
        sys.exit(1)

    print_banner(
        tool_name="GLOBAL FORENSIC SCANNER (globalscan)",
        sub_title="Universal Strings, Regex Flag Hunter & Metadata Analyzer"
    )

    scanner = GlobalScanner(
        file_path=target_file,
        min_string_len=args.min_len,
        custom_prefix=args.prefix
    )

    with console.status("[bold cyan]Scanning file, carving strings & hunting flag patterns...[/bold cyan]"):
        results = scanner.scan_all(
            max_records_per_cat=args.limit,
            enable_xor=not args.no_xor
        )

    # Render Visual Views
    if args.meta_only:
        print_metadata_panel(results["metadata"])
    elif args.flags_only:
        print_flags_table(results["flags"])
    elif args.keywords_only:
        print_sensitive_table(results["sensitive_matches"], max_rows=args.limit)
    else:
        print_metadata_panel(results["metadata"])
        print_flags_table(results["flags"])
        print_sensitive_table(results["sensitive_matches"], max_rows=args.limit)
        print_decoded_table(results["decoded_payloads"], max_rows=args.limit)

    # Export Handlers
    base_name = os.path.splitext(os.path.basename(target_file))[0]
    if args.export_all:
        if not args.md: args.md = f"{base_name}_globalscan.md"
        if not args.json: args.json = f"{base_name}_globalscan.json"
        if not args.csv: args.csv = f"{base_name}_globalscan.csv"

    if hasattr(args, 'md') and args.md:
        export_to_markdown(results, args.md)
    if hasattr(args, 'json') and args.json:
        export_to_json(results, args.json)
    if hasattr(args, 'csv') and args.csv:
        export_to_csv(results, args.csv)


if __name__ == "__main__":
    main()
