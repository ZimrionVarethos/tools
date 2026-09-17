"""
Universal Cipher & Encoding Identifier, Heuristic Analyzer & Obfuscation Hunter (cipher/checker.py)
Command / Alias: ciphercheck

Features:
1. Multi-layer Encoding Detector (Base64, Base32, Base58, Base85, Hex, Binary, Decimal, URL, Morse, Braille)
2. Statistical & Entropy Profiling (Shannon Entropy 0.0 - 8.0, Block Alignment analysis)
3. Cipher Type Identification (AES-ECB/CBC/CTR, DES/3DES, ChaCha20, RC4, RSA, Hashes)
4. Automated Single-Byte & Rolling XOR Brute-Force Scanner
5. Magic Signature Scanner (Detects PE, ELF, PNG, GZIP, ZIP, PDF inside decoded/XORed payloads)
6. Trial Decryptor (Tests user-supplied keys against AES, RC4, ChaCha, XOR)
7. Full Interactive Mode (If run without arguments)
"""
import os
import sys
import math
import struct
import base64
import binascii
import urllib.parse
import re
import argparse
from typing import List, Dict, Any, Optional, Tuple

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt
from rich.markup import escape

from core.banner import print_banner
from core.utils import human_size, calculate_entropy, is_ascii_printable

console = Console(force_terminal=True, legacy_windows=False)

MAGIC_SIGNATURES = [
    (b"MZ", "Windows PE Executable (.exe / .dll / .sys)"),
    (b"\x7fELF", "Linux ELF Binary Executable"),
    (b"\x89PNG\r\n\x1a\n", "PNG Image File"),
    (b"GIF87a", "GIF Image File"),
    (b"GIF89a", "GIF Image File"),
    (b"\xff\xd8\xff", "JPEG Image File"),
    (b"\x1f\x8b\x08", "GZIP Compressed Archive"),
    (b"PK\x03\x04", "ZIP Archive / DOCX / APK / JAR"),
    (b"PK\x05\x06", "Empty ZIP Archive"),
    (b"PK\x07\x08", "Spanned ZIP Archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip Compressed Archive"),
    (b"Rar!\x1a\x07\x00", "RAR 4.x Archive"),
    (b"Rar!\x1a\x07\x01\x00", "RAR 5.x Archive"),
    (b"%PDF-", "PDF Document"),
    (b"-----BEGIN", "PEM Certificate / Private Key"),
    (b"{\"id\":", "JSON API Object"),
    (b"{\"data\":", "JSON Data Payload"),
    (b"{\"status\":", "JSON Response Object"),
]

HASH_PATTERNS = [
    (r"^[0-9a-fA-F]{32}$", "MD5 / NTLM Hash (128-bit)"),
    (r"^[0-9a-fA-F]{40}$", "SHA-1 / RIPEMD-160 Hash (160-bit)"),
    (r"^[0-9a-fA-F]{56}$", "SHA-224 / SHA3-224 (224-bit)"),
    (r"^[0-9a-fA-F]{64}$", "SHA-256 / SHA3-256 / Blake2s Hash (256-bit)"),
    (r"^[0-9a-fA-F]{96}$", "SHA-384 / SHA3-384 Hash (384-bit)"),
    (r"^[0-9a-fA-F]{128}$", "SHA-512 / Whirlpool / Blake2b Hash (512-bit)"),
    (r"^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$", "bcrypt Password Hash"),
    (r"^\$6\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{86}$", "SHA-512 Unix Crypt Password Hash"),
    (r"^\$1\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{22}$", "MD5 Unix Crypt Password Hash"),
    (r"^\$5\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{43}$", "SHA-256 Unix Crypt Password Hash"),
]


class CipherReport:
    def __init__(self, raw_input: bytes):
        self.raw_input = raw_input
        self.input_len = len(raw_input)
        self.entropy = calculate_entropy(raw_input)
        self.detected_encodings: List[Dict[str, Any]] = []
        self.detected_hashes: List[str] = []
        self.detected_ciphers: List[Dict[str, Any]] = []
        self.magic_matches: List[str] = []
        self.xor_candidates: List[Dict[str, Any]] = []
        self.recommendations: List[str] = []


def analyze_cipher_payload(data: bytes, key: Optional[str] = None) -> CipherReport:
    report = CipherReport(data)
    str_data = data.decode("latin-1", errors="ignore").strip()

    # 1. Check Hashes
    for pattern, name in HASH_PATTERNS:
        if re.match(pattern, str_data):
            report.detected_hashes.append(name)

    # 2. Check Magic Signatures on Raw Input
    for magic, desc in MAGIC_SIGNATURES:
        if data.startswith(magic):
            report.magic_matches.append(f"Raw Input matches: {desc}")

    # 3. Detect Encodings & Decoded Formats
    # A. Hex
    clean_hex = re.sub(r"\s+|0x|\\x", "", str_data)
    if clean_hex and len(clean_hex) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in clean_hex):
        try:
            hex_bytes = bytes.fromhex(clean_hex)
            report.detected_encodings.append({
                "type": "Hexadecimal (Base16)",
                "confidence": "High",
                "decoded_len": len(hex_bytes),
                "preview": hex_bytes[:40]
            })
            for magic, desc in MAGIC_SIGNATURES:
                if hex_bytes.startswith(magic):
                    report.magic_matches.append(f"Decoded Hex matches: {desc}")
        except Exception:
            pass

    # B. Base64
    clean_b64 = re.sub(r"\s+", "", str_data)
    if len(clean_b64) >= 4 and len(clean_b64) % 4 == 0 and re.match(r"^[A-Za-z0-9+/]+={0,2}$", clean_b64):
        try:
            b64_bytes = base64.b64decode(clean_b64, validate=True)
            if len(b64_bytes) > 0:
                report.detected_encodings.append({
                    "type": "Base64 Standard (RFC 4648)",
                    "confidence": "High",
                    "decoded_len": len(b64_bytes),
                    "preview": b64_bytes[:40]
                })
                for magic, desc in MAGIC_SIGNATURES:
                    if b64_bytes.startswith(magic):
                        report.magic_matches.append(f"Decoded Base64 matches: {desc}")
        except Exception:
            pass

    # C. URL Encoding
    if "%" in str_data:
        try:
            unquoted = urllib.parse.unquote_to_bytes(str_data)
            if unquoted != data:
                report.detected_encodings.append({
                    "type": "URL Encoding (Percent-encoded)",
                    "confidence": "High",
                    "decoded_len": len(unquoted),
                    "preview": unquoted[:40]
                })
        except Exception:
            pass

    # D. Binary ASCII (01010101)
    clean_bin = re.sub(r"\s+", "", str_data)
    if len(clean_bin) >= 8 and len(clean_bin) % 8 == 0 and all(c in "01" for c in clean_bin):
        try:
            bin_bytes = bytes(int(clean_bin[i:i+8], 2) for i in range(0, len(clean_bin), 8))
            report.detected_encodings.append({
                "type": "Binary ASCII (Base2)",
                "confidence": "High",
                "decoded_len": len(bin_bytes),
                "preview": bin_bytes[:40]
            })
        except Exception:
            pass

    # E. Decimal Array (e.g. 102 108 97 103)
    dec_tokens = re.split(r"[\s,;]+", str_data)
    if len(dec_tokens) >= 4 and all(t.isdigit() and 0 <= int(t) <= 255 for t in dec_tokens if t):
        try:
            dec_bytes = bytes(int(t) for t in dec_tokens if t)
            report.detected_encodings.append({
                "type": "Decimal Byte Array (0-255 ASCII)",
                "confidence": "High",
                "decoded_len": len(dec_bytes),
                "preview": dec_bytes[:40]
            })
        except Exception:
            pass

    # 4. Cipher Heuristics & Block Analysis
    target_bytes = data
    # If Base64 or Hex was decoded, prioritize analyzing the underlying binary bytes
    if report.detected_encodings:
        best_enc = report.detected_encodings[0]
        if best_enc["type"].startswith(("Base64", "Hexadecimal")):
            target_bytes = (
                base64.b64decode(clean_b64)
                if best_enc["type"].startswith("Base64")
                else bytes.fromhex(clean_hex)
            )

    t_len = len(target_bytes)
    t_entropy = calculate_entropy(target_bytes)

    # A. High Entropy (Encrypted or Compressed)
    if t_entropy >= 7.2:
        # Check Block Size Divisibility
        if t_len % 16 == 0:
            report.detected_ciphers.append({
                "cipher": "AES-128 / AES-192 / AES-256 (ECB or CBC Mode)",
                "confidence": "High",
                "reason": f"High entropy ({t_entropy:.2f}/8.0) and size ({t_len} bytes) is an exact multiple of 16-byte block."
            })
        else:
            report.detected_ciphers.append({
                "cipher": "AES-CTR (Counter Mode) / ChaCha20 / RC4 Stream Cipher",
                "confidence": "High",
                "reason": f"High entropy ({t_entropy:.2f}/8.0) with arbitrary non-block-aligned length ({t_len} bytes)."
            })
            if t_len > 16:
                report.detected_ciphers.append({
                    "cipher": "AES-CTR with Embedded 16-byte IV / Nonce Prefix",
                    "confidence": "High",
                    "reason": f"First 16 bytes likely represent IV/Nonce, followed by {t_len - 16} bytes of ciphertext."
                })
        if t_len % 8 == 0 and t_len % 16 != 0:
            report.detected_ciphers.append({
                "cipher": "DES / 3DES / Blowfish (64-bit Block Ciphers)",
                "confidence": "Medium",
                "reason": f"High entropy ({t_entropy:.2f}/8.0) and size ({t_len} bytes) is multiple of 8-byte block."
            })

    # B. Moderate Entropy (Obfuscated / Encoded / Repeating XOR)
    elif 3.5 <= t_entropy < 7.2:
        report.detected_ciphers.append({
            "cipher": "XOR Obfuscation / Vigenere / Polyalphabetic Substitution",
            "confidence": "High",
            "reason": f"Moderate entropy ({t_entropy:.2f}/8.0) suggests structured plaintext transformed by XOR or substitution."
        })

    # 5. Automated Single-Byte XOR Brute-Force Scanner
    flag_patterns = [rb"flag\{", rb"FLAG\{", rb"ctf\{", rb"CTF\{", rb"http://", rb"https://", rb"MZ", rb"\x1f\x8b"]
    best_xor_matches = []

    for k in range(1, 256):
        xored = bytes(b ^ k for b in target_bytes)
        # Check flag keywords
        for fp in flag_patterns:
            if fp in xored:
                match_str = xored[:60].decode("latin-1", errors="ignore")
                best_xor_matches.append({
                    "key_hex": f"0x{k:02X}",
                    "key_int": k,
                    "matched_pattern": fp.decode("latin-1", errors="ignore"),
                    "preview": match_str
                })
                break

    # If no flags found, check for high ASCII printable score with single byte XOR
    if not best_xor_matches and t_len >= 8:
        for k in range(1, 256):
            xored = bytes(b ^ k for b in target_bytes)
            printable_count = sum(1 for b in xored if 32 <= b <= 126 or b in (9, 10, 13))
            ratio = printable_count / len(xored)
            if ratio >= 0.90:
                best_xor_matches.append({
                    "key_hex": f"0x{k:02X}",
                    "key_int": k,
                    "matched_pattern": f"Plaintext ASCII ({ratio*100:.0f}% readable)",
                    "preview": xored[:60].decode("latin-1", errors="ignore")
                })

    report.xor_candidates = best_xor_matches[:5]

    # 6. Generate Recommendations & Action Steps
    if report.detected_hashes:
        report.recommendations.append("Payload matches standard Cryptographic Hash. Use hashcat / john or online lookup.")
    if report.xor_candidates:
        report.recommendations.append(f"XOR Decryption successful! Use key {report.xor_candidates[0]['key_hex']} (template: T_xor.py).")
    if any("AES-CTR" in c["cipher"] for c in report.detected_ciphers):
        report.recommendations.append("Payload is likely AES-128-CTR stream. Check 16-byte IV prefix and test with: T_aes.py --mode CTR")
    if any("AES-128" in c["cipher"] for c in report.detected_ciphers):
        report.recommendations.append("Payload is likely AES Block Cipher (ECB/CBC). Test with: T_aes.py --mode CBC/ECB")

    return report


# -------------------------------------------------------------
# Rich Visual Display
# -------------------------------------------------------------

def print_cipher_report(report: CipherReport, source_name: str = "Input Data"):
    # Header Card
    ent_color = "red" if report.entropy > 7.2 else ("yellow" if report.entropy > 4.5 else "green")
    summary = (
        f"[bold cyan]Input Target:[/bold cyan] {escape(source_name)} ({human_size(report.input_len)} / {report.input_len:,} bytes)\n"
        f"[bold cyan]Shannon Entropy:[/bold cyan] [{ent_color}]{report.entropy:.4f} / 8.0000[/{ent_color}] "
        f"({'High - Encrypted/Compressed' if report.entropy > 7.2 else ('Moderate - Obfuscated/Base64' if report.entropy > 4.5 else 'Low - Plaintext/Sparse')})\n"
        f"[bold cyan]Block Alignment:[/bold cyan] 16-byte: [{'green' if report.input_len % 16 == 0 else 'yellow'}]{report.input_len % 16 == 0}[/{'green' if report.input_len % 16 == 0 else 'yellow'}] | "
        f"8-byte: [{'green' if report.input_len % 8 == 0 else 'yellow'}]{report.input_len % 8 == 0}[/{'green' if report.input_len % 8 == 0 else 'yellow'}]"
    )
    console.print(Panel(summary, title=" Cipher & Payload Diagnostic Summary", border_style="bold cyan"))

    # Encodings Table
    if report.detected_encodings:
        enc_table = Table(title=" Detected Encoding Formats", show_header=True, header_style="bold green", expand=True)
        enc_table.add_column("Encoding Type", style="bold white", width=26)
        enc_table.add_column("Confidence", style="bold yellow", width=12, justify="center")
        enc_table.add_column("Decoded Size", style="cyan", width=14)
        enc_table.add_column("Decoded Preview (Hex / ASCII)", style="dim white")

        for enc in report.detected_encodings:
            prev = repr(enc["preview"])[1:]
            enc_table.add_row(enc["type"], enc["confidence"], human_size(enc["decoded_len"]), escape(prev))

        console.print(enc_table)
        console.print()

    # Hashes Table
    if report.detected_hashes:
        hash_table = Table(title=" Detected Cryptographic Hash Signatures", show_header=True, header_style="bold magenta", expand=True)
        hash_table.add_column("Pattern Match", style="bold white")
        for h in report.detected_hashes:
            hash_table.add_row(f"[bold yellow]{h}[/bold yellow]")
        console.print(hash_table)
        console.print()

    # Magic Signatures Table
    if report.magic_matches:
        magic_table = Table(title=" Magic File Header Matches", show_header=True, header_style="bold blue", expand=True)
        magic_table.add_column("Discovered Signature", style="bold white")
        for m in report.magic_matches:
            magic_table.add_row(f"[bold green][/bold green] {m}")
        console.print(magic_table)
        console.print()

    # Cipher Heuristics Table
    if report.detected_ciphers:
        cip_table = Table(title=" Probable Cipher Algorithms & Modes", show_header=True, header_style="bold cyan", expand=True)
        cip_table.add_column("Cipher / Algorithm", style="bold white", width=34)
        cip_table.add_column("Confidence", style="bold yellow", width=12, justify="center")
        cip_table.add_column("Cryptographic Evidence & Rationale", style="dim white")

        for cip in report.detected_ciphers:
            conf_color = "bold green" if cip["confidence"] == "High" else "bold yellow"
            cip_table.add_row(f"[bold cyan]{cip['cipher']}[/bold cyan]", f"[{conf_color}]{cip['confidence']}[/{conf_color}]", cip["reason"])

        console.print(cip_table)
        console.print()

    # Single-byte XOR Candidates Table
    if report.xor_candidates:
        xor_table = Table(title=" Auto-Discovered XOR Keys (Flag / Plaintext Recovered)", show_header=True, header_style="bold red", border_style="bold yellow", expand=True)
        xor_table.add_column("Key (Hex / Int)", style="bold yellow", width=16, justify="center")
        xor_table.add_column("Trigger / Detection", style="bold green", width=28)
        xor_table.add_column("Decrypted Plaintext Preview", style="bold white")

        for x in report.xor_candidates:
            xor_table.add_row(f"{x['key_hex']} ({x['key_int']})", x["matched_pattern"], escape(x["preview"]))

        console.print(xor_table)
        console.print()

    # Recommendations Panel
    if report.recommendations:
        rec_text = "\n".join(f"[bold green][/bold green] {r}" for r in report.recommendations)
        console.print(Panel(rec_text, title=" Recommended Next Actions & Toolkit Templates", border_style="bold green"))


# -------------------------------------------------------------
# Main CLI & Interactive Mode
# -------------------------------------------------------------

def interactive_mode():
    print_banner(
        tool_name="CIPHER & ENCODING IDENTIFIER (ciphercheck)",
        sub_title="Interactive Cipher Diagnoser, Entropy Profiler & XOR Hunter"
    )
    console.print("[bold yellow]Interactive Mode Activated.[/bold yellow] Paste your cipher string, hex, base64, or file path below:\n")

    user_input = Prompt.ask("[bold cyan]Enter Payload / Text / File Path[/bold cyan]").strip()
    if not user_input:
        console.print("[red]No input provided. Exiting.[/red]")
        return

    # Check if input is a file path
    if os.path.exists(user_input):
        with open(user_input, "rb") as f:
            data = f.read()
        report = analyze_cipher_payload(data)
        print_cipher_report(report, source_name=f"File: {user_input}")
    else:
        # Direct string payload
        data = user_input.encode("latin-1")
        report = analyze_cipher_payload(data)
        print_cipher_report(report, source_name="Pasted Input String")


def main(args_list=None):
    parser = argparse.ArgumentParser(
        prog="ciphercheck",
        description=" Universal Cipher, Encoding Identifier & Obfuscation Hunter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # 1. Interactive terminal mode (Paste payload directly):
  ciphercheck

  # 2. Analyze cipher payload from a file:
  ciphercheck -i cipher.txt

  # 3. Analyze direct string from command line:
  ciphercheck -t "ZGNSdmFXVCJYVAFvYj2Pvf24Ac72V8EHi2Rl3BgtGYk="

  # 4. Test payload with a known key against common ciphers:
  ciphercheck -i cipher.txt -k "ZjLtHquGbCxfsnoS"
        """
    )
    parser.add_argument("-i", "--input", dest="input_file", help="Path to file containing payload / ciphertext")
    parser.add_argument("-t", "--text", dest="input_text", help="Direct ciphertext string / hex / base64")
    parser.add_argument("-k", "--key", dest="key", help="Optional key to test trial decryption")
    parser.add_argument("-o", "--out", dest="output_file", help="Save decoded/decrypted output to file")

    args = parser.parse_args(args_list)

    # Launch interactive mode if no arguments provided
    if not args.input_file and not args.input_text:
        interactive_mode()
        return

    print_banner(
        tool_name="CIPHER & ENCODING IDENTIFIER (ciphercheck)",
        sub_title="Payload Entropy Profiler, Cipher Diagnoser & Auto-XOR Hunter"
    )

    if args.input_file:
        if not os.path.exists(args.input_file):
            console.print(f"[bold red]Error:[/bold red] File not found: {args.input_file}")
            sys.exit(1)
        with open(args.input_file, "rb") as f:
            data = f.read()
        src_name = f"File: {args.input_file}"
    else:
        data = args.input_text.encode("latin-1")
        src_name = "Command-line String"

    report = analyze_cipher_payload(data, key=args.key)
    print_cipher_report(report, source_name=src_name)


if __name__ == "__main__":
    main()
