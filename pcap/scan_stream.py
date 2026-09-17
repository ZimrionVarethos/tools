#!/usr/bin/env python3
"""
 PCAP Scan Stream (pcapscanstream / pcap/scan_stream.py)
Automated Deep Stream & Payload Inspector for Network PCAP/PCAPNG Captures:
1. Protocol Filtering: Scan TCP (-tcp), UDP (-udp), ICMP (-icmp), or All (-all) streams.
2. Custom & Proprietary Header Detector (e.g. OVSH1, BAM2, CHCK, custom C-struct containers).
3. High-Entropy & Encrypted Payload Detector (Shannon Entropy H > 7.2, ChaCha20/AES ciphertext detection).
4. Automated XOR Obfuscation Brute-Force & Key Recovery (0x01..0xFF).
5. Sensitive Word & CTF Keyword Hunter (telemetry, key, iv, nonce, chacha, aes, secret, token, ws://).
6. Flag Pattern Recognizer (Strict ASCII Regex, Base64 decoded, Hex encoded).
7. WebSocket RFC 6455 Unmasking (Text & Binary Frames, Opcode 1/2).
8. Interactive Stream Drilldown (-s <ID>) & Hex Dump Visualizer.
9. Protocol Hierarchy Statistics (--phs) matching 'tshark -q -z io,phs'.
10. Payload Exporter (--export-dir, --export-stream).
"""
import os
import sys
import argparse
import re
import math
import zlib
import gzip
import base64
import struct
import json
from io import BytesIO
from typing import List, Dict, Any, Optional, Tuple, Set

# Ensure tools directory is on sys.path
TOOLS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if TOOLS_DIR not in sys.path:
    sys.path.insert(0, TOOLS_DIR)

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.markup import escape

from core.banner import print_banner
from core.utils import human_size
from pcap.pcap_engine import (
    PCAPReader, PCAPEngine, Packet, TCPStream,
    LINKTYPE_ETHERNET, IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP, IPPROTO_ICMPV6
)

console = Console(force_terminal=True, legacy_windows=False)

# -------------------------------------------------------------------------
# Detection Signatures & Dictionaries
# -------------------------------------------------------------------------

FLAG_REGEX = re.compile(
    r"\b([A-Za-z0-9_\.\-]{2,40})\{([A-Za-z0-9_!@#\$%\^&\*\(\)\-\+=\.\?\/\s,;:~`|<>]{3,120})\}\b"
    r"|\b(flag\[[A-Za-z0-9_\-\s]{2,100}\])\b"
    r"|\b(FLAG\[[A-Za-z0-9_\-\s]{2,100}\])\b",
    re.IGNORECASE
)

# Known File Magic Headers
FILE_MAGICS = [
    (b"\x89PNG\r\n\x1a\n", "PNG Image"),
    (b"\xff\xd8\xff", "JPEG Image"),
    (b"GIF87a", "GIF87a Image"),
    (b"GIF89a", "GIF89a Image"),
    (b"PK\x03\x04", "ZIP / Office / APK Archive"),
    (b"PK\x05\x06", "Empty ZIP Archive"),
    (b"PK\x07\x08", "Spanned ZIP Archive"),
    (b"Rar!\x1a\x07\x00", "RAR Archive v4"),
    (b"Rar!\x1a\x07\x01\x00", "RAR Archive v5"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip Archive"),
    (b"\x1f\x8b\x08", "GZIP Compressed Stream"),
    (b"BZh", "BZIP2 Compressed Stream"),
    (b"\xfd7zXZ\x00", "XZ Compressed Stream"),
    (b"\x7fELF", "Linux ELF Executable/Binary"),
    (b"MZ", "Windows PE / EXE / DLL Executable"),
    (b"%PDF-", "PDF Document"),
    (b"SQLite format 3\x00", "SQLite3 Database"),
    (b"\x00asm", "WebAssembly (.wasm) Binary"),
    (b"RIFF", "WAV / AVI / WebP Container"),
    (b"\xa1\xb2\xc3\xd4", "PCAP Capture (Microsec BE)"),
    (b"\xd4\xc3\xb2\xa1", "PCAP Capture (Microsec LE)"),
    (b"\x0a\x0d\x0d\x0a", "PCAPNG Capture File")
]

# Sensitive Words by Category
SENSITIVE_KEYWORDS = {
    "CTF / Exfil": [
        "flag", "ctf", "secret", "admin", "password", "passwd", "token",
        "credential", "private key", "shadow", "unauthorized", "leak", "exfil"
    ],
    "Crypto / Keys": [
        "key", "iv", "nonce", "salt", "telemetry", "kdf", "chacha", "chacha20",
        "aes", "aes-256", "rsa", "hmac", "sha256", "rotasi", "firmware", "cipher",
        "decrypt", "encrypt"
    ],
    "C2 / Commands": [
        "whoami", "powershell", "cmd.exe", "/bin/sh", "/bin/bash", "nc -e",
        "eval(", "exec(", "system(", "reverse", "shell", "stager", "beacon"
    ],
    "Custom Protocol": [
        "share_frames", "session_id", "envelope", "chunk", "ticket", "helpdesk",
        "ovsh", "bam2", "chck", "sync", "diag"
    ]
}

# Standard HTTP headers to ignore during keyword search
HTTP_HEADERS_NOISE = [
    "sec-websocket-key", "keep-alive", "content-type", "user-agent",
    "accept-encoding", "access-control-allow-headers", "cache-control",
    "public-key-pins", "content-security-policy", "set-cookie", "cookie"
]

KNOWN_XOR_PLAIN_TARGETS = [
    b"GET ", b"POST ", b"HTTP/", b"flag{", b"FLAG{", b"TNI26{", b"GEMASTIK{",
    b"\x89PNG", b"PK\x03\x04", b"MZ", b"\x7fELF", b"%PDF"
]


def calculate_entropy(data: bytes) -> float:
    """Calculates Shannon Entropy (0.0 - 8.0)."""
    if not data:
        return 0.0
    length = len(data)
    counts = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def is_valid_flag_string(candidate: str) -> bool:
    """Strictly validates if candidate is a genuine printable CTF flag."""
    if not candidate or len(candidate) < 5 or len(candidate) > 150:
        return False
    if "{" in candidate and candidate.endswith("}"):
        prefix, _, inside = candidate.partition("{")
        inside = inside[:-1]
        # Prefix must be alphanumeric / standard
        if not re.match(r"^[A-Za-z0-9_\.\-]{2,30}$", prefix):
            return False
        # Inside MUST be 100% printable ASCII characters
        if not all(32 <= ord(c) <= 126 for c in inside):
            return False
        # Must have at least one letter or digit
        if not re.search(r"[A-Za-z0-9]", inside):
            return False
        return True
    return False


def detect_custom_magic(data: bytes) -> Optional[str]:
    """
    Detects custom/proprietary container magic headers (e.g. OVSH1, BAM2, CHCK, ENC1).
    Heuristic: Starts with 3-8 printable ASCII chars (typically uppercase/alphanumeric)
    followed by null byte or binary lengths/structs.
    """
    if len(data) < 4:
        return None

    # Check for known custom headers first
    known_custom = [b"OVSH1", b"OVSH", b"BAM2", b"CHCK", b"FLAG", b"SYNC", b"TELE", b"ENC1", b"C2PK", b"RAW1"]
    for kc in known_custom:
        if data.startswith(kc):
            try:
                tag = kc.decode("ascii")
                return tag
            except Exception:
                pass

    # Generic custom container detection: 3-8 ASCII uppercase/alphanumeric bytes + (null or non-printable length)
    for length in range(3, min(9, len(data))):
        prefix = data[:length]
        if all((65 <= b <= 90) or (48 <= b <= 57) or b == 95 for b in prefix):  # Uppercase, digits, underscore
            next_byte = data[length] if length < len(data) else 0
            # If followed by null byte or non-ascii binary struct byte, likely a custom header!
            if next_byte == 0x00 or next_byte < 0x20 or next_byte > 0x7e:
                try:
                    return prefix.decode("ascii")
                except Exception:
                    pass
    return None


def unmask_websocket_frames(data: bytes) -> Tuple[bytes, List[Dict[str, Any]]]:
    """
    Parses and unmasks RFC 6455 WebSocket frames.
    Extracts text and binary payloads.
    """
    frames = []
    unmasked_payloads = bytearray()
    offset = 0

    while offset + 2 <= len(data):
        b1 = data[offset]
        b2 = data[offset + 1]
        fin = bool(b1 & 0x80)
        opcode = b1 & 0x0F
        masked = bool(b2 & 0x80)
        payload_len = b2 & 0x7F
        offset += 2

        if payload_len == 126:
            if offset + 2 > len(data): break
            payload_len = struct.unpack("!H", data[offset:offset+2])[0]
            offset += 2
        elif payload_len == 127:
            if offset + 8 > len(data): break
            payload_len = struct.unpack("!Q", data[offset:offset+8])[0]
            offset += 8

        mask_key = b""
        if masked:
            if offset + 4 > len(data): break
            mask_key = data[offset:offset+4]
            offset += 4

        if offset + payload_len > len(data):
            # Incomplete frame
            raw_chunk = data[offset:]
            if masked and mask_key:
                unmasked = bytes(b ^ mask_key[i % 4] for i, b in enumerate(raw_chunk))
            else:
                unmasked = raw_chunk
            unmasked_payloads.extend(unmasked)
            break

        chunk = data[offset:offset+payload_len]
        offset += payload_len

        if masked and mask_key:
            unmasked = bytes(b ^ mask_key[i % 4] for i, b in enumerate(chunk))
        else:
            unmasked = chunk

        opcode_names = {0: "Continuation", 1: "Text", 2: "Binary", 8: "Close", 9: "Ping", 10: "Pong"}
        frames.append({
            "opcode": opcode,
            "opcode_name": opcode_names.get(opcode, f"Opcode-{opcode}"),
            "fin": fin,
            "length": payload_len,
            "data": unmasked
        })
        unmasked_payloads.extend(unmasked)

    return bytes(unmasked_payloads), frames


def test_xor_obfuscation(data: bytes, sample_size: int = 64) -> Optional[Tuple[int, str, str]]:
    """
    Brute forces single-byte XOR (0x01..0xFF) on first sample_size bytes.
    Returns (key, matched_target, preview_str) if a match is found.
    """
    if len(data) < 4:
        return None
    sample = data[:sample_size]

    for key in range(1, 256):
        decrypted = bytes(b ^ key for b in sample)
        for target in KNOWN_XOR_PLAIN_TARGETS:
            if target in decrypted:
                preview = "".join(chr(b) if 32 <= b <= 126 else "." for b in decrypted[:40])
                return key, target.decode("latin-1", errors="replace"), preview
    return None


def search_flags_in_data(data: bytes) -> List[str]:
    """Finds flags in raw bytes, base64 strings, and hex sequences with strict validation."""
    found = []
    text = data.decode("latin-1", errors="ignore")

    # 1. Plain regex search
    for m in FLAG_REGEX.finditer(text):
        fl = m.group(0).strip()
        if is_valid_flag_string(fl) and fl not in found:
            found.append(fl)

    # 2. Base64 strings inside text
    b64_matches = re.findall(r"[A-Za-z0-9+/=]{16,}", text)
    for b_cand in b64_matches:
        try:
            padded = b_cand + "=" * ((4 - len(b_cand) % 4) % 4)
            dec = base64.b64decode(padded, validate=False)
            dec_text = dec.decode("latin-1", errors="ignore")
            for m in FLAG_REGEX.finditer(dec_text):
                fl_raw = m.group(0).strip()
                if is_valid_flag_string(fl_raw):
                    fl = f"[B64: {b_cand[:12]}...] {fl_raw}"
                    if fl not in found:
                        found.append(fl)
        except Exception:
            pass

    # 3. Hex strings inside text
    hex_matches = re.findall(r"[0-9a-fA-F]{20,}", text)
    for h_cand in hex_matches:
        if len(h_cand) % 2 == 0:
            try:
                dec = bytes.fromhex(h_cand)
                dec_text = dec.decode("latin-1", errors="ignore")
                for m in FLAG_REGEX.finditer(dec_text):
                    fl_raw = m.group(0).strip()
                    if is_valid_flag_string(fl_raw):
                        fl = f"[HEX: {h_cand[:12]}...] {fl_raw}"
                        if fl not in found:
                            found.append(fl)
            except Exception:
                pass

    return found


def analyze_stream_payload(
    stream_id: int,
    proto: str,
    src_endpoint: str,
    dst_endpoint: str,
    c2s_data: bytes,
    s2c_data: bytes
) -> Dict[str, Any]:
    """
    Performs deep multi-heuristic inspection on a single stream with anti-false-positive filtering.
    """
    combined_data = c2s_data + s2c_data
    total_len = len(combined_data)

    findings: List[str] = []
    tags: List[str] = []
    risk_score = 0  # 0: Low, 1: Medium, 2: High, 3: Critical

    is_standard_tls = (
        proto in ("TCP/TLS", "TLS") or
        src_endpoint.endswith(":443") or
        dst_endpoint.endswith(":443") or
        c2s_data.startswith(b"\x16\x03") or
        s2c_data.startswith(b"\x16\x03")
    )

    # 1. Entropy Calculation
    c2s_entropy = calculate_entropy(c2s_data)
    s2c_entropy = calculate_entropy(s2c_data)
    overall_entropy = calculate_entropy(combined_data)

    # Only flag High Entropy as suspicious if it's NOT a standard TLS handshake
    if total_len >= 32 and (overall_entropy >= 7.2 or c2s_entropy >= 7.2 or s2c_entropy >= 7.2):
        max_ent = max(overall_entropy, c2s_entropy, s2c_entropy)
        if not is_standard_tls:
            findings.append(f" [bold red]High Entropy / Encrypted[/bold red] (H = {max_ent:.2f}/8.0)")
            tags.append("ENCRYPTED/CIPHERTEXT")
            risk_score = max(risk_score, 2)
        else:
            tags.append("TLS_ENCRYPTED")

    # 2. Known File Magics
    for magic_bytes, magic_desc in FILE_MAGICS:
        if c2s_data.startswith(magic_bytes) or s2c_data.startswith(magic_bytes):
            findings.append(f" [cyan]File Magic:[/cyan] {magic_desc}")
            tags.append(f"MAGIC:{magic_desc.split()[0]}")
            risk_score = max(risk_score, 1)

    # 3. Custom & Proprietary Magic Headers (e.g. OVSH1, BAM2)
    c_magic = detect_custom_magic(c2s_data) or detect_custom_magic(s2c_data)
    if c_magic and not is_standard_tls:
        findings.append(f" [bold yellow]Custom Header:[/bold yellow] [bold white on blue] {c_magic} [/bold white on blue]")
        tags.append(f"CUSTOM_HDR:{c_magic}")
        risk_score = max(risk_score, 2)

    # 4. WebSocket Detection & Unmasking
    ws_frames = []
    if b"Upgrade: websocket" in combined_data or b"Sec-WebSocket-" in combined_data:
        findings.append(" [bold magenta]WebSocket Handshake[/bold magenta]")
        tags.append("WEBSOCKET")
        risk_score = max(risk_score, 1)

    # Try unmasking if potential WS binary stream
    ws_unmasked, ws_frames = unmask_websocket_frames(c2s_data)
    if ws_frames:
        for f in ws_frames:
            if f["opcode"] == 2:  # Binary
                findings.append(f" [magenta]WS Binary Frame[/magenta] ({human_size(f['length'])})")
                tags.append("WS_BINARY")
                risk_score = max(risk_score, 2)
                # Check custom magic inside unmasked WS data
                ws_magic = detect_custom_magic(f["data"])
                if ws_magic:
                    findings.append(f" [bold yellow]WS Custom Magic:[/bold yellow] [bold white on blue] {ws_magic} [/bold white on blue]")
                    tags.append(f"WS_MAGIC:{ws_magic}")
                    risk_score = max(risk_score, 2)

    # 5. XOR Obfuscation Brute Force (ignore if standard TLS)
    if not is_standard_tls:
        xor_res = test_xor_obfuscation(c2s_data) or test_xor_obfuscation(s2c_data)
        if xor_res:
            k, target_kw, preview = xor_res
            findings.append(f" [bold green]XOR Detected (Key 0x{k:02X}):[/bold green] '{preview}'")
            tags.append(f"XOR:0x{k:02X}")
            risk_score = max(risk_score, 2)

    # 6. Flag Hunter
    flags = search_flags_in_data(combined_data)
    if ws_unmasked:
        flags.extend(search_flags_in_data(ws_unmasked))

    if flags:
        for fl in flags:
            findings.append(f" [bold white on red] FLAG FOUND [/bold white on red] [bold yellow]{escape(fl)}[/bold yellow]")
            tags.append("FLAG")
            risk_score = 3

    # 7. Sensitive Word Search (Strip out standard HTTP headers first to eliminate false alarms)
    text_c2s = c2s_data.decode("latin-1", errors="ignore").lower()
    text_s2c = s2c_data.decode("latin-1", errors="ignore").lower()
    combined_text = text_c2s + "\n" + text_s2c

    # Clean out noisy header lines
    for noise_hdr in HTTP_HEADERS_NOISE:
        combined_text = re.sub(rf"{noise_hdr}\s*:[^\r\n]+", "", combined_text)

    kw_hits = {}
    for cat, kw_list in SENSITIVE_KEYWORDS.items():
        matched = []
        for w in kw_list:
            if re.search(r"\b" + re.escape(w) + r"\b", combined_text):
                matched.append(w)
        if matched:
            kw_hits[cat] = matched

    if kw_hits and not is_standard_tls:
        for cat, hits in kw_hits.items():
            hit_str = ", ".join(f"'{h}'" for h in hits[:4])
            if len(hits) > 4:
                hit_str += f" (+{len(hits)-4} more)"
            findings.append(f" [yellow]{cat}:[/yellow] {hit_str}")
            tags.append(f"KW:{hits[0]}")
            risk_score = max(risk_score, 1)

    # Summary preview (First 32 bytes hex + ASCII)
    preview_bytes = c2s_data[:32] if c2s_data else s2c_data[:32]
    hex_snip = " ".join(f"{b:02x}" for b in preview_bytes[:16])
    ascii_snip = "".join(chr(b) if 32 <= b <= 126 else "." for b in preview_bytes[:24])

    risk_label = "LOW"
    risk_style = "dim cyan"
    if risk_score == 3:
        risk_label = "CRITICAL"
        risk_style = "bold white on red"
    elif risk_score == 2:
        risk_label = "HIGH"
        risk_style = "bold red"
    elif risk_score == 1:
        risk_label = "MEDIUM"
        risk_style = "bold yellow"

    return {
        "stream_id": stream_id,
        "proto": proto,
        "src": src_endpoint,
        "dst": dst_endpoint,
        "c2s_len": len(c2s_data),
        "s2c_len": len(s2c_data),
        "total_len": total_len,
        "entropy": overall_entropy,
        "c2s_entropy": c2s_entropy,
        "s2c_entropy": s2c_entropy,
        "findings": findings,
        "tags": tags,
        "flags": flags,
        "risk_score": risk_score,
        "risk_label": risk_label,
        "risk_style": risk_style,
        "hex_preview": hex_snip,
        "ascii_preview": ascii_snip,
        "c2s_data": c2s_data,
        "s2c_data": s2c_data
    }


def render_hexdump(data: bytes, title: str = "", color_style: str = "white", max_bytes: int = 512):
    """Renders canonical hex dump."""
    if not data:
        console.print(f"[{color_style}]<Empty Payload>[/{color_style}]")
        return

    table = Table(
        title=title if title else None,
        show_header=True,
        header_style="bold yellow",
        border_style="dim cyan",
        expand=True
    )
    table.add_column("Offset", style="bold magenta", width=10, justify="right")
    table.add_column("Hex Bytes (16-byte width)", style=color_style, min_width=50)
    table.add_column("ASCII Preview", style="bright_white", width=20)

    display_data = data[:max_bytes]
    for i in range(0, len(display_data), 16):
        chunk = display_data[i : i + 16]
        hex_str_1 = " ".join(f"{b:02X}" for b in chunk[:8])
        hex_str_2 = " ".join(f"{b:02X}" for b in chunk[8:])
        hex_full = f"{hex_str_1:<23}   {hex_str_2:<23}"
        ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        table.add_row(f"0x{i:08X}", hex_full, escape(ascii_str))

    console.print(table)
    if len(data) > max_bytes:
        console.print(f"[dim yellow]... Truncated ({human_size(len(data) - max_bytes)} remaining). Use --export to dump entire payload.[/dim yellow]")


def render_protocol_hierarchy(engine: PCAPEngine):
    """Renders protocol hierarchy statistics table matching 'tshark -q -z io,phs'."""
    table = Table(
        title=" Protocol Hierarchy Statistics (PHS)",
        show_header=True,
        header_style="bold yellow",
        border_style="bold blue",
        expand=True
    )
    table.add_column("Protocol Layer", style="bold cyan", min_width=25)
    table.add_column("Packets", style="bold green", justify="right", width=12)
    table.add_column("Bytes", style="bold magenta", justify="right", width=14)
    table.add_column("Share", style="yellow", justify="right", width=10)

    total_pkts = len(engine.packets)
    total_bytes = sum(engine.protocol_bytes.values()) if engine.protocol_bytes else 1

    for proto, count in sorted(engine.protocol_counts.items(), key=lambda x: x[1], reverse=True):
        b_count = engine.protocol_bytes.get(proto, 0)
        pct = (b_count / total_bytes * 100.0) if total_bytes > 0 else 0.0
        table.add_row(proto, f"{count:,}", human_size(b_count), f"{pct:.1f}%")

    console.print(table)
    console.print()


def main(custom_args: Optional[List[str]] = None):
    parser = argparse.ArgumentParser(
        prog="pcapscanstream",
        description=" PCAP Scan Stream - Deep Network Payload & Stream Hunter"
    )
    parser.add_argument("pcap_file", help="Path to .pcap or .pcapng network capture file")
    
    # Protocol Filter Flags
    proto_group = parser.add_argument_group("Protocol Selection")
    proto_group.add_argument("-tcp", "--tcp", action="store_true", help="Scan TCP streams (Default)")
    proto_group.add_argument("-udp", "--udp", action="store_true", help="Scan UDP streams / conversations")
    proto_group.add_argument("-icmp", "--icmp", action="store_true", help="Scan ICMP packets / data payloads")
    proto_group.add_argument("-all", "--all", action="store_true", help="Scan all supported protocols (TCP, UDP, ICMP)")

    # Filtering & Drilldown
    filter_group = parser.add_argument_group("Filters & Stream Drilldown")
    filter_group.add_argument("-s", "--stream", type=int, default=None, help="Focus / Drilldown into a specific Stream ID")
    filter_group.add_argument("-p", "--pattern", type=str, default=None, help="Custom regex / keyword search filter")
    filter_group.add_argument("--min-size", type=int, default=0, help="Minimum total payload bytes threshold (e.g. --min-size 10)")
    filter_group.add_argument("--only-sus", action="store_true", help="Only show streams with Medium/High/Critical anomalies")
    filter_group.add_argument("--non-standard", action="store_true", help="Only show streams on non-standard ports (ignores 80/443)")
    
    # Views & Exports
    view_group = parser.add_argument_group("Output & Export Options")
    view_group.add_argument("--phs", "--hierarchy", action="store_true", help="Display Protocol Hierarchy Statistics (PHS)")
    view_group.add_argument("--export-dir", type=str, default=None, help="Directory to export suspicious streams to disk")
    view_group.add_argument("--export-stream", type=int, default=None, help="Export specific stream client/server payloads to disk")
    parser.add_argument("--json", action="store_true", help="Output analysis as JSON format")

    args = parser.parse_args(custom_args if custom_args is not None else sys.argv[1:])

    if not os.path.exists(args.pcap_file):
        console.print(f"[bold red]Error:[/bold red] File not found: {args.pcap_file}")
        sys.exit(1)

    if not args.json:
        print_banner("PCAP SCAN STREAM", "Deep Stream & Payload Hunter")
        console.print(f"[bold cyan]Target PCAP:[/bold cyan] {args.pcap_file} ({human_size(os.path.getsize(args.pcap_file))})")

    # Determine protocols
    scan_tcp = args.tcp or (not args.udp and not args.icmp and not args.all) or args.all
    scan_udp = args.udp or args.all
    scan_icmp = args.icmp or args.all

    # Parse PCAP
    engine = PCAPEngine(args.pcap_file)
    engine.analyze()

    if args.phs and not args.json:
        render_protocol_hierarchy(engine)

    # Collect streams to analyze
    stream_analyses: List[Dict[str, Any]] = []

    # 1. Process TCP Streams
    if scan_tcp:
        for stream_id, (key, stream) in enumerate(engine.tcp_streams.items()):
            src_ep = f"{stream.client_ip}:{stream.client_port}"
            dst_ep = f"{stream.server_ip}:{stream.server_port}"
            
            analysis = analyze_stream_payload(
                stream_id=stream.stream_id,
                proto="TCP" if stream.protocol_name == "TCP" else f"TCP/{stream.protocol_name}",
                src_endpoint=src_ep,
                dst_endpoint=dst_ep,
                c2s_data=stream.client_payload,
                s2c_data=stream.server_payload
            )
            stream_analyses.append(analysis)

    # 2. Process UDP Conversations
    if scan_udp:
        # Group UDP packets by 5-tuple
        udp_convs: Dict[str, Dict[str, Any]] = {}
        udp_counter = 1000  # Offset UDP stream IDs
        for pkt in engine.packets:
            if pkt.ip_proto == IPPROTO_UDP and pkt.src_ip and pkt.dst_ip:
                c_key = (
                    f"{pkt.src_ip}:{pkt.src_port}-{pkt.dst_ip}:{pkt.dst_port}"
                    if (pkt.src_ip < pkt.dst_ip or (pkt.src_ip == pkt.dst_ip and pkt.src_port <= pkt.dst_port))
                    else f"{pkt.dst_ip}:{pkt.dst_port}-{pkt.src_ip}:{pkt.src_port}"
                )
                if c_key not in udp_convs:
                    udp_counter += 1
                    udp_convs[c_key] = {
                        "id": udp_counter,
                        "client_ip": pkt.src_ip,
                        "client_port": pkt.src_port,
                        "server_ip": pkt.dst_ip,
                        "server_port": pkt.dst_port,
                        "c2s": bytearray(),
                        "s2c": bytearray()
                    }
                conv = udp_convs[c_key]
                if pkt.src_ip == conv["client_ip"] and pkt.src_port == conv["client_port"]:
                    conv["c2s"].extend(pkt.payload)
                else:
                    conv["s2c"].extend(pkt.payload)

        for conv in udp_convs.values():
            src_ep = f"{conv['client_ip']}:{conv['client_port']}"
            dst_ep = f"{conv['server_ip']}:{conv['server_port']}"
            analysis = analyze_stream_payload(
                stream_id=conv["id"],
                proto="UDP",
                src_endpoint=src_ep,
                dst_endpoint=dst_ep,
                c2s_data=bytes(conv["c2s"]),
                s2c_data=bytes(conv["s2c"])
            )
            stream_analyses.append(analysis)

    # 3. Process ICMP Payloads
    if scan_icmp and engine.icmp_packets:
        icmp_combined = bytearray()
        for p in engine.icmp_packets:
            icmp_combined.extend(p["payload"])
        
        analysis = analyze_stream_payload(
            stream_id=9999,
            proto="ICMP",
            src_endpoint="ICMP-Echo-Requests",
            dst_endpoint="ICMP-Echo-Replies",
            c2s_data=bytes(icmp_combined),
            s2c_data=b""
        )
        stream_analyses.append(analysis)

    # Apply filters
    filtered_streams = stream_analyses
    if args.stream is not None:
        filtered_streams = [s for s in filtered_streams if s["stream_id"] == args.stream]
    if args.min_size > 0:
        filtered_streams = [s for s in filtered_streams if s["total_len"] >= args.min_size]
    if args.only_sus:
        filtered_streams = [s for s in filtered_streams if s["risk_score"] >= 1]
    if args.non_standard:
        filtered_streams = [
            s for s in filtered_streams
            if not (s["src"].endswith(":80") or s["src"].endswith(":443") or s["dst"].endswith(":80") or s["dst"].endswith(":443"))
        ]
    if args.pattern:
        pat_re = re.compile(args.pattern, re.IGNORECASE)
        filtered_streams = [
            s for s in filtered_streams
            if pat_re.search(s["c2s_data"].decode("latin-1", errors="ignore")) or
               pat_re.search(s["s2c_data"].decode("latin-1", errors="ignore"))
        ]

    # JSON Output Mode
    if args.json:
        json_out = []
        for s in filtered_streams:
            json_out.append({
                "stream_id": s["stream_id"],
                "protocol": s["proto"],
                "src": s["src"],
                "dst": s["dst"],
                "total_bytes": s["total_len"],
                "entropy": round(s["entropy"], 3),
                "risk": s["risk_label"],
                "findings": s["findings"],
                "flags": s["flags"],
                "tags": s["tags"]
            })
        print(json.dumps(json_out, indent=2))
        return

    # Single Stream Drilldown Mode (-s <ID>)
    if args.stream is not None:
        if not filtered_streams:
            console.print(f"[bold red]Stream #{args.stream} not found in capture![/bold red]")
            return

        st = filtered_streams[0]
        console.print(Panel(
            f"[bold white]Stream #{st['stream_id']} Deep Forensic Breakdown[/bold white]\n"
            f"[cyan]Protocol:[/cyan] {st['proto']} | [yellow]Conversation:[/yellow] {st['src']}  {st['dst']}\n"
            f"[magenta]Total Size:[/magenta] {human_size(st['total_len'])} (Client: {human_size(st['c2s_len'])}, Server: {human_size(st['s2c_len'])})\n"
            f"[green]Entropy:[/green] {st['entropy']:.2f}/8.0 | [bold]Risk Level:[/bold] [{st['risk_style']}] {st['risk_label']} [/{st['risk_style']}]",
            title=f" Detailed Inspection: Stream #{st['stream_id']}",
            border_style="bold green"
        ))

        # Show Findings
        if st["findings"]:
            console.print("\n[bold yellow] Detected Anomalies & Signatures:[/bold yellow]")
            for f in st["findings"]:
                console.print(f"  • {f}")
            console.print()

        # Render Hex Dumps
        if st["c2s_data"]:
            render_hexdump(st["c2s_data"], f"Client  Server Payload ({human_size(st['c2s_len'])})", "cyan")
        if st["s2c_data"]:
            render_hexdump(st["s2c_data"], f"Server  Client Payload ({human_size(st['s2c_len'])})", "green")

        # Export if requested
        if args.export_dir:
            os.makedirs(args.export_dir, exist_ok=True)
            c2s_path = os.path.join(args.export_dir, f"stream_{st['stream_id']}_client.bin")
            s2c_path = os.path.join(args.export_dir, f"stream_{st['stream_id']}_server.bin")
            with open(c2s_path, "wb") as f: f.write(st["c2s_data"])
            with open(s2c_path, "wb") as f: f.write(st["s2c_data"])
            console.print(f"\n[bold green] Exported payloads to:[/bold green] {c2s_path} and {s2c_path}")
        return

    # Master Table View
    table = Table(
        title=f" Stream Scan Results ({len(filtered_streams)} Streams Analyzed)",
        show_header=True,
        header_style="bold yellow",
        border_style="dim cyan",
        expand=True
    )
    table.add_column("Stream", style="bold magenta", width=8, justify="center")
    table.add_column("Proto", style="cyan", width=12)
    table.add_column("Conversation (Src  Dst)", style="bright_white", width=34)
    table.add_column("Size", style="green", width=10, justify="right")
    table.add_column("Entropy", style="yellow", width=9, justify="right")
    table.add_column("Risk", width=10, justify="center")
    table.add_column("Anomalies / Signatures", style="white", min_width=35)
    table.add_column("Preview (Hex / ASCII)", style="dim white", min_width=25)

    sus_count = 0
    flag_count = 0

    for st in filtered_streams:
        if st["risk_score"] >= 1:
            sus_count += 1
        if st["flags"]:
            flag_count += len(st["flags"])

        # Format Findings summary
        findings_text = "\n".join(st["findings"][:3])
        if len(st["findings"]) > 3:
            findings_text += f"\n[dim yellow]+{len(st['findings'])-3} more...[/dim yellow]"
        if not findings_text:
            findings_text = "[dim]Normal traffic[/dim]"

        # Format Preview
        preview_text = f"[dim cyan]{st['hex_preview'][:24]}[/dim cyan]\n[bright_white]{escape(st['ascii_preview'][:20])}[/bright_white]"

        # Entropy formatting
        ent_str = f"{st['entropy']:.2f}"
        if st["entropy"] >= 7.2:
            ent_str = f"[bold red]{ent_str}[/bold red]"

        table.add_row(
            f"#{st['stream_id']}",
            st["proto"],
            f"{st['src']} \n{st['dst']}",
            human_size(st["total_len"]),
            ent_str,
            f"[{st['risk_style']}] {st['risk_label']} [/{st['risk_style']}]",
            findings_text,
            preview_text
        )

    console.print(table)
    console.print()

    # Summary Panel
    summary_msg = (
        f"[bold cyan]Total Streams Scanned:[/bold cyan] {len(filtered_streams)} | "
        f"[bold yellow]Suspicious Streams:[/bold yellow] {sus_count} | "
        f"[bold red]Flags Discovered:[/bold red] {flag_count}\n"
        f"[dim]Tip: Inspect a specific stream with [bold green]pcapscanstream {args.pcap_file} -s <STREAM_ID>[/bold green][/dim]"
    )
    console.print(Panel(summary_msg, border_style="bold green" if flag_count > 0 else "dim green"))

    # Export suspicious streams if requested
    if args.export_dir and sus_count > 0:
        os.makedirs(args.export_dir, exist_ok=True)
        for st in filtered_streams:
            if st["risk_score"] >= 2:
                p_c2s = os.path.join(args.export_dir, f"stream_{st['stream_id']}_client.bin")
                p_s2c = os.path.join(args.export_dir, f"stream_{st['stream_id']}_server.bin")
                if st["c2s_data"]:
                    with open(p_c2s, "wb") as f: f.write(st["c2s_data"])
                if st["s2c_data"]:
                    with open(p_s2c, "wb") as f: f.write(st["s2c_data"])
        console.print(f"[bold green] Exported all suspicious streams to:[/bold green] {args.export_dir}")


if __name__ == "__main__":
    main()
