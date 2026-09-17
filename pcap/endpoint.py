#!/usr/bin/env python3
"""
 PCAP Endpoint & C2 Hunter (pcapendpoint / pcap/endpoint.py)
Automated Multi-Stream Forensic Endpoint & Threat Scanner:
1. Universal Stream Endpoint Scan: Scans HTTP, TLS SNI, WebSockets, and DNS queries across all streams.
2. Advanced Threat & Suspicion Heuristics:
   - C2 / Beaconing: Detects C2 gates, heartbeats, tasking endpoints (/api/v1/hs, /gate, /beacon), polling sequences.
   - Fake Telemetry & Impersonation Hunter: Detects domains mimicking telemetry keywords (telemetry, analytics, connecttest, gstatic) on unauthorized roots.
   - Multi-Base Recursive Unpacker: Auto-decodes Base64, Base32, Hex, and URL-encoding across paths, query params, headers, and JSON bodies.
   - Secret & Cryptographic Seed Leaks: Carves cryptographic seeds (seed), session tokens (sid), AES keys, API keys, Bearer/Basic auth.
   - Data Exfiltration: Identifies exfil endpoints (/api/v1/up, /upload), base64 dumps, and large data blobs (>1KB).
   - CTF Flags: Regex discovery for flags (CTF{...}, flag{...}, etc.) across raw and multi-base decoded payloads.
   - Sensitive & Admin Endpoints: /admin, /login, /eval, /shell, /cmd, /debug, /.env, /.git.
   - High Entropy & DGA: Shannon entropy scoring on paths and subdomains.
3. Executive Summary First: Instantly lists which streams contain C2 endpoints, secrets, flags, exfiltrations, etc.
4. Actionable Drilldown (-s <ID>): Interactive Wireshark-style follow-stream with syntax-highlighted bidirectional conversation.
"""
import os
import sys
import argparse
import re
import json
import math
import collections
import subprocess
import urllib.parse
import base64
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

console = Console(force_terminal=True, legacy_windows=False)

# -------------------------------------------------------------------------
# Detection Dictionaries & Threat Heuristics
# -------------------------------------------------------------------------

# Canonical legitimate root domains for OS/Vendor Telemetry
OFFICIAL_TELEMETRY_ROOTS = {
    "gstatic.com",
    "google.com",
    "googleapis.com",
    "gvt1.com",
    "gvt2.com",
    "ggpht.com",
    "android.com",
    "windowsupdate.com",
    "microsoft.com",
    "msftconnecttest.com",
    "msftncsi.com",
    "apple.com",
    "icloud.com",
    "mozilla.org",
    "firefox.com",
    "ubuntu.com",
    "debian.org"
}

# Suspicious words often used by attackers or malware to disguise as telemetry
TELEMETRY_MIMIC_KEYWORDS = [
    "telemetry", "telemetri", "analytic", "analytics", "metric", "metrics",
    "beacon", "diagnostics", "crashreport", "connecttest", "connectivity",
    "gstatic", "google-api", "msft-update", "windows-update", "cloud-sync",
    "log-collector", "telemetry-service", "sys-check", "heartbeat", "tracking"
]

TELEMETRY_PATHS = {
    "/generate_204",
    "/gen_204",
    "/connecttest.txt",
    "/ncsi.txt",
    "/success.txt",
    "/canonical.html",
}

# Suspicious C2 & Beaconing Path Patterns
C2_PATH_KEYWORDS = [
    "api/v1", "api/v2", "api/v3", "c2", "beacon", "gate", "hs", "heartbeat",
    "handshake", "seed", "cmd", "command", "task", "poll", "ping",
    "checkin", "register", "agent", "bot", "drop", "tunnel"
]

# Exfiltration Path Patterns
EXFIL_PATH_KEYWORDS = [
    "up", "upload", "exfil", "drop", "dump", "push", "data", "submit", "file", "recv"
]

# Sensitive Administration & Exploit Path Patterns
SENSITIVE_PATHS = [
    "admin", "login", "root", "eval", "shell", "exec", "debug",
    "actuator", "swagger", "phpinfo", ".env", ".git", "passwd", "config"
]

# Keys to carve as Secrets / Credentials / Cryptographic Seeds
SECRET_KEYS = {
    "seed": "Cryptographic Seed / Key",
    "sid": "C2 Session ID",
    "session_id": "C2 Session ID",
    "session": "Session Token",
    "cmd": "C2 Command Instruction",
    "command": "C2 Command Instruction",
    "key": "Secret Key / Token",
    "secret": "Secret / Credential",
    "token": "Authentication Token",
    "auth": "Auth Token",
    "password": "Password",
    "passwd": "Password",
    "privkey": "Private Key",
    "private_key": "Private Key",
    "aes_key": "AES Key",
    "aes": "AES Cipher Key",
    "iv": "Initialization Vector",
    "nonce": "Cryptographic Nonce",
    "jwt": "JSON Web Token",
    "api_key": "API Secret Key",
    "access_token": "Access Token",
    "proto": "C2 Protocol Version",
    "interval": "Beacon Interval",
    "blob": "Exfiltrated Data Blob",
    "data": "Payload Data",
    "status": "C2 Ack Status",
    "received": "Exfiltrated Bytes Count",
    "sig": "Payload Signature / HMAC"
}

IPV4_REGEX = re.compile(r"^(\d{1,3}\.){3}\d{1,3}(:\d+)?$")

# Flag Regexes
FLAG_REGEXES = [
    re.compile(r"\b([A-Za-z0-9_\.\-]{2,30})\{([A-Za-z0-9_!@#\$%\^&\*\(\)\-\+=\.\?\/\s,;:~`|<>]{3,120})\}\b", re.IGNORECASE),
    re.compile(r"\b(flag\[[A-Za-z0-9_\-\s]{2,100}\])\b", re.IGNORECASE),
    re.compile(r"\b(FLAG\[[A-Za-z0-9_\-\s]{2,100}\])\b", re.IGNORECASE),
]


# -------------------------------------------------------------------------
# Multi-Base Recursive Decoding & Entropy Utilities
# -------------------------------------------------------------------------

def calculate_shannon_entropy(data: str) -> float:
    """Calculate Shannon Entropy (0.0 - 8.0) of a string."""
    if not data or len(data) < 4:
        return 0.0
    freq = collections.Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def try_multi_base_decode(raw_str: str, max_depth: int = 2) -> List[Tuple[str, str]]:
    """
    Attempts recursive unpacking across URL-encoding, Base64, Base32, and Hex.
    Returns list of (encoding_name, decoded_text).
    """
    if not raw_str or len(raw_str) < 4:
        return []

    results = []
    seen = {raw_str}

    def _unpack_step(current: str, depth: int, chain: str):
        if depth > max_depth or not current:
            return

        # 1. URL Decode
        try:
            url_dec = urllib.parse.unquote(current)
            if url_dec != current and url_dec not in seen:
                seen.add(url_dec)
                new_chain = f"{chain} -> URL-Decoded" if chain else "URL-Decoded"
                results.append((new_chain, url_dec))
                _unpack_step(url_dec, depth + 1, new_chain)
        except Exception:
            pass

        # 2. Hex Decode
        c_strip = current.strip()
        if len(c_strip) >= 6 and len(c_strip) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in c_strip):
            try:
                raw_bytes = bytes.fromhex(c_strip)
                if all(32 <= b <= 126 or b in (10, 13, 9) for b in raw_bytes):
                    hex_dec = raw_bytes.decode("utf-8", errors="replace")
                    if hex_dec not in seen and len(hex_dec) >= 3:
                        seen.add(hex_dec)
                        new_chain = f"{chain} -> Hex" if chain else "Hex"
                        results.append((new_chain, hex_dec))
                        _unpack_step(hex_dec, depth + 1, new_chain)
            except Exception:
                pass

        # 3. Base64 Decode (Standard & URL-safe)
        b64_cand = current.strip()
        if len(b64_cand) >= 4 and len(b64_cand) % 4 in (0, 2, 3) and re.match(r"^[A-Za-z0-9_\-\+/=]+$", b64_cand):
            # Normalize url-safe chars
            norm = b64_cand.replace("-", "+").replace("_", "/")
            norm += "=" * ((4 - len(norm) % 4) % 4)
            try:
                b_bytes = base64.b64decode(norm, validate=False)
                if len(b_bytes) >= 3 and all(32 <= b <= 126 or b in (10, 13, 9) for b in b_bytes):
                    b64_dec = b_bytes.decode("utf-8", errors="replace")
                    if b64_dec not in seen:
                        seen.add(b64_dec)
                        new_chain = f"{chain} -> Base64" if chain else "Base64"
                        results.append((new_chain, b64_dec))
                        _unpack_step(b64_dec, depth + 1, new_chain)
            except Exception:
                pass

        # 4. Base32 Decode
        b32_cand = current.strip().upper()
        if len(b32_cand) >= 8 and re.match(r"^[A-Z2-7=]+$", b32_cand):
            norm32 = b32_cand + "=" * ((8 - len(b32_cand) % 8) % 8)
            try:
                b32_bytes = base64.b32decode(norm32)
                if len(b32_bytes) >= 3 and all(32 <= b <= 126 or b in (10, 13, 9) for b in b32_bytes):
                    b32_dec = b32_bytes.decode("utf-8", errors="replace")
                    if b32_dec not in seen:
                        seen.add(b32_dec)
                        new_chain = f"{chain} -> Base32" if chain else "Base32"
                        results.append((new_chain, b32_dec))
                        _unpack_step(b32_dec, depth + 1, new_chain)
            except Exception:
                pass

    _unpack_step(raw_str, 1, "")
    return results


def check_domain_telemetry(host: str) -> Tuple[bool, bool, str]:
    """
    Inspects domain to distinguish Genuine OS Telemetry vs Spoofed/Masqueraded Telemetry.
    Returns: (is_legit_telemetry, is_fake_telemetry, note)
    """
    h_clean = host.split(":")[0].lower().strip()

    # 1. Check if domain strictly belongs to official vendor root
    for root in OFFICIAL_TELEMETRY_ROOTS:
        if h_clean == root or h_clean.endswith("." + root):
            return True, False, f"Official Vendor Root ({root})"

    # 2. Check if domain uses telemetry mimic keywords without official ownership
    for kw in TELEMETRY_MIMIC_KEYWORDS:
        if kw in h_clean:
            return False, True, f"Masqueraded Telemetry Mimic (contains '{kw}' on unofficial root '{h_clean}')"

    return False, False, "Non-Telemetry Domain"


def scan_for_flags(text: str) -> List[str]:
    """Search for CTF flags in any text payload."""
    if not text:
        return []
    found = []
    for rgx in FLAG_REGEXES:
        for match in rgx.finditer(text):
            found.append(match.group(0))
    return list(set(found))


def extract_endpoints_from_pcap(pcap_path: str) -> Tuple[List[Dict[str, Any]], Dict[str, Set[str]]]:
    """
    Extracts HTTP, TLS SNI, and DNS queries with multi-base decoding,
    fake telemetry detection, and high-entropy heuristic analysis.
    """
    cmd = [
        "tshark", "-r", pcap_path,
        "-Y", "http.request or (http.response and (http.response.code != 0)) or tls.handshake.type == 1",
        "-T", "fields",
        "-e", "frame.number",
        "-e", "frame.time_relative",
        "-e", "tcp.stream",
        "-e", "ip.src",
        "-e", "tcp.srcport",
        "-e", "ip.dst",
        "-e", "tcp.dstport",
        "-e", "http.request.method",
        "-e", "http.host",
        "-e", "http.request.uri",
        "-e", "http.response.code",
        "-e", "http.response.phrase",
        "-e", "http.content_type",
        "-e", "tls.handshake.extensions_server_name",
        "-e", "http.file_data"
    ]

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace")
    except Exception as e:
        console.print(f"[bold red]Failed to execute tshark:[/bold red] {e}")
        return [], {}

    endpoints = []
    stream_map: Dict[str, Dict[str, Any]] = {}

    for line in proc.stdout:
        line = line.strip()
        if not line:
            continue
        parts = line.split("\t")
        while len(parts) < 15:
            parts.append("")

        (
            frame_num, time_rel, stream_id, src_ip, src_port, dst_ip, dst_port,
            method, host, uri, resp_code, resp_phrase, content_type,
            tls_sni, file_data
        ) = parts[:15]

        if not stream_id:
            continue

        # Handle HTTP Request
        if method:
            full_url = f"http://{host}{uri}" if host else uri
            is_legit_tele, is_fake_tele, tele_note = check_domain_telemetry(host)

            entry = {
                "frame": frame_num,
                "time": float(time_rel) if time_rel else 0.0,
                "stream": stream_id,
                "protocol": "HTTP",
                "method": method,
                "host": host,
                "uri": uri,
                "full_url": full_url,
                "src": f"{src_ip}:{src_port}",
                "dst": f"{dst_ip}:{dst_port}",
                "dst_port": dst_port,
                "status": "-",
                "content_type": content_type,
                "req_body": "",
                "resp_body": "",
                "is_telemetry": is_legit_tele and any(uri.split("?")[0].lower() == p for p in TELEMETRY_PATHS),
                "tags": set(),
                "triggers": [],
                "carved_items": []  # List of (artifact_type, key, value, context)
            }

            # If fake telemetry mimic detected
            if is_fake_tele:
                entry["tags"].add("FAKE TELEMETRY")
                entry["triggers"].append(tele_note)

            # Parse raw payload bytes if any
            if file_data:
                try:
                    raw_bytes = bytes.fromhex(file_data)
                    entry["req_body"] = raw_bytes.decode("utf-8", errors="replace")
                except Exception:
                    entry["req_body"] = file_data

            # 1. Parse query parameters & Multi-Base Unpack
            if "?" in uri:
                parsed = urllib.parse.urlparse(full_url)
                qs = urllib.parse.parse_qs(parsed.query)
                for k, vals in qs.items():
                    val = vals[0] if len(vals) == 1 else ",".join(vals)
                    k_lower = k.lower()

                    # Direct parameter check
                    if k_lower in SECRET_KEYS:
                        entry["tags"].add("SECRET / SEED")
                        entry["carved_items"].append((SECRET_KEYS[k_lower], k, val, "URL Query Parameter"))
                        entry["triggers"].append(f"Param '{k}={val}'")
                    if k_lower in ["sid", "session", "id", "hb"]:
                        entry["tags"].add("C2 / BEACON")

                    # Recursive Multi-Base Decoding on Query Values
                    unpacked_list = try_multi_base_decode(val)
                    for enc_type, dec_val in unpacked_list:
                        # Check flags in decoded param
                        fls = scan_for_flags(dec_val)
                        for fl in fls:
                            entry["tags"].add("FLAG DETECTED")
                            entry["carved_items"].append(("CTF Flag", "flag", fl, f"Decoded ({enc_type}) from param '{k}'"))
                            entry["triggers"].append(f"Flag in param '{k}' ({enc_type}): {fl}")
                        
                        # Check secrets in decoded param
                        for sk, sdesc in SECRET_KEYS.items():
                            if sk in dec_val.lower():
                                entry["tags"].add("SECRET / SEED")
                                entry["carved_items"].append((sdesc, k, dec_val, f"Decoded ({enc_type}) from param '{k}'"))
                                entry["triggers"].append(f"Secret in param '{k}' ({enc_type})")

            # 2. Check path segments for multi-base encoding (e.g. /aGVsbG8=)
            path_parts = uri.split("?")[0].strip("/").split("/")
            for part in path_parts:
                unpacked_path = try_multi_base_decode(part)
                for enc_type, dec_part in unpacked_path:
                    fls = scan_for_flags(dec_part)
                    for fl in fls:
                        entry["tags"].add("FLAG DETECTED")
                        entry["carved_items"].append(("CTF Flag", "flag", fl, f"Decoded ({enc_type}) from URI path"))
                        entry["triggers"].append(f"Flag in URI ({enc_type}): {fl}")

            # 3. Parse JSON in Request Body & Multi-Base Unpack
            if entry["req_body"]:
                try:
                    js = json.loads(entry["req_body"])
                    if isinstance(js, dict):
                        for k, v in js.items():
                            v_str = str(v)
                            k_lower = k.lower()
                            if k_lower in SECRET_KEYS:
                                desc = SECRET_KEYS[k_lower]
                                if k_lower in ["seed", "key", "secret", "token", "password"]:
                                    entry["tags"].add("SECRET / SEED")
                                elif k_lower in ["sid", "cmd"]:
                                    entry["tags"].add("C2 / BEACON")
                                elif k_lower in ["data", "blob", "received"]:
                                    entry["tags"].add("EXFILTRATION")
                                
                                entry["carved_items"].append((desc, k, v_str, "Request JSON Body"))
                                entry["triggers"].append(f"Request JSON '{k}' ({len(v_str)} chars)")

                            # Multi-base decode JSON values
                            for enc_type, dec_val in try_multi_base_decode(v_str):
                                fls = scan_for_flags(dec_val)
                                for fl in fls:
                                    entry["tags"].add("FLAG DETECTED")
                                    entry["carved_items"].append(("CTF Flag", "flag", fl, f"Decoded ({enc_type}) from JSON '{k}'"))
                                    entry["triggers"].append(f"Flag in JSON '{k}' ({enc_type}): {fl}")
                except Exception:
                    pass

                # Check for CTF Flags in raw Request Body
                req_flags = scan_for_flags(entry["req_body"])
                for fl in req_flags:
                    entry["tags"].add("FLAG DETECTED")
                    entry["carved_items"].append(("CTF Flag", "flag", fl, "Request Payload Body"))
                    entry["triggers"].append(f"Flag detected: {fl}")

            # 4. Check for CTF Flags in URI
            uri_flags = scan_for_flags(uri)
            for fl in uri_flags:
                entry["tags"].add("FLAG DETECTED")
                entry["carved_items"].append(("CTF Flag", "flag", fl, "Request URI / URL"))
                entry["triggers"].append(f"Flag in URL: {fl}")

            # 5. Check for C2 Paths & Suspicious Keywords
            uri_lower = uri.lower()
            if any(kw in uri_lower for kw in C2_PATH_KEYWORDS):
                entry["tags"].add("C2 / BEACON")
                entry["triggers"].append(f"C2 Path Pattern in '{uri.split('?')[0]}'")

            # 6. Check for Exfiltration Paths
            if any(kw in uri_lower for kw in EXFIL_PATH_KEYWORDS) and method in ("POST", "PUT"):
                entry["tags"].add("EXFILTRATION")
                entry["triggers"].append(f"Exfil Method '{method}' to '{uri.split('?')[0]}'")

            # 7. Check for Sensitive Admin Paths
            if any(kw in uri_lower for kw in SENSITIVE_PATHS):
                entry["tags"].add("SENSITIVE ENDPOINT")
                entry["triggers"].append(f"Sensitive Path '{uri.split('?')[0]}'")

            # 8. Check for Direct IP Host & Non-Standard Ports
            h_clean = host.split(":")[0].strip()
            is_raw_ip = bool(IPV4_REGEX.match(h_clean))
            port_num = int(dst_port) if dst_port.isdigit() else 80
            if is_raw_ip:
                entry["tags"].add("SUSPICIOUS IP/PORT")
                entry["triggers"].append(f"Direct IP Host '{host}'")
            if port_num not in (80, 443, 8000) and port_num in (8080, 8443, 8888, 9001, 1337, 4444, 5555, 31337):
                entry["tags"].add("SUSPICIOUS IP/PORT")
                entry["triggers"].append(f"Non-Standard Web Port {port_num}")

            # 9. Shannon Entropy Check on Path
            ent = calculate_shannon_entropy(uri.split("?")[0])
            if ent >= 4.4 and len(uri.split("?")[0]) >= 16:
                entry["tags"].add("HIGH ENTROPY / OBFUSCATED")
                entry["triggers"].append(f"High Entropy Path (H={ent:.2f})")

            endpoints.append(entry)
            stream_map[stream_id] = entry

        # Handle HTTP Response
        elif resp_code:
            status_str = f"{resp_code} {resp_phrase}".strip()
            if stream_id in stream_map:
                req_entry = stream_map[stream_id]
                req_entry["status"] = status_str
                if content_type and not req_entry["content_type"]:
                    req_entry["content_type"] = content_type

                if file_data:
                    try:
                        raw_bytes = bytes.fromhex(file_data)
                        req_entry["resp_body"] = raw_bytes.decode("utf-8", errors="replace")
                    except Exception:
                        req_entry["resp_body"] = file_data

                    # Parse JSON in Response Body & Multi-Base Unpack
                    try:
                        js = json.loads(req_entry["resp_body"])
                        if isinstance(js, dict):
                            for k, v in js.items():
                                v_str = str(v)
                                k_lower = k.lower()
                                if k_lower in SECRET_KEYS:
                                    desc = SECRET_KEYS[k_lower]
                                    if k_lower in ["seed", "key", "secret", "token", "password"]:
                                        req_entry["tags"].add("SECRET / SEED")
                                    elif k_lower in ["sid", "cmd"]:
                                        req_entry["tags"].add("C2 / BEACON")
                                    elif k_lower in ["data", "blob", "received"]:
                                        req_entry["tags"].add("EXFILTRATION")

                                    req_entry["carved_items"].append((desc, k, v_str, "Response JSON Body"))
                                    req_entry["triggers"].append(f"Response JSON '{k}={v_str[:30]}'")

                                # Multi-base decode JSON values
                                for enc_type, dec_val in try_multi_base_decode(v_str):
                                    fls = scan_for_flags(dec_val)
                                    for fl in fls:
                                        req_entry["tags"].add("FLAG DETECTED")
                                        req_entry["carved_items"].append(("CTF Flag", "flag", fl, f"Decoded ({enc_type}) from JSON '{k}'"))
                                        req_entry["triggers"].append(f"Flag in response JSON '{k}' ({enc_type}): {fl}")
                    except Exception:
                        pass

                    # Check for CTF Flags in raw Response Body
                    resp_flags = scan_for_flags(req_entry["resp_body"])
                    for fl in resp_flags:
                        req_entry["tags"].add("FLAG DETECTED")
                        req_entry["carved_items"].append(("CTF Flag", "flag", fl, "Response Body"))
                        req_entry["triggers"].append(f"Flag detected: {fl}")

        # Handle TLS SNI
        elif tls_sni:
            is_legit_tele, is_fake_tele, tele_note = check_domain_telemetry(tls_sni)
            tags = set()
            triggers = []
            if is_fake_tele:
                tags.add("FAKE TELEMETRY")
                triggers.append(tele_note)
            elif not is_legit_tele:
                if any(x in tls_sni.lower() for x in ["ngrok", "duckdns", "hopto", "ddns", "tunnel", "pastebin"]):
                    tags.add("C2 / BEACON")
                    triggers.append(f"Suspicious Dynamic Domain '{tls_sni}'")
                if IPV4_REGEX.match(tls_sni):
                    tags.add("SUSPICIOUS IP/PORT")
                    triggers.append(f"Direct IP TLS SNI '{tls_sni}'")

            entry = {
                "frame": frame_num,
                "time": float(time_rel) if time_rel else 0.0,
                "stream": stream_id,
                "protocol": "TLS SNI",
                "method": "CONNECT/TLS",
                "host": tls_sni,
                "uri": "[TLS Handshake]",
                "full_url": f"https://{tls_sni}",
                "src": f"{src_ip}:{src_port}",
                "dst": f"{dst_ip}:{dst_port}",
                "dst_port": dst_port,
                "status": "TLS SNI",
                "content_type": "application/tls",
                "req_body": "",
                "resp_body": "",
                "is_telemetry": is_legit_tele,
                "tags": tags,
                "triggers": triggers,
                "carved_items": []
            }
            endpoints.append(entry)

    proc.wait()

    # Aggregate categories across streams
    categorized_streams: Dict[str, Set[str]] = {
        "C2 / BEACON": set(),
        "SECRET / SEED": set(),
        "EXFILTRATION": set(),
        "FLAG DETECTED": set(),
        "FAKE TELEMETRY": set(),
        "HIGH ENTROPY / OBFUSCATED": set(),
        "SENSITIVE ENDPOINT": set(),
        "SUSPICIOUS IP/PORT": set(),
    }

    for ep in endpoints:
        st_id = ep["stream"]
        for t in ep["tags"]:
            if t in categorized_streams:
                categorized_streams[t].add(st_id)

    return endpoints, categorized_streams


def follow_stream_conversation(pcap_path: str, stream_id: int):
    """Display interactive bidirectional conversation for a specific stream."""
    cmd = ["tshark", "-r", pcap_path, "-q", "-z", f"follow,tcp,ascii,{stream_id}"]
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace")
        output = res.stdout
    except Exception as e:
        console.print(f"[bold red]Failed to follow stream:[/bold red] {e}")
        return

    console.print(f"\n[bold yellow]══════════════════════════════════════════════════════════════════[/bold yellow]")
    console.print(f" [bold cyan]FOLLOW TCP STREAM #{stream_id}[/bold cyan]")
    console.print(f"[bold yellow]══════════════════════════════════════════════════════════════════[/bold yellow]\n")

    lines = output.splitlines()
    in_content = False
    for line in lines:
        if line.startswith("Filter:"):
            console.print(f"[dim]{line}[/dim]")
        elif line.startswith("Node 0:") or line.startswith("Node 1:"):
            console.print(f"[bold magenta]{line}[/bold magenta]")
        elif line.startswith("==="):
            in_content = True
        elif in_content:
            if line.startswith("\t"):
                console.print(f"[green]{escape(line.lstrip())}[/green]")
            elif line.isdigit() and len(line) <= 6:
                continue
            else:
                console.print(f"[cyan]{escape(line)}[/cyan]")
    console.print()


def render_executive_summary(categorized_streams: Dict[str, Set[str]]):
    """
    Renders punchy executive summary of suspicious endpoints discovered.
    """
    c2_streams = sorted(list(categorized_streams.get("C2 / BEACON", set())), key=lambda x: int(x) if x.isdigit() else 9999)
    secret_streams = sorted(list(categorized_streams.get("SECRET / SEED", set())), key=lambda x: int(x) if x.isdigit() else 9999)
    exfil_streams = sorted(list(categorized_streams.get("EXFILTRATION", set())), key=lambda x: int(x) if x.isdigit() else 9999)
    flag_streams = sorted(list(categorized_streams.get("FLAG DETECTED", set())), key=lambda x: int(x) if x.isdigit() else 9999)
    fake_tele_streams = sorted(list(categorized_streams.get("FAKE TELEMETRY", set())), key=lambda x: int(x) if x.isdigit() else 9999)
    entropy_streams = sorted(list(categorized_streams.get("HIGH ENTROPY / OBFUSCATED", set())), key=lambda x: int(x) if x.isdigit() else 9999)
    ip_streams = sorted(list(categorized_streams.get("SUSPICIOUS IP/PORT", set())), key=lambda x: int(x) if x.isdigit() else 9999)
    sens_streams = sorted(list(categorized_streams.get("SENSITIVE ENDPOINT", set())), key=lambda x: int(x) if x.isdigit() else 9999)

    has_suspicious = any([c2_streams, secret_streams, exfil_streams, flag_streams, fake_tele_streams, ip_streams, sens_streams])

    msg = []
    if has_suspicious:
        msg.append("[bold red][!] HASIL DETEKSI ENDPOINT MENCURIGAKAN DITEMUKAN:[/bold red]\n")
        if c2_streams:
            st_fmt = ", ".join(f"#{s}" for s in c2_streams)
            msg.append(f" • [bold red][*] C2 Endpoints & Beacons[/bold red]      : Ditemukan pada stream [bold yellow]{st_fmt}[/bold yellow]")
        if secret_streams:
            st_fmt = ", ".join(f"#{s}" for s in secret_streams)
            msg.append(f" • [bold yellow][*] Secrets & Cryptographic Seeds[/bold yellow]: Ditemukan pada stream [bold yellow]{st_fmt}[/bold yellow]")
        if exfil_streams:
            st_fmt = ", ".join(f"#{s}" for s in exfil_streams)
            msg.append(f" • [bold magenta][*] Data Exfiltration (Payloads)[/bold magenta] : Ditemukan pada stream [bold yellow]{st_fmt}[/bold yellow]")
        if fake_tele_streams:
            st_fmt = ", ".join(f"#{s}" for s in fake_tele_streams)
            msg.append(f" • [bold red on yellow][*] Fake Telemetry Mimic (Spoofed)[/bold red on yellow] : Ditemukan pada stream [bold yellow]{st_fmt}[/bold yellow]")
        if flag_streams:
            st_fmt = ", ".join(f"#{s}" for s in flag_streams)
            msg.append(f" • [bold bright_white on red][*] CTF Flags Discovered[/bold bright_white on red]         : Ditemukan pada stream [bold yellow]{st_fmt}[/bold yellow]")
        else:
            msg.append(f" • [dim][*] CTF Flags[/dim]                    : [dim]Tidak ada format flag teks biasa[/dim]")
        if entropy_streams:
            st_fmt = ", ".join(f"#{s}" for s in entropy_streams)
            msg.append(f" • [bold bright_cyan][*] High Entropy / Encoded Path[/bold bright_cyan]  : Ditemukan pada stream [bold yellow]{st_fmt}[/bold yellow]")
        if ip_streams:
            st_fmt = ", ".join(f"#{s}" for s in ip_streams)
            msg.append(f" • [bold cyan][!] Raw IP Host & Non-Std Ports[/bold cyan] : Ditemukan pada stream [bold yellow]{st_fmt}[/bold yellow]")
        if sens_streams:
            st_fmt = ", ".join(f"#{s}" for s in sens_streams)
            msg.append(f" • [bold orange3][*] Sensitive / Admin Endpoints[/bold orange3] : Ditemukan pada stream [bold yellow]{st_fmt}[/bold yellow]")
    else:
        msg.append("[bold green][+] Tidak ditemukan endpoint mencurigakan atau C2. Seluruh lalu lintas tergolong telemetri / web standar.[/bold green]")

    border_color = "bold red" if (c2_streams or secret_streams or exfil_streams or flag_streams or fake_tele_streams) else "dim green"
    console.print(Panel("\n".join(msg), title="[bold]RINGKASAN TEMUAN FORENSIK[/bold]", border_style=border_color, expand=True))
    console.print()


def render_suspicious_table(endpoints: List[Dict[str, Any]]):
    """
    Renders table of suspicious endpoints.
    """
    table = Table(
        title=" Daftar Endpoint Mencurigakan yang Ditemukan",
        show_header=True,
        header_style="bold yellow",
        border_style="bold red",
        expand=True
    )
    table.add_column("Stream", style="bold magenta", width=8, justify="center")
    table.add_column("Method", style="bold", width=8, justify="center")
    table.add_column("Endpoint URL", style="bright_white", min_width=32)
    table.add_column("Kategori Ancaman", style="bold", min_width=24)
    table.add_column("Pemicu / Detail Indikasi", style="dim cyan", min_width=30)
    table.add_column("Status", style="bold green", width=10, justify="center")

    tag_styles = {
        "C2 / BEACON": "bold red",
        "SECRET / SEED": "bold yellow",
        "EXFILTRATION": "bold magenta",
        "FLAG DETECTED": "bold white on red",
        "FAKE TELEMETRY": "bold red on yellow",
        "HIGH ENTROPY / OBFUSCATED": "bold bright_cyan",
        "SUSPICIOUS IP/PORT": "cyan",
        "SENSITIVE ENDPOINT": "orange3"
    }

    for ep in endpoints:
        if not ep["tags"] and ep["is_telemetry"]:
            continue

        st_str = f"#{ep['stream']}"
        m_str = f"[cyan]{ep['method']}[/cyan]" if ep['method'] == "GET" else f"[bold yellow]{ep['method']}[/bold yellow]" if ep['method'] == "POST" else f"[dim]{ep['method']}[/dim]"

        # Format badges
        badges = []
        for t in sorted(list(ep["tags"])):
            style = tag_styles.get(t, "white")
            badges.append(f"[{style}][{t}][/{style}]")
        badges_str = " ".join(badges) if badges else "[dim]Normal Web[/dim]"

        triggers_str = "; ".join(ep["triggers"][:3])
        if len(ep["triggers"]) > 3:
            triggers_str += f" (+{len(ep['triggers'])-3} more)"

        status_str = ep["status"]
        if status_str.startswith("200"):
            status_str = f"[bold green]{status_str}[/bold green]"
        elif status_str.startswith("204"):
            status_str = f"[dim green]{status_str}[/dim green]"

        table.add_row(
            st_str,
            m_str,
            ep['full_url'],
            badges_str,
            triggers_str,
            status_str
        )

    console.print(table)
    console.print()


def render_carved_artifacts_table(endpoints: List[Dict[str, Any]]):
    """
    Renders carved secrets, seeds, flags, and session credentials.
    """
    rows = []
    for ep in endpoints:
        for item_type, key, val, context in ep["carved_items"]:
            rows.append((ep["stream"], ep["full_url"], item_type, key, val, context))

    if not rows:
        return

    table = Table(
        title=" Detail Rahasia, Kredensial, Flag, & Seed yang Diekstrak",
        show_header=True,
        header_style="bold yellow",
        border_style="bold green",
        expand=True
    )
    table.add_column("Stream", style="bold magenta", width=8, justify="center")
    table.add_column("Endpoint URL", style="cyan", min_width=28)
    table.add_column("Tipe Artefak", style="bold yellow", min_width=20)
    table.add_column("Kunci", style="bright_white", width=12)
    table.add_column("Nilai yang Diekstrak", style="bold bright_white", min_width=30)
    table.add_column("Lokasi & Konteks", style="dim", min_width=20)

    for st_id, url, item_type, key, val, context in rows:
        val_display = val
        if len(val_display) > 45:
            val_display = val_display[:45] + "..."
        
        type_style = "bold green" if "Seed" in item_type or "Key" in item_type else "bold white on red" if "Flag" in item_type else "bold red" if "Command" in item_type else "bold cyan"

        table.add_row(
            f"#{st_id}",
            url,
            f"[{type_style}]{item_type}[/{type_style}]",
            key,
            escape(val_display),
            context
        )

    console.print(table)
    console.print()


def export_endpoints_payloads(endpoints: List[Dict[str, Any]], out_dir: str):
    """Export request and response payloads from flagged endpoints."""
    os.makedirs(out_dir, exist_ok=True)
    exported = 0
    for ep in endpoints:
        st_id = ep["stream"]
        if ep["req_body"]:
            fn = os.path.join(out_dir, f"stream_{st_id}_req.txt")
            with open(fn, "w", encoding="utf-8") as f:
                f.write(ep["req_body"])
            exported += 1
        if ep["resp_body"]:
            fn = os.path.join(out_dir, f"stream_{st_id}_resp.txt")
            with open(fn, "w", encoding="utf-8") as f:
                f.write(ep["resp_body"])
            exported += 1

    console.print(f"[bold green] Sukses mengekspor {exported} file payload ke:[/bold green] [cyan]{out_dir}[/cyan]")


def main(args_list=None):
    parser = argparse.ArgumentParser(
        prog="pcapendpoint",
        description=" PCAP Endpoint & Threat Hunter - Deteksi C2, Flag, Seed, Fake Telemetry & Exfiltration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  pcapendpoint wire.pcap                      # Scan otomatis seluruh stream & tampilkan endpoint mencurigakan
  pcapendpoint wire.pcap -s 49                # Follow percakapan HTTP stream 49
  pcapendpoint wire.pcap -s 51                # Follow percakapan HTTP stream 51
  pcapendpoint wire.pcap --all                # Tampilkan seluruh endpoint (termasuk telemetri OS)
  pcapendpoint wire.pcap -q "api/v1"          # Cari endpoint dengan substring tertentu
  pcapendpoint wire.pcap -o ./c2_dumps        # Export seluruh request/response payload ke folder
        """
    )
    parser.add_argument("pcap_file", help="Path ke file PCAP atau PCAPNG")
    parser.add_argument("-s", "--stream", type=int, help="Follow percakapan dua arah (request + response) untuk TCP Stream ID tertentu")
    parser.add_argument("-a", "--all", action="store_true", help="Tampilkan semua endpoint termasuk background telemetri OS normal")
    parser.add_argument("-q", "--search", help="Filter endpoint berdasarkan kata kunci (URL, Host, Param)")
    parser.add_argument("-m", "--method", help="Filter berdasarkan HTTP method (GET, POST, dll.)")
    parser.add_argument("-o", "--export-dir", help="Folder tujuan untuk export payload dari stream yang mencurigakan")

    args = parser.parse_args(args_list)

    if not os.path.exists(args.pcap_file):
        console.print(f"[bold red]Error:[/bold red] File tidak ditemukan: {args.pcap_file}")
        sys.exit(1)

    # If stream follow mode is requested
    if args.stream is not None:
        follow_stream_conversation(args.pcap_file, args.stream)
        return

    print_banner(
        tool_name="PCAP ENDPOINT & THREAT HUNTER (pcapendpoint)",
        sub_title="Automated Multi-Stream Forensic Endpoint Scanner (C2, Flags, Seeds & Exfil)"
    )

    with console.status("[bold cyan]Memindai seluruh stream & menganalisis endpoint mencurigakan...[/bold cyan]"):
        endpoints, categorized_streams = extract_endpoints_from_pcap(args.pcap_file)

    if not endpoints:
        console.print("[bold red]Tidak ada endpoint HTTP atau TLS yang terdeteksi di capture ini.[/bold red]")
        return

    # Apply search/method filters if specified
    filtered = endpoints
    if args.method:
        m_upper = args.method.upper()
        filtered = [ep for ep in filtered if ep["method"].upper() == m_upper]

    if args.search:
        q = args.search.lower()
        filtered = [
            ep for ep in filtered
            if q in ep["host"].lower()
            or q in ep["uri"].lower()
            or q in ep["full_url"].lower()
            or any(q in str(k).lower() or q in str(v).lower() for _, k, v, _ in ep["carved_items"])
        ]

    # If not --all, isolate suspicious endpoints (those with threat tags)
    suspicious_endpoints = [ep for ep in filtered if ep["tags"]]
    display_endpoints = filtered if args.all else suspicious_endpoints

    # 1. Print Executive Summary
    render_executive_summary(categorized_streams)

    # 2. Print Suspicious Endpoints Table
    if display_endpoints:
        render_suspicious_table(display_endpoints)
    else:
        console.print("[dim yellow]Tidak ada endpoint mencurigakan pada filter yang dipilih.[/dim yellow]\n")

    # 3. Print Carved Secrets, Seeds, Flags & Parameters Table
    render_carved_artifacts_table(display_endpoints)

    # 4. Actionable Tips Box
    tips = (
        "[bold cyan]Tips Tindakan Selanjutnya:[/bold cyan]\n"
        "  • Follow percakapan stream: [bold yellow]pcapendpoint " + args.pcap_file + " -s <STREAM_ID>[/bold yellow]\n"
        "  • Tampilkan seluruh traffic: [bold yellow]pcapendpoint " + args.pcap_file + " --all[/bold yellow]\n"
        "  • Ekspor semua payload:     [bold yellow]pcapendpoint " + args.pcap_file + " -o ./c2_dumps[/bold yellow]"
    )
    console.print(Panel(tips, border_style="dim cyan", expand=True))

    # Export if requested
    if args.export_dir:
        export_endpoints_payloads(suspicious_endpoints, args.export_dir)


if __name__ == "__main__":
    main()
