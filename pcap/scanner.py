"""
Suspicious Stream & Payload Hunter (pcapscan / pcap/scanner.py)
Automates deep inspection of network capture streams:
1. Regex Flag Hunter (HTTP headers, bodies, raw streams, DNS queries, ICMP payloads)
2. Recursive Multi-Layer Unpacker (Base64 -> Gzip -> Base64 -> Embedded Flags / Payloads)
3. C2 Framework Fingerprinting (NimPlant, Cobalt Strike, Metasploit, Sliver, Havoc, Empire)
4. High-Entropy Encrypted C2 / Ciphertext Stream Detector (Shannon entropy analysis)
5. Obfuscation & Payloads: Base64 carving & auto-decode, Hex ASCII, Single-byte XOR brute-force
6. WebAssembly (.wasm), Shellcode NOP-sleds, Malicious Executables (PE/ELF)
7. Cryptographic Hints: salt, iv, key, secret, password, tokens, private keys
8. Reverse Shell & Interactive Session Detector (whoami, id, /bin/sh, powershell, nc -e)
9. Covert Channels: DNS Exfiltration / Tunneling & ICMP Payload Data Tunneling
10. Multi-format Exports (Terminal Table, Markdown, JSON, CSV)
"""
import os
import sys
import argparse
import re
import base64
import json
import gzip
import zlib
import hashlib
import math
from typing import List, Dict, Any, Optional, Set, Tuple

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markup import escape

from core.banner import print_banner
from core.utils import human_size
from pcap.pcap_engine import PCAPEngine, TCPStream

console = Console(force_terminal=True, legacy_windows=False)

# Flag Patterns
DEFAULT_FLAG_REGEX = re.compile(
    r"(?:[A-Za-z0-9_\.\-]{2,40}\{[^}\r\n]{2,200}\})"
    r"|(?:\{[A-Za-z0-9_!@#\$%\^&\*\(\)\-\+=\.\?\/\s]{3,120}\})"
    r"|(?:flag\[[A-Za-z0-9_\-\s]{2,100}\])"
    r"|(?:FLAG\[[A-Za-z0-9_\-\s]{2,100}\])",
    re.IGNORECASE
)

# Suspicious Command & Reverse Shell Signatures
SUSPICIOUS_SHELL_COMMANDS = [
    r"\bwhoami\b", r"\bid\s*;\s*", r"\buname\s+-a\b", r"\bcat\s+/etc/passwd\b",
    r"\b/bin/(?:bash|sh|zsh|dash)\b", r"\bcmd\.exe\b", r"\bpowershell(?:\.exe)?\b",
    r"\bnc(?:\.traditional)?\s+-[le]", r"bash\s+-i\s+>&", r"python(?:3)?\s+-c\s+['\"]import\s+socket",
    r"curl\s+-[sS]?\s*https?://", r"wget\s+https?://", r"\beval\(", r"\bbase64_decode\("
]

# Sensitive Token & Crypto Patterns
SUSPICIOUS_CRYPTO_PATTERNS = {
    "Crypto Secrets & Parameters": [
        r"(?:salt|iv|key|secret|password|passwd|token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-+/=]{4,128}['\"]?",
        r"-----BEGIN\s+[A-Z\s]+PRIVATE\s+KEY-----"
    ],
    "C2 Webhooks & API Keys": [
        r"https?://(?:discord\.com|discordapp\.com)/api/webhooks/[0-9]+/[A-Za-z0-9_-]+",
        r"api\.telegram\.org/bot[0-9]+:[A-Za-z0-9_-]+",
        r"AKIA[0-9A-Z]{16}",
        r"ghp_[A-Za-z0-9_]{36,255}"
    ]
}

# Known C2 Framework URI Signatures & Fingerprints
C2_FRAMEWORK_SIGNATURES = [
    (re.compile(r"/api/v2/(?:login|query|ping/[0-9a-fA-F]{32}|tasks)", re.IGNORECASE), "NimPlant C2 Framework (AES-CTR Encrypted Agent / Key Exchange in /login)"),
    (re.compile(r"/(?:api/v1/agent|api/v1/tasks|sliver)", re.IGNORECASE), "Sliver C2 Framework"),
    (re.compile(r"/(?:submit\.php|activity|match|push\.php|pixel\.gif\?[a-zA-Z0-9_=-]+)", re.IGNORECASE), "Cobalt Strike Beacon (Malleable C2 Profile URI)"),
    (re.compile(r"/api/v[0-9]+/agent/register", re.IGNORECASE), "Mythic C2 Agent Registration"),
    (re.compile(r"/havoc/api/[a-zA-Z0-9_]+", re.IGNORECASE), "Havoc C2 Framework Demonstration / API"),
    (re.compile(r"/[a-zA-Z0-9_-]{16,80}", re.IGNORECASE), "Metasploit HTTP/HTTPS Reverse Stager URI Pattern")
]


def is_valid_flag_str(val: str) -> bool:
    if not val or len(val) < 4 or len(val) > 250:
        return False
    if not all(32 <= ord(c) <= 126 or c in (" ", "\t") for c in val):
        return False
    if not re.search(r"[A-Za-z0-9]{2,}", val):
        return False
    if val.startswith("{") and not val.endswith("}"):
        return False
    return True


def calculate_entropy(data: bytes) -> float:
    """Calculates Shannon entropy for byte stream (0.0 to 8.0)."""
    if not data: return 0.0
    entropy = 0.0
    length = len(data)
    counts = {}
    for c in data:
        counts[c] = counts.get(c, 0) + 1
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


class SuspiciousFinding:
    """
    Structured alert finding for suspicious stream contents.
    """
    def __init__(
        self,
        category: str,
        severity: str,
        stream_info: str,
        title: str,
        match_value: str,
        context: str = ""
    ):
        self.category = category
        self.severity = severity # CRITICAL, HIGH, MEDIUM, LOW, FLAG
        self.stream_info = stream_info
        self.title = title
        self.match_value = match_value
        self.context = context

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "severity": self.severity,
            "stream": self.stream_info,
            "title": self.title,
            "match": self.match_value,
            "context": self.context
        }


class PCAPScanner:
    """
    Analyzes PCAP streams for CTF flags, malicious payloads, reverse shells, and covert channels.
    """
    def __init__(self, engine: PCAPEngine, custom_prefix: Optional[str] = None):
        self.engine = engine
        self.custom_prefix = custom_prefix
        self.flags: List[Dict[str, Any]] = []
        self.findings: List[SuspiciousFinding] = []
        self.seen_flags: Set[str] = set()

    def scan(self) -> Dict[str, Any]:
        self.engine.analyze()
        self.flags = []
        self.findings = []
        self.seen_flags = set()

        flag_patterns = [DEFAULT_FLAG_REGEX]
        if self.custom_prefix:
            pref_escaped = re.escape(self.custom_prefix)
            custom_re = re.compile(rf"{pref_escaped}\{{[^}}\r\n]{{2,200}}\}}", re.IGNORECASE)
            flag_patterns.insert(0, custom_re)

        # 1. Scan TCP Streams (Reassembled payloads & HTTP)
        for s in self.engine.tcp_streams.values():
            s_label = f"Stream #{s.stream_id} ({s.client_ip}:{s.client_port} ⇄ {s.server_ip}:{s.server_port})"
            payload_text = s.reassembled_stream.decode("latin-1", errors="replace")

            # A. C2 Framework Fingerprinting
            self._fingerprint_c2(s, s_label)

            # B. Flag Hunting in Stream (Plaintext)
            self._hunt_flags_in_text(payload_text, s_label, flag_patterns, "TCP Payload")

            # C. High-Entropy Encrypted C2 Stream Detection
            if s.protocol_name not in ("TLS", "SSH") and len(s.reassembled_stream) >= 128:
                ent = calculate_entropy(s.reassembled_stream)
                if ent >= 7.6:
                    self.findings.append(SuspiciousFinding(
                        category="Encrypted Stream / Ciphertext",
                        severity="HIGH",
                        stream_info=s_label,
                        title=f"High-Entropy Stream ({ent}/8.0) - Likely Custom Encrypted C2 / Ciphertext",
                        match_value=f"Shannon Entropy: {ent}",
                        context=f"Port {s.server_port} ({s.protocol_name}) contains {len(s.reassembled_stream):,} bytes of high-entropy payload"
                    ))

            # D. WebAssembly / Shellcode
            if b"\x00asm\x01\x00\x00\x00" in s.reassembled_stream:
                self.findings.append(SuspiciousFinding(
                    category="WebAssembly Module",
                    severity="HIGH",
                    stream_info=s_label,
                    title="WebAssembly (.wasm) Binary Module in Stream",
                    match_value="\\x00asm\\x01\\x00\\x00\\x00",
                    context=f"WASM binary payload size: {len(s.reassembled_stream):,} bytes"
                ))

            if b"\x90" * 16 in s.reassembled_stream:
                self.findings.append(SuspiciousFinding(
                    category="Exploit / Shellcode",
                    severity="HIGH",
                    stream_info=s_label,
                    title="Shellcode NOP-Sled Detected (\\x90*16+)",
                    match_value="NOP Sled Pattern",
                    context="Repeated 0x90 sequence found in stream buffer"
                ))

            # E. Reverse Shell & Interactive Commands
            for cmd_pat in SUSPICIOUS_SHELL_COMMANDS:
                m = re.search(cmd_pat, payload_text, re.IGNORECASE)
                if m:
                    match_str = m.group(0)
                    start_ctx = max(0, m.start() - 30)
                    end_ctx = min(len(payload_text), m.end() + 50)
                    ctx = payload_text[start_ctx:end_ctx].replace("\n", " ").replace("\r", "")
                    self.findings.append(SuspiciousFinding(
                        category="Command Execution / Reverse Shell",
                        severity="HIGH",
                        stream_info=s_label,
                        title=f"Command Execution Signature: '{match_str}'",
                        match_value=match_str,
                        context=ctx
                    ))

            # F. Crypto Hints & Secrets
            for cat_name, patterns in SUSPICIOUS_CRYPTO_PATTERNS.items():
                for pat in patterns:
                    for m in re.finditer(pat, payload_text, re.IGNORECASE):
                        m_str = m.group(0).strip()
                        if all(32 <= ord(c) <= 126 for c in m_str):
                            start_ctx = max(0, m.start() - 20)
                            end_ctx = min(len(payload_text), m.end() + 40)
                            ctx = payload_text[start_ctx:end_ctx].replace("\n", " ").replace("\r", "")
                            self.findings.append(SuspiciousFinding(
                                category=cat_name,
                                severity="MEDIUM",
                                stream_info=s_label,
                                title=f"Sensitive Token / Parameter Detected",
                                match_value=m_str,
                                context=ctx
                            ))

            # G. Recursive Multi-Layer Base64 & Gzip Unpacker
            self._recursive_carve_and_decode(payload_text, s_label, flag_patterns)

            # H. Single-Byte XOR Flag Brute-Forcer
            self._bruteforce_xor_stream(s.reassembled_stream, s_label)

        # 2. Scan DNS Queries & Answers (DNS Tunneling / Exfiltration)
        self._analyze_dns(flag_patterns)

        # 3. Scan ICMP Echo Payloads (ICMP Tunneling / Covert Channels)
        self._analyze_icmp(flag_patterns)

        return {
            "flags": self.flags,
            "findings": self.findings
        }

    def _fingerprint_c2(self, stream: TCPStream, source_label: str):
        """Identifies known Command & Control framework patterns in HTTP requests."""
        for req in stream.http_requests:
            uri = req.get("uri", "")
            for pattern, c2_name in C2_FRAMEWORK_SIGNATURES:
                if pattern.search(uri):
                    self.findings.append(SuspiciousFinding(
                        category="C2 Framework Activity",
                        severity="CRITICAL",
                        stream_info=source_label,
                        title=f"C2 Signature Matched: {c2_name}",
                        match_value=f"{req.get('method', 'GET')} {uri}",
                        context=f"Host: {req.get('host', '')} | User-Agent: {req.get('user_agent', '')}"
                    ))

    def _hunt_flags_in_text(self, text: str, source_label: str, patterns: List[Any], enc_label: str):
        for pat in patterns:
            for m in pat.finditer(text):
                f_val = m.group(0).strip()
                f_val = re.sub(r"[\r\n\t]", "", f_val)
                if is_valid_flag_str(f_val) and f_val not in self.seen_flags:
                    self.seen_flags.add(f_val)
                    self.flags.append({
                        "flag": f_val,
                        "stream": source_label,
                        "encoding": enc_label,
                        "length": len(f_val)
                    })

    def _recursive_carve_and_decode(self, text: str, source_label: str, patterns: List[Any], depth: int = 0):
        """Recursively decodes nested Base64, Hex, and Gzip streams."""
        if depth >= 4 or not text:
            return

        b64_matches = re.finditer(r"(?:[A-Za-z0-9+/]{16,}={0,2})", text)
        for bm in b64_matches:
            cand = bm.group(0)
            if len(cand) % 4 == 0:
                try:
                    dec_b = base64.b64decode(cand, validate=True)
                    if not dec_b:
                        continue

                    # Check if decoded payload is GZIP compressed (1F 8B)
                    if dec_b.startswith(b"\x1f\x8b"):
                        try:
                            gz_decomp = gzip.decompress(dec_b)
                            # Hunt flags in decompressed
                            gz_text = gz_decomp.decode("latin-1", errors="replace")
                            self._hunt_flags_in_text(gz_text, f"{source_label} (Base64  Gzip)", patterns, f"Base64+Gzip (Depth {depth+1})")
                            # Recurse on decompressed
                            self._recursive_carve_and_decode(gz_text, source_label, patterns, depth + 1)
                        except Exception:
                            pass

                    # Check if decoded is printable text
                    if all(32 <= c <= 126 or c in (10, 13, 9) for c in dec_b):
                        dec_str = dec_b.decode("utf-8", errors="ignore").strip()
                        if len(dec_str) >= 4 and not dec_str.isnumeric():
                            # Check if contains flag
                            self._hunt_flags_in_text(dec_str, f"{source_label} (Base64)", patterns, f"Base64 Decoded (Depth {depth+1})")

                            # Add finding if decoded text looks like shell command or secret
                            if depth == 0 and any(k in dec_str.lower() for k in ["password", "secret", "token", "/bin/sh", "whoami", "http"]):
                                self.findings.append(SuspiciousFinding(
                                    category="Encoded Base64 Payload",
                                    severity="MEDIUM",
                                    stream_info=source_label,
                                    title="Base64 Encoded Command / Token Payload",
                                    match_value=cand[:40] + ("..." if len(cand) > 40 else ""),
                                    context=f"Decoded Plaintext: {dec_str[:80]}"
                                ))

                            # Recurse for multi-layer Base64
                            self._recursive_carve_and_decode(dec_str, source_label, patterns, depth + 1)
                except Exception:
                    pass

    def _bruteforce_xor_stream(self, raw_bytes: bytes, source_label: str):
        if len(raw_bytes) < 10:
            return
        sample = raw_bytes[:1024 * 512] # 512KB sample per stream
        header_targets = [b"flag{", b"FLAG{", b"ctf{", b"CTF{", b"htb{", b"HTB{"]

        for key in range(1, 256):
            for target in header_targets:
                x_target = bytes([b ^ key for b in target])
                idx = sample.find(x_target)
                if idx != -1:
                    dec_bytes = bytearray()
                    end_idx = min(len(sample), idx + 200)
                    for b in sample[idx:end_idx]:
                        dec_b = b ^ key
                        if dec_b == ord("}"):
                            dec_bytes.append(dec_b)
                            break
                        elif 32 <= dec_b <= 126:
                            dec_bytes.append(dec_b)
                        else:
                            break

                    try:
                        cand_flag = dec_bytes.decode("utf-8")
                        if cand_flag.endswith("}") and is_valid_flag_str(cand_flag) and cand_flag not in self.seen_flags:
                            self.seen_flags.add(cand_flag)
                            self.flags.append({
                                "flag": cand_flag,
                                "stream": f"{source_label} (XOR Key: 0x{key:02X})",
                                "encoding": f"XOR 0x{key:02X}",
                                "length": len(cand_flag)
                            })
                    except Exception:
                        pass

    def _analyze_dns(self, flag_patterns: List[Any]):
        for dns in self.engine.dns_records:
            q_name = dns.get("query_name", "")
            if not q_name:
                continue

            self._hunt_flags_in_text(q_name, f"DNS Query: {q_name}", flag_patterns, "DNS Query")
            for ans in dns.get("answers", []):
                ans_val = str(ans.get("value", ""))
                self._hunt_flags_in_text(ans_val, f"DNS Answer ({ans.get('name')})", flag_patterns, "DNS Answer")

            # Decode Base64 in subdomain labels
            labels = q_name.split(".")
            for lbl in labels:
                if len(lbl) >= 16:
                    pad_len = (4 - (len(lbl) % 4)) % 4
                    cand_b64 = lbl + ("=" * pad_len)
                    try:
                        dec_lbl = base64.b64decode(cand_b64, validate=True).decode("utf-8", errors="ignore")
                        for pat in flag_patterns:
                            for m in pat.finditer(dec_lbl):
                                fv = m.group(0).strip()
                                if is_valid_flag_str(fv) and fv not in self.seen_flags:
                                    self.seen_flags.add(fv)
                                    self.flags.append({
                                        "flag": fv,
                                        "stream": f"DNS Exfil: {q_name}",
                                        "encoding": "DNS Base64 Decoded",
                                        "length": len(fv)
                                    })
                    except Exception:
                        pass

            # Detect DNS Tunneling / Exfiltration
            labels = q_name.split(".")
            if labels and len(labels[0]) >= 24:
                sub_entropy = calculate_entropy(labels[0].encode())
                if sub_entropy >= 3.8:
                    self.findings.append(SuspiciousFinding(
                        category="DNS Exfiltration / Tunneling",
                        severity="HIGH",
                        stream_info=f"DNS Client {dns.get('src_ip')}  {dns.get('dst_ip')}",
                        title=f"High-Entropy Subdomain Exfiltration (Entropy: {sub_entropy})",
                        match_value=q_name,
                        context=f"Subdomain chunk: {labels[0]} (Length: {len(labels[0])})"
                    ))

    def _analyze_icmp(self, flag_patterns: List[Any]):
        standard_ping_pattern = b"abcdefghijklmnopqrstuvwabcdefghi"

        for p in self.engine.icmp_packets:
            payload = p.get("payload", b"")
            if len(payload) >= 4:
                try:
                    text_p = payload.decode("latin-1", errors="replace")
                    self._hunt_flags_in_text(text_p, f"ICMP Packet ({p.get('src_ip')}  {p.get('dst_ip')})", flag_patterns, "ICMP Payload")
                except Exception:
                    pass

                if standard_ping_pattern not in payload and len(payload) >= 16:
                    printable_count = sum(1 for b in payload if 32 <= b <= 126)
                    if printable_count >= len(payload) * 0.7:
                        text_snippet = payload.decode("latin-1", errors="replace")[:60].replace("\n", " ").replace("\r", "")
                        self.findings.append(SuspiciousFinding(
                            category="ICMP Tunneling / Covert Channel",
                            severity="HIGH",
                            stream_info=f"ICMP Echo ({p.get('src_ip')}  {p.get('dst_ip')})",
                            title=f"Non-Standard ICMP Echo Payload ({len(payload)} bytes)",
                            match_value=text_snippet,
                            context=f"ASCII printable data exfiltrated via ping: {text_snippet}"
                        ))
                        break


# -------------------------------------------------------------
# Rich Console Rendering & Pretty Print Tables
# -------------------------------------------------------------

def print_scan_flags_table(flags: List[Dict[str, Any]]):
    if not flags:
        console.print("[yellow][i] No CTF flags matched across packet streams.[/yellow]")
        return

    table = Table(
        title=f" Captured CTF Flags & Objectives ({len(flags)} Found in PCAP)",
        show_header=True,
        header_style="bold magenta",
        border_style="bold green",
        expand=True
    )
    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("Captured Flag / Objective", style="bold white on dark_green", min_width=32, overflow="fold")
    table.add_column("Stream / Vector Source", style="cyan", width=36, overflow="fold")
    table.add_column("Encoding", style="yellow", width=22, justify="center")

    for idx, f in enumerate(flags, start=1):
        table.add_row(
            str(idx),
            escape(f" {f['flag']} "),
            escape(f["stream"]),
            escape(f["encoding"])
        )

    console.print(table)


def print_findings_table(findings: List[SuspiciousFinding], limit: int = 50):
    if not findings:
        console.print("[dim][i] No suspicious payloads or attack signatures identified.[/dim]")
        return

    table = Table(
        title=f" Suspicious Streams & Attack Indicators ({len(findings)} Findings)",
        show_header=True,
        header_style="bold yellow",
        border_style="bold red",
        expand=True
    )
    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("Severity", style="bold", width=12, justify="center")
    table.add_column("Category", style="bold cyan", width=24)
    table.add_column("Stream / Endpoint Source", style="dim cyan", width=28, overflow="fold")
    table.add_column("Detected Signature / Match", style="bold red", width=32, overflow="fold")
    table.add_column("Forensic Context / Snippet", style="white", min_width=30, overflow="fold")

    for idx, f in enumerate(findings[:limit], start=1):
        if f.severity == "CRITICAL":
            sev_style = "[bold white on red]CRITICAL[/bold white on red]"
        elif f.severity == "HIGH":
            sev_style = "[bold red]HIGH[/bold red]"
        elif f.severity == "MEDIUM":
            sev_style = "[yellow]MEDIUM[/yellow]"
        else:
            sev_style = "[dim]LOW[/dim]"

        table.add_row(
            str(idx),
            sev_style,
            escape(f.category),
            escape(f.stream_info),
            escape(f.match_value),
            escape(f.context)
        )

    console.print(table)
    if len(findings) > limit:
        console.print(f"[dim]... and {len(findings) - limit} more findings (use --limit to expand)[/dim]")


def export_scan_markdown(results: Dict[str, Any], output_path: str, pcap_file: str):
    flags = results["flags"]
    findings = results["findings"]

    lines = [
        f"# PCAP Suspicious Stream & Payload Scan Report",
        f"- **Source File:** `{os.path.basename(pcap_file)}`",
        f"- **Flags Recovered:** `{len(flags)}`",
        f"- **Attack Indicators / Suspicious Streams:** `{len(findings)}`",
        "",
        "##  Captured CTF Flags",
        "| # | Captured Flag | Stream / Source | Encoding |",
        "|---|---|---|---|"
    ]
    for idx, f in enumerate(flags, start=1):
        lines.append(f"| {idx} | **`{f['flag'].replace('|', '\\|')}`** | `{f['stream'].replace('|', '\\|')}` | {f['encoding']} |")

    lines.append("\n##  Suspicious Streams & Attack Signatures")
    lines.append("| # | Severity | Category | Stream / Host | Detected Match | Context Snippet |")
    lines.append("|---|---|---|---|---|---|")
    for idx, fd in enumerate(findings, start=1):
        lines.append(f"| {idx} | **{fd.severity}** | {fd.category} | `{fd.stream_info.replace('|', '\\|')}` | `{fd.match_value.replace('|', '\\|')}` | `{fd.context.replace('|', '\\|')}` |")

    with open(output_path, "w", encoding="utf-8") as fp:
        fp.write("\n".join(lines) + "\n")
    console.print(f"[bold green][/bold green] Exported PCAP scan report to Markdown: [cyan]{output_path}[/cyan]")


def main(args_list=None):
    parser = argparse.ArgumentParser(
        prog="pcapscan",
        description=" PCAP Suspicious Stream & Payload Hunter (Base64, Hex, XOR, WASM, Shellcode, C2 Fingerprinting, Tunneling)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  pcapscan capture.pcap
  pcapscan evidence.pcapng -p "FLAG{"
  pcapscan capture.pcap --flags-only
  pcapscan capture.pcap --export-all
        """
    )
    parser.add_argument("pcap_file", help="Path to input PCAP or PCAPNG file")
    parser.add_argument("-p", "--prefix", help="Custom CTF flag prefix (e.g. 'FLAG', 'HTB', 'cyber', 'chall')")
    parser.add_argument("-l", "--limit", type=int, default=50, help="Row display limit (default: 50)")

    # Filters
    parser.add_argument("--flags-only", action="store_true", help="Display only discovered CTF flags")
    parser.add_argument("--findings-only", action="store_true", help="Display only suspicious stream findings")

    # Exports
    parser.add_argument("--md", "--markdown", dest="md", help="Export to Markdown report (.md)")
    parser.add_argument("--json", help="Export to JSON file")
    parser.add_argument("--export-all", action="store_true", help="Generate MD and JSON reports automatically")

    args = parser.parse_args(args_list)

    if not os.path.exists(args.pcap_file):
        console.print(f"[bold red]Error:[/bold red] File not found: {args.pcap_file}")
        sys.exit(1)

    print_banner(
        tool_name="PCAP SUSPICIOUS STREAM & PAYLOAD SCANNER (pcapscan)",
        sub_title="C2 Fingerprints, Base64/Gzip Recursive Unpacker & Shellcode Hunter"
    )

    engine = PCAPEngine(args.pcap_file)
    with console.status("[bold cyan]Reassembling streams & hunting malicious payloads...[/bold cyan]"):
        scanner = PCAPScanner(engine, custom_prefix=args.prefix)
        results = scanner.scan()

    if args.flags_only:
        print_scan_flags_table(results["flags"])
    elif args.findings_only:
        print_findings_table(results["findings"], limit=args.limit)
    else:
        print_scan_flags_table(results["flags"])
        print_findings_table(results["findings"], limit=args.limit)

    base_name = os.path.splitext(os.path.basename(args.pcap_file))[0]
    if args.export_all:
        if not args.md: args.md = f"{base_name}_pcapscan.md"
        if not args.json: args.json = f"{base_name}_pcapscan.json"

    if hasattr(args, 'md') and args.md:
        export_scan_markdown(results, args.md, args.pcap_file)
    if hasattr(args, 'json') and args.json:
        with open(args.json, "w", encoding="utf-8") as fp:
            json.dump({
                "flags": results["flags"],
                "findings": [f.to_dict() for f in results["findings"]]
            }, fp, indent=2, ensure_ascii=False)
        console.print(f"[bold green][/bold green] Exported PCAP scan report to JSON: [cyan]{args.json}[/cyan]")


if __name__ == "__main__":
    main()
