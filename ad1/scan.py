"""
AD1 User Directory Scanner & Sensitive Artifacts Finder (ad1scan)
Engineered for Digital Forensics & Incident Response (DFIR) and CTF Investigations.

Features:
- Scans User profile hierarchies (Users/, home/, Documents, Desktop, Downloads, AppData, etc.)
- Builds clean, intuitive, visual folder & file tree with depth controls.
- Automatic detection & real-time highlighting of:
  * Sensitive files: (passwords, secrets, keys, credentials, tokens, .kdbx, id_rsa, .env)
  * CTF Flags: regex matching for flag{...}, FLAG{...}, ctf{...}, htb{...}, picoCTF{...}, etc.
  * Base64 encoded strings in filenames and file contents (with automatic ASCII decoding verification)
  * Private Keys, SSH keys, AWS tokens, API keys
- Multi-format reporting (Rich Terminal Tree & Table, Markdown, JSON, CSV, Interactive HTML)
"""
import sys
import os
import re
import base64
import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Set, Tuple

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from rich.console import Console
from rich.tree import Tree
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from ad1.parser import AD1Parser
from ad1.models import AD1Item
from core.banner import print_ad1_banner
from core.utils import human_size, format_datetime

console = Console(force_terminal=True, legacy_windows=False)

# Sensitive Keywords in Filenames
SENSITIVE_FILENAME_KEYWORDS = [
    "flag", "secret", "password", "passwords", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "credential", "credentials", "shadow", "sam", "ntds.dit",
    "keepass", "kdbx", "wallet", "seed", "seedphrase", "recovery", "private_key",
    "vault", "loot", "sensitive", "confidential", "dump", "leak", "exploit",
    "payload", "backdoor", "c2", ".env"
]

# Sensitive Extensions
SENSITIVE_EXTENSIONS = {
    ".kdbx", ".key", ".pem", ".pfx", ".p12", ".ovpn", ".sqlite", ".sqlite3", ".db",
    ".bak", ".old", ".dump", ".dmp", ".vmdk", ".7z", ".rar", ".zip", ".gz", ".tar",
    ".flag", ".ps1", ".vbs", ".bat", ".sh", ".py", ".conf", ".cfg", ".ini", ".env", ".json"
}

# Flag Regex Patterns
RE_FLAGS = [
    re.compile(r"(?:flag|FLAG|ctf|CTF|htb|HTB|picoCTF|thm|THM)\{[^}\n\r\t ]{3,200}\}"),
    re.compile(r"flag_[a-zA-Z0-9_\-]{8,64}", re.IGNORECASE),
    re.compile(r"FLAG:[a-zA-Z0-9_\-]{8,64}")
]

# Base64 Pattern
RE_BASE64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")

# Private Key & API Key Patterns
RE_PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")
RE_AWS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
RE_GITHUB_TOKEN = re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}\b")


def is_valid_base64_ascii(s: str) -> Tuple[bool, str]:
    """
    Checks if string is valid base64 and decodes to readable ASCII/UTF-8.
    """
    # Clean padding if needed
    clean_s = s.strip("-_= ")
    if len(clean_s) < 12:
        return False, ""
    
    pad_needed = (4 - len(clean_s) % 4) % 4
    padded = clean_s + ("=" * pad_needed)

    try:
        raw = base64.b64decode(padded)
        if len(raw) < 6:
            return False, ""
        text = raw.decode("utf-8")
        printable_ratio = sum(1 for c in text if 32 <= ord(c) <= 126 or c in "\n\r\t") / len(text)
        if printable_ratio > 0.80:
            return True, text
    except Exception:
        pass
    return False, ""


class AD1Scanner:
    """
    Scans user directories in an AD1 image and identifies sensitive files, flags, and keys.
    """
    def __init__(self, parser: AD1Parser, scan_content: bool = True):
        self.parser = parser
        self.scan_content = scan_content

    def scan(self, target_user: Optional[str] = None, full_image: bool = False) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        if not self.parser.items:
            self.parser.build_tree()

        scanned_entries = []
        stats = {
            "total_files": 0,
            "total_folders": 0,
            "sensitive_matches": 0,
            "flags_found": 0,
            "keys_found": 0,
            "base64_strings": 0
        }

        # Filter items to User scope by default, unless full_image requested
        for item in self.parser.items:
            path_norm = item.full_path.replace("\\", "/")
            path_lower = path_norm.lower()

            if item.is_dir:
                stats["total_folders"] += 1
            else:
                stats["total_files"] += 1

            # Scope filtering
            if not full_image:
                if not any(k in path_lower for k in ["users/", "home/", "documents and settings/"]):
                    # If outside users, only keep if name contains flag or secret
                    if not any(sk in item.item_name.lower() for sk in ["flag", "secret", "loot", "pass"]):
                        continue

            if target_user:
                if f"users/{target_user.lower()}" not in path_lower and f"home/{target_user.lower()}" not in path_lower:
                    continue

            # Analyze item for sensitive indicators
            finding = self._inspect_item(item, path_norm)
            if finding["is_sensitive"]:
                stats["sensitive_matches"] += 1
                if finding["flags"]:
                    stats["flags_found"] += len(finding["flags"])
                if finding["private_keys"] or finding["api_keys"]:
                    stats["keys_found"] += len(finding["private_keys"]) + len(finding["api_keys"])
                if finding["base64_matches"]:
                    stats["base64_strings"] += len(finding["base64_matches"])

            scanned_entries.append(finding)

        return scanned_entries, stats

    def _inspect_item(self, item: AD1Item, path_norm: str) -> Dict[str, Any]:
        name = item.item_name
        name_lower = name.lower()
        _, ext = os.path.splitext(name_lower)

        is_sensitive = False
        reasons = []
        flags = []
        private_keys = []
        api_keys = []
        base64_matches = []
        content_preview = None

        if not item.is_dir:
            # 1. Filename Keyword Match
            for kw in SENSITIVE_FILENAME_KEYWORDS:
                if kw in name_lower:
                    is_sensitive = True
                    reasons.append(f"Filename contains keyword '{kw}'")
                    break

            # 2. Sensitive Extension Match
            if ext in SENSITIVE_EXTENSIONS and not is_sensitive:
                if ext in [".kdbx", ".key", ".pem", ".pfx", ".p12", ".flag", ".env"]:
                    is_sensitive = True
                    reasons.append(f"Sensitive file extension: '{ext}'")

            # 3. Base64 in Filename
            b64_name_match = RE_BASE64.search(name)
            if b64_name_match:
                cand = b64_name_match.group(0)
                is_b64, dec = is_valid_base64_ascii(cand)
                if is_b64:
                    is_sensitive = True
                    base64_matches.append(f"Filename Base64: {cand} -> '{dec}'")
                    reasons.append(f"Base64 string in filename decoded: '{dec}'")

            # 4. Content Inspection (for small files < 128 KB)
            if self.scan_content and item.decompressed_size < 131072:
                should_scan_content = (
                    is_sensitive or
                    ext in [".txt", ".log", ".flag", ".json", ".xml", ".yml", ".yaml", ".sh", ".ps1", ".py", ".env", ".cfg", ".conf", ".md", ".ini", ""]
                )
                if should_scan_content and item.decompressed_size > 0:
                    raw_bytes = self.parser.read_file_bytes(item)
                    if raw_bytes:
                        text = raw_bytes.decode("latin-1", errors="replace")

                        # Scan for Flags
                        for pattern in RE_FLAGS:
                            for m in pattern.finditer(text):
                                fl = m.group(0)
                                if fl not in flags:
                                    flags.append(fl)
                                    is_sensitive = True
                                    reasons.append(f" FLAG FOUND: {fl}")

                        # Scan for Private Keys
                        for m in RE_PRIVATE_KEY.finditer(text):
                            pk = m.group(0)
                            if pk not in private_keys:
                                private_keys.append(pk)
                                is_sensitive = True
                                reasons.append(f" Private Key Header detected: {pk}")

                        # Scan for AWS / GitHub Keys
                        for m in RE_AWS_KEY.finditer(text):
                            k = m.group(0)
                            if k not in api_keys:
                                api_keys.append(k)
                                is_sensitive = True
                                reasons.append(f" AWS Key detected: {k}")

                        for m in RE_GITHUB_TOKEN.finditer(text):
                            k = m.group(0)
                            if k not in api_keys:
                                api_keys.append(k)
                                is_sensitive = True
                                reasons.append(f" GitHub Token detected: {k}")

                        # Scan for Base64 in content
                        for m in RE_BASE64.finditer(text):
                            cand = m.group(0)
                            is_b64, dec = is_valid_base64_ascii(cand)
                            if is_b64 and len(dec.strip()) >= 5 and dec not in str(base64_matches):
                                if any(k in dec.lower() for k in ["flag", "pass", "secret", "ctf", "key", "admin"]):
                                    base64_matches.append(f"{cand} -> '{dec}'")
                                    is_sensitive = True
                                    reasons.append(f" Base64 Secret in content: '{dec}'")

                        # Preview first 120 chars if sensitive
                        if is_sensitive and not content_preview:
                            clean_lines = [l.strip() for l in text.splitlines() if l.strip()][:3]
                            content_preview = " | ".join(clean_lines)[:140]

        return {
            "name": name,
            "path": path_norm,
            "is_dir": item.is_dir,
            "size": item.decompressed_size,
            "size_str": human_size(item.decompressed_size) if not item.is_dir else "<DIR>",
            "is_sensitive": is_sensitive,
            "reasons": reasons,
            "flags": flags,
            "private_keys": private_keys,
            "api_keys": api_keys,
            "base64_matches": base64_matches,
            "content_preview": content_preview
        }


def build_and_render_tree(entries: List[Dict[str, Any]], max_depth: int = 5, query: Optional[str] = None):
    """
    Renders an intuitive, colorful visual tree with sensitive findings highlighted.
    """
    root_tree = Tree(" [bold white]AD1 Evidence Root[/bold white]")
    path_nodes: Dict[str, Any] = {"": root_tree}

    # Sort entries by path
    sorted_entries = sorted(entries, key=lambda x: x["path"])

    for item in sorted_entries:
        path = item["path"]
        parts = path.strip("/").split("/")

        if len(parts) > max_depth:
            continue

        # Build tree parent nodes
        curr_path = ""
        parent_node = root_tree

        for idx, part in enumerate(parts):
            prev_path = curr_path
            curr_path = f"{curr_path}/{part}" if curr_path else part
            is_last = (idx == len(parts) - 1)

            if curr_path not in path_nodes:
                if is_last:
                    # Leaf item
                    if item["is_dir"]:
                        node_label = f" [bold cyan]{part}[/bold cyan]"
                    else:
                        size_txt = f"[dim]({item['size_str']})[/dim]"
                        if item["flags"]:
                            node_label = f" [bold red] {part}[/bold red] {size_txt} [bold yellow][FLAG: {', '.join(item['flags'])}][/bold yellow]"
                        elif item["is_sensitive"]:
                            reasons_txt = f" [bold yellow] [{'; '.join(item['reasons'][:2])}][/bold yellow]"
                            node_label = f" [bold yellow] {part}[/bold yellow] {size_txt}{reasons_txt}"
                        else:
                            node_label = f" [white]{part}[/white] {size_txt}"

                    new_node = parent_node.add(node_label)
                    path_nodes[curr_path] = new_node
                else:
                    # Intermediate folder
                    new_node = parent_node.add(f" [bold cyan]{part}[/bold cyan]")
                    path_nodes[curr_path] = new_node
                    parent_node = new_node
            else:
                parent_node = path_nodes[curr_path]

    console.print(root_tree)


def print_sensitive_table(entries: List[Dict[str, Any]], max_rows: int = 100):
    sensitive_items = [e for e in entries if e["is_sensitive"]]
    if not sensitive_items:
        console.print("[green] No sensitive files or CTF flags detected in scanned paths.[/green]")
        return

    table = Table(
        title=f" Flagged Sensitive Files & CTF Artifacts ({len(sensitive_items)} Total Found)",
        show_header=True,
        header_style="bold magenta",
        border_style="dim red",
        expand=True
    )

    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("File / Artifact Name", style="bold cyan", width=22)
    table.add_column("Full Path", style="white", min_width=32, overflow="fold")
    table.add_column("Size", style="green", width=9, justify="right")
    table.add_column("Flagged Indicators & Findings", style="bold yellow", min_width=35, overflow="fold")

    for idx, item in enumerate(sensitive_items[:max_rows], start=1):
        name = item["name"]
        path = item["path"]
        size_str = item["size_str"]

        findings = []
        if item["flags"]:
            for fl in item["flags"]:
                findings.append(f"[bold red] FLAG:[/bold red] [bold white on red] {fl} [/bold white on red]")
        if item["private_keys"]:
            for pk in item["private_keys"]:
                findings.append(f"[bold yellow] KEY:[/bold yellow] {pk}")
        if item["api_keys"]:
            for ak in item["api_keys"]:
                findings.append(f"[bold yellow] API KEY:[/bold yellow] {ak}")
        if item["base64_matches"]:
            for b64 in item["base64_matches"]:
                findings.append(f"[bold cyan] BASE64:[/bold cyan] {b64}")

        for r in item["reasons"]:
            if not any(f in r for f in ["FLAG FOUND", "Private Key Header", "AWS Key", "GitHub Token", "Base64 Secret"]):
                findings.append(f"[yellow]•[/yellow] {r}")

        if item.get("content_preview"):
            findings.append(f"[dim italic]Preview: {item['content_preview']}[/dim italic]")

        findings_text = "\n".join(findings)

        table.add_row(
            str(idx),
            f" [bold red]{name}[/bold red]" if item["flags"] else f" [bold yellow]{name}[/bold yellow]",
            path,
            size_str,
            findings_text
        )

    console.print(table)

    if len(sensitive_items) > max_rows:
        console.print(f"[italic dim]... showing top {max_rows} of {len(sensitive_items)} records. Use --export-all or --md to view all records.[/italic dim]\n")


def export_scan_markdown(entries: List[Dict[str, Any]], stats: Dict[str, Any], output_path: str, source_name: str = "Evidence Image"):
    generated_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    sensitive_items = [e for e in entries if e["is_sensitive"]]

    lines = [
        f"# DFIR Forensic Report - Directory Scan & Sensitive Artifacts",
        f"- **Evidence Source:** `{source_name}`",
        f"- **Generated:** `{generated_time}`",
        f"- **Total Files Scanned:** `{stats.get('total_files', 0)}` (Folders: `{stats.get('total_folders', 0)}`)",
        f"- **Sensitive / Flagged Files:** `{len(sensitive_items)}`",
        "",
        "## Summary Insights",
        f"- ** CTF Flags Found:** `{stats.get('flags_found', 0)}`",
        f"- ** Private / API Keys:** `{stats.get('keys_found', 0)}`",
        f"- ** Base64 Secret Strings:** `{stats.get('base64_strings', 0)}`",
        "",
        "## Flagged Sensitive Files",
        "| # | File Name | Full Path | Size | Flagged Findings / Flags / Decoded Secrets |",
        "|---|---|---|:---:|---|"
    ]

    for idx, item in enumerate(sensitive_items, start=1):
        name = item["name"].replace("|", "\\|")
        path = item["path"].replace("|", "\\|")
        size_str = item["size_str"]

        findings_list = []
        if item["flags"]:
            for fl in item["flags"]:
                findings_list.append(f" **FLAG:** `{fl}`")
        if item["private_keys"]:
            for pk in item["private_keys"]:
                findings_list.append(f" **KEY:** `{pk}`")
        if item["api_keys"]:
            for ak in item["api_keys"]:
                findings_list.append(f" **API TOKEN:** `{ak}`")
        if item["base64_matches"]:
            for b64 in item["base64_matches"]:
                findings_list.append(f" **BASE64:** `{b64}`")
        for r in item["reasons"]:
            if not any(f in r for f in ["FLAG FOUND", "Private Key Header", "AWS Key", "GitHub Token", "Base64 Secret"]):
                findings_list.append(f"• {r}")
        if item.get("content_preview"):
            findings_list.append(f"*Preview:* `{item['content_preview']}`")

        findings_md = "<br>".join(findings_list) if findings_list else "*Sensitive Match*"
        prefix = " " if item["flags"] else " "

        lines.append(f"| {idx} | {prefix}**`{name}`** | `{path}` | {size_str} | {findings_md} |")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    console.print(f"[bold green][/bold green] Exported {len(sensitive_items)} sensitive records to Markdown (MD): [cyan]{output_path}[/cyan]")


def export_scan_json(entries: List[Dict[str, Any]], stats: Dict[str, Any], output_path: str):
    payload = {
        "stats": stats,
        "flagged_count": len([e for e in entries if e["is_sensitive"]]),
        "flagged_entries": [e for e in entries if e["is_sensitive"]],
        "all_scanned_count": len(entries)
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    console.print(f"[bold green][/bold green] Exported scan results to JSON: [cyan]{output_path}[/cyan]")


def export_scan_csv(entries: List[Dict[str, Any]], output_path: str):
    import csv
    sensitive_items = [e for e in entries if e["is_sensitive"]]
    fieldnames = ["name", "path", "is_dir", "size", "size_str", "reasons", "flags", "private_keys", "api_keys", "base64_matches", "content_preview"]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for e in sensitive_items:
            row = dict(e)
            row["reasons"] = "; ".join(e.get("reasons", []))
            row["flags"] = "; ".join(e.get("flags", []))
            row["private_keys"] = "; ".join(e.get("private_keys", []))
            row["api_keys"] = "; ".join(e.get("api_keys", []))
            row["base64_matches"] = "; ".join(e.get("base64_matches", []))
            writer.writerow(row)
    console.print(f"[bold green][/bold green] Exported {len(sensitive_items)} sensitive records to CSV: [cyan]{output_path}[/cyan]")


def export_scan_html(entries: List[Dict[str, Any]], stats: Dict[str, Any], output_path: str, source_name: str = "Evidence Image"):
    sensitive_items = [e for e in entries if e["is_sensitive"]]
    json_payload = json.dumps(sensitive_items, ensure_ascii=False)
    generated_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>DFIR Forensic Report - Sensitive Files & Flags ({source_name})</title>
    <style>
        :root {{ --bg: #0f172a; --surface: #1e293b; --surface-hover: #334155; --border: #334155; --text: #f8fafc; --text-muted: #94a3b8; --accent: #38bdf8; --danger: #f43f5e; }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
        body {{ background: var(--bg); color: var(--text); padding: 24px; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 20px; }}
        .title {{ font-size: 24px; font-weight: 700; }}
        .title span {{ color: var(--accent); }}
        .badge {{ background: #991b1b; color: #fecaca; padding: 4px 10px; border-radius: 999px; font-size: 12px; font-weight: 600; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 20px; }}
        .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }}
        .card .label {{ font-size: 12px; color: var(--text-muted); text-transform: uppercase; }}
        .card .val {{ font-size: 24px; font-weight: 700; margin-top: 4px; }}
        .controls {{ display: flex; gap: 12px; margin-bottom: 16px; }}
        .search-box {{ flex: 1; background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 10px 14px; color: #fff; font-size: 14px; outline: none; }}
        table {{ width: 100%; border-collapse: collapse; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; font-size: 13px; }}
        th {{ background: #111827; color: var(--text-muted); padding: 12px 14px; text-align: left; position: sticky; top: 0; }}
        td {{ padding: 12px 14px; border-bottom: 1px solid var(--border); vertical-align: top; word-break: break-all; }}
        tr:hover {{ background: var(--surface-hover); }}
        .flag-box {{ background: #881337; border: 1px solid #e11d48; padding: 4px 8px; border-radius: 4px; color: #ffe4e6; font-weight: 700; display: inline-block; margin-top: 4px; }}
        .key-box {{ background: #713f12; border: 1px solid #ca8a04; padding: 4px 8px; border-radius: 4px; color: #fef08a; font-weight: 600; display: inline-block; margin-top: 4px; }}
        .b64-box {{ background: #1e1b4b; border: 1px solid #4f46e5; padding: 4px 8px; border-radius: 4px; color: #c7d2fe; display: inline-block; margin-top: 4px; }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <div class="title">DFIR <span>Sensitive Artifacts & Flag Scanner</span> Report</div>
            <div style="font-size: 13px; color: var(--text-muted); margin-top: 4px;">Evidence: <strong>{source_name}</strong> | Generated: {generated_time}</div>
        </div>
        <div class="badge">Sensitive Artifacts Scan</div>
    </div>
    <div class="stats-grid">
        <div class="card"><div class="label">Total Scanned Files</div><div class="val">{stats.get('total_files', 0)}</div></div>
        <div class="card"><div class="label">Sensitive / Flagged Files</div><div class="val" style="color: var(--danger);">{len(sensitive_items)}</div></div>
        <div class="card"><div class="label">Flags Detected</div><div class="val" style="color: #f43f5e;">{stats.get('flags_found', 0)}</div></div>
        <div class="card"><div class="label">Keys & Secrets</div><div class="val" style="color: #fbbf24;">{stats.get('keys_found', 0)}</div></div>
    </div>
    <div class="controls">
        <input type="text" id="searchInput" class="search-box" placeholder=" Live Search: Flag name, Path, Key, Decoded Secret...">
    </div>
    <table>
        <thead>
            <tr>
                <th style="width: 50px;">#</th>
                <th style="width: 220px;">File Name</th>
                <th>Full Path</th>
                <th style="width: 100px;">Size</th>
                <th>Findings & Extracted Secrets</th>
            </tr>
        </thead>
        <tbody id="tbody"></tbody>
    </table>
    <script>
        const raw = {json_payload};
        let filtered = [...raw];
        function render() {{
            const tb = document.getElementById('tbody');
            tb.innerHTML = '';
            filtered.forEach((item, idx) => {{
                const tr = document.createElement('tr');
                let findingsHtml = '';
                if (item.flags && item.flags.length) {{
                    item.flags.forEach(f => {{ findingsHtml += `<div><span class="flag-box"> FLAG: ${{f}}</span></div>`; }});
                }}
                if (item.private_keys && item.private_keys.length) {{
                    item.private_keys.forEach(k => {{ findingsHtml += `<div><span class="key-box"> ${{k}}</span></div>`; }});
                }}
                if (item.api_keys && item.api_keys.length) {{
                    item.api_keys.forEach(k => {{ findingsHtml += `<div><span class="key-box"> API: ${{k}}</span></div>`; }});
                }}
                if (item.base64_matches && item.base64_matches.length) {{
                    item.base64_matches.forEach(b => {{ findingsHtml += `<div><span class="b64-box"> ${{b}}</span></div>`; }});
                }}
                if (item.reasons && item.reasons.length) {{
                    findingsHtml += `<div style="margin-top: 4px; color: #cbd5e1;">• ${{item.reasons.join('<br>• ')}}</div>`;
                }}
                if (item.content_preview) {{
                    findingsHtml += `<div style="margin-top: 4px; font-size: 11px; color: #94a3b8; font-style: italic;">Preview: ${{item.content_preview}}</div>`;
                }}

                tr.innerHTML = `
                    <td style="color: #64748b;">${{idx + 1}}</td>
                    <td><strong style="color: ${{item.flags && item.flags.length ? '#f43f5e' : '#fbbf24'}};">${{item.name || ''}}</strong></td>
                    <td style="font-family: monospace; color: #f8fafc;">${{item.path || ''}}</td>
                    <td style="color: #4ade80;">${{item.size_str || ''}}</td>
                    <td>${{findingsHtml}}</td>
                `;
                tb.appendChild(tr);
            }});
        }}
        document.getElementById('searchInput').addEventListener('input', (e) => {{
            const q = e.target.value.toLowerCase().trim();
            filtered = raw.filter(i => JSON.stringify(i).toLowerCase().includes(q));
            render();
        }});
        render();
    </script>
</body>
</html>"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    console.print(f"[bold green][/bold green] Generated interactive HTML Scan report: [cyan]{output_path}[/cyan]")


def main(args_list=None):
    parser = argparse.ArgumentParser(
        prog="ad1 scan",
        description=" Scan AD1 user directories, display folder hierarchy tree, and highlight sensitive files, flags, keys, and base64 strings.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ad1scan evidence.ad1
  ad1scan evidence.ad1 --tree-only -d 4
  ad1scan evidence.ad1 --sensitive-only
  ad1scan evidence.ad1 --user Alice
  ad1scan evidence.ad1 --full
  ad1scan evidence.ad1 --md scan_report.md --json scan.json
  ad1scan evidence.ad1 --export-all
        """
    )
    parser.add_argument("input", help="Path to input AD1 image file")
    parser.add_argument("-u", "--user", help="Filter scan to specific user profile (e.g. Alice)")
    parser.add_argument("-d", "--depth", type=int, default=5, help="Visual tree max depth (default: 5)")
    parser.add_argument("-q", "--query", help="Filter files by keyword in path or name")
    parser.add_argument("--full", action="store_true", help="Scan entire AD1 image instead of user profile directory only")
    parser.add_argument("--no-content", action="store_true", help="Skip deep file content inspection")
    parser.add_argument("--tree-only", action="store_true", help="Only render directory tree")
    parser.add_argument("--sensitive-only", "--flags-only", dest="sensitive_only", action="store_true", help="Only display table of flagged sensitive files/flags")
    parser.add_argument("-l", "--limit", type=int, default=100, help="Row display limit in table (default: 100)")

    # Export options
    parser.add_argument("--md", "--markdown", dest="md", help="Export to Markdown (.md) report")
    parser.add_argument("--json", help="Export to JSON file")
    parser.add_argument("--csv", help="Export to CSV file")
    parser.add_argument("--html", help="Export to interactive HTML report")
    parser.add_argument("--export-all", action="store_true", help="Generate MD, JSON, CSV, and HTML reports automatically")

    args = parser.parse_args(args_list)

    if not os.path.exists(args.input):
        console.print(f"[bold red]Error:[/bold red] File not found: {args.input}")
        sys.exit(1)

    print_ad1_banner("AD1 USER DIRECTORY & SENSITIVE SCANNER (ad1scan)")
    console.print(f"[dim]Opening image container:[/dim] [cyan]{args.input}[/cyan]\n")

    with console.status("[bold cyan]Scanning directory hierarchy and inspecting artifacts...[/bold cyan]"):
        parser_ad1 = AD1Parser(args.input)
        scanner = AD1Scanner(parser_ad1, scan_content=not args.no_content)
        entries, stats = scanner.scan(target_user=args.user, full_image=args.full)

    if not entries:
        console.print("[bold yellow] No files or directories found in the specified scan scope.[/bold yellow]")
        parser_ad1.close()
        return

    # Filter query if specified
    if args.query:
        q_low = args.query.lower()
        entries = [e for e in entries if q_low in e["path"].lower() or q_low in str(e["reasons"]).lower()]

    # 1. Render Visual Tree (unless sensitive-only is specified)
    if not args.sensitive_only:
        console.print("\n[bold cyan] User Directory Hierarchy Tree:[/bold cyan]")
        build_and_render_tree(entries, max_depth=args.depth, query=args.query)

    # 2. Render Sensitive Artifacts Table (unless tree-only is specified)
    if not args.tree_only:
        console.print("\n")
        print_sensitive_table(entries, max_rows=args.limit)

    # Insights Panel
    summary = Text()
    summary.append(" Scan & Sensitive Artifact Insights:\n", style="bold green")
    summary.append(f"  • Total Scanned Files   : {stats['total_files']} (Folders: {stats['total_folders']})\n", style="white")
    summary.append(f"  • Flagged Sensitive     : {stats['sensitive_matches']} files matched suspicious/sensitive rules\n", style="bold yellow" if stats['sensitive_matches'] else "green")
    if stats["flags_found"]:
        summary.append(f"  •  CTF Flags Found    : {stats['flags_found']} flags extracted!\n", style="bold red")
    if stats["keys_found"]:
        summary.append(f"  •  Keys & API Tokens  : {stats['keys_found']} private/API keys discovered!\n", style="bold red")
    if stats["base64_strings"]:
        summary.append(f"  •  Base64 Secrets     : {stats['base64_strings']} valid decoded strings!\n", style="cyan")

    console.print(Panel(summary, border_style="red" if stats["flags_found"] or stats["sensitive_matches"] else "green", title="Scan Summary", title_align="left"))

    # Export handlers
    base_name = os.path.splitext(os.path.basename(args.input))[0]
    if args.export_all:
        if not args.md: args.md = f"{base_name}_scan.md"
        if not args.json: args.json = f"{base_name}_scan.json"
        if not args.csv: args.csv = f"{base_name}_scan.csv"
        if not args.html: args.html = f"{base_name}_scan.html"

    if hasattr(args, 'md') and args.md: export_scan_markdown(entries, stats, args.md, source_name=base_name)
    if hasattr(args, 'json') and args.json: export_scan_json(entries, stats, args.json)
    if hasattr(args, 'csv') and args.csv: export_scan_csv(entries, args.csv)
    if hasattr(args, 'html') and args.html: export_scan_html(entries, stats, args.html, source_name=base_name)

    parser_ad1.close()


if __name__ == "__main__":
    main()
