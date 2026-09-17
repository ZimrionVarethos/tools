#!/usr/bin/env python3
"""
AD1 NTUSER.DAT User Registry Forensics Analyzer
Extracts UserAssist (ROT13 executed programs), TypedPaths, RunMRU (Win+R), RecentDocs, and WordWheelQuery.
Can be executed directly: python ad1/ntuser.py <evidence.ad1>
"""
import sys
import os
import re
import struct
import codecs
import argparse
import csv
import json
from collections import Counter
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from core.banner import print_ad1_banner
from core.utils import filetime_to_datetime, format_datetime
from core.registry import RegistryHive
from ad1.parser import AD1Parser
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

console = Console(force_terminal=True, legacy_windows=False)


class AD1NTUserAnalyzer:
    """
    Scans AD1 images for all user NTUSER.DAT registry hives and extracts behavioral user artifacts.
    """
    def __init__(self, parser: AD1Parser):
        self.parser = parser
        self.extracted_entries: List[Dict[str, Any]] = []

    def scan_and_extract(self) -> List[Dict[str, Any]]:
        if not self.parser.items:
            self.parser.build_tree()

        all_entries = []

        for item in self.parser.items:
            if item.is_dir or item.decompressed_size < 1024:
                continue

            name_lower = item.item_name.lower()
            path_lower = item.full_path.lower()

            if name_lower == "ntuser.dat" or "users/" in path_lower and "ntuser.dat" in name_lower:
                hive_bytes = self.parser.read_file_bytes(item)
                if not hive_bytes:
                    continue

                user_name = self._extract_user_from_path(item.full_path)
                entries = self.parse_ntuser_hive(hive_bytes, user_name, item.full_path)
                all_entries.extend(entries)

        self.extracted_entries = all_entries
        return all_entries

    def _extract_user_from_path(self, full_path: str) -> str:
        clean = full_path.replace("\\", "/")
        m = re.search(r"(?:^|/|[a-zA-Z]:/)(?:Users|Documents and Settings|home)/([^/]+)/", clean, re.IGNORECASE)
        return m.group(1) if m else "DefaultUser"

    def parse_ntuser_hive(self, hive_bytes: bytes, user_name: str, source_path: str) -> List[Dict[str, Any]]:
        entries = []
        hive = RegistryHive(hive_bytes)
        if not hive.root:
            return entries

        # 1. UserAssist (ROT13 Executed Programs)
        user_assist_key = hive.open_key("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist")
        if user_assist_key:
            for guid, sub in user_assist_key.subkeys.items():
                count_key = sub.get_subkey("Count")
                if not count_key:
                    continue

                for enc_name, val in count_key.values.items():
                    if not enc_name or not val.raw_data:
                        continue

                    # Decode ROT-13
                    decoded_name = codecs.decode(enc_name, "rot_13")
                    
                    # Parse binary UserAssist structure
                    raw = val.raw_data
                    run_count = 0
                    focus_count = 0
                    focus_time_ms = 0
                    last_exec_dt = None

                    # Win7/10/11 72-byte structure
                    if len(raw) >= 72:
                        run_count = struct.unpack("<I", raw[4:8])[0]
                        focus_count = struct.unpack("<I", raw[8:12])[0]
                        focus_time_ms = struct.unpack("<I", raw[12:16])[0]
                        ft_raw = struct.unpack("<Q", raw[60:68])[0]
                        last_exec_dt = filetime_to_datetime(ft_raw)
                    elif len(raw) >= 16:
                        # WinXP 16-byte structure
                        run_count = struct.unpack("<I", raw[4:8])[0]
                        ft_raw = struct.unpack("<Q", raw[8:16])[0]
                        last_exec_dt = filetime_to_datetime(ft_raw)

                    time_str = format_datetime(last_exec_dt) if last_exec_dt else "N/A"

                    # Clean GUID prefixes if any (e.g. {1AC14E77-02E7...}\notepad.exe)
                    clean_display = decoded_name
                    if clean_display.startswith("{") and "}\\" in clean_display:
                        clean_display = clean_display.split("}\\", 1)[1]

                    entries.append({
                        "user": user_name,
                        "category": "UserAssist (GUI Execution)",
                        "artifact": clean_display,
                        "raw_value": decoded_name,
                        "run_count": run_count,
                        "focus_count": focus_count,
                        "focus_time_seconds": round(focus_time_ms / 1000.0, 2) if focus_time_ms else 0,
                        "timestamp": time_str,
                        "timestamp_obj": last_exec_dt,
                        "source_hive": source_path
                    })

        # 2. TypedPaths (Explorer Address Bar History)
        typed_paths_key = hive.open_key("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths")
        if typed_paths_key:
            for val_name, val in typed_paths_key.values.items():
                if val.value:
                    entries.append({
                        "user": user_name,
                        "category": "TypedPaths (Explorer Address Bar)",
                        "artifact": str(val.value),
                        "raw_value": val_name,
                        "run_count": 1,
                        "focus_count": 0,
                        "focus_time_seconds": 0,
                        "timestamp": format_datetime(typed_paths_key.timestamp) if typed_paths_key.timestamp else "N/A",
                        "timestamp_obj": typed_paths_key.timestamp,
                        "source_hive": source_path
                    })

        # 3. RunMRU (Win + R Commands Executed)
        run_mru_key = hive.open_key("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU")
        if run_mru_key:
            for val_name, val in run_mru_key.values.items():
                if val_name != "MRUList" and val.value:
                    cmd_str = str(val.value).rstrip("\\1")
                    entries.append({
                        "user": user_name,
                        "category": "RunMRU (Win+R Command)",
                        "artifact": cmd_str,
                        "raw_value": val_name,
                        "run_count": 1,
                        "focus_count": 0,
                        "focus_time_seconds": 0,
                        "timestamp": format_datetime(run_mru_key.timestamp) if run_mru_key.timestamp else "N/A",
                        "timestamp_obj": run_mru_key.timestamp,
                        "source_hive": source_path
                    })

        # 4. WordWheelQuery (Explorer Search Queries)
        word_wheel_key = hive.open_key("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery")
        if word_wheel_key:
            for val_name, val in word_wheel_key.values.items():
                if val_name != "MRUListEx" and val.value:
                    q_str = str(val.value)
                    if isinstance(val.raw_data, bytes) and not isinstance(val.value, str):
                        try:
                            q_str = val.raw_data.decode("utf-16-le").rstrip("\x00")
                        except Exception:
                            q_str = str(val.value)

                    entries.append({
                        "user": user_name,
                        "category": "WordWheelQuery (Explorer Search)",
                        "artifact": q_str,
                        "raw_value": val_name,
                        "run_count": 1,
                        "focus_count": 0,
                        "focus_time_seconds": 0,
                        "timestamp": format_datetime(word_wheel_key.timestamp) if word_wheel_key.timestamp else "N/A",
                        "timestamp_obj": word_wheel_key.timestamp,
                        "source_hive": source_path
                    })

        # 5. RecentDocs
        recent_docs_key = hive.open_key("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs")
        if recent_docs_key:
            for val_name, val in recent_docs_key.values.items():
                if val_name != "MRUListEx" and val.raw_data:
                    doc_name = ""
                    try:
                        # Extract null-terminated unicode string from binary record
                        doc_name = val.raw_data.split(b"\x00\x00")[0].decode("utf-16-le", errors="ignore").rstrip("\x00")
                    except Exception:
                        pass
                    if doc_name and len(doc_name) > 1:
                        entries.append({
                            "user": user_name,
                            "category": "RecentDocs (Recently Opened File)",
                            "artifact": doc_name,
                            "raw_value": val_name,
                            "run_count": 1,
                            "focus_count": 0,
                            "focus_time_seconds": 0,
                            "timestamp": format_datetime(recent_docs_key.timestamp) if recent_docs_key.timestamp else "N/A",
                            "timestamp_obj": recent_docs_key.timestamp,
                            "source_hive": source_path
                        })

        return entries


def print_ntuser_table(entries: List[Dict[str, Any]], max_rows: int = 100):
    if not entries:
        console.print("[yellow] No NTUSER.DAT user activity artifacts found in the AD1 image.[/yellow]")
        return

    table = Table(
        title=f" NTUSER.DAT User Activity Records ({len(entries)} Total Artifacts)",
        show_header=True,
        header_style="bold magenta",
        border_style="dim blue",
        expand=True
    )

    table.add_column("#", style="dim", width=5, justify="right")
    table.add_column("User Account", style="bold cyan", width=15)
    table.add_column("Artifact Category", style="yellow", width=25)
    table.add_column("Executed Program / Path / Command", style="white", min_width=35, overflow="fold")
    table.add_column("Run Count", style="bold green", width=10, justify="center")
    table.add_column("Last Activity (UTC)", style="bold yellow", width=22)

    display = entries[:max_rows]
    for idx, item in enumerate(display, start=1):
        user = item.get("user", "Default")
        category = item.get("category", "General")
        artifact = item.get("artifact", "")
        run_count = str(item.get("run_count", 1))
        ts = item.get("timestamp", "N/A")

        table.add_row(
            str(idx),
            user,
            category,
            artifact,
            run_count,
            ts
        )

    console.print(table)

    if len(entries) > max_rows:
        console.print(f"[italic dim]... showing top {max_rows} of {len(entries)} records. Use --export-csv, --export-json, or --export-html to view all records.[/italic dim]\n")

    # Summary Statistics
    cats = Counter(e.get("category", "Other") for e in entries)
    users = Counter(e.get("user", "Default") for e in entries)

    summary = Text()
    summary.append(" Forensic User Activity Insights:\n", style="bold green")
    summary.append(f"  • Total Artifacts Found : {len(entries)}\n", style="white")
    summary.append(f"  • User Accounts         : {', '.join([f'{u} ({c})' for u, c in users.items()])}\n", style="cyan")
    summary.append(f"  • Category Breakdown    : {', '.join([f'{k}: {v}' for k, v in cats.items()])}\n", style="yellow")

    console.print(Panel(summary, border_style="green", title="User Artifact Insights", title_align="left"))


def export_ntuser_csv(entries: List[Dict[str, Any]], output_path: str):
    fieldnames = ["user", "category", "artifact", "run_count", "focus_count", "focus_time_seconds", "timestamp", "source_hive"]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for e in entries:
            writer.writerow(e)
    console.print(f"[bold green][/bold green] Exported {len(entries)} NTUSER records to CSV: [cyan]{output_path}[/cyan]")


def export_ntuser_json(entries: List[Dict[str, Any]], output_path: str):
    clean = []
    for e in entries:
        d = dict(e)
        if "timestamp_obj" in d:
            if d["timestamp_obj"]:
                d["timestamp_iso"] = d["timestamp_obj"].isoformat()
            del d["timestamp_obj"]
        clean.append(d)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(clean, f, indent=2, ensure_ascii=False)
    console.print(f"[bold green][/bold green] Exported {len(entries)} NTUSER records to JSON: [cyan]{output_path}[/cyan]")


def export_ntuser_markdown(entries: List[Dict[str, Any]], output_path: str, source_name: str = "Evidence Image"):
    generated_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    cats = Counter(e.get("category", "Other") for e in entries)
    users = Counter(e.get("user", "Default") for e in entries)

    lines = [
        f"# DFIR Forensic Report - User Activity (NTUSER.DAT)",
        f"- **Evidence Source:** `{source_name}`",
        f"- **Generated:** `{generated_time}`",
        f"- **Total Artifacts:** `{len(entries)}`",
        "",
        "## Summary Insights",
        f"- **User Accounts:** {', '.join([f'{u} ({c})' for u, c in users.items()])}",
        f"- **Categories:** {', '.join([f'{k}: {v}' for k, v in cats.items()])}",
        "",
        "## User Behavioral Activity Records",
        "| # | User | Category | Executed Artifact / Command / Path | Runs | Last Activity (UTC) |",
        "|---|---|---|---|:---:|---|"
    ]

    for idx, item in enumerate(entries, start=1):
        user = item.get("user", "Default")
        category = item.get("category", "General")
        artifact = (item.get("artifact") or "").replace("|", "\\|")
        run_count = item.get("run_count", 1)
        ts = item.get("timestamp", "N/A")

        lines.append(f"| {idx} | **{user}** | `{category}` | `{artifact}` | {run_count} | {ts} |")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    console.print(f"[bold green][/bold green] Exported {len(entries)} NTUSER records to Markdown (MD): [cyan]{output_path}[/cyan]")


def export_ntuser_html(entries: List[Dict[str, Any]], output_path: str, source_name: str = "Evidence Image"):
    clean = []
    for e in entries:
        d = dict(e)
        if "timestamp_obj" in d:
            if d["timestamp_obj"]:
                d["timestamp_iso"] = d["timestamp_obj"].isoformat()
            del d["timestamp_obj"]
        clean.append(d)

    json_payload = json.dumps(clean, ensure_ascii=False)
    generated_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>DFIR Forensic Report - User Activity Registry ({source_name})</title>
    <style>
        :root {{ --bg: #0f172a; --surface: #1e293b; --surface-hover: #334155; --border: #334155; --text: #f8fafc; --text-muted: #94a3b8; --accent: #38bdf8; }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
        body {{ background: var(--bg); color: var(--text); padding: 24px; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 20px; }}
        .title {{ font-size: 24px; font-weight: 700; }}
        .title span {{ color: var(--accent); }}
        .badge {{ background: #1e3a8a; color: #93c5fd; padding: 4px 10px; border-radius: 999px; font-size: 12px; font-weight: 600; }}
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
        .cat-tag {{ display: inline-block; padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: 600; background: #374151; color: #f3f4f6; }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <div class="title">DFIR <span>User Activity (NTUSER.DAT)</span> Report</div>
            <div style="font-size: 13px; color: var(--text-muted); margin-top: 4px;">Evidence: <strong>{source_name}</strong> | Generated: {generated_time}</div>
        </div>
        <div class="badge">NTUSER Registry Artifacts</div>
    </div>
    <div class="stats-grid">
        <div class="card"><div class="label">Total Artifacts</div><div class="val">{len(entries)}</div></div>
        <div class="card"><div class="label">Users Detected</div><div class="val">{len(set(e.get('user') for e in entries))}</div></div>
    </div>
    <div class="controls">
        <input type="text" id="searchInput" class="search-box" placeholder=" Search User, Program, Typed Path, RunMRU Command...">
    </div>
    <table>
        <thead>
            <tr>
                <th style="width: 50px;">#</th>
                <th style="width: 120px;">User</th>
                <th style="width: 180px;">Category</th>
                <th>Executed Artifact / Command / Path</th>
                <th style="width: 70px; text-align: center;">Runs</th>
                <th style="width: 180px;">Timestamp (UTC)</th>
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
                tr.innerHTML = `
                    <td style="color: #64748b;">${{idx + 1}}</td>
                    <td style="color: #38bdf8; font-weight: 600;">${{item.user || 'Default'}}</td>
                    <td><span class="cat-tag">${{item.category || 'General'}}</span></td>
                    <td style="color: #f8fafc; font-family: monospace;">${{item.artifact || ''}}</td>
                    <td style="text-align: center; color: #4ade80; font-weight: 700;">${{item.run_count || 1}}</td>
                    <td style="color: #fbbf24; font-family: monospace;">${{item.timestamp || 'N/A'}}</td>
                `;
                tb.appendChild(tr);
            }});
        }}
        document.getElementById('searchInput').addEventListener('input', (e) => {{
            const q = e.target.value.toLowerCase().trim();
            filtered = raw.filter(i => (i.user||'').toLowerCase().includes(q) || (i.category||'').toLowerCase().includes(q) || (i.artifact||'').toLowerCase().includes(q));
            render();
        }});
        render();
    </script>
</body>
</html>"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    console.print(f"[bold green][/bold green] Generated interactive HTML NTUSER report: [cyan]{output_path}[/cyan]")


def main(args_list=None):
    parser = argparse.ArgumentParser(
        prog="ad1 ntuser",
        description=" Extract and analyze NTUSER.DAT user registry artifacts from AccessData AD1 logical images.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  tools ad1 ntuser evidence.ad1
  tools ad1 ntuser evidence.ad1 --query "powershell"
  tools ad1 ntuser evidence.ad1 --export-all
        """
    )
    parser.add_argument("input", help="Path to input AD1 image file")
    parser.add_argument("-q", "--query", help="Filter by user, program, command, or path")
    parser.add_argument("-l", "--limit", type=int, default=100, help="Row display limit in terminal (default: 100)")
    parser.add_argument("--csv", help="Export to CSV file")
    parser.add_argument("--json", help="Export to JSON file")
    parser.add_argument("--md", "--markdown", dest="md", help="Export to Markdown (.md) report")
    parser.add_argument("--html", help="Export to interactive HTML report")
    parser.add_argument("--export-all", action="store_true", help="Generate MD, JSON, CSV, and HTML reports automatically")

    args = parser.parse_args(args_list)

    if not os.path.exists(args.input):
        console.print(f"[bold red]Error:[/bold red] File not found: {args.input}")
        sys.exit(1)

    print_ad1_banner("AD1 NTUSER USER ACTIVITY ANALYZER (ad1NTUSER)")
    console.print(f"[dim]Opening image container:[/dim] [cyan]{args.input}[/cyan]\n")

    with console.status("[bold cyan]Scanning & parsing NTUSER.DAT hives...[/bold cyan]"):
        parser_ad1 = AD1Parser(args.input)
        analyzer = AD1NTUserAnalyzer(parser_ad1)
        entries = analyzer.scan_and_extract()

    if not entries:
        console.print("[bold yellow] No NTUSER.DAT registry hives found in the AD1 container.[/bold yellow]")
        parser_ad1.close()
        return

    if args.query:
        q_low = args.query.lower()
        entries = [
            e for e in entries
            if q_low in (e.get("user") or "").lower()
            or q_low in (e.get("category") or "").lower()
            or q_low in (e.get("artifact") or "").lower()
        ]

    limit = args.limit if args.limit else 100
    print_ntuser_table(entries, max_rows=limit)

    base_name = os.path.splitext(os.path.basename(args.input))[0]
    if args.export_all:
        if not args.md: args.md = f"{base_name}_ntuser.md"
        if not args.json: args.json = f"{base_name}_ntuser.json"
        if not args.csv: args.csv = f"{base_name}_ntuser.csv"
        if not args.html: args.html = f"{base_name}_ntuser.html"

    if hasattr(args, 'md') and args.md: export_ntuser_markdown(entries, args.md, source_name=base_name)
    if hasattr(args, 'json') and args.json: export_ntuser_json(entries, args.json)
    if hasattr(args, 'csv') and args.csv: export_ntuser_csv(entries, args.csv)
    if hasattr(args, 'html') and args.html: export_ntuser_html(entries, args.html, source_name=base_name)

    parser_ad1.close()


if __name__ == "__main__":
    main()
