#!/usr/bin/env python3
"""
AD1 Recent Activity Forensics Analyzer
Extracts and parses Windows Shell Link (.lnk) files, JumpLists (Automatic/Custom Destinations), and Recent Docs.
Can be executed directly: python ad1/recent.py <evidence.ad1>
"""
import sys
import os
import re
import struct
import argparse
import csv
import json
import io
from collections import Counter
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from core.banner import print_ad1_banner
from core.utils import filetime_to_datetime, format_datetime, human_size
from ad1.parser import AD1Parser
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

console = Console(force_terminal=True, legacy_windows=False)


# Known JumpList AppIDs mapping
KNOWN_APP_IDS = {
    "9b9cdc69c1c24e2b": "Notepad",
    "12d347c5404d19bc": "Windows Media Player",
    "1bc392b8e104a00e": "Remote Desktop Connection",
    "7e4dca80246863e3": "File Explorer",
    "a7b933e25fb6fc9e": "Paint",
    "28c8b86deab549a1": "Internet Explorer",
    "5d696d521de238c3": "Google Chrome",
    "ede4e050146059c3": "Microsoft Edge",
    "d00655d2aa12ff6d": "Mozilla Firefox",
    "fb3b0dbfee4c1f86": "VLC Media Player",
    "918e0ecb43d17e23": "Microsoft Word",
    "ec503e4f776b3528": "Microsoft Excel",
    "74465d77174620f4": "Microsoft PowerPoint"
}


class LNKParser:
    """
    Pure Python Windows Shell Link (.lnk) binary structure parser.
    """
    @staticmethod
    def parse_lnk(data: bytes) -> Dict[str, Any]:
        if len(data) < 0x4c:
            return {}

        header_size = struct.unpack("<I", data[0:4])[0]
        if header_size != 0x4C:
            return {}

        flags = struct.unpack("<I", data[0x14:0x18])[0]
        file_attrs = struct.unpack("<I", data[0x18:0x1C])[0]

        # Timestamps (FILETIME)
        cr_raw = struct.unpack("<Q", data[0x1C:0x24])[0]
        ac_raw = struct.unpack("<Q", data[0x24:0x2C])[0]
        wr_raw = struct.unpack("<Q", data[0x2C:0x34])[0]
        file_size = struct.unpack("<I", data[0x34:0x38])[0]

        target_created = filetime_to_datetime(cr_raw)
        target_accessed = filetime_to_datetime(ac_raw)
        target_modified = filetime_to_datetime(wr_raw)

        has_target_id = bool(flags & 0x01)
        has_link_info = bool(flags & 0x02)
        has_name = bool(flags & 0x04)
        has_rel_path = bool(flags & 0x08)
        has_work_dir = bool(flags & 0x10)
        has_arguments = bool(flags & 0x20)
        is_unicode = bool(flags & 0x80)

        offset = 0x4C

        # 1. Target IDList
        if has_target_id and offset + 2 <= len(data):
            id_list_size = struct.unpack("<H", data[offset:offset + 2])[0]
            offset += 2 + id_list_size

        local_path = ""
        net_path = ""

        # 2. LinkInfo
        if has_link_info and offset + 4 <= len(data):
            link_info_size = struct.unpack("<I", data[offset:offset + 4])[0]
            link_info_end = offset + link_info_size
            
            if offset + 0x1C <= len(data) and link_info_size >= 0x1C:
                header_size = struct.unpack("<I", data[offset + 4:offset + 8])[0]
                link_flags = struct.unpack("<I", data[offset + 8:offset + 12])[0]
                local_base_offset = struct.unpack("<I", data[offset + 16:offset + 20])[0]
                net_offset = struct.unpack("<I", data[offset + 20:offset + 24])[0]

                # Local base path
                if local_base_offset > 0 and offset + local_base_offset < len(data):
                    path_bytes = data[offset + local_base_offset:link_info_end]
                    local_path = path_bytes.split(b"\x00")[0].decode("latin-1", errors="replace")

                # Network share path
                if net_offset > 0 and offset + net_offset < len(data):
                    net_bytes = data[offset + net_offset:link_info_end]
                    net_path = net_bytes.split(b"\x00")[0].decode("latin-1", errors="replace")

            offset = link_info_end

        # Helper to read string data
        def read_str_data(curr_off: int) -> Tuple[str, int]:
            if curr_off + 2 > len(data):
                return "", curr_off
            char_count = struct.unpack("<H", data[curr_off:curr_off + 2])[0]
            curr_off += 2
            if is_unicode:
                byte_len = char_count * 2
                if curr_off + byte_len > len(data):
                    return "", curr_off
                val = data[curr_off:curr_off + byte_len].decode("utf-16-le", errors="replace")
            else:
                byte_len = char_count
                if curr_off + byte_len > len(data):
                    return "", curr_off
                val = data[curr_off:curr_off + byte_len].decode("latin-1", errors="replace")
            return val, curr_off + byte_len

        name_str = ""
        rel_path_str = ""
        work_dir_str = ""
        args_str = ""

        if has_name:
            name_str, offset = read_str_data(offset)
        if has_rel_path:
            rel_path_str, offset = read_str_data(offset)
        if has_work_dir:
            work_dir_str, offset = read_str_data(offset)
        if has_arguments:
            args_str, offset = read_str_data(offset)

        target = local_path or net_path or rel_path_str or name_str

        return {
            "target_path": target,
            "local_path": local_path,
            "network_path": net_path,
            "relative_path": rel_path_str,
            "working_directory": work_dir_str,
            "arguments": args_str,
            "file_size": file_size,
            "target_created": target_created,
            "target_accessed": target_accessed,
            "target_modified": target_modified
        }


class AD1RecentAnalyzer:
    """
    Scans AD1 containers for Recent Items, LNK files, and JumpLists.
    """
    def __init__(self, parser: AD1Parser):
        self.parser = parser
        self.extracted_entries: List[Dict[str, Any]] = []

    def scan_and_extract(self) -> List[Dict[str, Any]]:
        if not self.parser.items:
            self.parser.build_tree()

        all_entries = []

        for item in self.parser.items:
            if item.is_dir or item.decompressed_size < 32:
                continue

            name_lower = item.item_name.lower()
            path_lower = item.full_path.lower()

            # 1. Shell Link files (.lnk)
            if name_lower.endswith(".lnk") or "/recent/" in path_lower or "\\recent\\" in path_lower:
                file_bytes = self.parser.read_file_bytes(item)
                if not file_bytes or len(file_bytes) < 0x4C or file_bytes[:4] != b"\x4c\x00\x00\x00":
                    continue

                user_name = self._extract_user(item.full_path)
                parsed_lnk = LNKParser.parse_lnk(file_bytes)
                if not parsed_lnk or not parsed_lnk.get("target_path"):
                    continue

                target = parsed_lnk.get("target_path", "")
                args = parsed_lnk.get("arguments", "")
                if args:
                    target = f"{target} {args}"

                mod_time = parsed_lnk.get("target_modified")
                acc_time = parsed_lnk.get("target_accessed")
                best_dt = mod_time or acc_time
                time_str = format_datetime(best_dt) if best_dt else "N/A"

                all_entries.append({
                    "user": user_name,
                    "type": "LNK Shortcut",
                    "name": item.item_name,
                    "target_path": target,
                    "file_size": parsed_lnk.get("file_size", 0),
                    "file_size_str": human_size(parsed_lnk.get("file_size", 0)),
                    "timestamp": time_str,
                    "timestamp_obj": best_dt,
                    "source_path": item.full_path
                })

            # 2. JumpLists (.automaticDestinations-ms / .customDestinations-ms)
            elif name_lower.endswith(".automaticdestinations-ms") or name_lower.endswith(".customdestinations-ms"):
                file_bytes = self.parser.read_file_bytes(item)
                if file_bytes:
                    user_name = self._extract_user(item.full_path)
                    entries = self._parse_jumplist(file_bytes, item.item_name, user_name, item.full_path)
                    all_entries.extend(entries)

        # Sort newest first
        def sort_key(rec):
            dt = rec.get("timestamp_obj")
            return dt.timestamp() if dt else 0

        all_entries.sort(key=sort_key, reverse=True)
        self.extracted_entries = all_entries
        return all_entries

    def _extract_user(self, full_path: str) -> str:
        clean = full_path.replace("\\", "/")
        m = re.search(r"(?:^|/|[a-zA-Z]:/)(?:Users|Documents and Settings|home)/([^/]+)/", clean, re.IGNORECASE)
        return m.group(1) if m else "DefaultUser"

    def _parse_jumplist(self, file_bytes: bytes, file_name: str, user_name: str, source_path: str) -> List[Dict[str, Any]]:
        entries = []
        app_id = file_name.split(".")[0].lower()
        app_name = KNOWN_APP_IDS.get(app_id, f"AppID [{app_id}]")

        try:
            import olefile
            if olefile.isOleFile(io.BytesIO(file_bytes)):
                ole = olefile.OleFileIO(io.BytesIO(file_bytes))
                if ole.exists("DestList"):
                    stream_data = ole.openstream("DestList").read()
                    # DestList header is 32 bytes (Win7/8) or 32/40 bytes (Win10/11)
                    # Entries follow with 114/128 bytes records
                    if len(stream_data) >= 32:
                        offset = 32
                        while offset + 114 <= len(stream_data):
                            # Last access FILETIME at offset + 8
                            ft_raw = struct.unpack("<Q", stream_data[offset + 8:offset + 16])[0]
                            access_dt = filetime_to_datetime(ft_raw)
                            time_str = format_datetime(access_dt) if access_dt else "N/A"

                            # Unicode path length at offset + 24
                            path_char_len = struct.unpack("<H", stream_data[offset + 24:offset + 26])[0]
                            path_bytes_len = path_char_len * 2
                            
                            # Path is stored after the 114-byte struct
                            path_start = offset + 114
                            path_str = ""
                            if path_start + path_bytes_len <= len(stream_data):
                                raw_p = stream_data[path_start:path_start + path_bytes_len]
                                path_str = raw_p.decode("utf-16-le", errors="replace").rstrip("\x00")

                            if path_str:
                                entries.append({
                                    "user": user_name,
                                    "type": f"JumpList ({app_name})",
                                    "name": os.path.basename(path_str) or file_name,
                                    "target_path": path_str,
                                    "file_size": 0,
                                    "file_size_str": "N/A",
                                    "timestamp": time_str,
                                    "timestamp_obj": access_dt,
                                    "source_path": source_path
                                })

                            offset = path_start + path_bytes_len + 4
                ole.close()
        except Exception:
            pass

        return entries


def print_recent_table(entries: List[Dict[str, Any]], max_rows: int = 100):
    if not entries:
        console.print("[yellow] No Recent files, LNK shortcuts, or JumpLists found in the AD1 image.[/yellow]")
        return

    table = Table(
        title=f" Recent Items & LNK Activity Records ({len(entries)} Total Files)",
        show_header=True,
        header_style="bold magenta",
        border_style="dim blue",
        expand=True
    )

    table.add_column("#", style="dim", width=5, justify="right")
    table.add_column("User", style="bold cyan", width=12)
    table.add_column("Artifact Type", style="magenta", width=22)
    table.add_column("Accessed Target Path / Document", style="white", min_width=38, overflow="fold")
    table.add_column("Size", style="green", width=10, justify="right")
    table.add_column("Last Access (UTC)", style="bold yellow", width=22)

    display = entries[:max_rows]
    for idx, item in enumerate(display, start=1):
        user = item.get("user", "Default")
        a_type = item.get("type", "LNK")
        target = item.get("target_path", "")
        size_str = item.get("file_size_str", "N/A")
        ts = item.get("timestamp", "N/A")

        table.add_row(
            str(idx),
            user,
            a_type,
            target,
            size_str,
            ts
        )

    console.print(table)

    if len(entries) > max_rows:
        console.print(f"[italic dim]... showing top {max_rows} of {len(entries)} records. Use --export-csv, --export-json, or --export-html to view all records.[/italic dim]\n")

    types_count = Counter(e.get("type", "Other") for e in entries)
    users = Counter(e.get("user", "Default") for e in entries)

    summary = Text()
    summary.append(" Recent Activity Insights:\n", style="bold green")
    summary.append(f"  • Total Recent Items Found : {len(entries)}\n", style="white")
    summary.append(f"  • User Accounts            : {', '.join([f'{u} ({c})' for u, c in users.items()])}\n", style="cyan")
    summary.append(f"  • Artifact Types           : {', '.join([f'{k}: {v}' for k, v in types_count.items()])}\n", style="yellow")

    console.print(Panel(summary, border_style="green", title="Recent Activity Insights", title_align="left"))


def export_recent_csv(entries: List[Dict[str, Any]], output_path: str):
    fieldnames = ["user", "type", "name", "target_path", "file_size", "file_size_str", "timestamp", "source_path"]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for e in entries:
            writer.writerow(e)
    console.print(f"[bold green][/bold green] Exported {len(entries)} Recent records to CSV: [cyan]{output_path}[/cyan]")


def export_recent_json(entries: List[Dict[str, Any]], output_path: str):
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
    console.print(f"[bold green][/bold green] Exported {len(entries)} Recent records to JSON: [cyan]{output_path}[/cyan]")


def export_recent_markdown(entries: List[Dict[str, Any]], output_path: str, source_name: str = "Evidence Image"):
    generated_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    types_count = Counter(e.get("type", "Other") for e in entries)
    users = Counter(e.get("user", "Default") for e in entries)

    lines = [
        f"# DFIR Forensic Report - Recent Files & LNK Activity",
        f"- **Evidence Source:** `{source_name}`",
        f"- **Generated:** `{generated_time}`",
        f"- **Total Items:** `{len(entries)}`",
        "",
        "## Summary Insights",
        f"- **User Accounts:** {', '.join([f'{u} ({c})' for u, c in users.items()])}",
        f"- **Artifact Types:** {', '.join([f'{k}: {v}' for k, v in types_count.items()])}",
        "",
        "## Recent Files & Shortcut Records",
        "| # | User | Type | Target Path / Document | Size | Last Access (UTC) |",
        "|---|---|---|---|:---:|---|"
    ]

    for idx, item in enumerate(entries, start=1):
        user = item.get("user", "Default")
        a_type = item.get("type", "LNK")
        target = (item.get("target_path") or "").replace("|", "\\|")
        size_str = item.get("file_size_str", "N/A")
        ts = item.get("timestamp", "N/A")

        lines.append(f"| {idx} | **{user}** | `{a_type}` | `{target}` | {size_str} | {ts} |")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    console.print(f"[bold green][/bold green] Exported {len(entries)} Recent records to Markdown (MD): [cyan]{output_path}[/cyan]")


def export_recent_html(entries: List[Dict[str, Any]], output_path: str, source_name: str = "Evidence Image"):
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
    <title>DFIR Forensic Report - Recent Files & LNK Activity ({source_name})</title>
    <style>
        :root {{ --bg: #0f172a; --surface: #1e293b; --surface-hover: #334155; --border: #334155; --text: #f8fafc; --text-muted: #94a3b8; --accent: #38bdf8; }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
        body {{ background: var(--bg); color: var(--text); padding: 24px; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 20px; }}
        .title {{ font-size: 24px; font-weight: 700; }}
        .title span {{ color: var(--accent); }}
        .badge {{ background: #065f46; color: #6ee7b7; padding: 4px 10px; border-radius: 999px; font-size: 12px; font-weight: 600; }}
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
        .type-tag {{ display: inline-block; padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: 600; background: #064e3b; color: #a7f3d0; }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <div class="title">DFIR <span>Recent Files & LNK Activity</span> Report</div>
            <div style="font-size: 13px; color: var(--text-muted); margin-top: 4px;">Evidence: <strong>{source_name}</strong> | Generated: {generated_time}</div>
        </div>
        <div class="badge">LNK / JumpLists Artifacts</div>
    </div>
    <div class="stats-grid">
        <div class="card"><div class="label">Total Recent Files</div><div class="val">{len(entries)}</div></div>
        <div class="card"><div class="label">Users Detected</div><div class="val">{len(set(e.get('user') for e in entries))}</div></div>
    </div>
    <div class="controls">
        <input type="text" id="searchInput" class="search-box" placeholder=" Search User, Target Path, Document Name...">
    </div>
    <table>
        <thead>
            <tr>
                <th style="width: 50px;">#</th>
                <th style="width: 120px;">User</th>
                <th style="width: 180px;">Type</th>
                <th>Target Path / Document</th>
                <th style="width: 100px;">Size</th>
                <th style="width: 180px;">Last Access (UTC)</th>
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
                    <td><span class="type-tag">${{item.type || 'LNK'}}</span></td>
                    <td style="color: #f8fafc; font-family: monospace;">${{item.target_path || ''}}</td>
                    <td style="color: #34d399;">${{item.file_size_str || 'N/A'}}</td>
                    <td style="color: #fbbf24; font-family: monospace;">${{item.timestamp || 'N/A'}}</td>
                `;
                tb.appendChild(tr);
            }});
        }}
        document.getElementById('searchInput').addEventListener('input', (e) => {{
            const q = e.target.value.toLowerCase().trim();
            filtered = raw.filter(i => (i.user||'').toLowerCase().includes(q) || (i.type||'').toLowerCase().includes(q) || (i.target_path||'').toLowerCase().includes(q));
            render();
        }});
        render();
    </script>
</body>
</html>"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    console.print(f"[bold green][/bold green] Generated interactive HTML Recent Activity report: [cyan]{output_path}[/cyan]")


def main(args_list=None):
    parser = argparse.ArgumentParser(
        prog="ad1 recent",
        description=" Extract and analyze Recent items, LNK files, and JumpLists from AccessData AD1 logical images.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  tools ad1 recent evidence.ad1
  tools ad1 recent evidence.ad1 --query "pdf"
  tools ad1 recent evidence.ad1 --export-all
        """
    )
    parser.add_argument("input", help="Path to input AD1 image file")
    parser.add_argument("-q", "--query", help="Filter by target path, file name, or user")
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

    print_ad1_banner("AD1 RECENT ACTIVITY ANALYZER (ad1recent)")
    console.print(f"[dim]Opening image container:[/dim] [cyan]{args.input}[/cyan]\n")

    with console.status("[bold cyan]Scanning & parsing Recent items, LNKs, and JumpLists...[/bold cyan]"):
        parser_ad1 = AD1Parser(args.input)
        analyzer = AD1RecentAnalyzer(parser_ad1)
        entries = analyzer.scan_and_extract()

    if not entries:
        console.print("[bold yellow] No Recent items, LNK files, or JumpLists found in the AD1 container.[/bold yellow]")
        parser_ad1.close()
        return

    if args.query:
        q_low = args.query.lower()
        entries = [
            e for e in entries
            if q_low in (e.get("user") or "").lower()
            or q_low in (e.get("type") or "").lower()
            or q_low in (e.get("target_path") or "").lower()
            or q_low in (e.get("name") or "").lower()
        ]

    limit = args.limit if args.limit else 100
    print_recent_table(entries, max_rows=limit)

    base_name = os.path.splitext(os.path.basename(args.input))[0]
    if args.export_all:
        if not args.md: args.md = f"{base_name}_recent.md"
        if not args.json: args.json = f"{base_name}_recent.json"
        if not args.csv: args.csv = f"{base_name}_recent.csv"
        if not args.html: args.html = f"{base_name}_recent.html"

    if hasattr(args, 'md') and args.md: export_recent_markdown(entries, args.md, source_name=base_name)
    if hasattr(args, 'json') and args.json: export_recent_json(entries, args.json)
    if hasattr(args, 'csv') and args.csv: export_recent_csv(entries, args.csv)
    if hasattr(args, 'html') and args.html: export_recent_html(entries, args.html, source_name=base_name)

    parser_ad1.close()


if __name__ == "__main__":
    main()
