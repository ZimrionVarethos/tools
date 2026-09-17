#!/usr/bin/env python3
"""
AD1 Amcache (Amcache.hve) Execution Artifacts Forensics Analyzer
Can be executed directly: python ad1/amcache.py <evidence.ad1>
"""
import sys
import os
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
from core.utils import human_size, format_datetime
from core.registry import RegistryHive
from ad1.parser import AD1Parser
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

console = Console(force_terminal=True, legacy_windows=False)


class AD1AmcacheAnalyzer:
    """
    Locates and parses Windows Amcache.hve within an AD1 logical forensic container.
    Extracts program execution artifacts, SHA1 hashes, execution times, and installed applications.
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

            if name_lower == "amcache.hve" or "appcompat/programs/amcache.hve" in path_lower or "appcompat\\programs\\amcache.hve" in path_lower:
                hive_bytes = self.parser.read_file_bytes(item)
                if not hive_bytes:
                    continue

                entries = self.parse_amcache_bytes(hive_bytes, item.full_path)
                all_entries.extend(entries)

        self.extracted_entries = all_entries
        return all_entries

    def parse_amcache_bytes(self, hive_bytes: bytes, source_path: str) -> List[Dict[str, Any]]:
        entries = []
        hive = RegistryHive(hive_bytes)
        if not hive.root:
            return entries

        # 1. Windows 10/11 InventoryApplicationFile
        inv_files_key = hive.open_key("Root\\InventoryApplicationFile")
        if inv_files_key:
            for file_id, file_key in inv_files_key.subkeys.items():
                file_path = file_key.get_value("LowerCaseLongPath") or file_key.get_value("LongPath") or file_key.get_value("Name") or ""
                sha1 = file_key.get_value("FileId") or file_key.get_value("SHA1") or file_id or ""
                # Clean 0000 prefix in Amcache SHA1
                if isinstance(sha1, str) and sha1.startswith("0000") and len(sha1) == 44:
                    sha1 = sha1[4:]

                size = file_key.get_value("Size") or file_key.get_value("FileSize") or 0
                link_date = file_key.get_value("LinkDate") or ""
                publisher = file_key.get_value("Publisher") or file_key.get_value("Company") or ""
                version = file_key.get_value("BinProductVersion") or file_key.get_value("Version") or ""
                is_os = bool(file_key.get_value("IsOsComponent", 0))

                exec_time = file_key.timestamp
                time_str = format_datetime(exec_time) if exec_time else (str(link_date) if link_date else "N/A")

                name = file_key.get_value("Name") or os.path.basename(file_path) if file_path else file_id

                entries.append({
                    "name": name,
                    "path": file_path,
                    "sha1": sha1,
                    "size": size,
                    "size_str": human_size(size) if isinstance(size, int) else str(size),
                    "publisher": publisher,
                    "version": version,
                    "compilation_time": str(link_date),
                    "timestamp": time_str,
                    "timestamp_obj": exec_time,
                    "is_os_component": is_os,
                    "source_hive": source_path,
                    "amcache_type": "Win10/11 InventoryApplicationFile"
                })

        # 2. Windows 7/8/8.1 Root\File
        root_file_key = hive.open_key("Root\\File")
        if root_file_key:
            for vol_or_file, sub_key in root_file_key.subkeys.items():
                # Some versions nest under Volume GUIDs, others directly under File
                target_keys = sub_key.subkeys.values() if sub_key.subkeys else [sub_key]
                for fk in target_keys:
                    file_path = fk.get_value("15") or ""
                    sha1 = fk.get_value("101") or ""
                    if isinstance(sha1, str) and sha1.startswith("0000") and len(sha1) == 44:
                        sha1 = sha1[4:]

                    size = fk.get_value("100") or 0
                    publisher = fk.get_value("1") or ""
                    description = fk.get_value("2") or ""
                    version = fk.get_value("3") or ""
                    name = fk.get_value("0") or os.path.basename(file_path) if file_path else fk.name

                    exec_time = fk.timestamp
                    time_str = format_datetime(exec_time) if exec_time else "N/A"

                    if file_path or sha1:
                        entries.append({
                            "name": name,
                            "path": file_path,
                            "sha1": sha1,
                            "size": size,
                            "size_str": human_size(size) if isinstance(size, int) else str(size),
                            "publisher": publisher,
                            "version": version,
                            "compilation_time": description,
                            "timestamp": time_str,
                            "timestamp_obj": exec_time,
                            "is_os_component": False,
                            "source_hive": source_path,
                            "amcache_type": "Win7/8 File"
                        })

        # 3. Windows 10/11 InventoryApplication (Installed Programs)
        inv_app_key = hive.open_key("Root\\InventoryApplication")
        if inv_app_key and not entries:
            for app_id, app_key in inv_app_key.subkeys.items():
                name = app_key.get_value("Name") or app_id
                root_path = app_key.get_value("RootDirPath") or ""
                version = app_key.get_value("Version") or ""
                publisher = app_key.get_value("Publisher") or ""
                uninstall_str = app_key.get_value("UninstallString") or ""
                exec_time = app_key.timestamp
                time_str = format_datetime(exec_time) if exec_time else "N/A"

                entries.append({
                    "name": name,
                    "path": root_path or uninstall_str,
                    "sha1": app_id,
                    "size": 0,
                    "size_str": "N/A",
                    "publisher": publisher,
                    "version": version,
                    "compilation_time": "N/A",
                    "timestamp": time_str,
                    "timestamp_obj": exec_time,
                    "is_os_component": False,
                    "source_hive": source_path,
                    "amcache_type": "Win10/11 InventoryApplication"
                })

        return entries


def print_amcache_table(entries: List[Dict[str, Any]], max_rows: int = 100):
    if not entries:
        console.print("[yellow] No Amcache execution entries found in the AD1 image.[/yellow]")
        return

    table = Table(
        title=f" Amcache.hve Program Execution Records ({len(entries)} Total Files)",
        show_header=True,
        header_style="bold magenta",
        border_style="dim blue",
        expand=True
    )

    table.add_column("#", style="dim", width=5, justify="right")
    table.add_column("Program Name", style="bold cyan", width=20)
    table.add_column("Executable Path", style="white", min_width=35, overflow="fold")
    table.add_column("SHA1 Hash", style="yellow", width=42)
    table.add_column("File Size", style="green", width=10, justify="right")
    table.add_column("Publisher / Vendor", style="magenta", width=20)
    table.add_column("Key Modified (UTC)", style="bold yellow", width=22)

    display = entries[:max_rows]
    for idx, item in enumerate(display, start=1):
        name = item.get("name") or "Unknown"
        path = item.get("path") or "[dim]N/A[/dim]"
        sha1 = item.get("sha1") or "[dim]N/A[/dim]"
        size_str = item.get("size_str", "0 B")
        publisher = item.get("publisher") or "[dim]Unknown[/dim]"
        ts = item.get("timestamp", "N/A")

        table.add_row(
            str(idx),
            name,
            path,
            sha1,
            size_str,
            publisher,
            ts
        )

    console.print(table)

    if len(entries) > max_rows:
        console.print(f"[italic dim]... showing top {max_rows} of {len(entries)} records. Use --export-csv, --export-json, or --export-html to view all records.[/italic dim]\n")

    # Insights
    publishers = Counter(e.get("publisher", "Unknown") for e in entries if e.get("publisher"))
    paths = [e.get("path", "") for e in entries if e.get("path")]
    temp_execs = [p for p in paths if any(k in p.lower() for k in ["temp", "appdata", "downloads", "tmp"])]

    summary = Text()
    summary.append(" Forensic Amcache Insights:\n", style="bold green")
    summary.append(f"  • Total Executables Found : {len(entries)}\n", style="white")
    summary.append(f"  • Unique SHA1 Hashes      : {len(set(e.get('sha1') for e in entries if e.get('sha1')))}\n", style="cyan")
    if temp_execs:
        summary.append(f"  • Suspicious Exec Locations: {len(temp_execs)} binaries ran from Temp/AppData/Downloads!\n", style="bold red")
    if publishers:
        top_pubs = ", ".join([f"{p} ({c})" for p, c in publishers.most_common(4)])
        summary.append(f"  • Top Publishers          : {top_pubs}\n", style="yellow")

    console.print(Panel(summary, border_style="green", title="Amcache Execution Insights", title_align="left"))


def export_amcache_csv(entries: List[Dict[str, Any]], output_path: str):
    fieldnames = ["name", "path", "sha1", "size", "size_str", "publisher", "version", "compilation_time", "timestamp", "amcache_type", "source_hive"]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for e in entries:
            writer.writerow(e)
    console.print(f"[bold green][/bold green] Exported {len(entries)} Amcache records to CSV: [cyan]{output_path}[/cyan]")


def export_amcache_json(entries: List[Dict[str, Any]], output_path: str):
    clean_entries = []
    for e in entries:
        d = dict(e)
        if "timestamp_obj" in d:
            if d["timestamp_obj"]:
                d["timestamp_iso"] = d["timestamp_obj"].isoformat()
            del d["timestamp_obj"]
        clean_entries.append(d)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(clean_entries, f, indent=2, ensure_ascii=False)
    console.print(f"[bold green][/bold green] Exported {len(entries)} Amcache records to JSON: [cyan]{output_path}[/cyan]")


def export_amcache_markdown(entries: List[Dict[str, Any]], output_path: str, source_name: str = "Evidence Image"):
    generated_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    publishers = Counter(e.get("publisher", "Unknown") for e in entries if e.get("publisher"))
    paths = [e.get("path", "") for e in entries if e.get("path")]
    temp_execs = [p for p in paths if any(k in p.lower() for k in ["temp", "appdata", "downloads", "tmp"])]

    lines = [
        f"# DFIR Forensic Report - Amcache.hve Program Executions",
        f"- **Evidence Source:** `{source_name}`",
        f"- **Generated:** `{generated_time}`",
        f"- **Total Binaries:** `{len(entries)}`",
        "",
        "## Summary Insights",
        f"- **Unique SHA1 Hashes:** {len(set(e.get('sha1') for e in entries if e.get('sha1')))}",
        f"- **Suspicious Execution Locations (Temp/AppData/Downloads):** {len(temp_execs)}",
        f"- **Top Publishers:** {', '.join([f'{p} ({c})' for p, c in publishers.most_common(4)])}",
        "",
        "## Executable Binaries",
        "| # | Program Name | Executable Path | SHA1 Hash | Size | Publisher | Key Modified (UTC) |",
        "|---|---|---|---|:---:|---|---|"
    ]

    for idx, item in enumerate(entries, start=1):
        name = (item.get("name") or "Unknown").replace("|", "\\|")
        path = (item.get("path") or "N/A").replace("|", "\\|")
        sha1 = item.get("sha1") or "N/A"
        size_str = item.get("size_str", "0 B")
        publisher = (item.get("publisher") or "Unknown").replace("|", "\\|")
        ts = item.get("timestamp", "N/A")

        p_lower = path.lower()
        if any(k in p_lower for k in ["temp", "appdata", "downloads"]):
            path_display = f" `{path}`"
        else:
            path_display = f"`{path}`"

        lines.append(f"| {idx} | **{name}** | {path_display} | `{sha1}` | {size_str} | {publisher} | {ts} |")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    console.print(f"[bold green][/bold green] Exported {len(entries)} Amcache records to Markdown (MD): [cyan]{output_path}[/cyan]")


def export_amcache_html(entries: List[Dict[str, Any]], output_path: str, source_name: str = "Evidence Image"):
    clean_entries = []
    for e in entries:
        d = dict(e)
        if "timestamp_obj" in d:
            if d["timestamp_obj"]:
                d["timestamp_iso"] = d["timestamp_obj"].isoformat()
            del d["timestamp_obj"]
        clean_entries.append(d)

    json_payload = json.dumps(clean_entries, ensure_ascii=False)
    generated_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>DFIR Forensic Report - Amcache Program Executions ({source_name})</title>
    <style>
        :root {{ --bg: #0f172a; --surface: #1e293b; --surface-hover: #334155; --border: #334155; --text: #f8fafc; --text-muted: #94a3b8; --accent: #38bdf8; --warn: #f59e0b; --danger: #ef4444; }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
        body {{ background: var(--bg); color: var(--text); padding: 24px; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 20px; }}
        .title {{ font-size: 24px; font-weight: 700; }}
        .title span {{ color: var(--accent); }}
        .badge {{ background: #7c2d12; color: #fdba74; padding: 4px 10px; border-radius: 999px; font-size: 12px; font-weight: 600; }}
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
        .sha1-tag {{ font-family: monospace; color: #fbbf24; font-size: 12px; }}
        .path-tag {{ color: #e2e8f0; font-weight: 500; }}
        .suspicious-tag {{ background: #7f1d1d; color: #fca5a5; padding: 2px 6px; border-radius: 4px; font-size: 10px; font-weight: 700; margin-left: 6px; }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <div class="title">DFIR <span>Amcache Execution</span> Report</div>
            <div style="font-size: 13px; color: var(--text-muted); margin-top: 4px;">Evidence: <strong>{source_name}</strong> | Generated: {generated_time}</div>
        </div>
        <div class="badge">Amcache.hve Forensic Artifact</div>
    </div>
    <div class="stats-grid">
        <div class="card"><div class="label">Total Binaries</div><div class="val">{len(entries)}</div></div>
        <div class="card"><div class="label">Unique Hashes</div><div class="val">{len(set(e.get('sha1') for e in entries if e.get('sha1')))}</div></div>
    </div>
    <div class="controls">
        <input type="text" id="searchInput" class="search-box" placeholder=" Search Program Name, Path, SHA1 Hash, Publisher...">
    </div>
    <table id="amTable">
        <thead>
            <tr>
                <th style="width: 50px;">#</th>
                <th>Program & Binary Path</th>
                <th>SHA1 Hash</th>
                <th style="width: 100px;">Size</th>
                <th>Publisher</th>
                <th style="width: 180px;">Key Timestamp (UTC)</th>
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
                const pLower = (item.path || '').toLowerCase();
                const isSuspicious = pLower.includes('temp') || pLower.includes('appdata') || pLower.includes('downloads');
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td style="color: #64748b;">${{idx + 1}}</td>
                    <td>
                        <div class="path-tag">${{item.name || 'Unknown'}}${{isSuspicious ? '<span class="suspicious-tag">SUSPICIOUS PATH</span>' : ''}}</div>
                        <div style="color: #94a3b8; font-size: 11px; margin-top: 2px;">${{item.path || 'N/A'}}</div>
                    </td>
                    <td><span class="sha1-tag">${{item.sha1 || 'N/A'}}</span></td>
                    <td style="color: #34d399;">${{item.size_str || '0 B'}}</td>
                    <td style="color: #c084fc;">${{item.publisher || 'Unknown'}}</td>
                    <td style="color: #fbbf24; font-family: monospace;">${{item.timestamp || 'N/A'}}</td>
                `;
                tb.appendChild(tr);
            }});
        }}
        document.getElementById('searchInput').addEventListener('input', (e) => {{
            const q = e.target.value.toLowerCase().trim();
            filtered = raw.filter(i => (i.name||'').toLowerCase().includes(q) || (i.path||'').toLowerCase().includes(q) || (i.sha1||'').toLowerCase().includes(q) || (i.publisher||'').toLowerCase().includes(q));
            render();
        }});
        render();
    </script>
</body>
</html>"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    console.print(f"[bold green][/bold green] Generated interactive HTML Amcache report: [cyan]{output_path}[/cyan]")


def main(args_list=None):
    parser = argparse.ArgumentParser(
        prog="ad1 amcache",
        description=" Extract and analyze Amcache.hve execution artifacts from AccessData AD1 logical images.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  tools ad1 amcache evidence.ad1
  tools ad1 amcache evidence.ad1 --query "malware"
  tools ad1 amcache evidence.ad1 --export-all
        """
    )
    parser.add_argument("input", help="Path to input AD1 image file")
    parser.add_argument("-q", "--query", help="Filter by program name, path, hash, or publisher")
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

    print_ad1_banner("AD1 AMCACHE EXECUTION ANALYZER (ad1amcache)")
    console.print(f"[dim]Opening image container:[/dim] [cyan]{args.input}[/cyan]\n")

    with console.status("[bold cyan]Scanning & parsing Amcache.hve hive...[/bold cyan]"):
        parser_ad1 = AD1Parser(args.input)
        analyzer = AD1AmcacheAnalyzer(parser_ad1)
        entries = analyzer.scan_and_extract()

    if not entries:
        console.print("[bold yellow] No Amcache.hve hive found in the AD1 container.[/bold yellow]")
        parser_ad1.close()
        return

    if args.query:
        q_low = args.query.lower()
        entries = [
            e for e in entries
            if q_low in (e.get("name") or "").lower()
            or q_low in (e.get("path") or "").lower()
            or q_low in (e.get("sha1") or "").lower()
            or q_low in (e.get("publisher") or "").lower()
        ]

    limit = args.limit if args.limit else 100
    print_amcache_table(entries, max_rows=limit)

    base_name = os.path.splitext(os.path.basename(args.input))[0]
    if args.export_all:
        if not args.md: args.md = f"{base_name}_amcache.md"
        if not args.json: args.json = f"{base_name}_amcache.json"
        if not args.csv: args.csv = f"{base_name}_amcache.csv"
        if not args.html: args.html = f"{base_name}_amcache.html"

    if hasattr(args, 'md') and args.md: export_amcache_markdown(entries, args.md, source_name=base_name)
    if hasattr(args, 'json') and args.json: export_amcache_json(entries, args.json)
    if hasattr(args, 'csv') and args.csv: export_amcache_csv(entries, args.csv)
    if hasattr(args, 'html') and args.html: export_amcache_html(entries, args.html, source_name=base_name)

    parser_ad1.close()


if __name__ == "__main__":
    main()
