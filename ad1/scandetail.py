"""
AD1 User Personal Files & Documents Forensics Analyzer (ad1scandetail)
Engineered for Digital Forensics & CTF Investigations.

Specifically designed for zero-noise hunting of user documents, notes, photos,
downloads, and personal files:
- Excludes AppData, cache, browser storage, and OS runtime noise.
- Focuses strictly on: Desktop, Documents, Downloads, Pictures/Photos, Videos, Music, OneDrive, Notes.
- Categorizes files by Type: Documents/Notes, Images/Photos, Audio/Video, Archives, Scripts/Keys.
- Supports targeting specific users (e.g. -u SERV, -u bagas) or auto-detecting all user accounts.
- Inspects small text notes and documents for secret previews and CTF flags.
- Multi-format reporting (Rich Terminal Tables, Markdown, JSON, CSV, Interactive HTML).
"""
import os
import sys
import argparse
import json
import re
from collections import Counter
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Set, Tuple

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from ad1.parser import AD1Parser
from ad1.models import AD1Item
from core.banner import print_ad1_banner
from core.utils import human_size, format_datetime

console = Console(force_terminal=True, legacy_windows=False)

# File Categories & Extensions
CATEGORY_EXTENSIONS = {
    "Documents & Notes": {
        ".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt", ".txt", ".md",
        ".rtf", ".odt", ".ods", ".odp", ".csv", ".note", ".one", ".pages", ".numbers", ".keynote"
    },
    "Images & Photos": {
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".svg", ".heic", ".raw",
        ".cr2", ".nef", ".tiff", ".tif", ".ico", ".psd"
    },
    "Audio & Videos": {
        ".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv", ".webm", ".mp3", ".wav",
        ".m4a", ".flac", ".aac", ".ogg", ".wma"
    },
    "Archives & Backups": {
        ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".iso", ".bak", ".backup"
    },
    "Scripts & Keys": {
        ".py", ".sh", ".ps1", ".bat", ".vbs", ".js", ".sql", ".env", ".key", ".kdbx",
        ".pem", ".pfx", ".ovpn", ".conf", ".cfg", ".yml", ".yaml", ".flag"
    }
}

# Folders to Exclude (Zero Noise Filter)
EXCLUDED_FOLDER_KEYWORDS = [
    "/appdata/", "\\appdata\\",
    "/application data/", "\\application data\\",
    "/local settings/", "\\local settings\\",
    "/windows/", "\\windows\\",
    "/program files/", "\\program files\\",
    "/program files (x86)/", "\\program files (x86)\\",
    "/programdata/", "\\programdata\\",
    "/system volume information/", "\\system volume information\\",
    "$recycle.bin", "/msocache/"
]

# Non-human system accounts to filter out from auto-detect
SYSTEM_ACCOUNTS = {"public", "all users", "default", "default user", "default.migrated", "networkservice", "localservice"}

# Flag patterns
RE_FLAGS = [
    re.compile(r"(?:flag|FLAG|ctf|CTF|htb|HTB|picoCTF|thm|THM)\{[^}\n\r\t ]{3,200}\}")
]


def classify_file_category(filename: str) -> str:
    _, ext = os.path.splitext(filename.lower())
    for category, ext_set in CATEGORY_EXTENSIONS.items():
        if ext in ext_set:
            return category
    return "Other User Files"


class AD1ScanDetailAnalyzer:
    """
    Clean, zero-noise scanner for user documents, notes, photos, and personal artifacts.
    """
    def __init__(self, parser: AD1Parser, scan_content: bool = True):
        self.parser = parser
        self.scan_content = scan_content

    def scan_user_artifacts(self, target_user: Optional[str] = None, category_filter: Optional[str] = None) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        if not self.parser.items:
            self.parser.build_tree()

        results = []
        user_counts = Counter()
        category_counts = Counter()
        flags_found = []

        for item in self.parser.items:
            if item.is_dir or item.decompressed_size == 0:
                continue

            path_norm = item.full_path.replace("\\", "/")
            path_lower = path_norm.lower()

            # 1. Check if item is inside User home directory
            m_user = re.search(r"(?:^|/)(?:users|home|documents and settings)/([^/]+)/", path_norm, re.IGNORECASE)
            if not m_user:
                continue

            detected_user = m_user.group(1)

            # Skip system / default user profiles unless explicitly targeted
            if not target_user and detected_user.lower() in SYSTEM_ACCOUNTS:
                continue

            # Target user filtering
            if target_user and target_user.lower() != detected_user.lower():
                continue

            # 2. Exclude AppData and OS junk (Zero Noise Rule)
            if any(ex in path_lower for ex in EXCLUDED_FOLDER_KEYWORDS):
                continue

            # Ignore NTUSER.DAT and generic registry files in root of user
            if item.item_name.lower() in ["ntuser.dat", "ntuser.ini", "ntuser.dat.log", "thumbs.db", "desktop.ini", "iconcache.db"]:
                continue

            # Classify category
            cat = classify_file_category(item.item_name)
            if category_filter and category_filter.lower() not in cat.lower():
                continue

            # Content preview & Flag search for small text/document/script files (< 64KB)
            content_preview = ""
            file_flags = []
            _, ext = os.path.splitext(item.item_name.lower())

            if self.scan_content and item.decompressed_size < 65536:
                if ext in [".txt", ".md", ".note", ".csv", ".json", ".flag", ".env", ".py", ".sh", ".ps1", ".bat", ".sql", ".conf", ".cfg", ".ini", ".xml", ""]:
                    raw_bytes = self.parser.read_file_bytes(item)
                    if raw_bytes:
                        try:
                            text = raw_bytes.decode("utf-8", errors="replace")
                        except Exception:
                            text = raw_bytes.decode("latin-1", errors="replace")

                        # Search for flags
                        for pat in RE_FLAGS:
                            for m in pat.finditer(text):
                                fl = m.group(0)
                                if fl not in file_flags:
                                    file_flags.append(fl)
                                    flags_found.append(fl)

                        # Clean 1-line preview
                        lines = [l.strip() for l in text.splitlines() if l.strip()][:2]
                        if lines:
                            content_preview = " | ".join(lines)[:120]

            entry = {
                "name": item.item_name,
                "user": detected_user,
                "category": cat,
                "path": path_norm,
                "size": item.decompressed_size,
                "size_str": human_size(item.decompressed_size),
                "extension": ext,
                "preview": content_preview,
                "flags": file_flags
            }

            results.append(entry)
            user_counts[detected_user] += 1
            category_counts[cat] += 1

        # Sort: Flags first, then by Category, then by Name
        results.sort(key=lambda x: (not bool(x["flags"]), x["user"].lower(), x["category"], x["name"].lower()))

        stats = {
            "total_files": len(results),
            "users": dict(user_counts),
            "categories": dict(category_counts),
            "flags_count": len(flags_found),
            "flags": flags_found
        }

        return results, stats


def print_scandetail_table(entries: List[Dict[str, Any]], stats: Dict[str, Any], max_rows: int = 100):
    if not entries:
        console.print("[yellow] No personal user documents, photos, or notes found (AppData excluded).[/yellow]")
        return

    table = Table(
        title=f" User Personal Files & Documents ({len(entries)} Total Files - AppData Excluded)",
        show_header=True,
        header_style="bold magenta",
        border_style="dim cyan",
        expand=True
    )

    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("User", style="bold cyan", width=12)
    table.add_column("Category", style="magenta", width=20)
    table.add_column("File / Document Name", style="bold white", width=28)
    table.add_column("Location / Path", style="white", min_width=32, overflow="fold")
    table.add_column("Size", style="green", width=9, justify="right")
    table.add_column("Content Preview / CTF Flag", style="yellow", min_width=30, overflow="fold")

    for idx, item in enumerate(entries[:max_rows], start=1):
        name = item["name"]
        user = item["user"]
        cat = item["category"]
        path = item["path"]
        size_str = item["size_str"]

        # Category icon badge
        if "Document" in cat: cat_badge = " " + cat
        elif "Image" in cat: cat_badge = " " + cat
        elif "Audio" in cat: cat_badge = " " + cat
        elif "Archive" in cat: cat_badge = " " + cat
        elif "Script" in cat: cat_badge = " " + cat
        else: cat_badge = " " + cat

        # Name styling (Red highlight if flag found)
        if item["flags"]:
            name_styled = f"[bold red] {name}[/bold red]"
            preview_styled = f"[bold white on red] FLAG: {', '.join(item['flags'])} [/bold white on red]\n[dim italic]{item['preview']}[/dim italic]"
        else:
            name_styled = f"[bold]{name}[/bold]"
            preview_styled = f"[dim italic]{item['preview']}[/dim italic]" if item["preview"] else "[dim]-[/dim]"

        table.add_row(
            str(idx),
            user,
            cat_badge,
            name_styled,
            path,
            size_str,
            preview_styled
        )

    console.print(table)

    if len(entries) > max_rows:
        console.print(f"[italic dim]... showing top {max_rows} of {len(entries)} records. Use --export-all or --md to view all records.[/italic dim]\n")

    # Summary Panel
    summary = Text()
    summary.append(" User Documents & Artifacts Summary:\n", style="bold green")
    summary.append(f"  • Total Personal Files Found: {stats['total_files']} (AppData Excluded)\n", style="white")
    summary.append(f"  • User Breakdown            : {', '.join([f'{u} ({c} files)' for u, c in stats['users'].items()])}\n", style="cyan")
    summary.append(f"  • Category Breakdown        : {', '.join([f'{k}: {v}' for k, v in stats['categories'].items()])}\n", style="yellow")
    if stats["flags_count"]:
        summary.append(f"  •  CTF Flags Extracted    : {stats['flags_count']} flags: {', '.join(stats['flags'])}\n", style="bold red")

    console.print(Panel(summary, border_style="green" if not stats["flags_count"] else "red", title="User Artifacts Insights", title_align="left"))


def export_scandetail_markdown(entries: List[Dict[str, Any]], stats: Dict[str, Any], output_path: str, source_name: str = "Evidence Image"):
    generated_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines = [
        f"# DFIR Forensic Report - User Personal Files & Documents",
        f"- **Evidence Source:** `{source_name}`",
        f"- **Generated:** `{generated_time}`",
        f"- **Total Personal Files:** `{stats['total_files']}` (AppData Excluded)",
        "",
        "## Summary Insights",
        f"- **Users Detected:** {', '.join([f'{u} ({c} files)' for u, c in stats['users'].items()])}",
        f"- **Categories:** {', '.join([f'{k}: {v}' for k, v in stats['categories'].items()])}",
        f"- ** CTF Flags Found:** `{stats['flags_count']}`",
        "",
        "## User Documents, Photos & Artifacts",
        "| # | User | Category | File Name | Full Location Path | Size | Preview / Flag |",
        "|---|---|---|---|---|:---:|---|"
    ]

    for idx, item in enumerate(entries, start=1):
        user = item["user"]
        cat = item["category"]
        name = item["name"].replace("|", "\\|")
        path = item["path"].replace("|", "\\|")
        size_str = item["size_str"]

        flag_txt = f" **FLAG:** `{', '.join(item['flags'])}`<br>" if item["flags"] else ""
        prev_txt = f"*{item['preview'].replace('|', '/')[:100]}*" if item["preview"] else "-"
        preview_md = f"{flag_txt}{prev_txt}"

        prefix = " " if item["flags"] else ""
        lines.append(f"| {idx} | **{user}** | `{cat}` | {prefix}**{name}** | `{path}` | {size_str} | {preview_md} |")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    console.print(f"[bold green][/bold green] Exported {len(entries)} user personal records to Markdown (MD): [cyan]{output_path}[/cyan]")


def export_scandetail_json(entries: List[Dict[str, Any]], stats: Dict[str, Any], output_path: str):
    payload = {
        "stats": stats,
        "entries": entries
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    console.print(f"[bold green][/bold green] Exported user records to JSON: [cyan]{output_path}[/cyan]")


def export_scandetail_csv(entries: List[Dict[str, Any]], output_path: str):
    import csv
    fieldnames = ["user", "category", "name", "path", "size", "size_str", "extension", "preview", "flags"]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for e in entries:
            row = dict(e)
            row["flags"] = "; ".join(e.get("flags", []))
            writer.writerow(row)
    console.print(f"[bold green][/bold green] Exported {len(entries)} user records to CSV: [cyan]{output_path}[/cyan]")


def export_scandetail_html(entries: List[Dict[str, Any]], stats: Dict[str, Any], output_path: str, source_name: str = "Evidence Image"):
    json_payload = json.dumps(entries, ensure_ascii=False)
    generated_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>DFIR Forensic Report - User Documents & Personal Files ({source_name})</title>
    <style>
        :root {{ --bg: #0f172a; --surface: #1e293b; --surface-hover: #334155; --border: #334155; --text: #f8fafc; --text-muted: #94a3b8; --accent: #38bdf8; --danger: #f43f5e; }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
        body {{ background: var(--bg); color: var(--text); padding: 24px; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 20px; }}
        .title {{ font-size: 24px; font-weight: 700; }}
        .title span {{ color: var(--accent); }}
        .badge {{ background: #0369a1; color: #e0f2fe; padding: 4px 10px; border-radius: 999px; font-size: 12px; font-weight: 600; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 20px; }}
        .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }}
        .card .label {{ font-size: 12px; color: var(--text-muted); text-transform: uppercase; }}
        .card .val {{ font-size: 24px; font-weight: 700; margin-top: 4px; }}
        .controls {{ display: flex; gap: 12px; margin-bottom: 16px; flex-wrap: wrap; }}
        .search-box {{ flex: 1; min-width: 250px; background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 10px 14px; color: #fff; font-size: 14px; outline: none; }}
        .filter-btn {{ background: var(--surface); border: 1px solid var(--border); color: var(--text); padding: 8px 14px; border-radius: 6px; cursor: pointer; font-size: 13px; font-weight: 600; }}
        .filter-btn.active {{ background: #0284c7; border-color: #38bdf8; color: #fff; }}
        table {{ width: 100%; border-collapse: collapse; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; font-size: 13px; }}
        th {{ background: #111827; color: var(--text-muted); padding: 12px 14px; text-align: left; position: sticky; top: 0; }}
        td {{ padding: 12px 14px; border-bottom: 1px solid var(--border); vertical-align: top; word-break: break-all; }}
        tr:hover {{ background: var(--surface-hover); }}
        .tag {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; background: #1e293b; border: 1px solid #475569; }}
        .tag-doc {{ background: #1e3a8a; border-color: #3b82f6; color: #bfdbfe; }}
        .tag-img {{ background: #14532d; border-color: #22c55e; color: #bbf7d0; }}
        .tag-script {{ background: #581c87; border-color: #a855f7; color: #e9d5ff; }}
        .flag-box {{ background: #881337; border: 1px solid #e11d48; padding: 4px 8px; border-radius: 4px; color: #ffe4e6; font-weight: 700; display: inline-block; margin-bottom: 4px; }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <div class="title">DFIR <span>User Personal Documents & Media</span> Report</div>
            <div style="font-size: 13px; color: var(--text-muted); margin-top: 4px;">Evidence: <strong>{source_name}</strong> | Generated: {generated_time} (AppData Excluded)</div>
        </div>
        <div class="badge">Zero-Noise User Artifacts</div>
    </div>
    <div class="stats-grid">
        <div class="card"><div class="label">Total Personal Files</div><div class="val">{stats['total_files']}</div></div>
        <div class="card"><div class="label">Users Detected</div><div class="val" style="color: var(--accent);">{len(stats['users'])}</div></div>
        <div class="card"><div class="label">CTF Flags Found</div><div class="val" style="color: var(--danger);">{stats['flags_count']}</div></div>
    </div>
    <div class="controls">
        <input type="text" id="searchInput" class="search-box" placeholder=" Search file name, user, folder, or preview...">
        <button class="filter-btn active" onclick="filterCat('ALL')">All Files</button>
        <button class="filter-btn" onclick="filterCat('Documents')"> Documents</button>
        <button class="filter-btn" onclick="filterCat('Images')"> Photos</button>
        <button class="filter-btn" onclick="filterCat('Scripts')"> Scripts/Keys</button>
    </div>
    <table>
        <thead>
            <tr>
                <th style="width: 50px;">#</th>
                <th style="width: 100px;">User</th>
                <th style="width: 160px;">Category</th>
                <th style="width: 220px;">File Name</th>
                <th>Full Path</th>
                <th style="width: 90px;">Size</th>
                <th style="width: 260px;">Preview / Flag</th>
            </tr>
        </thead>
        <tbody id="tbody"></tbody>
    </table>
    <script>
        const raw = {json_payload};
        let activeCat = 'ALL';
        let searchQuery = '';

        function getCatClass(cat) {{
            if (cat.includes('Document')) return 'tag-doc';
            if (cat.includes('Image')) return 'tag-img';
            if (cat.includes('Script')) return 'tag-script';
            return '';
        }}

        function render() {{
            const tb = document.getElementById('tbody');
            tb.innerHTML = '';
            const filtered = raw.filter(item => {{
                const matchCat = (activeCat === 'ALL') || (item.category && item.category.includes(activeCat));
                const matchSearch = !searchQuery || JSON.stringify(item).toLowerCase().includes(searchQuery);
                return matchCat && matchSearch;
            }});

            filtered.forEach((item, idx) => {{
                const tr = document.createElement('tr');
                let flagHtml = '';
                if (item.flags && item.flags.length) {{
                    flagHtml = `<div class="flag-box"> FLAG: ${{item.flags.join(', ')}}</div>`;
                }}
                let prevHtml = item.preview ? `<div style="font-size: 11px; color: #94a3b8; font-style: italic;">${{item.preview}}</div>` : '<span style="color: #64748b;">-</span>';

                tr.innerHTML = `
                    <td style="color: #64748b;">${{idx + 1}}</td>
                    <td style="color: #38bdf8; font-weight: 600;">${{item.user || 'User'}}</td>
                    <td><span class="tag ${{getCatClass(item.category || '')}}">${{item.category || 'Other'}}</span></td>
                    <td><strong style="color: ${{item.flags && item.flags.length ? '#f43f5e' : '#f8fafc'}};">${{item.name || ''}}</strong></td>
                    <td style="font-family: monospace; font-size: 12px; color: #cbd5e1;">${{item.path || ''}}</td>
                    <td style="color: #4ade80;">${{item.size_str || ''}}</td>
                    <td>${{flagHtml}}${{prevHtml}}</td>
                `;
                tb.appendChild(tr);
            }});
        }}

        function filterCat(cat) {{
            activeCat = cat;
            document.querySelectorAll('.filter-btn').forEach(btn => {{
                btn.classList.toggle('active', btn.innerText.includes(cat) || (cat === 'ALL' && btn.innerText === 'All Files'));
            }});
            render();
        }}

        document.getElementById('searchInput').addEventListener('input', (e) => {{
            searchQuery = e.target.value.toLowerCase().trim();
            render();
        }});

        render();
    </script>
</body>
</html>"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    console.print(f"[bold green][/bold green] Generated interactive HTML User Artifacts report: [cyan]{output_path}[/cyan]")


def main(args_list=None):
    parser = argparse.ArgumentParser(
        prog="ad1 scandetail",
        description=" Zero-noise user documents, photos, notes, and personal files finder (Excludes AppData & OS junk).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ad1scandetail evidence.ad1
  ad1scandetail evidence.ad1 -u Alice
  ad1scandetail evidence.ad1 -u SERV
  ad1scandetail evidence.ad1 -c "Documents"
  ad1scandetail evidence.ad1 -c "Images"
  ad1scandetail evidence.ad1 --md user_files.md --json user_files.json
  ad1scandetail evidence.ad1 --export-all
        """
    )
    parser.add_argument("input", help="Path to input AD1 image file")
    parser.add_argument("-u", "--user", help="Target specific username (e.g. Alice, SERV, bagas)")
    parser.add_argument("-c", "--category", help="Filter by category (e.g. Documents, Images, Photos, Audio, Scripts)")
    parser.add_argument("-l", "--limit", type=int, default=100, help="Row display limit in terminal (default: 100)")
    parser.add_argument("--no-content", action="store_true", help="Skip reading file content for preview and flags")

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

    print_ad1_banner("AD1 USER PERSONAL FILES & DOCUMENTS (ad1scandetail)")
    console.print(f"[dim]Opening image container:[/dim] [cyan]{args.input}[/cyan]\n")

    with console.status("[bold cyan]Scanning user profile personal folders (AppData excluded)...[/bold cyan]"):
        parser_ad1 = AD1Parser(args.input)
        analyzer = AD1ScanDetailAnalyzer(parser_ad1, scan_content=not args.no_content)
        entries, stats = analyzer.scan_user_artifacts(target_user=args.user, category_filter=args.category)

    if not entries:
        scope_txt = f" for user '{args.user}'" if args.user else ""
        console.print(f"[bold yellow] No user personal documents or files found{scope_txt} (AppData excluded).[/bold yellow]")
        parser_ad1.close()
        return

    print_scandetail_table(entries, stats, max_rows=args.limit)

    base_name = os.path.splitext(os.path.basename(args.input))[0]
    if args.export_all:
        if not args.md: args.md = f"{base_name}_personal_files.md"
        if not args.json: args.json = f"{base_name}_personal_files.json"
        if not args.csv: args.csv = f"{base_name}_personal_files.csv"
        if not args.html: args.html = f"{base_name}_personal_files.html"

    if hasattr(args, 'md') and args.md: export_scandetail_markdown(entries, stats, args.md, source_name=base_name)
    if hasattr(args, 'json') and args.json: export_scandetail_json(entries, stats, args.json)
    if hasattr(args, 'csv') and args.csv: export_scandetail_csv(entries, args.csv)
    if hasattr(args, 'html') and args.html: export_scandetail_html(entries, stats, args.html, source_name=base_name)

    parser_ad1.close()


if __name__ == "__main__":
    main()
