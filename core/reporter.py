"""
Multi-Format Forensic Report Generator (CLI Table, CSV, JSON, HTML)
"""
import os
import sys
import json
import csv
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from collections import Counter

# Ensure UTF-8 output on Windows terminal
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

console = Console(force_terminal=True, legacy_windows=False)


def print_history_table(history_entries: List[Dict[str, Any]], max_rows: int = 100):
    """
    Print a rich table to the console with browser history entries.
    """
    if not history_entries:
        console.print("[yellow] No browser history entries found.[/yellow]")
        return

    table = Table(
        title=f" Extracted Browser History ({len(history_entries)} Total Records)",
        show_header=True,
        header_style="bold magenta",
        border_style="dim blue",
        expand=True
    )

    table.add_column("#", style="dim", width=5, justify="right")
    table.add_column("Browser", style="bold cyan", width=10)
    table.add_column("Profile / User", style="green", width=18)
    table.add_column("Visit Time (UTC)", style="yellow", width=22)
    table.add_column("Title / Search Query", style="white", min_width=25)
    table.add_column("URL", style="blue", min_width=35, overflow="fold")
    table.add_column("Visits", style="bold red", width=7, justify="center")

    display_entries = history_entries[:max_rows]
    for idx, item in enumerate(display_entries, start=1):
        browser = item.get("browser", "Unknown")
        user_prof = item.get("profile", "") or item.get("user", "Default")
        visit_time = item.get("visit_time_str", "N/A")
        
        title = item.get("title") or ""
        search_terms = item.get("search_terms")
        if search_terms:
            title_display = f" [bold yellow]{search_terms}[/bold yellow]\n[dim]{title}[/dim]" if title else f" [bold yellow]{search_terms}[/bold yellow]"
        else:
            title_display = title if title else "[dim italic]No Title[/dim italic]"

        url = item.get("url", "")
        visits = str(item.get("visit_count", 1))

        table.add_row(
            str(idx),
            browser,
            user_prof,
            visit_time,
            title_display,
            url,
            visits
        )

    console.print(table)

    if len(history_entries) > max_rows:
        console.print(f"[italic dim]... showing top {max_rows} of {len(history_entries)} records. Use --export-csv, --export-json, or --export-html to view all records.[/italic dim]\n")

    # Summary Statistics
    print_history_summary(history_entries)


def print_history_summary(history_entries: List[Dict[str, Any]]):
    """
    Print summary statistics (top domains, browser distribution, search terms).
    """
    if not history_entries:
        return

    browser_counts = Counter(item.get("browser", "Unknown") for item in history_entries)
    domain_counts = Counter(item.get("domain", "") for item in history_entries if item.get("domain"))
    search_queries = [item.get("search_terms") for item in history_entries if item.get("search_terms")]

    summary_text = Text()
    summary_text.append(" Summary Statistics:\n", style="bold green")
    summary_text.append(f"  • Total URLs Extracted : {len(history_entries)}\n", style="white")
    
    browsers_str = ", ".join([f"{k}: {v}" for k, v in browser_counts.items()])
    summary_text.append(f"  • Browsers Detected    : {browsers_str}\n", style="white")
    
    if domain_counts:
        top_5_domains = ", ".join([f"{d} ({c})" for d, c in domain_counts.most_common(5)])
        summary_text.append(f"  • Top Domains Visited  : {top_5_domains}\n", style="cyan")

    if search_queries:
        summary_text.append(f"  • Search Queries Found : {len(search_queries)} queries\n", style="yellow")

    console.print(Panel(summary_text, border_style="green", title="Forensic Insights", title_align="left"))


def export_to_csv(history_entries: List[Dict[str, Any]], output_path: str):
    """
    Export entries to CSV file.
    """
    if not history_entries:
        console.print("[yellow]No data to export to CSV.[/yellow]")
        return

    fieldnames = [
        "browser", "user", "profile", "visit_time_utc", "url", "title",
        "visit_count", "typed_count", "domain", "search_terms",
        "transition", "source_file"
    ]

    with open(output_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for item in history_entries:
            row = {
                "browser": item.get("browser", ""),
                "user": item.get("user", ""),
                "profile": item.get("profile", ""),
                "visit_time_utc": item.get("visit_time_str", ""),
                "url": item.get("url", ""),
                "title": item.get("title", ""),
                "visit_count": item.get("visit_count", 0),
                "typed_count": item.get("typed_count", 0),
                "domain": item.get("domain", ""),
                "search_terms": item.get("search_terms", ""),
                "transition": item.get("transition", ""),
                "source_file": item.get("source_file", "")
            }
            writer.writerow(row)

    console.print(f"[bold green][/bold green] Exported {len(history_entries)} records to CSV: [cyan]{output_path}[/cyan]")


def _to_serializable(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    clean_list = []
    for item in entries:
        d = dict(item)
        if "visit_time_obj" in d:
            if d["visit_time_obj"]:
                d["visit_time_iso"] = d["visit_time_obj"].isoformat()
            del d["visit_time_obj"]
        clean_list.append(d)
    return clean_list


def _clean_json_object(obj: Any) -> Any:
    if isinstance(obj, dict):
        res = {}
        for k, v in obj.items():
            if k == "visit_time_obj":
                continue
            res[k] = _clean_json_object(v)
        return res
    elif isinstance(obj, list):
        return [_clean_json_object(i) for i in obj]
    elif isinstance(obj, datetime):
        return obj.isoformat()
    return obj


def export_to_json(history_entries: List[Dict[str, Any]], output_path: str, dpapi_triage: Optional[Dict[str, Any]] = None):
    """
    Export browser history records to a JSON file.
    """
    serializable_data = _to_serializable(history_entries)
    clean_dpapi = _clean_json_object(dpapi_triage) if dpapi_triage and dpapi_triage.get("triggered") else None
    payload = {
        "stats": {
            "total_records": len(history_entries),
            "browsers": dict(Counter(item.get("browser", "Unknown") for item in history_entries)),
            "search_queries_count": len([item for item in history_entries if item.get("search_terms")])
        },
        "dpapi_triage": clean_dpapi,
        "history_entries": serializable_data
    }
    with open(output_path, mode="w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    console.print(f"[bold green][/bold green] Exported {len(history_entries)} records to JSON: [cyan]{output_path}[/cyan]")


def export_to_markdown(history_entries: List[Dict[str, Any]], output_path: str, source_name: str = "Evidence Image", dpapi_triage: Optional[Dict[str, Any]] = None):
    """
    Export browser history records to a clean Markdown (.md) forensic report.
    """
    generated_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    browser_counts = Counter(item.get("browser", "Unknown") for item in history_entries)
    domain_counts = Counter(item.get("domain", "") for item in history_entries if item.get("domain"))
    search_queries = [item for item in history_entries if item.get("search_terms")]

    lines = [
        f"# DFIR Forensic Report - Browser History",
        f"- **Evidence Source:** `{source_name}`",
        f"- **Generated:** `{generated_time}`",
        f"- **Total Records:** `{len(history_entries)}`",
        "",
        "## Summary Insights",
        f"- **Browsers Detected:** {', '.join([f'{k} ({v})' for k, v in browser_counts.items()])}",
        f"- **Unique Domains:** {len(domain_counts)}",
        f"- **Search Queries Found:** {len(search_queries)}",
        ""
    ]

    # Include DPAPI section if triggered
    if dpapi_triage and dpapi_triage.get("triggered"):
        lines.append("##  Automated DPAPI Credential Decryption Triage")
        for prof in dpapi_triage.get("profiles", []):
            user = prof.get("user")
            browser = prof.get("browser")
            target_dir = prof.get("target_dir")
            creds = prof.get("stored_credentials", [])
            lines.append(f"### Profile: `{user}` ({browser})")
            lines.append(f"- **Extracted Decryption Bundle Directory:** `{target_dir}`")
            lines.append(f"- **Stored Credentials Found:** `{len(creds)} accounts`")
            lines.append("")
            if creds:
                lines.append("| # | Username / Account | Origin / Login URL | Encryption Scheme | Times Used |")
                lines.append("|---|---|---|---|:---:|")
                for c_idx, c in enumerate(creds, start=1):
                    u = c.get("username", "").replace("|", "\\|")
                    orig = c.get("origin_url", "").replace("|", "\\|")
                    enc = c.get("encryption", "")
                    tu = c.get("times_used", 0)
                    lines.append(f"| {c_idx} | **`{u}`** | `{orig}` | {enc} | {tu} |")
                lines.append("")

        # Decrypted Plaintext Passwords
        dec_creds = dpapi_triage.get("decrypted_credentials", [])
        if dec_creds:
            lines.append("###  Decrypted Plaintext Credentials")
            lines.append("| # | User | Origin URL | Username / Account | Plaintext Password | Times Used |")
            lines.append("|---|---|---|---|---|:---:|")
            for c_idx, c in enumerate(dec_creds, start=1):
                u = c.get("user", "").replace("|", "\\|")
                orig = c.get("origin_url", "").replace("|", "\\|")
                usr = c.get("username", "").replace("|", "\\|")
                pwd = c.get("password", "").replace("|", "\\|")
                tu = c.get("times_used", 0)
                lines.append(f"| {c_idx} | **{u}** | `{orig}` | `{usr}` | **`{pwd}`** | {tu} |")
            lines.append("")

    lines.extend([
        "## Visited URLs",
        "| # | Browser | User / Profile | Visit Time (UTC) | Title / Search Query | URL | Visits |",
        "|---|---|---|---|---|---|:---:|"
    ])

    for idx, item in enumerate(history_entries, start=1):
        browser = item.get("browser", "Unknown")
        user_prof = item.get("profile") or item.get("user") or "Default"
        v_time = item.get("visit_time_str", "N/A")
        
        title = (item.get("title") or "").replace("|", "\\|")
        search = item.get("search_terms")
        if search:
            title_display = f" **Search:** `{search}`<br>{title}" if title else f" **Search:** `{search}`"
        else:
            title_display = title if title else "*No Title*"

        url = (item.get("url") or "").replace("|", "\\|")
        visits = item.get("visit_count", 1)

        lines.append(f"| {idx} | {browser} | {user_prof} | {v_time} | {title_display} | {url} | {visits} |")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    console.print(f"[bold green][/bold green] Exported {len(history_entries)} records to Markdown (MD): [cyan]{output_path}[/cyan]")


def export_to_html(history_entries: List[Dict[str, Any]], output_path: str, source_name: str = "Evidence Image"):
    """
    Generate an interactive, responsive HTML forensic report with live filtering,
    search, and analytics.
    """
    generated_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    total_records = len(history_entries)
    browser_counts = Counter(item.get("browser", "Unknown") for item in history_entries)
    domain_counts = Counter(item.get("domain", "") for item in history_entries if item.get("domain"))
    top_domains = domain_counts.most_common(10)
    search_queries = [item for item in history_entries if item.get("search_terms")]

    # Prepare JSON safe payload for the web table
    serializable_data = _to_serializable(history_entries)
    json_data = json.dumps(serializable_data, ensure_ascii=False)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DFIR Forensic Report - Browser History ({source_name})</title>
    <style>
        :root {{
            --bg: #0f172a;
            --surface: #1e293b;
            --surface-hover: #334155;
            --border: #334155;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent: #38bdf8;
            --accent-purple: #a855f7;
            --accent-green: #22c55e;
            --accent-yellow: #eab308;
            --accent-red: #ef4444;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif; }}
        body {{ background-color: var(--bg); color: var(--text-primary); padding: 24px; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; padding-bottom: 20px; border-bottom: 1px solid var(--border); margin-bottom: 24px; }}
        .title {{ font-size: 24px; font-weight: 700; color: var(--text-primary); }}
        .title span {{ color: var(--accent); }}
        .subtitle {{ font-size: 13px; color: var(--text-secondary); margin-top: 4px; }}
        .badge {{ background: #0369a1; color: #fff; padding: 4px 10px; border-radius: 9999px; font-size: 12px; font-weight: 600; }}
        
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; }}
        .stat-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 18px; }}
        .stat-card .label {{ font-size: 12px; text-transform: uppercase; color: var(--text-secondary); letter-spacing: 0.5px; }}
        .stat-card .value {{ font-size: 26px; font-weight: 700; color: var(--text-primary); margin-top: 6px; }}

        .controls {{ display: flex; gap: 12px; margin-bottom: 20px; flex-wrap: wrap; }}
        .search-box {{ flex: 1; min-width: 250px; background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 10px 14px; color: #fff; font-size: 14px; outline: none; }}
        .search-box:focus {{ border-color: var(--accent); }}
        .select-filter {{ background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 10px 14px; color: #fff; font-size: 14px; outline: none; }}

        .table-container {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; overflow-x: auto; }}
        table {{ width: 100%; border-collapse: collapse; text-align: left; font-size: 13px; }}
        th {{ background: #111827; color: var(--text-secondary); padding: 12px 16px; font-weight: 600; border-bottom: 1px solid var(--border); position: sticky; top: 0; }}
        td {{ padding: 12px 16px; border-bottom: 1px solid var(--border); vertical-align: top; word-break: break-all; }}
        tr:hover {{ background-color: var(--surface-hover); }}
        
        .browser-tag {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }}
        .tag-chrome {{ background: #1e3a8a; color: #93c5fd; }}
        .tag-edge {{ background: #064e3b; color: #6ee7b7; }}
        .tag-firefox {{ background: #7c2d12; color: #fdba74; }}
        .tag-brave {{ background: #701a75; color: #f0abfc; }}
        .tag-safari {{ background: #1e293b; color: #cbd5e1; border: 1px solid #475569; }}
        .tag-other {{ background: #374151; color: #d1d5db; }}
        
        .search-term-badge {{ display: inline-block; background: #854d0e; color: #fef08a; padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: 600; margin-bottom: 4px; }}
        .url-link {{ color: var(--accent); text-decoration: none; }}
        .url-link:hover {{ text-decoration: underline; }}
        .domain-tag {{ color: var(--text-secondary); font-size: 11px; margin-top: 2px; }}
        
        .pagination {{ display: flex; justify-content: space-between; align-items: center; padding: 16px; background: var(--surface); border-top: 1px solid var(--border); }}
        .btn {{ background: #3b82f6; color: #fff; border: none; padding: 8px 14px; border-radius: 6px; cursor: pointer; font-size: 13px; font-weight: 500; }}
        .btn:disabled {{ background: #475569; cursor: not-allowed; }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <div class="title">DFIR <span>Browser Forensics</span> Report</div>
            <div class="subtitle">Evidence: <strong>{source_name}</strong> | Generated: {generated_time}</div>
        </div>
        <div class="badge">Forensic Grade Artifact</div>
    </div>

    <div class="stats-grid">
        <div class="stat-card">
            <div class="label">Total Visited URLs</div>
            <div class="value">{total_records}</div>
        </div>
        <div class="stat-card">
            <div class="label">Browsers Detected</div>
            <div class="value">{len(browser_counts)}</div>
        </div>
        <div class="stat-card">
            <div class="label">Unique Domains</div>
            <div class="value">{len(domain_counts)}</div>
        </div>
        <div class="stat-card">
            <div class="label">Search Queries</div>
            <div class="value">{len(search_queries)}</div>
        </div>
    </div>

    <div class="controls">
        <input type="text" id="searchInput" class="search-box" placeholder=" Search URL, Page Title, Domain, Search terms, or User profile...">
        <select id="browserFilter" class="select-filter">
            <option value="ALL">All Browsers</option>
            {' '.join([f'<option value="{b}">{b} ({c})</option>' for b, c in browser_counts.items()])}
        </select>
        <select id="typeFilter" class="select-filter">
            <option value="ALL">All Entries</option>
            <option value="SEARCH_ONLY">Search Queries Only </option>
        </select>
    </div>

    <div class="table-container">
        <table id="historyTable">
            <thead>
                <tr>
                    <th style="width: 50px;">#</th>
                    <th style="width: 100px;">Browser</th>
                    <th style="width: 150px;">Profile / User</th>
                    <th style="width: 180px;">Visit Time (UTC)</th>
                    <th>Title & Search Terms</th>
                    <th>URL & Domain</th>
                    <th style="width: 70px; text-align: center;">Visits</th>
                </tr>
            </thead>
            <tbody id="tableBody">
            </tbody>
        </table>
    </div>

    <div class="pagination">
        <div id="pageInfo" style="color: var(--text-secondary); font-size: 13px;">Showing 0 of 0</div>
        <div>
            <button id="prevBtn" class="btn" onclick="prevPage()">Previous</button>
            <button id="nextBtn" class="btn" onclick="nextPage()" style="margin-left: 8px;">Next</button>
        </div>
    </div>

    <script>
        const rawData = {json_data};
        let filteredData = [...rawData];
        let currentPage = 1;
        const pageSize = 50;

        function getBrowserTagClass(b) {{
            const lower = (b || '').toLowerCase();
            if (lower.includes('chrome')) return 'tag-chrome';
            if (lower.includes('edge')) return 'tag-edge';
            if (lower.includes('firefox')) return 'tag-firefox';
            if (lower.includes('brave')) return 'tag-brave';
            if (lower.includes('safari')) return 'tag-safari';
            return 'tag-other';
        }}

        function renderTable() {{
            const tbody = document.getElementById('tableBody');
            tbody.innerHTML = '';

            const start = (currentPage - 1) * pageSize;
            const end = Math.min(start + pageSize, filteredData.length);
            const pageRecords = filteredData.slice(start, end);

            pageRecords.forEach((item, index) => {{
                const tr = document.createElement('tr');
                const tagClass = getBrowserTagClass(item.browser);
                
                let searchHtml = '';
                if (item.search_terms) {{
                    searchHtml = `<div class="search-term-badge"> Search: ${{escapeHtml(item.search_terms)}}</div>`;
                }}
                const titleHtml = item.title ? escapeHtml(item.title) : '<span style="color: #64748b; font-style: italic;">No Title</span>';
                const domainHtml = item.domain ? `<div class="domain-tag"> ${{escapeHtml(item.domain)}}</div>` : '';

                tr.innerHTML = `
                    <td style="color: #64748b; text-align: right;">${{start + index + 1}}</td>
                    <td><span class="browser-tag ${{tagClass}}">${{escapeHtml(item.browser || 'Unknown')}}</span></td>
                    <td style="color: #38bdf8;">${{escapeHtml(item.profile || item.user || 'Default')}}</td>
                    <td style="color: #fbbf24; font-family: monospace;">${{escapeHtml(item.visit_time_str || 'N/A')}}</td>
                    <td>${{searchHtml}}<div>${{titleHtml}}</div></td>
                    <td><a class="url-link" href="${{escapeHtml(item.url || '')}}" target="_blank" rel="noreferrer">${{escapeHtml(item.url || '')}}</a>${{domainHtml}}</td>
                    <td style="text-align: center; font-weight: 700; color: #f87171;">${{item.visit_count || 1}}</td>
                `;
                tbody.appendChild(tr);
            }});

            document.getElementById('pageInfo').innerText = `Showing ${{filteredData.length > 0 ? start + 1 : 0}} to ${{end}} of ${{filteredData.length}} records`;
            document.getElementById('prevBtn').disabled = (currentPage <= 1);
            document.getElementById('nextBtn').disabled = (end >= filteredData.length);
        }}

        function escapeHtml(str) {{
            if (!str) return '';
            return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        }}

        function applyFilter() {{
            const query = document.getElementById('searchInput').value.toLowerCase().trim();
            const browser = document.getElementById('browserFilter').value;
            const type = document.getElementById('typeFilter').value;

            filteredData = rawData.filter(item => {{
                if (browser !== 'ALL' && item.browser !== browser) return false;
                if (type === 'SEARCH_ONLY' && !item.search_terms) return false;
                
                if (query) {{
                    const matchUrl = (item.url || '').toLowerCase().includes(query);
                    const matchTitle = (item.title || '').toLowerCase().includes(query);
                    const matchDomain = (item.domain || '').toLowerCase().includes(query);
                    const matchTerms = (item.search_terms || '').toLowerCase().includes(query);
                    const matchUser = (item.profile || item.user || '').toLowerCase().includes(query);
                    return matchUrl || matchTitle || matchDomain || matchTerms || matchUser;
                }}
                return true;
            }});

            currentPage = 1;
            renderTable();
        }}

        function prevPage() {{
            if (currentPage > 1) {{
                currentPage--;
                renderTable();
            }}
        }}

        function nextPage() {{
            if ((currentPage * pageSize) < filteredData.length) {{
                currentPage++;
                renderTable();
            }}
        }}

        document.getElementById('searchInput').addEventListener('input', applyFilter);
        document.getElementById('browserFilter').addEventListener('change', applyFilter);
        document.getElementById('typeFilter').addEventListener('change', applyFilter);

        renderTable();
    </script>
</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    console.print(f"[bold green][/bold green] Generated interactive HTML report: [cyan]{output_path}[/cyan]")
