"""
AD1 Browser Extensions & Orphan Storage Triage Tool (ad1extensions)
Engineered for Digital Forensics & Incident Response (DFIR).

Performs 3-point correlation across Chromium profiles (Chrome, Edge, Brave, Opera):
1. Preferences & Secure Preferences (Manifest, install source, permissions, timestamps)
2. Binary Extensions/ Directory (Active unpacked/packed extensions)
3. Residual Storage in Local Extension Settings & Sync Extension Settings (LevelDB)

Features:
- Pure Python LevelDB .ldb/.log parser & deep stream carver (Zero C++/plyvel dependencies)
- Whitelist baseline for Google/Microsoft/Brave built-in components (eliminates false positives)
- Automatic detection of ORPHAN / PURGED extensions (e.g. deleted cookie stealers)
- Carves exfiltration C2s (Discord Webhooks, Telegram Bot APIs, Ngrok, IPs)
- Carves stolen cookie markers (c_user, xs, datr, sessionid, auth_token)
- Multi-format reporting (Console Rich Table, Markdown, JSON, CSV, Interactive HTML)
"""
import os
import sys
import json
import argparse
import re
from collections import Counter
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

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
from core.utils import format_datetime, human_size, webkit_to_datetime
from core.leveldb import parse_extension_leveldb_files

console = Console(force_terminal=True, legacy_windows=False)

# Whitelist of standard built-in Chromium / Google / Edge / Brave extensions
KNOWN_BUILTIN_EXTENSIONS = {
    # Google Chrome Built-in
    "ghbmnnjooekpmoecnnnilnnbdlolhkhi": "Google Docs Offline",
    "nmmhkkegccagdldgiimedpiccmgmieda": "Chrome Web Store Payments",
    "pkedcjkdefgpdelpbcmbmeomcjbeemfm": "Chrome Media Router",
    "kmendfapggjehodndflmmgagdbamhnfd": "CryptoTokenExtension",
    "mhjfbmdgcfjbbpaeojofohoefgiehjai": "Chrome PDF Viewer",
    "aapocclcgogkmnckokdopfmhonfmgoek": "Google Slides",
    "felcaaldnbdncclmgdcncolpebgiejap": "Google Sheets",
    "aohghmighlieiainnegkcijnfilokake": "Google Docs",
    "apdfllfdahgahflhgihiffgeghgajagl": "Google Hangouts",
    "pjkljhegncpnkpknbcohdijeoejaffcm": "Google Security Key",
    "gfdkimpbcpahaombhbimeihdjnejgicl": "Brave Shields",
    "mnojpmjdhmbfiplnakflbeinfakpmepm": "Brave Rewards",
    "odbfpeeihdkbihmopkbjmoonfanlbfcl": "Brave News",
    "nekilbihkhleigikggagbeohhmfmgnap": "Microsoft Edge DevTools",
    "bbijccikjhflclhlkcgcbogbgcdaflha": "Microsoft Edge Collections",
    "inomeogfingihgjfjlpeplalcfajhgai": "Chrome Cloud Print",
    "hhaikkgfdolachndlhikkllbemgahaeg": "Chrome Auto Import",
    "mgndgkgfdbpggknjhimeogbmiefjdnmk": "Chrome Component Extension",
}

DANGEROUS_PERMISSIONS = {
    "cookies", "<all_urls>", "webRequest", "webRequestBlocking", "storage",
    "tabs", "management", "privacy", "proxy", "declarativeNetRequest", "nativeMessaging",
    "http://*/*", "https://*/*"
}


class AD1ExtensionAnalyzer:
    """
    Correlates and triages browser extensions and residual LevelDB storage.
    """
    def __init__(self, parser: AD1Parser):
        self.parser = parser

    def scan_and_triage(self) -> List[Dict[str, Any]]:
        if not self.parser.items:
            self.parser.build_tree()

        # Group items by User Profile directory
        # e.g., Users/Alice/AppData/Local/Google/Chrome/User Data/Default
        profile_map: Dict[str, Dict[str, Any]] = {}

        for item in self.parser.items:
            if item.is_dir:
                continue

            path_norm = item.full_path.replace("\\", "/")
            path_lower = path_norm.lower()

            # Identify Chromium user profile root
            m = re.search(r"(.*?/(?:google/chrome|microsoft/edge|brave-browser|opera software/[^/]+)/user data/[^/]+)", path_lower)
            if not m:
                # Also match generic Default / Profile \d+
                m = re.search(r"(.*?/(?:appdata/local|appdata/roaming)/[^/]+/[^/]+/[^/]+/[^/]+)", path_lower)
                if not m:
                    continue

            prof_root = m.group(1)
            if prof_root not in profile_map:
                profile_map[prof_root] = {
                    "preferences": None,
                    "secure_preferences": None,
                    "installed_extensions": set(),
                    "local_storage_files": {},  # ext_id -> {filename: bytes}
                    "sync_storage_files": {},
                    "indexeddb_folders": set(),
                    "profile_path": prof_root,
                    "user": self._extract_user_from_path(path_norm),
                    "browser": self._extract_browser_from_path(path_norm)
                }

            # 1. Preferences JSON
            if path_lower.endswith("/preferences") and "/extensions" not in path_lower:
                profile_map[prof_root]["preferences"] = item
            elif path_lower.endswith("/secure preferences"):
                profile_map[prof_root]["secure_preferences"] = item

            # 2. Installed Binary Extensions (Extensions/<ext_id>/<version>/...)
            m_ext = re.search(r"/extensions/([a-z0-9_]{32})/", path_lower)
            if m_ext:
                profile_map[prof_root]["installed_extensions"].add(m_ext.group(1))

            # 3. Local Extension Settings (Local Extension Settings/<ext_id>/<file>)
            m_loc = re.search(r"/local extension settings/([a-z0-9_]{32})/([^/]+)$", path_lower)
            if m_loc:
                ext_id = m_loc.group(1)
                file_name = m_loc.group(2)
                if ext_id not in profile_map[prof_root]["local_storage_files"]:
                    profile_map[prof_root]["local_storage_files"][ext_id] = {}
                # Read file bytes for LevelDB analysis
                b = self.parser.read_file_bytes(item)
                if b:
                    profile_map[prof_root]["local_storage_files"][ext_id][file_name] = b

            # 4. Sync Extension Settings
            m_sync = re.search(r"/sync extension settings/([a-z0-9_]{32})/([^/]+)$", path_lower)
            if m_sync:
                ext_id = m_sync.group(1)
                file_name = m_sync.group(2)
                if ext_id not in profile_map[prof_root]["sync_storage_files"]:
                    profile_map[prof_root]["sync_storage_files"][ext_id] = {}
                b = self.parser.read_file_bytes(item)
                if b:
                    profile_map[prof_root]["sync_storage_files"][ext_id][file_name] = b

            # 5. IndexedDB
            m_idx = re.search(r"/indexeddb/chrome-extension_([a-z0-9_]{32})_0\.indexeddb", path_lower)
            if m_idx:
                profile_map[prof_root]["indexeddb_folders"].add(m_idx.group(1))

        # Perform 3-point correlation for each profile
        all_triaged: List[Dict[str, Any]] = []

        for prof_root, pdata in profile_map.items():
            triaged = self._correlate_profile_extensions(pdata)
            all_triaged.extend(triaged)

        # Sort: Suspicious / Orphan first, then by name
        all_triaged.sort(key=lambda x: (not x["is_suspicious"], not x["is_orphan"], x["name"].lower()))
        return all_triaged

    def _correlate_profile_extensions(self, pdata: Dict[str, Any]) -> List[Dict[str, Any]]:
        results = []
        user = pdata["user"]
        browser = pdata["browser"]
        pref_settings: Dict[str, Any] = {}

        # Parse Preferences / Secure Preferences JSON
        target_pref = pdata["secure_preferences"] or pdata["preferences"]
        if target_pref:
            raw_bytes = self.parser.read_file_bytes(target_pref)
            if raw_bytes:
                try:
                    pref_json = json.loads(raw_bytes.decode("utf-8", errors="replace"))
                    pref_settings = pref_json.get("extensions", {}).get("settings", {})
                except Exception:
                    pass

        # Gather union of all extension IDs seen in Preferences, Extensions/, and Storage
        all_ext_ids = set(pref_settings.keys()) | pdata["installed_extensions"] | set(pdata["local_storage_files"].keys()) | set(pdata["sync_storage_files"].keys()) | pdata["indexeddb_folders"]

        for ext_id in all_ext_ids:
            if not ext_id or len(ext_id) < 16:
                continue

            is_builtin = ext_id in KNOWN_BUILTIN_EXTENSIONS
            builtin_name = KNOWN_BUILTIN_EXTENSIONS.get(ext_id)

            pref_info = pref_settings.get(ext_id, {})
            manifest = pref_info.get("manifest", {})

            # Extension Name
            name = builtin_name or manifest.get("name") or pref_info.get("path") or f"Extension [{ext_id[:8]}...]"
            version = manifest.get("version") or "N/A"
            description = manifest.get("description", "")
            
            # Install Source & Flags
            from_webstore = pref_info.get("from_webstore", True)
            was_installed_by_default = pref_info.get("was_installed_by_default", False)
            install_source = pref_info.get("location", 1)  # 1 = internal, 4 = external crx, etc.
            is_sideloaded = not from_webstore or install_source in [4, 5]

            # Timestamps
            install_time_raw = pref_info.get("install_time")
            install_time_dt = None
            if install_time_raw:
                try:
                    install_time_dt = webkit_to_datetime(int(install_time_raw))
                except Exception:
                    pass
            install_time_str = format_datetime(install_time_dt) if install_time_dt else "N/A"

            # Permissions
            declared_perms = manifest.get("permissions", [])
            if isinstance(declared_perms, list):
                perms_list = [str(p) for p in declared_perms]
            else:
                perms_list = []

            flagged_perms = [p for p in perms_list if any(dp in p.lower() for dp in DANGEROUS_PERMISSIONS)]

            # Check presence across locations
            has_binary_dir = ext_id in pdata["installed_extensions"]
            local_files = pdata["local_storage_files"].get(ext_id, {})
            sync_files = pdata["sync_storage_files"].get(ext_id, {})
            has_storage = bool(local_files or sync_files)
            has_indexeddb = ext_id in pdata["indexeddb_folders"]

            # Parse LevelDB storage files for C2s, tokens, cookies
            storage_kvs = []
            iocs = {"discord_webhooks": [], "telegram_bots": [], "suspicious_urls": [], "ip_endpoints": [], "cookie_keys": [], "extracted_json": []}
            
            if local_files:
                storage_kvs, iocs = parse_extension_leveldb_files(local_files)

            # Determine Status & Anomaly Score
            is_orphan = False
            status = "ACTIVE"
            score = 0
            flag_reasons = []

            if is_builtin:
                status = "BUILTIN / OFFICIAL"
            elif has_storage and not has_binary_dir:
                is_orphan = True
                status = "ORPHAN / PURGED (Deleted Extension)"
                score += 40
                flag_reasons.append("Residual LevelDB storage exists, but extension folder was DELETED/PURGED")
            elif not has_binary_dir and not has_storage:
                status = "UNINSTALLED (Manifest Only)"
            elif is_sideloaded:
                status = "SIDELOADED / UNPACKED"
                score += 30
                flag_reasons.append("Sideloaded from local directory / developer mode")

            if flagged_perms:
                score += len(flagged_perms) * 10
                flag_reasons.append(f"Dangerous permissions: {', '.join(flagged_perms)}")

            if iocs["discord_webhooks"]:
                score += 50
                flag_reasons.append(f"Exfiltration Discord Webhooks carved: {len(iocs['discord_webhooks'])}")
            if iocs["telegram_bots"]:
                score += 50
                flag_reasons.append(f"Exfiltration Telegram Bot API carved: {len(iocs['telegram_bots'])}")
            if iocs["cookie_keys"]:
                score += 35
                flag_reasons.append(f"Stolen session/cookie keys carved: {', '.join(iocs['cookie_keys'])}")
            if iocs["ip_endpoints"]:
                score += 25
                flag_reasons.append(f"Suspicious IP endpoints carved: {', '.join(iocs['ip_endpoints'][:3])}")

            is_suspicious = score >= 30 and not is_builtin

            results.append({
                "id": ext_id,
                "name": name,
                "version": version,
                "user": user,
                "browser": browser,
                "status": status,
                "is_builtin": is_builtin,
                "is_orphan": is_orphan,
                "is_sideloaded": is_sideloaded,
                "is_suspicious": is_suspicious,
                "anomaly_score": score,
                "flag_reasons": flag_reasons,
                "permissions": perms_list,
                "flagged_permissions": flagged_perms,
                "install_time": install_time_str,
                "install_time_obj": install_time_dt,
                "has_binary_dir": has_binary_dir,
                "has_storage": has_storage,
                "storage_file_count": len(local_files) + len(sync_files),
                "iocs": iocs,
                "storage_kvs_count": len(storage_kvs),
                "profile_path": pdata["profile_path"]
            })

        return results

    def _extract_user_from_path(self, path: str) -> str:
        m = re.search(r"(?:^|/|[a-zA-Z]:/)(?:Users|Documents and Settings|home)/([^/]+)/", path, re.IGNORECASE)
        return m.group(1) if m else "DefaultUser"

    def _extract_browser_from_path(self, path: str) -> str:
        p_low = path.lower()
        if "chrome" in p_low: return "Google Chrome"
        if "edge" in p_low: return "Microsoft Edge"
        if "brave" in p_low: return "Brave Browser"
        if "opera" in p_low: return "Opera"
        return "Chromium"


def print_extension_table(entries: List[Dict[str, Any]], show_all: bool = False, max_rows: int = 100):
    # By default, filter out benign built-ins unless show_all is requested
    display_entries = entries if show_all else [e for e in entries if not e.get("is_builtin")]
    
    if not display_entries:
        if not show_all and entries:
            console.print("[green] No third-party or suspicious extensions found (All detected extensions are built-in official browser components). Use --all to view built-in extensions.[/green]")
        else:
            console.print("[yellow] No browser extensions or residual storage found in the AD1 image.[/yellow]")
        return

    table = Table(
        title=f" Browser Extensions & Residual Storage Triage ({len(display_entries)} Total)",
        show_header=True,
        header_style="bold magenta",
        border_style="dim blue",
        expand=True
    )

    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("Extension Name", style="bold cyan", width=22)
    table.add_column("Extension ID", style="dim white", width=18)
    table.add_column("Status & Triage", style="bold", width=28)
    table.add_column("User / Browser", style="magenta", width=16)
    table.add_column("Flagged Artifacts & Carved IoCs", style="white", min_width=35, overflow="fold")

    for idx, item in enumerate(display_entries[:max_rows], start=1):
        name = item.get("name") or "Unknown"
        ext_id = item.get("id") or "N/A"
        short_id = f"{ext_id[:8]}...{ext_id[-6:]}" if len(ext_id) > 16 else ext_id
        status = item.get("status", "UNKNOWN")
        user_br = f"{item.get('user', 'User')}\n[dim]{item.get('browser', 'Chrome')}[/dim]"

        # Status styling
        if item.get("is_suspicious") or item.get("is_orphan"):
            status_styled = f"[bold red] {status}[/bold red]"
        elif item.get("is_sideloaded"):
            status_styled = f"[bold yellow] {status}[/bold yellow]"
        elif item.get("is_builtin"):
            status_styled = f"[dim green] {status}[/dim green]"
        else:
            status_styled = f"[green]{status}[/green]"

        # Findings Summary
        findings = []
        if item.get("flag_reasons"):
            for fr in item["flag_reasons"]:
                findings.append(f"[bold yellow]•[/bold yellow] {fr}")

        iocs = item.get("iocs", {})
        if iocs.get("discord_webhooks"):
            for wh in iocs["discord_webhooks"][:2]:
                findings.append(f"[bold red] Discord Webhook:[/bold red] [cyan]{wh}[/cyan]")
        if iocs.get("telegram_bots"):
            for tg in iocs["telegram_bots"][:2]:
                findings.append(f"[bold red] Telegram Bot:[/bold red] [cyan]{tg}[/cyan]")
        if iocs.get("cookie_keys"):
            findings.append(f"[bold red] Carved Cookies:[/bold red] {', '.join(iocs['cookie_keys'])}")
        if iocs.get("ip_endpoints"):
            findings.append(f"[bold yellow] Carved IPs:[/bold yellow] {', '.join(iocs['ip_endpoints'][:3])}")

        findings_text = "\n".join(findings) if findings else "[dim]Normal / Clean[/dim]"

        table.add_row(
            str(idx),
            name,
            short_id,
            status_styled,
            user_br,
            findings_text
        )

    console.print(table)

    if len(display_entries) > max_rows:
        console.print(f"[italic dim]... showing top {max_rows} of {len(display_entries)} records. Use --export-all or --md to view all records.[/italic dim]\n")

    # Forensic Insights Panel
    orphans = [e for e in entries if e.get("is_orphan")]
    suspicious = [e for e in entries if e.get("is_suspicious")]
    sideloaded = [e for e in entries if e.get("is_sideloaded")]

    summary = Text()
    summary.append(" Browser Extension Forensic Insights:\n", style="bold green")
    summary.append(f"  • Total Extensions Detected : {len(entries)} (Third-Party/Storage: {len(display_entries)}, Built-in: {len(entries) - len(display_entries)})\n", style="white")
    if orphans:
        summary.append(f"  • Orphan / Deleted Storage  : {len(orphans)} residual extension folders found (binary purged)!\n", style="bold red")
    if suspicious:
        summary.append(f"  • High-Signal Suspicious    : {len(suspicious)} extensions flagged with malicious indicators/IoCs!\n", style="bold red")
    if sideloaded:
        summary.append(f"  • Sideloaded / Unpacked     : {len(sideloaded)} extensions installed outside official Web Store.\n", style="yellow")

    console.print(Panel(summary, border_style="red" if suspicious or orphans else "green", title="Extension Triage Insights", title_align="left"))


def export_extensions_markdown(entries: List[Dict[str, Any]], output_path: str, source_name: str = "Evidence Image"):
    generated_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    orphans = [e for e in entries if e.get("is_orphan")]
    suspicious = [e for e in entries if e.get("is_suspicious")]

    lines = [
        f"# DFIR Forensic Report - Browser Extensions & Residual Storage",
        f"- **Evidence Source:** `{source_name}`",
        f"- **Generated:** `{generated_time}`",
        f"- **Total Extensions Analyzed:** `{len(entries)}`",
        "",
        "## Summary Insights",
        f"- **High-Risk / Suspicious Extensions:** `{len(suspicious)}`",
        f"- **Orphan Storage (Purged/Deleted Binary):** `{len(orphans)}`",
        "",
        "## Extension Triage Details",
        "| # | Name | ID Hash | User & Browser | Status | Flagged Permissions / Findings | Carved IoCs (C2 / Cookies) |",
        "|---|---|---|---|---|---|---|"
    ]

    for idx, item in enumerate(entries, start=1):
        name = (item.get("name") or "Unknown").replace("|", "\\|")
        ext_id = item.get("id") or "N/A"
        user = item.get("user", "User")
        browser = item.get("browser", "Chrome")
        status = item.get("status", "ACTIVE")

        if item.get("is_suspicious") or item.get("is_orphan"):
            status_md = f" **`{status}`**"
        else:
            status_md = f"`{status}`"

        # Findings
        findings_list = item.get("flag_reasons", [])
        findings_md = "<br>".join([f"• {f}" for f in findings_list]) if findings_list else "*Clean*"

        # Carved IoCs
        iocs = item.get("iocs", {})
        ioc_lines = []
        if iocs.get("discord_webhooks"):
            for wh in iocs["discord_webhooks"]:
                ioc_lines.append(f" **Discord Webhook:** `{wh}`")
        if iocs.get("telegram_bots"):
            for tg in iocs["telegram_bots"]:
                ioc_lines.append(f" **Telegram Bot:** `{tg}`")
        if iocs.get("cookie_keys"):
            ioc_lines.append(f" **Cookies:** `{', '.join(iocs['cookie_keys'])}`")
        if iocs.get("ip_endpoints"):
            ioc_lines.append(f" **IPs:** `{', '.join(iocs['ip_endpoints'])}`")

        iocs_md = "<br>".join(ioc_lines) if ioc_lines else "*None*"

        lines.append(f"| {idx} | **{name}** | `{ext_id}` | {user}<br>({browser}) | {status_md} | {findings_md} | {iocs_md} |")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    console.print(f"[bold green][/bold green] Exported {len(entries)} Extension records to Markdown (MD): [cyan]{output_path}[/cyan]")


def export_extensions_json(entries: List[Dict[str, Any]], output_path: str):
    clean = []
    for e in entries:
        d = dict(e)
        if "install_time_obj" in d:
            if d["install_time_obj"]:
                d["install_time_iso"] = d["install_time_obj"].isoformat()
            del d["install_time_obj"]
        clean.append(d)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(clean, f, indent=2, ensure_ascii=False)
    console.print(f"[bold green][/bold green] Exported {len(entries)} Extension records to JSON: [cyan]{output_path}[/cyan]")


def export_extensions_csv(entries: List[Dict[str, Any]], output_path: str):
    import csv
    fieldnames = ["id", "name", "version", "user", "browser", "status", "is_suspicious", "is_orphan", "is_sideloaded", "flag_reasons", "permissions", "discord_webhooks", "telegram_bots", "cookie_keys", "install_time", "profile_path"]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for e in entries:
            row = dict(e)
            row["flag_reasons"] = "; ".join(e.get("flag_reasons", []))
            row["permissions"] = "; ".join(e.get("permissions", []))
            iocs = e.get("iocs", {})
            row["discord_webhooks"] = "; ".join(iocs.get("discord_webhooks", []))
            row["telegram_bots"] = "; ".join(iocs.get("telegram_bots", []))
            row["cookie_keys"] = "; ".join(iocs.get("cookie_keys", []))
            writer.writerow(row)
    console.print(f"[bold green][/bold green] Exported {len(entries)} Extension records to CSV: [cyan]{output_path}[/cyan]")


def export_extensions_html(entries: List[Dict[str, Any]], output_path: str, source_name: str = "Evidence Image"):
    clean = []
    for e in entries:
        d = dict(e)
        if "install_time_obj" in d:
            if d["install_time_obj"]:
                d["install_time_iso"] = d["install_time_obj"].isoformat()
            del d["install_time_obj"]
        clean.append(d)

    json_payload = json.dumps(clean, ensure_ascii=False)
    generated_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>DFIR Forensic Report - Extensions & Residual Storage ({source_name})</title>
    <style>
        :root {{ --bg: #0f172a; --surface: #1e293b; --surface-hover: #334155; --border: #334155; --text: #f8fafc; --text-muted: #94a3b8; --accent: #38bdf8; --danger: #f43f5e; }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
        body {{ background: var(--bg); color: var(--text); padding: 24px; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 20px; }}
        .title {{ font-size: 24px; font-weight: 700; }}
        .title span {{ color: var(--accent); }}
        .badge {{ background: #881337; color: #fecdd3; padding: 4px 10px; border-radius: 999px; font-size: 12px; font-weight: 600; }}
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
        .status-danger {{ color: var(--danger); font-weight: 700; }}
        .status-warn {{ color: #fbbf24; font-weight: 600; }}
        .status-clean {{ color: #4ade80; }}
        .ioc-box {{ background: #450a0a; border: 1px solid #991b1b; padding: 6px 10px; border-radius: 4px; color: #fca5a5; font-size: 12px; margin-top: 4px; }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <div class="title">DFIR <span>Browser Extensions & Residual Storage</span> Report</div>
            <div style="font-size: 13px; color: var(--text-muted); margin-top: 4px;">Evidence: <strong>{source_name}</strong> | Generated: {generated_time}</div>
        </div>
        <div class="badge">LevelDB & Residual Triage</div>
    </div>
    <div class="stats-grid">
        <div class="card"><div class="label">Total Extensions</div><div class="val">{len(entries)}</div></div>
        <div class="card"><div class="label">Suspicious / High Risk</div><div class="val" style="color: var(--danger);">{len([e for e in entries if e.get('is_suspicious')])}</div></div>
        <div class="card"><div class="label">Orphan / Purged Storage</div><div class="val" style="color: #fbbf24;">{len([e for e in entries if e.get('is_orphan')])}</div></div>
    </div>
    <div class="controls">
        <input type="text" id="searchInput" class="search-box" placeholder=" Search Extension Name, ID, User, Permissions, or Carved C2 Webhook...">
    </div>
    <table>
        <thead>
            <tr>
                <th style="width: 50px;">#</th>
                <th style="width: 200px;">Extension Name & ID</th>
                <th style="width: 140px;">User & Browser</th>
                <th style="width: 180px;">Status</th>
                <th>Findings & Carved IoCs</th>
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
                const iocs = item.iocs || {{}};
                let iocHtml = '';
                if (iocs.discord_webhooks && iocs.discord_webhooks.length) {{
                    iocHtml += `<div class="ioc-box"> <strong>Discord Webhook:</strong> ${{iocs.discord_webhooks.join(', ')}}</div>`;
                }}
                if (iocs.telegram_bots && iocs.telegram_bots.length) {{
                    iocHtml += `<div class="ioc-box"> <strong>Telegram Bot:</strong> ${{iocs.telegram_bots.join(', ')}}</div>`;
                }}
                if (iocs.cookie_keys && iocs.cookie_keys.length) {{
                    iocHtml += `<div class="ioc-box" style="background:#1e1b4b;border-color:#4338ca;color:#c7d2fe;"> <strong>Stolen Cookies:</strong> ${{iocs.cookie_keys.join(', ')}}</div>`;
                }}

                let statusClass = item.is_suspicious || item.is_orphan ? 'status-danger' : (item.is_sideloaded ? 'status-warn' : 'status-clean');

                tr.innerHTML = `
                    <td style="color: #64748b;">${{idx + 1}}</td>
                    <td>
                        <strong style="color: #38bdf8;">${{item.name || 'Unknown'}}</strong>
                        <div style="font-size: 11px; color: #94a3b8; font-family: monospace; margin-top: 2px;">${{item.id || ''}}</div>
                    </td>
                    <td>${{item.user || 'User'}}<br><span style="font-size: 11px; color: #94a3b8;">${{item.browser || ''}}</span></td>
                    <td class="${{statusClass}}">${{item.status || 'ACTIVE'}}</td>
                    <td>
                        <div style="color: #e2e8f0;">${{(item.flag_reasons || []).join('<br>• ')}}</div>
                        ${{iocHtml}}
                    </td>
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
    console.print(f"[bold green][/bold green] Generated interactive HTML Extension report: [cyan]{output_path}[/cyan]")


def main(args_list=None):
    parser = argparse.ArgumentParser(
        prog="ad1 extensions",
        description=" Triage browser extensions, detect orphan residual LevelDB storage, and carve C2s/cookies from AccessData AD1 images.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ad1extensions evidence.ad1
  ad1extensions evidence.ad1 --all
  ad1extensions evidence.ad1 --md extensions_report.md --json extensions.json
  ad1extensions evidence.ad1 --export-all
        """
    )
    parser.add_argument("input", help="Path to input AD1 image file")
    parser.add_argument("-q", "--query", help="Filter by extension name, ID, user, or C2/cookie keyword")
    parser.add_argument("-a", "--all", action="store_true", help="Show all extensions including official built-in browser components")
    parser.add_argument("-l", "--limit", type=int, default=100, help="Row display limit in terminal (default: 100)")
    
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

    print_ad1_banner("AD1 BROWSER EXTENSIONS & ORPHAN TRIAGE (ad1extensions)")
    console.print(f"[dim]Opening image container:[/dim] [cyan]{args.input}[/cyan]\n")

    with console.status("[bold cyan]Scanning Preferences, Extensions & LevelDB residual storage...[/bold cyan]"):
        parser_ad1 = AD1Parser(args.input)
        analyzer = AD1ExtensionAnalyzer(parser_ad1)
        entries = analyzer.scan_and_triage()

    if not entries:
        console.print("[bold yellow] No browser profiles or extension artifacts found in the AD1 container.[/bold yellow]")
        parser_ad1.close()
        return

    if args.query:
        q_low = args.query.lower()
        entries = [
            e for e in entries
            if q_low in (e.get("name") or "").lower()
            or q_low in (e.get("id") or "").lower()
            or q_low in (e.get("user") or "").lower()
            or q_low in str(e.get("flag_reasons") or "").lower()
            or q_low in str(e.get("iocs") or "").lower()
        ]

    limit = args.limit if args.limit else 100
    print_extension_table(entries, show_all=args.all, max_rows=limit)

    base_name = os.path.splitext(os.path.basename(args.input))[0]
    if args.export_all:
        if not args.md: args.md = f"{base_name}_extensions.md"
        if not args.json: args.json = f"{base_name}_extensions.json"
        if not args.csv: args.csv = f"{base_name}_extensions.csv"
        if not args.html: args.html = f"{base_name}_extensions.html"

    if hasattr(args, 'md') and args.md: export_extensions_markdown(entries, args.md, source_name=base_name)
    if hasattr(args, 'json') and args.json: export_extensions_json(entries, args.json)
    if hasattr(args, 'csv') and args.csv: export_extensions_csv(entries, args.csv)
    if hasattr(args, 'html') and args.html: export_extensions_html(entries, args.html, source_name=base_name)

    parser_ad1.close()


if __name__ == "__main__":
    main()
