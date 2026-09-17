"""
Windows Memory Dump & Process Analyzer (dmpscan / dmp/scanner.py)
Automates digital forensics and CTF triage on Windows Minidump (.dmp) files:
1. Process Triage & PEB Reconnaissance (!peb, PID, Architecture, Command Line, Env Variables)
2. Loaded Modules Matrix (lm, Base Address, Size, Version, Paths)
3. In-Memory CTF Flag Hunter (ASCII, UTF-16LE, Base64)
4. Multi-format Exports (Terminal Tables, Markdown, JSON)
"""
import os
import sys
import argparse
import re
import base64
import json
import hashlib
from typing import List, Dict, Any, Optional, Set, Tuple

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.markup import escape

from core.banner import print_banner
from core.utils import human_size
from dmp.dmp_engine import DMPEngine, DMPModule, DMPMemorySegment

console = Console(force_terminal=True, legacy_windows=False)

# Strict Flag Regex for CTF flags without noise from NTSTATUS errors
DEFAULT_FLAG_REGEX = re.compile(
    r"(?:[A-Za-z0-9_\.\-]{2,40}\{[A-Za-z0-9_!@#\$%\^&\*\(\)\-\+=\.\?\/:;\s]{2,200}\})"
    r"|(?:flag\[[A-Za-z0-9_\-\s]{2,100}\])"
    r"|(?:FLAG\[[A-Za-z0-9_\-\s]{2,100}\])",
    re.IGNORECASE
)


def is_valid_flag_str(val: str) -> bool:
    if not val or len(val) < 6 or len(val) > 250:
        return False
    if not all(32 <= ord(c) <= 126 for c in val):
        return False
    if not re.search(r"[A-Za-z0-9]{2,}", val):
        return False
    if "{" in val and not val.endswith("}"):
        return False
    # Filter out common programming / OS artifacts
    if any(val.startswith(x) for x in ["typedef", "struct", "class", "namespace", "import", "using", "function", "void"]):
        return False
    return True


class DMPScanner:
    def __init__(self, engine: DMPEngine, custom_prefix: Optional[str] = None):
        self.engine = engine
        self.custom_prefix = custom_prefix
        self.flags: List[Dict[str, Any]] = []
        self.seen_flags: Set[str] = set()

    def scan(self) -> Dict[str, Any]:
        self.engine.analyze()
        self.flags = []
        self.seen_flags = set()

        flag_patterns = [DEFAULT_FLAG_REGEX]
        if self.custom_prefix:
            pref_escaped = re.escape(self.custom_prefix)
            custom_re = re.compile(rf"{pref_escaped}\{{[^}}\r\n\x00]{{2,200}}\}}", re.IGNORECASE)
            flag_patterns.insert(0, custom_re)

        for seg in self.engine.segments:
            try:
                data = self.engine.read_bytes(seg.start_addr, seg.size)
                if not data:
                    continue

                # 1. Flag Hunting in ASCII
                ascii_text = data.decode("latin-1", errors="replace")
                self._hunt_flags(ascii_text, seg.start_addr, flag_patterns, "ASCII Memory")

                # 2. Flag Hunting in UTF-16LE
                try:
                    utf16_text = data.decode("utf-16le", errors="ignore")
                    self._hunt_flags(utf16_text, seg.start_addr, flag_patterns, "Unicode (UTF-16LE)")
                except Exception:
                    pass

                # 3. Base64 Carving & Decoding in Memory
                self._carve_base64_flags(ascii_text, seg.start_addr, flag_patterns)

            except Exception:
                continue

        return {
            "flags": self.flags
        }

    def _hunt_flags(self, text: str, base_addr: int, patterns: List[Any], enc_label: str):
        for pat in patterns:
            for m in pat.finditer(text):
                fv = m.group(0).strip().replace("\x00", "")
                if is_valid_flag_str(fv) and fv not in self.seen_flags:
                    self.seen_flags.add(fv)
                    self.flags.append({
                        "flag": fv,
                        "vaddr": f"0x{base_addr + m.start():X}",
                        "encoding": enc_label,
                        "length": len(fv)
                    })

    def _carve_base64_flags(self, text: str, base_addr: int, patterns: List[Any]):
        for bm in re.finditer(r"(?:[A-Za-z0-9+/]{16,}={0,2})", text):
            cand = bm.group(0)
            if len(cand) % 4 == 0:
                try:
                    dec_b = base64.b64decode(cand, validate=True)
                    if dec_b and all(32 <= c <= 126 or c in (10, 13, 9) for c in dec_b):
                        dec_str = dec_b.decode("utf-8", errors="ignore").strip()
                        self._hunt_flags(dec_str, base_addr + bm.start(), patterns, "Base64 Decoded")
                except Exception:
                    pass


# -------------------------------------------------------------
# Rich Console Rendering
# -------------------------------------------------------------

def print_peb_table(engine: DMPEngine):
    panel_content = (
        f"[bold cyan]Process Name:[/bold cyan] [bold white]{engine.process_name or 'N/A'}[/bold white]\n"
        f"[bold cyan]Process ID (PID):[/bold cyan] [yellow]{engine.pid}[/yellow]\n"
        f"[bold cyan]Architecture:[/bold cyan] {engine.architecture} | [bold cyan]OS Version:[/bold cyan] {engine.os_version}\n"
        f"[bold cyan]Creation Time:[/bold cyan] {engine.create_time.strftime('%Y-%m-%d %H:%M:%S UTC') if engine.create_time else 'N/A'}\n"
        f"[bold cyan]Memory Size:[/bold cyan] {human_size(engine.file_size)} | [bold cyan]Committed Segments:[/bold cyan] {len(engine.segments):,}"
    )
    console.print(Panel(panel_content, title=" Process Information & Environment Summary", border_style="bold green"))

    if engine.peb_info.get("environment_variables"):
        env_table = Table(
            title=" Recovered Environment Variables",
            show_header=True,
            header_style="bold magenta",
            border_style="dim cyan",
            expand=True
        )
        env_table.add_column("Variable", style="bold cyan", width=26)
        env_table.add_column("Value", style="white", overflow="fold")

        for k, v in list(engine.peb_info["environment_variables"].items())[:20]:
            env_table.add_row(escape(k), escape(v))

        console.print(env_table)
        console.print()


def print_modules_table(engine: DMPEngine, limit: int = 50):
    if not engine.modules:
        return

    table = Table(
        title=f" Loaded Modules & Libraries ({len(engine.modules)} Modules)",
        show_header=True,
        header_style="bold yellow",
        border_style="bold cyan",
        expand=True
    )
    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("Base Address", style="bold magenta", width=18)
    table.add_column("Size", style="yellow", width=12, justify="right")
    table.add_column("Module Name / Path", style="bold white", min_width=30, overflow="fold")
    table.add_column("Version", style="dim cyan", width=18)

    for idx, m in enumerate(engine.modules[:limit], start=1):
        table.add_row(
            str(idx),
            f"0x{m.base_addr:016X}",
            human_size(m.size),
            escape(m.name),
            escape(m.version)
        )

    console.print(table)
    if len(engine.modules) > limit:
        console.print(f"[dim]... and {len(engine.modules) - limit} more modules (use --limit to expand)[/dim]")
    console.print()


def print_flags_table(flags: List[Dict[str, Any]]):
    if not flags:
        console.print("[yellow][i] No CTF flags matched across memory space.[/yellow]")
        return

    table = Table(
        title=f" Captured CTF Flags ({len(flags)} Found in Memory)",
        show_header=True,
        header_style="bold magenta",
        border_style="bold green",
        expand=True
    )
    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("Captured Flag / Objective", style="bold white on dark_green", min_width=32, overflow="fold")
    table.add_column("Virtual Address", style="bold cyan", width=20, justify="center")
    table.add_column("Encoding", style="yellow", width=22, justify="center")

    for idx, f in enumerate(flags, start=1):
        table.add_row(
            str(idx),
            escape(f" {f['flag']} "),
            f["vaddr"],
            f["encoding"]
        )

    console.print(table)


def export_markdown_report(engine: DMPEngine, results: Dict[str, Any], output_path: str):
    lines = [
        f"# Windows Memory Dump Analysis Report",
        f"- **File:** `{os.path.basename(engine.file_path)}`",
        f"- **Process Name:** `{engine.process_name}`",
        f"- **PID:** `{engine.pid}`",
        f"- **Architecture:** `{engine.architecture}`",
        f"- **OS Version:** `{engine.os_version}`",
        "",
        "##  Captured CTF Flags",
        "| # | Flag | Address | Encoding |",
        "|---|---|---|---|"
    ]
    for idx, f in enumerate(results["flags"], start=1):
        lines.append(f"| {idx} | **`{f['flag'].replace('|', '\\|')}`** | `{f['vaddr']}` | {f['encoding']} |")

    lines.append("\n##  Loaded Modules")
    lines.append("| Base Address | Size | Module Name | Version |")
    lines.append("|---|---|---|---|")
    for m in engine.modules[:100]:
        lines.append(f"| `0x{m.base_addr:016X}` | {human_size(m.size)} | `{m.name}` | `{m.version}` |")

    with open(output_path, "w", encoding="utf-8") as fp:
        fp.write("\n".join(lines) + "\n")
    console.print(f"[bold green][/bold green] Exported DMP report to Markdown: [cyan]{output_path}[/cyan]")


def main(args_list=None):
    parser = argparse.ArgumentParser(
        prog="dmpscan",
        description=" Windows Minidump & Process Memory Forensics Analyzer (PEB, Modules, Flags)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  dmpscan DbgInfo.DMP
  dmpscan memory.dmp --peb
  dmpscan memory.dmp --modules
  dmpscan memory.dmp --flags-only
  dmpscan memory.dmp -p "FLAG{"
  dmpscan memory.dmp --export-all
        """
    )
    parser.add_argument("dmp_file", help="Path to Windows Minidump / Memory Dump (.dmp) file")
    parser.add_argument("-p", "--prefix", help="Custom CTF flag prefix (e.g. 'FLAG', 'HTB', 'cyber')")
    parser.add_argument("-l", "--limit", type=int, default=50, help="Row display limit (default: 50)")

    # Display filters
    parser.add_argument("--peb", action="store_true", help="Display only PEB and environment variables")
    parser.add_argument("--modules", action="store_true", help="Display only loaded modules list (lm)")
    parser.add_argument("--flags-only", action="store_true", help="Display only discovered CTF flags")

    # Exports
    parser.add_argument("--md", "--markdown", dest="md", help="Export report to Markdown (.md)")
    parser.add_argument("--json", help="Export report to JSON file")
    parser.add_argument("--export-all", action="store_true", help="Generate MD and JSON reports automatically")

    args = parser.parse_args(args_list)

    if not os.path.exists(args.dmp_file):
        console.print(f"[bold red]Error:[/bold red] File not found: {args.dmp_file}")
        sys.exit(1)

    print_banner(
        tool_name="WINDOWS MEMORY & PROCESS ANALYZER (dmpscan)",
        sub_title="Process Triage, PEB, Loaded Modules & In-Memory Flag Hunter"
    )

    engine = DMPEngine(args.dmp_file)
    with console.status("[bold cyan]Parsing memory segments, PEB & scanning virtual memory space...[/bold cyan]"):
        scanner = DMPScanner(engine, custom_prefix=args.prefix)
        results = scanner.scan()

    if args.peb:
        print_peb_table(engine)
    elif args.modules:
        print_modules_table(engine, limit=args.limit)
    elif args.flags_only:
        print_flags_table(results["flags"])
    else:
        print_peb_table(engine)
        print_modules_table(engine, limit=args.limit)
        print_flags_table(results["flags"])

        # Show helpful tip for dmpdump
        main_exe_name = engine.process_name or "main.exe"
        main_base = "0x0"
        for m in engine.modules:
            if m.name.lower().endswith(".exe"):
                main_base = f"0x{m.base_addr:X}"
                break
        console.print()
        console.print(Panel(
            f"[bold white] Next Step - Memory & Binary Dumping:[/bold white]\n"
            f"To dump the main executable or any memory address to disk, run:\n"
            f"  [bold yellow]dmpdump {args.dmp_file} --main -o ./{main_exe_name}[/bold yellow]\n"
            f"  [bold yellow]dmpdump {args.dmp_file} -i {main_base} -o ./{main_exe_name}[/bold yellow]\n"
            f"  [bold yellow]dmpdump {args.dmp_file} --all-modules -o ./dumped_modules/[/bold yellow]",
            title=" Extract Binaries with dmpdump",
            border_style="cyan"
        ))

    base_name = os.path.splitext(os.path.basename(args.dmp_file))[0]
    if args.export_all:
        if not args.md: args.md = f"{base_name}_dmpscan.md"
        if not args.json: args.json = f"{base_name}_dmpscan.json"

    if hasattr(args, 'md') and args.md:
        export_markdown_report(engine, results, args.md)
    if hasattr(args, 'json') and args.json:
        with open(args.json, "w", encoding="utf-8") as fp:
            json.dump({
                "process": {
                    "name": engine.process_name,
                    "pid": engine.pid,
                    "arch": engine.architecture,
                    "os": engine.os_version,
                    "env": engine.peb_info.get("environment_variables", {})
                },
                "modules": [{"name": m.name, "base": f"0x{m.base_addr:X}", "size": m.size} for m in engine.modules],
                "flags": results["flags"]
            }, fp, indent=2, ensure_ascii=False)
        console.print(f"[bold green][/bold green] Exported DMP scan report to JSON: [cyan]{args.json}[/cyan]")


if __name__ == "__main__":
    main()
