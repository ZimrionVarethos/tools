"""
Ghidra Interactive On-Demand AI Companion CLI (exe/ghidrabridge.py)
Command / Alias: ghidrabridge, ghidracli

Interacts strictly ON-DEMAND with active Ghidra instance via local bridge (http://127.0.0.1:13370).
Nothing runs automatically without user command.
"""
import sys
import os
import json
import urllib.request
import urllib.error
import argparse

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich.markup import escape

from core.banner import print_banner

console = Console(force_terminal=True, legacy_windows=False)
def get_candidate_urls(endpoint: str) -> list:
    urls = []

    # 1. Try WSL default route gateway (e.g. 172.27.80.1)
    try:
        import subprocess
        out = subprocess.check_output(["ip", "route", "show", "default"], text=True)
        for part in out.split():
            if part.count('.') == 3:
                urls.append(f"http://{part}:13370{endpoint}")
                break
    except Exception:
        pass

    # 2. Localhost & loopbacks
    urls.extend([
        f"http://127.0.0.1:13370{endpoint}",
        f"http://localhost:13370{endpoint}"
    ])

    # 3. Check WSL nameserver
    if os.path.exists("/etc/resolv.conf"):
        try:
            with open("/etc/resolv.conf", "r") as f:
                for line in f:
                    if line.strip().startswith("nameserver"):
                        ns = line.split()[1]
                        urls.append(f"http://{ns}:13370{endpoint}")
        except Exception:
            pass

    return urls

def query_bridge(endpoint: str, method: str = "GET", data: dict = None) -> dict:
    candidate_urls = get_candidate_urls(endpoint)
    body = json.dumps(data).encode("utf-8") if data else None
    last_err = None

    for url in candidate_urls:
        req = urllib.request.Request(url, method=method)
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, data=body, timeout=3) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            last_err = e

    console.print("[bold red][-] Ghidra AI Bridge Server is NOT running or not reachable.[/bold red]")
    console.print("[dim]Cara mengaktifkan di Ghidra:\n1. Buka Ghidra GUI di Windows\n2. Menu: 'Window' -> 'Script Manager'\n3. Cari 'GhidraAIBridge.java' -> Klik tombol Run (Play hijau)\n4. Bridge akan aktif di background (tanpa popup naga!).[/dim]")
    sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        prog="ghidracli",
        description=" Ghidra On-Demand AI Companion CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # 1. Check if Ghidra bridge is connected:
  ghidracli status

  # 2. Decompile & inspect function at cursor position in Ghidra:
  ghidracli current

  # 3. Decompile function at a specific address:
  ghidracli decompile 0x14000115a

  # 4. Show cross-references (XREFs) to an address:
  ghidracli xref 0x1400014b0

  # 5. Rename a function in Ghidra on-demand:
  ghidracli rename 0x140001100 rc4_decrypt_payload

  # 6. Add comment to an instruction in Ghidra:
  ghidracli comment 0x14000115a "RC4 Decryption Key: xobvrE_x11mb"
        """
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Status
    subparsers.add_parser("status", help="Check bridge connection status")

    # Current
    subparsers.add_parser("current", help="Inspect function at current cursor position")

    # Decompile
    dec_p = subparsers.add_parser("decompile", help="Decompile function at address")
    dec_p.add_argument("address", help="Target memory address (e.g. 0x14000115a)")

    # XREF
    xref_p = subparsers.add_parser("xref", help="List all cross-references to address")
    xref_p.add_argument("address", help="Target memory address")

    # Rename
    ren_p = subparsers.add_parser("rename", help="Rename function at address")
    ren_p.add_argument("address", help="Target memory address")
    ren_p.add_argument("name", help="New function name")

    # Comment
    com_p = subparsers.add_parser("comment", help="Add plate comment at address")
    com_p.add_argument("address", help="Target memory address")
    com_p.add_argument("text", help="Comment text")

    # Strings
    subparsers.add_parser("strings", help="List defined strings in active program")

    args = parser.parse_args()

    if not args.command or args.command == "status":
        res = query_bridge("/status")
        print_banner(tool_name="GHIDRA AI COMPANION (ghidracli)", sub_title="On-Demand Interactive Ghidra Bridge")
        console.print(f"[bold green] Connected to Ghidra Instance![/bold green]")
        console.print(f"[bold cyan]Active Program:[/bold cyan] [bold white]{res.get('program')}[/bold white]")
        console.print(f"[bold cyan]Image Base:[/bold cyan] [bold magenta]{res.get('base')}[/bold magenta]\n")
        return

    print_banner(tool_name="GHIDRA AI COMPANION (ghidracli)", sub_title="On-Demand Interactive Ghidra Bridge")

    if args.command == "current":
        res = query_bridge("/current")
        console.print(f"[bold cyan]Cursor Address:[/bold cyan] {res.get('address')} | [bold cyan]Function:[/bold cyan] {res.get('function')} (Entry: {res.get('entry')})\n")
        code = res.get("code", "")
        if code:
            syntax = Syntax(code, "c", theme="monokai", line_numbers=True)
            console.print(Panel(syntax, title=f"Decompiled: {res.get('function')}", border_style="bold green"))

    elif args.command == "decompile":
        res = query_bridge(f"/decompile?addr={args.address}")
        console.print(f"[bold cyan]Function Name:[/bold cyan] {res.get('function')} | [bold cyan]Entry:[/bold cyan] {res.get('entry')}\n")
        code = res.get("code", "")
        if code:
            syntax = Syntax(code, "c", theme="monokai", line_numbers=True)
            console.print(Panel(syntax, title=f"Decompiled: {res.get('function')}", border_style="bold green"))

    elif args.command == "xref":
        res = query_bridge(f"/xrefs?addr={args.address}")
        xrefs = res.get("xrefs", [])
        table = Table(title=f"Cross-References to {args.address} ({len(xrefs)} found)", show_header=True, header_style="bold magenta", expand=True)
        table.add_column("From Address", style="bold cyan")
        table.add_column("Reference Type", style="bold yellow")
        for x in xrefs:
            table.add_row(x["from"], x["type"])
        console.print(table)

    elif args.command == "rename":
        res = query_bridge("/rename", method="POST", data={"addr": args.address, "name": args.name})
        console.print(f"[bold green] {res.get('message')}[/bold green]")

    elif args.command == "comment":
        res = query_bridge("/comment", method="POST", data={"addr": args.address, "comment": args.text})
        console.print(f"[bold green] {res.get('message')}[/bold green]")

    elif args.command == "strings":
        res = query_bridge("/strings")
        strings = res.get("strings", [])
        table = Table(title=f"Defined Strings in Program ({len(strings)} previewed)", show_header=True, header_style="bold cyan", expand=True)
        table.add_column("Memory Address", style="bold magenta", width=18)
        table.add_column("String Value", style="white")
        for s in strings:
            table.add_row(s["addr"], escape(s["value"]))
        console.print(table)

if __name__ == "__main__":
    main()
