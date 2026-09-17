"""
Ghidra Interactive On-Demand AI Companion Analyzer & Navigator (assembly/ghidra/analyzer.py)
Alias: ghidraanalyze, ghidracli, ghidrabridge

Full-featured CLI tool communicating with Ghidra GUI on-demand:
1. Status & Active Program inspection
2. Move GUI Cursor (goto)
3. Search (Strings, Symbols, Windows APIs)
4. Call Tree (Callers & Callees)
5. Function Variables & Stack Inspector (vars)
6. Decompilation with Rich C Syntax Highlighting (decompile, current)
7. Dynamic Refactoring (rename, comment)
"""
import sys
import os
import json
import urllib.request
import urllib.parse
import urllib.error
import argparse

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich.tree import Tree
from rich.markup import escape

from core.banner import print_banner
from core.utils import human_size

console = Console(force_terminal=True, legacy_windows=False)

def get_candidate_urls(endpoint: str) -> list:
    ports = [13370, 13371, 13372, 13373, 13374, 13375]
    # Check port file if available
    port_files = [
        os.path.expanduser("~/.ghidra_bridge_port"),
        "/mnt/c/Users/ASUS Series/.ghidra_bridge_port"
    ]
    for pf in port_files:
        if os.path.exists(pf):
            try:
                with open(pf, "r") as f:
                    p_val = int(f.read().strip())
                    if p_val not in ports:
                        ports.insert(0, p_val)
                    else:
                        ports.remove(p_val)
                        ports.insert(0, p_val)
            except Exception:
                pass

    hosts = []
    # 1. WSL default route gateway (e.g. 172.27.80.1)
    try:
        import subprocess
        out = subprocess.check_output(["ip", "route", "show", "default"], text=True)
        for part in out.split():
            if part.count('.') == 3:
                hosts.append(part)
                break
    except Exception:
        pass

    # 2. Localhost & loopbacks
    hosts.extend(["127.0.0.1", "localhost"])

    # 3. Check WSL nameserver
    if os.path.exists("/etc/resolv.conf"):
        try:
            with open("/etc/resolv.conf", "r") as f:
                for line in f:
                    if line.strip().startswith("nameserver"):
                        hosts.append(line.split()[1])
        except Exception:
            pass

    urls = []
    for p in ports:
        for h in hosts:
            urls.append(f"http://{h}:{p}{endpoint}")

    return urls

def query_bridge(endpoint: str, method: str = "GET", data: dict = None) -> dict:
    candidate_urls = get_candidate_urls(endpoint)
    body = json.dumps(data).encode("utf-8") if data else None

    for url in candidate_urls:
        req = urllib.request.Request(url, method=method)
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, data=body, timeout=3) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception:
            pass

    console.print("[bold red][-] Ghidra AI Bridge Server is NOT running or not reachable.[/bold red]")
    console.print("[dim]Cara mengaktifkan di Ghidra:\n1. Buka Ghidra GUI di Windows\n2. Menu: 'Window' -> 'Script Manager'\n3. Cari 'GhidraAIBridge.java' -> Klik tombol Run (Play hijau)\n4. Bridge akan aktif di background tanpa popup.[/dim]")
    sys.exit(1)

def clean_pseudo_c(code: str) -> str:
    if not code:
        return ""
    import re
    # 1. Clean compiler warnings and boilerplate comments
    cleaned = re.sub(r'/\* WARNING:.*?\*/\n?', '', code)
    cleaned = re.sub(r'/\* Library Function.*?\*/\n?', '', cleaned)

    # 2. Simplify Ghidra modulo and optimization idioms
    # Modulo pattern: [(int)uVar + (int)(uVar / 0xc) * 0x800000ff] -> [uVar % 12]
    cleaned = re.sub(r'\[\(int\)(\w+)\s*\+\s*\(int\)\(\1\s*/\s*0x([0-9a-fA-F]+)\)\s*\*\s*0x800000ff\]', lambda m: f'[{m.group(1)} % {int(m.group(2), 16)}]', cleaned)
    cleaned = re.sub(r'\[\(int\)(\w+)\s*\+\s*\(int\)\(\1\s*/\s*(\d+)\)\s*\*\s*0x800000ff\]', r'[\1 % \2]', cleaned)

    # Modulo 256 idiom
    cleaned = re.sub(r'(\w+)\s*=\s*\(int\)(\w+)\s*\+\s*1U\s*&\s*0x800000ff;\s*if\s*\(\(int\)\1\s*<\s*0\)\s*\{\s*\1\s*=\s*\(\1\s*-\s*1\s*\|\s*0xffffff00\)\s*\+\s*1;\s*\}', r'\1 = (\2 + 1) % 256;', cleaned)

    # 3. Replace Ghidra undefined/raw types with standard C/C++ types
    type_map = [
        (r'\bundefined8\b', 'uint64_t'),
        (r'\bundefined4\b', 'uint32_t'),
        (r'\bundefined2\b', 'uint16_t'),
        (r'\bundefined1\b', 'uint8_t'),
        (r'\bundefined\b', 'void'),
        (r'\bulonglong\b', 'uint64_t'),
        (r'\blonglong\b', 'int64_t'),
        (r'\buint\b', 'uint32_t'),
        (r'\bushort\b', 'uint16_t'),
        (r'\bbyte\b', 'uint8_t'),
        (r'\(undefined8 \*\)', '(void *)'),
        (r'\(undefined4 \*\)', '(uint32_t *)'),
        (r'\bcode \*\b', 'void (*)()'),
    ]
    for pattern, repl in type_map:
        cleaned = re.sub(pattern, repl, cleaned)

    # 4. Simplify CONCAT macros
    cleaned = re.sub(r'CONCAT71\([^,]+,\s*([^)]+)\)', r'(\1)', cleaned)
    cleaned = re.sub(r'CONCAT44\(([^,]+),\s*([^)]+)\)', r'((((uint64_t)\1) << 32) | ((uint32_t)\2))', cleaned)
    cleaned = re.sub(r'CONCAT22\(([^,]+),\s*([^)]+)\)', r'((((uint32_t)\1) << 16) | ((uint16_t)\2))', cleaned)
    cleaned = re.sub(r'CONCAT11\(([^,]+),\s*([^)]+)\)', r'((((uint16_t)\1) << 8) | ((uint8_t)\2))', cleaned)

    # 5. Clean compiler label prefixes & variables
    cleaned = re.sub(r'FID_conflict:', '', cleaned)
    cleaned = re.sub(r'local_res18', 'old_protect', cleaned)
    cleaned = re.sub(r'local_res20', 'timeout_ms', cleaned)
    cleaned = re.sub(r'local_res', 'var_', cleaned)
    cleaned = re.sub(r'local_108', 'sbox', cleaned)

    # 6. Collapse excessive blank lines
    cleaned = re.sub(r'\n{3,}', '\n\n', cleaned)
    return cleaned.strip()

def explain_c_logic(code: str, func_name: str) -> list:
    insights = []
    if '_Xtime_get_ticks' in code or 'RDTSC' in code or 'GetTickCount' in code:
        insights.append("[bold yellow] Anti-Debug Timing Check:[/bold yellow] Mengukur selisih waktu eksekusi CPU ticks untuk mendeteksi breakpoint / debugger.")
    if 'VirtualProtect' in code or 'VirtualAlloc' in code:
        if '0x40' in code or 'PAGE_EXECUTE_READWRITE' in code:
            insights.append("[bold red] Memory RWX Allocation (0x40):[/bold red] Mengubah permission memori jadi [bold white]PAGE_EXECUTE_READWRITE[/bold white] untuk mengeksekusi Shellcode.")
    if '0x100' in code and ('do {' in code or 'while' in code) and ('local_' in code or 'sbox' in code or '108' in code):
        insights.append("[bold magenta] RC4 Key Scheduling Algorithm (KSA):[/bold magenta] Menginisialisasi S-Box 256-byte (0..255) dengan kunci teks.")
    if '^' in code and ('local_' in code or 'sbox' in code or 'FUN_' in code or '108' in code):
        insights.append("[bold cyan] In-Place Payload Decryption (PRGA):[/bold cyan] Melakukan operasi XOR dekripsi pada buffer ciphertext di memori.")
    if 'FUN_1400014b0();' in code or '(*' in code:
        insights.append("[bold green] Shellcode Execution:[/bold green] Memanggil pointer memori payload yang baru saja selesai didekripsi.")
    if '__scrt_' in code or '_cexit' in code:
        insights.append("[bold blue] Microsoft CRT Boilerplate:[/bold blue] Inisialisasi C-Runtime sebelum memanggil fungsi [bold white]main()[/bold white] utama.")
    return insights

def display_decompiled_view(func_name: str, entry_addr: str, raw_code: str, show_raw: bool = False):
    if not raw_code:
        console.print("[dim]No decompiled code returned.[/dim]\n")
        return

    clean_code = clean_pseudo_c(raw_code)
    insights = explain_c_logic(raw_code, func_name)

    if insights:
        panel_text = "\n".join(f"• {ins}" for ins in insights)
        console.print(Panel(panel_text, title=" AI Reverse Engineering & Logic Breakdown", border_style="bold yellow"))

    if show_raw:
        syntax_raw = Syntax(raw_code, "c", theme="monokai", line_numbers=True)
        console.print(Panel(syntax_raw, title=f"Raw Ghidra Pseudo-C: {func_name} ({entry_addr})", border_style="bold red"))
    else:
        syntax_clean = Syntax(clean_code, "c", theme="monokai", line_numbers=True)
        console.print(Panel(syntax_clean, title=f" Clean Reconstructed C/C++: {func_name} ({entry_addr})", border_style="bold green"))

def main(args=None):
    parser = argparse.ArgumentParser(
        prog="ghidraanalyze",
        description=" Ghidra Interactive On-Demand AI Companion & Reverse Engineering Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  status                   Cek status koneksi bridge & program aktif
  stop                     Matikan Ghidra bridge server secara aman
  goto <addr>              Geser kursor & navigasi layar Ghidra GUI ke alamat
  current                  Decompile, rekonstruksi C bersih, & bedah fungsi di posisi kursor
  decompile <addr>         Decompile & rekonstruksi fungsi di alamat tertentu ke C bersih
  search <query>           Cari string, simbol, atau Windows API di program
  callers <addr>           Pohon fungsi pemanggil (Call Tree)
  callees <addr>           Fungsi apa saja yang dipanggil oleh fungsi ini
  vars <addr>              Daftar variabel lokal, parameter, dan stack layout
  xref <addr>              Daftar cross-references ke alamat
  rename <addr> <name>     Ganti nama fungsi/simbol di layar Ghidra
  comment <addr> "<text>"  Pasang komentar catatan di baris assembly
  strings                  Lihat daftar string yang terdefinisi di program
        """
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Status & Stop
    subparsers.add_parser("status", help="Cek status koneksi bridge")
    subparsers.add_parser("stop", help="Matikan server Ghidra bridge")

    # Goto
    goto_p = subparsers.add_parser("goto", help="Geser layar Ghidra GUI ke alamat spesifik")
    goto_p.add_argument("address", help="Target memory address (e.g. 0x14000115a)")

    # Current
    cur_p = subparsers.add_parser("current", help="Inspect fungsi di posisi kursor Ghidra saat ini")
    cur_p.add_argument("--raw", action="store_true", help="Tampilkan raw Ghidra decompiler")

    # Decompile
    dec_p = subparsers.add_parser("decompile", help="Decompile & rekonstruksi fungsi ke C bersih")
    dec_p.add_argument("address", help="Target memory address (e.g. 0x140001090)")
    dec_p.add_argument("--raw", action="store_true", help="Tampilkan raw Ghidra decompiler")

    # Search
    search_p = subparsers.add_parser("search", help="Cari string, simbol, atau Windows API")
    search_p.add_argument("query", help="Text/symbol to search")
    search_p.add_argument("--type", choices=["all", "string", "symbol", "api"], default="all", help="Search category")

    # Callers
    callers_p = subparsers.add_parser("callers", help="Pohon fungsi pemanggil (Callers / Who calls this)")
    callers_p.add_argument("address", help="Target function address")

    # Callees
    callees_p = subparsers.add_parser("callees", help="Daftar fungsi yang dipanggil (Callees / Outgoing calls)")
    callees_p.add_argument("address", help="Target function address")

    # Vars
    vars_p = subparsers.add_parser("vars", help="Daftar variabel lokal, tipe data, dan stack storage")
    vars_p.add_argument("address", help="Target function address")

    # XREF
    xref_p = subparsers.add_parser("xref", help="Daftar Cross-References (XREFs)")
    xref_p.add_argument("address", help="Target address")

    # Rename
    ren_p = subparsers.add_parser("rename", help="Rename fungsi di layar Ghidra")
    ren_p.add_argument("address", help="Target function address")
    ren_p.add_argument("name", help="New function name")

    # Comment
    com_p = subparsers.add_parser("comment", help="Tambah plate comment di Ghidra")
    com_p.add_argument("address", help="Target address")
    com_p.add_argument("text", help="Comment text")

    # Strings
    subparsers.add_parser("strings", help="Lihat daftar strings di biner")

    # Cryptohunt / Key Harvester
    hunt_p = subparsers.add_parser("cryptohunt", help="Bongkar key (32B/16B), nonce, dan konstanta crypto dari binary/dump")
    hunt_p.add_argument("target", help="Path to binary / dump file")
    hunt_p.add_argument("--size", default="32,16,12,8", help="Target byte sizes (default: 32,16,12,8)")
    hunt_p.add_argument("--near", help="Search near string or symbol")
    hunt_p.add_argument("--pair", action="store_true", help="Auto-detect paired {Nonce, Key} structs")
    hunt_p.add_argument("--test-decrypt", dest="ciphertext", help="Ciphertext to test against keys")
    hunt_p.add_argument("--prefix", default="", help="Expected plaintext prefix")
    hunt_p.add_argument("--limit", type=int, default=30, help="Max candidate rows to display")

    args, remaining_args = parser.parse_known_args(args)

    print_banner(tool_name="GHIDRA REVERSING ANALYZER (ghidraanalyze)", sub_title="On-Demand Interactive Ghidra CLI Companion")

    if not args.command or args.command == "status":
        res = query_bridge("/status")
        console.print(f"[bold green] Connected to Ghidra Instance![/bold green]")
        console.print(f"[bold cyan]Active Program:[/bold cyan] [bold white]{res.get('program')}[/bold white]")
        console.print(f"[bold cyan]Image Base:[/bold cyan] [bold magenta]{res.get('base')}[/bold magenta]")
        console.print(f"[bold cyan]Address Range:[/bold cyan] {res.get('min_addr')} - {res.get('max_addr')}\n")

    elif args.command == "stop":
        res = query_bridge("/stop")
        console.print(f"[bold green] {res.get('message', 'Ghidra Bridge Server has been stopped successfully!')}[/bold green]\n")

    elif args.command == "goto":
        res = query_bridge(f"/goto?addr={args.address}")
        console.print(f"[bold green] {res.get('message')}[/bold green]")
        console.print(f"[dim]Layar Ghidra GUI lo sekarang sudah bergeser ke {args.address}![/dim]\n")

    elif args.command == "current":
        res = query_bridge("/current")
        console.print(f"[bold cyan]Cursor Address:[/bold cyan] {res.get('address')} | [bold cyan]Function:[/bold cyan] {res.get('function')} (Entry: {res.get('entry')})\n")
        display_decompiled_view(res.get("function"), res.get("entry"), res.get("code", ""), show_raw=args.raw)

    elif args.command == "decompile":
        res = query_bridge(f"/decompile?addr={args.address}")
        console.print(f"[bold cyan]Function Name:[/bold cyan] {res.get('function')} | [bold cyan]Entry:[/bold cyan] {res.get('entry')}\n")
        display_decompiled_view(res.get("function"), res.get("entry"), res.get("code", ""), show_raw=args.raw)

    elif args.command == "search":
        encoded_q = urllib.parse.quote(args.query)
        res = query_bridge(f"/search?q={encoded_q}&type={args.type}")
        results = res.get("results", [])
        table = Table(title=f"Search Results for '{args.query}' ({len(results)} found)", show_header=True, header_style="bold cyan", expand=True)
        table.add_column("Type", style="bold yellow", width=12)
        table.add_column("Address", style="bold magenta", width=18)
        table.add_column("Name / Content", style="white")
        for r in results:
            table.add_row(r.get("type", ""), r.get("addr", ""), escape(r.get("name", "")))
        console.print(table)

    elif args.command == "callers":
        res = query_bridge(f"/callers?addr={args.address}")
        callers = res.get("callers", [])
        tree = Tree(f"[bold cyan]Function Target:[/bold cyan] [bold white]{res.get('target')}[/bold white]")
        call_branch = tree.add(f"[bold yellow]Caller Functions ({len(callers)} found):[/bold yellow]")
        for c in callers:
            call_branch.add(f"[bold green]{c.get('name')}[/bold green] ([dim]{c.get('entry')}[/dim])")
        console.print(tree)

    elif args.command == "callees":
        res = query_bridge(f"/callees?addr={args.address}")
        callees = res.get("callees", [])
        tree = Tree(f"[bold cyan]Function:[/bold cyan] [bold white]{res.get('function')}[/bold white]")
        out_branch = tree.add(f"[bold yellow]Outgoing Calls ({len(callees)} functions called):[/bold yellow]")
        for c in callees:
            ext = " [bold magenta][API][/bold magenta]" if c.get("is_external") else ""
            out_branch.add(f"{c.get('name')}{ext} ([dim]{c.get('entry')}[/dim])")
        console.print(tree)

    elif args.command == "vars":
        res = query_bridge(f"/vars?addr={args.address}")
        vars_list = res.get("variables", [])
        table = Table(title=f"Variables & Stack Storage in {res.get('function')}", show_header=True, header_style="bold magenta", expand=True)
        table.add_column("Variable Name", style="bold cyan")
        table.add_column("Kind", style="bold yellow", width=12)
        table.add_column("Data Type", style="green")
        table.add_column("Size", style="white", justify="right")
        table.add_column("Storage (Stack/Register)", style="bold blue")
        for v in vars_list:
            table.add_row(v.get("name"), v.get("kind"), v.get("type"), f"{v.get('size')} B", v.get("storage"))
        console.print(table)

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

    elif args.command == "cryptohunt":
        from cipher.cryptohunt import main as hunt_main
        pass_args = [args.target]
        if args.size: pass_args.extend(["--size", args.size])
        if args.near: pass_args.extend(["--near", args.near])
        if args.pair: pass_args.append("--pair")
        if args.ciphertext: pass_args.extend(["--test-decrypt", args.ciphertext])
        if args.prefix: pass_args.extend(["--prefix", args.prefix])
        if args.limit: pass_args.extend(["--limit", str(args.limit)])
        if remaining_args: pass_args.extend(remaining_args)
        hunt_main(pass_args)

if __name__ == "__main__":
    main()
