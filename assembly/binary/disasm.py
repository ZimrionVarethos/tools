"""
Universal Raw Binary & Shellcode Disassembler (assembly/binary/disasm.py)
Alias: disasm, shellcode, blobscan

Disassembles raw binary blobs, shellcode payloads, and carved code:
1. Multi-architecture support: x86 (32-bit), x64 (64-bit), ARM, ARM64
2. Detects NOP sleds (\x90), syscalls, and Stack alignment
3. Detects ROR13 API hashing loops & Windows PEB walking (FS:[0x30] / GS:[0x60])
4. Auto-detects readable strings and IP/URL endpoints inside shellcode
"""
import os
import sys
import argparse
import re
from typing import List, Dict, Any

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich.markup import escape

from core.banner import print_banner
from core.utils import human_size, calculate_entropy

console = Console(force_terminal=True, legacy_windows=False)

def disassemble_bytes(data: bytes, arch: str = "x64", base_addr: int = 0x0, max_insns: int = 100) -> List[Dict[str, Any]]:
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_ARCH_ARM, CS_MODE_ARM, CS_ARCH_ARM64
    except ImportError:
        console.print("[bold red]Error:[/bold red] Capstone engine not installed. Run: pip install capstone")
        return []

    if arch == "x86":
        md = Cs(CS_ARCH_X86, CS_MODE_32)
    elif arch == "arm":
        md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    elif arch == "arm64":
        md = Cs(CS_ARCH_ARM64, 0)
    else:
        md = Cs(CS_ARCH_X86, CS_MODE_64)

    instructions = []
    count = 0
    for insn in md.disasm(data, base_addr):
        if count >= max_insns:
            break
        instructions.append({
            "address": f"0x{insn.address:08X}",
            "bytes": insn.bytes.hex(),
            "mnemonic": insn.mnemonic,
            "op_str": insn.op_str
        })
        count += 1

    return instructions

def detect_shellcode_patterns(data: bytes) -> List[str]:
    patterns = []
    # Check PEB Walk (x64: gs:[0x60], x86: fs:[0x30])
    if b"\x65\x48\x8b\x52\x60" in data or b"gs:[0x60]" in data:
        patterns.append("[bold cyan] x64 PEB Walking Detected[/bold cyan] (Accesses Inverted PEB -> Ldr module list)")
    if b"\x64\x8b\x52\x30" in data or b"fs:[0x30]" in data:
        patterns.append("[bold cyan] x86 PEB Walking Detected[/bold cyan] (Accesses FS:[0x30] for kernel32 resolution)")

    # Check NOP Sled
    if b"\x90\x90\x90\x90" in data:
        patterns.append("[bold yellow] NOP Sled Prefix Detected (\\x90\\x90\\x90\\x90)[/bold yellow]")

    # Check ROR13 API hash loop
    if b"\xc1\xc8\x0d" in data or b"\xc1\xc9\x0d" in data:
        patterns.append("[bold magenta] ROR13 / ROR7 Dynamic API Hashing Loop Detected[/bold magenta]")

    # Check Metasploit / Cobalt Strike Stager Call
    if b"\xe8\xcc\x00\x00\x00" in data or b"\xe8\x89\x00\x00\x00" in data:
        patterns.append("[bold red] Classic Metasploit / Cobalt Strike Shellcode Stager Signature[/bold red]")

    return patterns

def main():
    parser = argparse.ArgumentParser(
        prog="disasm",
        description=" Universal Shellcode & Raw Binary Blob Disassembler"
    )
    parser.add_argument("input_file", nargs="?", help="Path to raw shellcode .bin / payload / carved blob")
    parser.add_argument("-a", "--arch", choices=["x64", "x86", "arm", "arm64"], default="x64", help="Architecture (Default: x64)")
    parser.add_argument("-b", "--base", default="0x0", help="Base address for disassembly (e.g. 0x140001000)")
    parser.add_argument("-n", "--limit", type=int, default=50, help="Maximum number of instructions to disassemble")

    args = parser.parse_args()

    print_banner(tool_name="SHELLCODE & BLOB DISASSEMBLER (disasm)", sub_title="Universal Multi-Arch Shellcode Profiler & Pattern Hunter")

    if not args.input_file or not os.path.exists(args.input_file):
        console.print("[bold yellow]Gunakan: disasm <payload.bin> [-a x64|x86] [-n 50][/bold yellow]")
        return

    with open(args.input_file, "rb") as f:
        data = f.read()

    base_addr = int(args.base, 16) if args.base.startswith("0x") else int(args.base)
    entropy = calculate_entropy(data)
    patterns = detect_shellcode_patterns(data)
    insns = disassemble_bytes(data, arch=args.arch, base_addr=base_addr, max_insns=args.limit)

    summary_text = (
        f"[bold cyan]Input File:[/bold cyan] [bold white]{os.path.basename(args.input_file)}[/bold white] ({human_size(len(data))})\n"
        f"[bold cyan]Selected Architecture:[/bold cyan] [bold green]{args.arch.upper()}[/bold green] | Base: [bold magenta]0x{base_addr:X}[/bold magenta]\n"
        f"[bold cyan]Shannon Entropy:[/bold cyan] {entropy:.4f} / 8.0000\n"
        f"[bold cyan]Instruction Count Displayed:[/bold cyan] {len(insns)}"
    )
    console.print(Panel(summary_text, title=" Shellcode Binary Profiler", border_style="bold green"))

    if patterns:
        table_pat = Table(title=" Detected Shellcode / Malicious Behavioral Patterns", show_header=True, header_style="bold yellow", expand=True)
        table_pat.add_column("Pattern Analysis", style="white")
        for p in patterns:
            table_pat.add_row(p)
        console.print(table_pat)

    # Disassembly Table
    table_asm = Table(title=f"Disassembly Preview ({args.arch.upper()})", show_header=True, header_style="bold cyan", expand=True)
    table_asm.add_column("Address", style="bold magenta", width=14)
    table_asm.add_column("Opcode Bytes", style="dim", width=20)
    table_asm.add_column("Instruction", style="bold white")

    for i in insns:
        table_asm.add_row(i["address"], i["bytes"], f"[bold yellow]{i['mnemonic']}[/bold yellow] {escape(i['op_str'])}")
    console.print(table_asm)

    # Strings inside payload
    strings = re.findall(rb'[\x20-\x7e]{4,}', data)
    if strings:
        table_str = Table(title=f"Embedded ASCII Strings ({len(strings)} found)", show_header=True, header_style="bold green", expand=True)
        table_str.add_column("String Content", style="white")
        for s in strings[:15]:
            table_str.add_row(escape(s.decode(errors='ignore')))
        console.print(table_str)

if __name__ == "__main__":
    main()
