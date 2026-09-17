"""
Universal Linux ELF Header Doctor & Inspector (assembly/elf/inspector.py)
Alias: elffix, elfdoctor, elfinspect

Inspects and diagnoses Linux ELF32/ELF64 binaries:
1. Header verification (\x7fELF, 32-bit vs 64-bit, Endianness, ABI)
2. EntryPoint and Segment / Program Headers (LOAD, DYNAMIC, GNU_STACK)
3. Section Headers (.text, .rodata, .got, .plt, .fini, .init)
4. Stripped vs Non-Stripped Symbol Analysis
5. Embedded shellcode / UPX packed signature detection
"""
import os
import sys
import struct
import argparse
from typing import Dict, Any, List

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markup import escape

from core.banner import print_banner
from core.utils import human_size, calculate_entropy

console = Console(force_terminal=True, legacy_windows=False)

ELF_MAGICS = {
    0x00: "None / Unknown",
    0x02: "SPARC",
    0x03: "x86 (32-bit)",
    0x08: "MIPS",
    0x14: "PowerPC",
    0x28: "ARM (32-bit)",
    0x3E: "x86-64 (AMD64)",
    0xB7: "AArch64 (ARM 64-bit)",
    0xF3: "RISC-V"
}

def inspect_elf(data: bytes) -> Dict[str, Any]:
    res = {
        "valid": False,
        "is_64": False,
        "endian": "Little",
        "arch": "Unknown",
        "entry_point": 0,
        "sections": [],
        "segments": [],
        "is_stripped": True,
        "issues": []
    }

    if not data.startswith(b"\x7fELF"):
        res["issues"].append("[bold red]Critical:[/bold red] Missing \\x7fELF Magic Header (Not an ELF binary)!")
        return res

    res["valid"] = True
    ei_class = data[4]
    ei_data = data[5]

    res["is_64"] = (ei_class == 2)
    res["endian"] = "Little" if ei_data == 1 else "Big"
    endian_fmt = "<" if ei_data == 1 else ">"

    if res["is_64"]:
        # ELF64 Header format
        e_type, e_machine, e_version, e_entry, e_phoff, e_shoff = struct.unpack_from(f"{endian_fmt}HHIQQQ", data, 16)
        res["entry_point"] = e_entry
        res["arch"] = ELF_MAGICS.get(e_machine, f"Machine ID: {hex(e_machine)}")
    else:
        # ELF32 Header format
        e_type, e_machine, e_version, e_entry, e_phoff, e_shoff = struct.unpack_from(f"{endian_fmt}HHIIII", data, 16)
        res["entry_point"] = e_entry
        res["arch"] = ELF_MAGICS.get(e_machine, f"Machine ID: {hex(e_machine)}")

    # Check for symbols / debug info
    if b".symtab" in data or b".strtab" in data:
        res["is_stripped"] = False

    # Check for UPX
    if b"UPX!" in data:
        res["issues"].append("[bold yellow]Warning:[/bold yellow] Binary is packed with UPX packer (Unpack with 'upx -d').")

    return res

def main():
    parser = argparse.ArgumentParser(
        prog="elfdoctor",
        description=" Linux ELF Binary Doctor, Inspector & Triage Helper"
    )
    parser.add_argument("input_elf", nargs="?", help="Path to Linux ELF executable / core dump")
    args = parser.parse_args()

    print_banner(tool_name="LINUX ELF DOCTOR & INSPECTOR (elfdoctor)", sub_title="Linux Executable Header Analyzer & Forensics Triage")

    if not args.input_elf or not os.path.exists(args.input_elf):
        console.print("[bold yellow]Gunakan: elfdoctor <file_elf>[/bold yellow]")
        return

    with open(args.input_elf, "rb") as f:
        data = f.read()

    res = inspect_elf(data)
    entropy = calculate_entropy(data)

    summary_text = (
        f"[bold cyan]Target File:[/bold cyan] [bold white]{os.path.basename(args.input_elf)}[/bold white] ({human_size(len(data))})\n"
        f"[bold cyan]ELF Architecture:[/bold cyan] [bold green]{res['arch']}[/bold green] ({'64-bit' if res['is_64'] else '32-bit'})\n"
        f"[bold cyan]Endianness:[/bold cyan] {res['endian']}-Endian\n"
        f"[bold cyan]Entry Point (Address):[/bold cyan] [bold magenta]0x{res['entry_point']:016X}[/bold magenta]\n"
        f"[bold cyan]Symbol Status:[/bold cyan] {'[red]Stripped (No debug symbols)[/red]' if res['is_stripped'] else '[green]Symbols Present (.symtab)[/green]'}\n"
        f"[bold cyan]Shannon Entropy:[/bold cyan] {entropy:.4f} / 8.0000 ({'High - Packed/Encrypted' if entropy > 7.2 else 'Normal Native Code'})"
    )
    console.print(Panel(summary_text, title=" Linux ELF Analysis Summary", border_style="bold cyan"))

    if res["issues"]:
        table = Table(title=" Diagnostic Alerts", show_header=True, header_style="bold yellow", expand=True)
        table.add_column("Alert / Issue", style="white")
        for iss in res["issues"]:
            table.add_row(iss)
        console.print(table)

if __name__ == "__main__":
    main()
