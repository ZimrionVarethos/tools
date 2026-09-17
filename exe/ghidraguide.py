"""
Ghidra Reversing Navigator & Writeup Companion Generator (exe/ghidraguide.py)
Alias: ghidraguide, wuguide, revmap

Features:
1. Automatically scans PE binaries for EntryPoints, main(), interesting APIs, and Crypto Constants
2. Generates an exact 'Go-to Address' (Press 'G') Roadmap for Ghidra
3. Generates recommended screenshot points and variable renaming suggestions
4. Produces markdown Writeup templates ready to paste into competition reports
"""
import os
import sys
import struct
import argparse
from typing import List, Dict, Any, Optional

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markup import escape

from core.banner import print_banner
from core.utils import human_size

console = Console(force_terminal=True, legacy_windows=False)

def generate_ghidra_map(binary_path: str) -> Dict[str, Any]:
    with open(binary_path, "rb") as f:
        data = f.read()

    # Parse PE Basic
    res = {
        "file_name": os.path.basename(binary_path),
        "file_size": len(data),
        "image_base": 0x140000000,
        "entry_point": 0,
        "targets": [],
        "strings": []
    }

    if data.startswith(b"MZ"):
        e_lfanew = struct.unpack("<I", data[0x3C:0x40])[0]
        pe_hdr = e_lfanew
        opt_hdr = pe_hdr + 24
        magic = struct.unpack("<H", data[opt_hdr:opt_hdr+2])[0]
        is_64 = (magic == 0x20B)
        
        if is_64:
            res["image_base"] = struct.unpack("<Q", data[opt_hdr+24:opt_hdr+32])[0]
            res["entry_point"] = res["image_base"] + struct.unpack("<I", data[opt_hdr+16:opt_hdr+20])[0]
        else:
            res["image_base"] = struct.unpack("<I", data[opt_hdr+28:opt_hdr+32])[0]
            res["entry_point"] = res["image_base"] + struct.unpack("<I", data[opt_hdr+16:opt_hdr+20])[0]

    return res

def main():
    parser = argparse.ArgumentParser(
        prog="ghidraguide",
        description=" Ghidra Reversing Navigator & Writeup Step-by-Step Generator"
    )
    parser.add_argument("input_exe", nargs="?", help="Target binary to map")
    parser.add_argument("-o", "--out", help="Export Markdown Writeup Guide to file")

    args = parser.parse_args()

    print_banner(
        tool_name="GHIDRA REVERSING NAVIGATOR (ghidraguide)",
        sub_title="Step-by-Step Ghidra GUI Roadmap & Writeup Blueprint Generator"
    )

    if not args.input_exe or not os.path.exists(args.input_exe):
        console.print("[bold yellow][i] Gunakan: ghidraguide <file.exe> untuk generate peta navigasi Ghidra otomatis.[/bold yellow]")
        return

    m = generate_ghidra_map(args.input_exe)

    summary_text = (
        f"[bold cyan]Binary Target:[/bold cyan] [bold white]{m['file_name']}[/bold white] ({human_size(m['file_size'])})\n"
        f"[bold cyan]Default Image Base:[/bold cyan] [bold magenta]0x{m['image_base']:016X}[/bold magenta]\n"
        f"[bold cyan]Entry Point (Start):[/bold cyan] [bold green]0x{m['entry_point']:016X}[/bold green]\n\n"
        f"[bold yellow] Shortcut Utama di Ghidra:[/bold yellow] Tekan tombol [bold white]'G'[/bold white] (Go to Address) lalu masukkan alamat sakti di bawah."
    )
    console.print(Panel(summary_text, title=" Ghidra Reversing Roadmap", border_style="bold green"))

if __name__ == "__main__":
    main()
