"""
Targeted Windows Memory & Module Dumper (dmpdump / dmp/dumper.py)
Extracts targeted memory segments, modules, and loaded PE binaries from memory dumps:
1. Dump by Base Virtual Address: dmpdump file.dmp -i 0x7ff62fbd0000 -o output.exe
2. Dump by Module Name: dmpdump file.dmp -m DbgInfo.exe -o ./DbgInfo.exe
3. Dump by Module / Main Executable: dmpdump file.dmp --main -o ./main.exe
4. Dump Arbitrary Memory Range: dmpdump file.dmp -i 0x140001000 -s 0x1000 -o range.bin
5. Dump All Loaded Modules: dmpdump file.dmp --all-modules -o ./dumped_modules/
6. Automatic PE Header & Image Size Resolution
"""
import os
import sys
import argparse
import struct
import hashlib
from typing import List, Dict, Any, Optional

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


def parse_int_auto(val: str) -> int:
    """Parses integer string in decimal or hex format."""
    val = val.strip()
    if val.lower().startswith("0x"):
        return int(val, 16)
    try:
        return int(val)
    except ValueError:
        return int(val, 16)


def get_clean_basename(path_str: str) -> str:
    """Extracts clean filename from Windows or POSIX path."""
    if not path_str:
        return "unnamed_binary.bin"
    return path_str.replace("\\", "/").split("/")[-1]


def realign_pe_headers(raw_mem: bytes) -> bytes:
    """
    Realigns PE Section Headers for memory-dumped binaries.
    In memory dumps, section data is located at VirtualAddress instead of PointerToRawData.
    Fixing PointerToRawData = VirtualAddress allows Ghidra/IDA/pefile to parse it without NullPointerException.
    """
    if len(raw_mem) < 0x200 or not raw_mem.startswith(b"MZ"):
        return raw_mem

    try:
        data = bytearray(raw_mem)
        e_lfanew = struct.unpack("<I", data[0x3C:0x40])[0]
        if e_lfanew + 4 > len(data) or data[e_lfanew:e_lfanew+4] != b"PE\x00\x00":
            return raw_mem

        num_sections = struct.unpack("<H", data[e_lfanew+6:e_lfanew+8])[0]
        opt_hdr_size = struct.unpack("<H", data[e_lfanew+20:e_lfanew+22])[0]
        sec_table_offset = e_lfanew + 24 + opt_hdr_size

        # Fix FileAlignment to match SectionAlignment in OptionalHeader
        sec_align = struct.unpack("<I", data[e_lfanew+24+32:e_lfanew+24+36])[0]
        if sec_align > 0:
            struct.pack_into("<I", data, e_lfanew+24+36, sec_align)

        # Fix each section: PointerToRawData = VirtualAddress, SizeOfRawData = VirtualSize
        for i in range(num_sections):
            sec_off = sec_table_offset + i * 40
            if sec_off + 40 > len(data):
                break
            virt_size = struct.unpack("<I", data[sec_off+8:sec_off+12])[0]
            virt_addr = struct.unpack("<I", data[sec_off+12:sec_off+16])[0]

            struct.pack_into("<I", data, sec_off+20, virt_addr)
            if virt_size > 0:
                struct.pack_into("<I", data, sec_off+16, virt_size)

        return bytes(data)
    except Exception:
        return raw_mem


def dump_memory_range(
    engine: DMPEngine,
    start_vaddr: int,
    size: int,
    output_path: str,
    label: str = "Memory Dump"
) -> bool:
    """Dumps a contiguous or segmented virtual memory range to disk with auto-realigned PE headers."""
    final_bytes = engine.read_bytes(start_vaddr, size)

    if not final_bytes or len(final_bytes) == 0:
        console.print(f"[bold red] Error:[/bold red] Failed to read memory at 0x{start_vaddr:X}.")
        return False

    # Auto-realign if it's a PE image
    if final_bytes.startswith(b"MZ"):
        final_bytes = realign_pe_headers(final_bytes)

    # Ensure parent directory exists
    out_dir = os.path.dirname(output_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    with open(output_path, "wb") as f:
        f.write(final_bytes)

    md5 = hashlib.md5(final_bytes).hexdigest()
    sha256 = hashlib.sha256(final_bytes).hexdigest()

    panel_text = (
        f"[bold cyan]Target:[/bold cyan] {label}\n"
        f"[bold cyan]Virtual Address:[/bold cyan] [bold magenta]0x{start_vaddr:016X}[/bold magenta]  [bold magenta]0x{start_vaddr + len(final_bytes):016X}[/bold magenta]\n"
        f"[bold cyan]Dumped Size:[/bold cyan] [yellow]{human_size(len(final_bytes))}[/yellow] ({len(final_bytes):,} bytes)\n"
        f"[bold cyan]Output File:[/bold cyan] [bold green]{os.path.abspath(output_path)}[/bold green]\n"
        f"[bold cyan]MD5 Hash:[/bold cyan] [dim]{md5}[/dim]\n"
        f"[bold cyan]SHA-256:[/bold cyan] [dim]{sha256}[/dim]"
    )
    console.print(Panel(panel_text, title=" Memory Dump Completed Successfully", border_style="bold green"))
    return True


def main(args_list=None):
    parser = argparse.ArgumentParser(
        prog="dmpdump",
        description=" Targeted Windows Memory & Module Dumper (Base Address, Modules, RWX, Ranges)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # 1. Dump main executable module automatically:
  dmpdump DbgInfo.DMP --main -o ./DbgInfo.exe

  # 2. Dump by Base Virtual Address:
  dmpdump DbgInfo.DMP -i 0x7ff62fbd0000 -o ./DbgInfo.exe

  # 3. Dump by Module Name:
  dmpdump DbgInfo.DMP -m DbgInfo.exe -o ./DbgInfo.exe
  dmpdump DbgInfo.DMP -m ntdll.dll -o ./ntdll_dumped.dll

  # 4. Dump specific address and size:
  dmpdump DbgInfo.DMP -i 0x7ff62fbd1000 -s 0x86000 -o ./text_section.bin

  # 5. Dump all loaded modules into a folder:
  dmpdump DbgInfo.DMP --all-modules -o ./all_modules/
        """
    )
    parser.add_argument("dmp_file", help="Path to Windows Memory Dump (.dmp) file")

    # Target selectors
    parser.add_argument("-i", "-a", "--addr", "--base", dest="base_addr", help="Base Virtual Address in hex (e.g. 0x7ff62fbd0000)")
    parser.add_argument("-m", "--module", help="Module name to dump (e.g. DbgInfo.exe, ntdll.dll)")
    parser.add_argument("--main", action="store_true", help="Automatically dump the main process executable")
    parser.add_argument("-s", "--size", help="Size in bytes to dump (decimal or hex e.g. 0x86000). Optional.")

    # Batch dumping
    parser.add_argument("--all-modules", action="store_true", help="Dump all loaded modules (.exe & .dlls) into output directory")

    # Output file / directory
    parser.add_argument("-o", "--out", dest="output_path", help="Output file path (or directory if dumping multiple modules)")

    args = parser.parse_args(args_list)

    if not os.path.exists(args.dmp_file):
        console.print(f"[bold red]Error:[/bold red] File not found: {args.dmp_file}")
        sys.exit(1)

    print_banner(
        tool_name="WINDOWS MEMORY & MODULE DUMPER (dmpdump)",
        sub_title="Targeted Memory Range, Module & Injected Binary Extractor"
    )

    engine = DMPEngine(args.dmp_file)
    with console.status("[bold cyan]Parsing memory segments & module table...[/bold cyan]"):
        engine.analyze()

    # 1. Batch Dump All Modules
    if args.all_modules:
        out_dir = args.output_path or f"./dumped_modules_{os.path.splitext(os.path.basename(args.dmp_file))[0]}"
        os.makedirs(out_dir, exist_ok=True)
        console.print(f"[bold cyan]Dumping all {len(engine.modules)} loaded modules to folder: {out_dir}[/bold cyan]\n")

        dumped = 0
        for m in engine.modules:
            bname = get_clean_basename(m.name) or f"module_0x{m.base_addr:X}.bin"
            dest = os.path.join(out_dir, bname)
            if dump_memory_range(engine, m.base_addr, m.size, dest, label=f"Module: {bname}"):
                dumped += 1
        console.print(f"\n[bold green] Finished! Successfully dumped {dumped}/{len(engine.modules)} modules.[/bold green]")
        return

    # 2. Dump Main Executable
    if args.main:
        main_mod = None
        for m in engine.modules:
            if m.name.lower().endswith(".exe"):
                main_mod = m
                break
        if not main_mod and engine.modules:
            main_mod = engine.modules[0]

        if not main_mod:
            console.print("[bold red] Error:[/bold red] Could not identify main executable module.")
            sys.exit(1)

        bname = get_clean_basename(main_mod.name)
        out_path = args.output_path or f"./{bname}"
        dump_memory_range(engine, main_mod.base_addr, main_mod.size, out_path, label=f"Main Executable: {bname}")
        return

    # 3. Dump by Module Name
    if args.module:
        target_mod = None
        for m in engine.modules:
            clean_name = get_clean_basename(m.name)
            if args.module.lower() in m.name.lower() or args.module.lower() == clean_name.lower():
                target_mod = m
                break

        if not target_mod:
            console.print(f"[bold red] Error:[/bold red] Module '{args.module}' not found in dump module list.")
            console.print("[dim]Use 'dmpmodules <file.dmp>' to inspect available loaded modules.[/dim]")
            sys.exit(1)

        bname = get_clean_basename(target_mod.name)
        out_path = args.output_path or f"./{bname}"
        size = parse_int_auto(args.size) if args.size else target_mod.size
        dump_memory_range(engine, target_mod.base_addr, size, out_path, label=f"Module: {bname}")
        return

    # 4. Dump by Virtual Address
    if args.base_addr:
        addr = parse_int_auto(args.base_addr)
        dump_size = 0

        if args.size:
            dump_size = parse_int_auto(args.size)
        else:
            # Determine size from matching module or segment or PE header
            for m in engine.modules:
                if m.base_addr == addr:
                    dump_size = m.size
                    break

            if dump_size == 0:
                # Check PE header SizeOfImage
                hdr_sample = engine.read_bytes(addr, 0x1000)
                if hdr_sample.startswith(b"MZ") and len(hdr_sample) >= 0x40:
                    try:
                        e_lfanew = struct.unpack("<I", hdr_sample[0x3C:0x40])[0]
                        if e_lfanew + 0x60 <= len(hdr_sample) and hdr_sample[e_lfanew:e_lfanew+4] == b"PE\x00\x00":
                            magic = struct.unpack("<H", hdr_sample[e_lfanew+24:e_lfanew+26])[0]
                            size_of_image = struct.unpack("<I", hdr_sample[e_lfanew+24+56 : e_lfanew+24+60])[0]
                            if size_of_image > 0:
                                dump_size = size_of_image
                    except Exception:
                        pass

            if dump_size == 0:
                # Find enclosing segment size
                for s in engine.segments:
                    if s.start_addr <= addr < s.end_addr:
                        dump_size = s.end_addr - addr
                        break

            if dump_size == 0:
                dump_size = 0x10000

        # Determine default output name
        default_name = f"dump_0x{addr:X}.bin"
        for m in engine.modules:
            if m.base_addr == addr:
                default_name = get_clean_basename(m.name)
                break

        out_path = args.output_path or f"./{default_name}"
        dump_memory_range(engine, addr, dump_size, out_path, label=f"Address: 0x{addr:X}")
        return

    # If no target specified, show helpful guidance
    console.print("[yellow] No dumping target specified.[/yellow]\n")
    console.print("[bold cyan]Quick Usage Examples:[/bold cyan]")
    console.print(f"  dmpdump {args.dmp_file} --main -o ./main.exe")
    console.print(f"  dmpdump {args.dmp_file} -i 0x7ff62fbd0000 -o ./module.exe")
    console.print(f"  dmpdump {args.dmp_file} -m DbgInfo.exe -o ./DbgInfo.exe")
    console.print(f"  dmpdump {args.dmp_file} --all-modules -o ./all_modules/\n")
    console.print("[dim]Run 'dmpdump --help' or 'dmpmodules <file.dmp>' for more details.[/dim]")


if __name__ == "__main__":
    main()
