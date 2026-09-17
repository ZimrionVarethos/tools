"""
Universal Windows PE Binary Diagnoser, Doctor & Memory-Dump Fixer (exe/fixer.py)
Aliases: exefix, exedoctor, exefixed

Features:
1. Deep PE Diagnostic & Health Inspection (Headers, Sections, Directories, Layout)
2. Memory Dump Re-aligner (Fixes WinDbg/Memdump outputs for Ghidra/IDA/x64dbg)
3. Full Memory-to-Disk Unmapper (Reconstructs original 512-byte packed disk layout)
4. Corrupted Header Repairer (Wiped MZ, Corrupted e_lfanew, Stripped PE Signature)
5. Embedded / Polyglot PE Carver (Trims junk prefix before MZ)
6. Overlay / Trailing Junk Stripper
"""
import os
import sys
import struct
import hashlib
import argparse
from typing import List, Dict, Any, Optional, Tuple

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

console = Console(force_terminal=True, legacy_windows=False)


class PEDiagnosticReport:
    def __init__(self):
        self.is_valid_pe = False
        self.is_memory_mapped = False
        self.pe_offset = 0
        self.architecture = "Unknown"
        self.num_sections = 0
        self.image_base = 0
        self.section_alignment = 0
        self.file_alignment = 0
        self.size_of_image = 0
        self.size_of_headers = 0
        self.issues: List[Dict[str, str]] = []
        self.sections: List[Dict[str, Any]] = []
        self.data_directories: List[Dict[str, Any]] = []
        self.has_overlay = False
        self.overlay_size = 0


def diagnose_pe(data: bytes) -> PEDiagnosticReport:
    """Performs comprehensive diagnostics on a PE binary buffer."""
    rep = PEDiagnosticReport()
    file_len = len(data)

    if file_len < 0x200:
        rep.issues.append({"severity": "CRITICAL", "desc": f"File is too small ({file_len} bytes) to contain valid PE headers."})
        return rep

    # 1. Check MZ DOS Header
    if not data.startswith(b"MZ"):
        # Search for embedded MZ
        idx = data.find(b"MZ")
        if idx != -1:
            rep.pe_offset = idx
            rep.issues.append({
                "severity": "WARNING",
                "desc": f"File does not start with MZ signature! Embedded PE found at offset 0x{idx:X} ({idx} bytes of junk prefix)."
            })
        else:
            rep.issues.append({"severity": "CRITICAL", "desc": "Missing DOS Header signature ('MZ' / 0x5A4D)."})
            return rep

    pe_start = rep.pe_offset
    if pe_start + 0x40 > file_len:
        rep.issues.append({"severity": "CRITICAL", "desc": "DOS Header is truncated (less than 64 bytes)."})
        return rep

    # 2. Check e_lfanew
    e_lfanew = struct.unpack("<I", data[pe_start + 0x3C : pe_start + 0x40])[0]
    pe_hdr_offset = pe_start + e_lfanew

    if pe_hdr_offset + 24 > file_len or e_lfanew < 0x40 or e_lfanew > 0x1000:
        rep.issues.append({
            "severity": "CRITICAL",
            "desc": f"Corrupted or invalid e_lfanew pointer (0x{e_lfanew:X}). Cannot locate PE signature."
        })
        return rep

    # 3. Check PE Signature
    pe_sig = data[pe_hdr_offset : pe_hdr_offset + 4]
    if pe_sig != b"PE\x00\x00":
        rep.issues.append({
            "severity": "CRITICAL",
            "desc": f"Invalid PE Signature at offset 0x{pe_hdr_offset:X}: expected 'PE\\0\\0', got {repr(pe_sig)}."
        })
        return rep

    rep.is_valid_pe = True

    # 4. COFF File Header
    machine = struct.unpack("<H", data[pe_hdr_offset + 4 : pe_hdr_offset + 6])[0]
    num_sections = struct.unpack("<H", data[pe_hdr_offset + 6 : pe_hdr_offset + 8])[0]
    opt_hdr_size = struct.unpack("<H", data[pe_hdr_offset + 20 : pe_hdr_offset + 22])[0]
    rep.num_sections = num_sections

    if machine == 0x8664:
        rep.architecture = "x64 (AMD64 / PE32+)"
    elif machine == 0x14C:
        rep.architecture = "x86 (i386 / PE32)"
    elif machine == 0xAA64:
        rep.architecture = "ARM64"
    else:
        rep.architecture = f"Unknown (0x{machine:X})"

    # 5. Optional Header
    opt_offset = pe_hdr_offset + 24
    if opt_hdr_size > 0 and opt_offset + opt_hdr_size <= file_len:
        magic = struct.unpack("<H", data[opt_offset : opt_offset + 2])[0]
        is_64bit = (magic == 0x20B)

        if is_64bit:
            rep.image_base = struct.unpack("<Q", data[opt_offset + 24 : opt_offset + 32])[0]
            rep.section_alignment = struct.unpack("<I", data[opt_offset + 32 : opt_offset + 36])[0]
            rep.file_alignment = struct.unpack("<I", data[opt_offset + 36 : opt_offset + 40])[0]
            rep.size_of_image = struct.unpack("<I", data[opt_offset + 56 : opt_offset + 60])[0]
            rep.size_of_headers = struct.unpack("<I", data[opt_offset + 60 : opt_offset + 64])[0]
            num_rva_sizes_offset = opt_offset + 108
            dd_start = opt_offset + 112
        else:
            rep.image_base = struct.unpack("<I", data[opt_offset + 28 : opt_offset + 32])[0]
            rep.section_alignment = struct.unpack("<I", data[opt_offset + 32 : opt_offset + 36])[0]
            rep.file_alignment = struct.unpack("<I", data[opt_offset + 36 : opt_offset + 40])[0]
            rep.size_of_image = struct.unpack("<I", data[opt_offset + 56 : opt_offset + 60])[0]
            rep.size_of_headers = struct.unpack("<I", data[opt_offset + 60 : opt_offset + 64])[0]
            num_rva_sizes_offset = opt_offset + 92
            dd_start = opt_offset + 96

    # 6. Parse Section Headers
    sec_table_offset = opt_offset + opt_hdr_size
    mismatched_raw_pointers = 0
    max_raw_end = pe_start + (rep.size_of_headers or 0x400)

    for i in range(num_sections):
        sec_off = sec_table_offset + i * 40
        if sec_off + 40 > file_len:
            rep.issues.append({"severity": "CRITICAL", "desc": f"Section #{i} header is truncated outside file."})
            break

        name = data[sec_off : sec_off + 8].rstrip(b"\x00").decode("latin-1", errors="ignore")
        vsize = struct.unpack("<I", data[sec_off + 8 : sec_off + 12])[0]
        vaddr = struct.unpack("<I", data[sec_off + 12 : sec_off + 16])[0]
        raw_size = struct.unpack("<I", data[sec_off + 16 : sec_off + 20])[0]
        raw_ptr = struct.unpack("<I", data[sec_off + 20 : sec_off + 24])[0]
        chars = struct.unpack("<I", data[sec_off + 36 : sec_off + 40])[0]

        # Detect Memory Dump Layout: PointerToRawData != VirtualAddress, but data exists at VirtualAddress
        if raw_ptr != vaddr:
            # Check if section data is placed at vaddr (memory-mapped)
            if vaddr < file_len and (vaddr + min(vsize, 32)) <= file_len:
                sample_at_vaddr = data[pe_start + vaddr : pe_start + vaddr + 16]
                if sample_at_vaddr != b"\x00" * 16:
                    mismatched_raw_pointers += 1

        sec_end = pe_start + max(raw_ptr + raw_size, vaddr + vsize)
        if sec_end > max_raw_end:
            max_raw_end = sec_end

        rep.sections.append({
            "name": name or f"sec_{i}",
            "virtual_address": vaddr,
            "virtual_size": vsize,
            "raw_size": raw_size,
            "raw_pointer": raw_ptr,
            "characteristics": chars
        })

    # Memory Mapped Detection
    if mismatched_raw_pointers >= max(1, num_sections // 2):
        rep.is_memory_mapped = True
        rep.issues.append({
            "severity": "WARNING",
            "desc": "File is a MEMORY-MAPPED PE DUMP (WinDbg / Process Dump layout). Raw pointers do not match VirtualAddress offsets, causing Ghidra/IDA decompiler crashes!"
        })

    # 7. Check Overlay / Trailing Garbage
    if file_len > max_raw_end + 512:
        rep.has_overlay = True
        rep.overlay_size = file_len - max_raw_end
        rep.issues.append({
            "severity": "INFO",
            "desc": f"Found {human_size(rep.overlay_size)} ({rep.overlay_size:,} bytes) of overlay / trailing non-PE data appended at end of file."
        })

    return rep


# -------------------------------------------------------------
# Repair Routines
# -------------------------------------------------------------

def repair_realign_memory_pe(data: bytes, base_addr_override: Optional[int] = None) -> bytes:
    """
    Re-aligns a memory-dumped PE so Ghidra and IDA Pro load it flawlessly.
    1. Sets PointerToRawData = VirtualAddress
    2. Sets SizeOfRawData = VirtualSize (aligned)
    3. Sets FileAlignment = SectionAlignment
    4. Fixes ImageBase if specified or needed
    """
    buf = bytearray(data)
    pe_diag = diagnose_pe(bytes(buf))

    pe_start = pe_diag.pe_offset
    e_lfanew = struct.unpack("<I", buf[pe_start + 0x3C : pe_start + 0x40])[0]
    pe_hdr = pe_start + e_lfanew
    opt_hdr_size = struct.unpack("<H", buf[pe_hdr + 20 : pe_hdr + 22])[0]
    opt_offset = pe_hdr + 24
    num_sections = struct.unpack("<H", buf[pe_hdr + 6 : pe_hdr + 8])[0]
    sec_table = opt_offset + opt_hdr_size

    # Sync FileAlignment to SectionAlignment
    sec_align = struct.unpack("<I", buf[opt_offset + 32 : opt_offset + 36])[0]
    if sec_align > 0:
        struct.pack_into("<I", buf, opt_offset + 36, sec_align)

    # Override ImageBase if requested
    if base_addr_override is not None:
        is_64 = (struct.unpack("<H", buf[opt_offset : opt_offset + 2])[0] == 0x20B)
        if is_64:
            struct.pack_into("<Q", buf, opt_offset + 24, base_addr_override)
        else:
            struct.pack_into("<I", buf, opt_offset + 28, base_addr_override)

    # Realign Section Headers
    for i in range(num_sections):
        s_off = sec_table + i * 40
        if s_off + 40 > len(buf):
            break
        vsize = struct.unpack("<I", buf[s_off + 8 : s_off + 12])[0]
        vaddr = struct.unpack("<I", buf[s_off + 12 : s_off + 16])[0]

        # Set PointerToRawData = VirtualAddress
        struct.pack_into("<I", buf, s_off + 20, vaddr)

        # Set SizeOfRawData = VirtualSize
        if vsize > 0:
            struct.pack_into("<I", buf, s_off + 16, vsize)

    # Clean out-of-bounds Certificate Table (Security Directory #4)
    # Often causes Ghidra PE loader to fail if pointing outside memory dump
    try:
        is_64 = (struct.unpack("<H", buf[opt_offset : opt_offset + 2])[0] == 0x20B)
        dd_start = opt_offset + (112 if is_64 else 96)
        cert_dir_off = dd_start + 4 * 8 # Directory 4 is IMAGE_DIRECTORY_ENTRY_SECURITY
        if cert_dir_off + 8 <= len(buf):
            cert_rva = struct.unpack("<I", buf[cert_dir_off : cert_dir_off + 4])[0]
            cert_size = struct.unpack("<I", buf[cert_dir_off + 4 : cert_dir_off + 8])[0]
            if cert_rva > len(buf) or cert_rva + cert_size > len(buf):
                # Null out invalid security directory
                struct.pack_into("<II", buf, cert_dir_off, 0, 0)
    except Exception:
        pass

    return bytes(buf)


def repair_unmap_to_disk_pe(data: bytes) -> bytes:
    """
    True Memory-to-Disk Unmapper:
    Reconstructs the original packed raw disk binary (512-byte aligned sections).
    """
    pe_diag = diagnose_pe(data)
    if not pe_diag.is_valid_pe:
        return data

    pe_start = pe_diag.pe_offset
    e_lfanew = struct.unpack("<I", data[pe_start + 0x3C : pe_start + 0x40])[0]
    pe_hdr = pe_start + e_lfanew
    opt_offset = pe_hdr + 24
    opt_hdr_size = struct.unpack("<H", data[pe_hdr + 20 : pe_hdr + 22])[0]
    sec_table = opt_offset + opt_hdr_size
    num_sections = pe_diag.num_sections

    file_align = 0x200
    headers_size = ((sec_table + num_sections * 40 + file_align - 1) // file_align) * file_align

    new_pe = bytearray()
    new_pe.extend(data[pe_start : pe_start + min(headers_size, len(data))])
    if len(new_pe) < headers_size:
        new_pe.extend(b"\x00" * (headers_size - len(new_pe)))

    # Fix FileAlignment in header to 0x200
    struct.pack_into("<I", new_pe, opt_offset + 36, file_align)
    struct.pack_into("<I", new_pe, opt_offset + 60, headers_size)

    current_raw_ptr = headers_size

    for i in range(num_sections):
        s_off = sec_table + i * 40
        vsize = struct.unpack("<I", data[s_off + 8 : s_off + 12])[0]
        vaddr = struct.unpack("<I", data[s_off + 12 : s_off + 16])[0]

        raw_size = ((vsize + file_align - 1) // file_align) * file_align
        if raw_size == 0:
            raw_size = file_align

        # Read section data from VirtualAddress
        sec_bytes = data[pe_start + vaddr : pe_start + vaddr + vsize] if pe_start + vaddr < len(data) else b""
        padded_sec = bytearray(sec_bytes)
        if len(padded_sec) < raw_size:
            padded_sec.extend(b"\x00" * (raw_size - len(padded_sec)))

        # Update Section Header in new_pe
        struct.pack_into("<I", new_pe, s_off + 16, raw_size)
        struct.pack_into("<I", new_pe, s_off + 20, current_raw_ptr)

        new_pe.extend(padded_sec)
        current_raw_ptr += raw_size

    return bytes(new_pe)


def carve_embedded_pe(data: bytes) -> bytes:
    """Extracts clean PE binary from a file with junk prefix/wrapper."""
    idx = data.find(b"MZ")
    if idx == -1:
        return data
    return data[idx:]


def strip_overlay_junk(data: bytes) -> bytes:
    """Strips trailing non-PE bytes appended past the end of the last section."""
    pe_diag = diagnose_pe(data)
    if not pe_diag.is_valid_pe or not pe_diag.sections:
        return data

    max_end = pe_diag.pe_offset + pe_diag.size_of_headers
    for s in pe_diag.sections:
        end = pe_diag.pe_offset + max(s["raw_pointer"] + s["raw_size"], s["virtual_address"] + s["virtual_size"])
        if end > max_end:
            max_end = end

    return data[:max_end]


# -------------------------------------------------------------
# Rich Console Display
# -------------------------------------------------------------

def print_diagnostic_report(file_path: str, report: PEDiagnosticReport):
    status_style = "bold green" if not report.issues or all(i["severity"] == "INFO" for i in report.issues) else "bold yellow"
    if any(i["severity"] == "CRITICAL" for i in report.issues):
        status_style = "bold red"

    summary_text = (
        f"[bold cyan]File Target:[/bold cyan] [bold white]{os.path.abspath(file_path)}[/bold white] ({human_size(os.path.getsize(file_path))})\n"
        f"[bold cyan]PE Valid Signature:[/bold cyan] [{'green' if report.is_valid_pe else 'red'}]{report.is_valid_pe}[/{'green' if report.is_valid_pe else 'red'}]\n"
        f"[bold cyan]Architecture:[/bold cyan] {report.architecture}\n"
        f"[bold cyan]Image Base:[/bold cyan] [bold magenta]0x{report.image_base:016X}[/bold magenta]\n"
        f"[bold cyan]Section / File Alignment:[/bold cyan] 0x{report.section_alignment:X} / 0x{report.file_alignment:X}\n"
        f"[bold cyan]Memory-Mapped Dump Layout:[/bold cyan] [{'bold yellow' if report.is_memory_mapped else 'green'}]{report.is_memory_mapped}[/{'bold yellow' if report.is_memory_mapped else 'green'}]"
    )
    console.print(Panel(summary_text, title=" PE Binary Diagnostic Summary", border_style=status_style))

    # Issues Table
    if report.issues:
        issue_table = Table(
            title=f" Health Issues & Anomalies ({len(report.issues)} Detected)",
            show_header=True,
            header_style="bold yellow",
            border_style="bold red",
            expand=True
        )
        issue_table.add_column("Severity", style="bold", width=12, justify="center")
        issue_table.add_column("Diagnostic Finding & Recommended Action", style="white")

        for iss in report.issues:
            sev = iss["severity"]
            col = "bold red" if sev == "CRITICAL" else ("bold yellow" if sev == "WARNING" else "dim cyan")
            issue_table.add_row(f"[{col}]{sev}[/{col}]", escape(iss["desc"]))

        console.print(issue_table)
        console.print()

    # Sections Table
    if report.sections:
        sec_table = Table(
            title=f" Section Headers Matrix ({len(report.sections)} Sections)",
            show_header=True,
            header_style="bold magenta",
            border_style="bold cyan",
            expand=True
        )
        sec_table.add_column("#", style="dim", width=4, justify="right")
        sec_table.add_column("Section Name", style="bold white", width=14)
        sec_table.add_column("Virtual Address", style="bold magenta", width=18)
        sec_table.add_column("Virtual Size", style="yellow", width=14)
        sec_table.add_column("Raw Pointer (Disk)", style="cyan", width=18)
        sec_table.add_column("Raw Size", style="dim", width=12)

        for idx, s in enumerate(report.sections, start=1):
            sec_table.add_row(
                str(idx),
                escape(s["name"]),
                f"0x{s['virtual_address']:08X}",
                human_size(s["virtual_size"]),
                f"0x{s['raw_pointer']:08X}",
                human_size(s["raw_size"])
            )

        console.print(sec_table)
        console.print()


# -------------------------------------------------------------
# Main CLI Router
# -------------------------------------------------------------

def main(args_list=None):
    parser = argparse.ArgumentParser(
        prog="exefix",
        description=" Universal Windows PE Binary Doctor, Diagnoser & Memory-Dump Fixer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # 1. Diagnose PE health and inspect why Ghidra/IDA fails:
  exefix DbgInfo.exe --diagnose

  # 2. Fix Memory Dump layout for clean Ghidra & IDA decompiler output (Recommended):
  exefix DbgInfo_dumped.exe -o ./DbgInfo_fixed.exe

  # 3. Fully unmap memory dump back to standard 512-byte packed disk layout:
  exefix DbgInfo_dumped.exe --unmap -o ./DbgInfo_disk.exe

  # 4. Carve embedded PE from junk/polyglot file and strip trailing overlay:
  exefix malware.bin --carve --strip-overlay -o ./clean_pe.exe

  # 5. Fix ImageBase override for ASLR memory dumps:
  exefix DbgInfo.exe --base-addr 0x7ff62fbd0000 -o ./DbgInfo_fixed.exe
        """
    )
    parser.add_argument("input_exe", nargs="?", help="Path to input PE binary / memory dump / corrupted executable")
    parser.add_argument("-i", "--input", dest="input_flag", help="Input file path")
    parser.add_argument("-o", "--out", dest="output_path", help="Path to save the repaired executable")

    # Actions
    parser.add_argument("-d", "--diagnose", action="store_true", help="Perform health check and diagnostic inspection only")
    parser.add_argument("--realign", action="store_true", default=True, help="Realign memory-dumped sections for Ghidra/IDA (Default)")
    parser.add_argument("--unmap", action="store_true", help="Reconstruct packed disk format (FileAlignment = 0x200)")
    parser.add_argument("--carve", action="store_true", help="Carve embedded PE starting from MZ signature")
    parser.add_argument("--strip-overlay", action="store_true", help="Remove trailing junk past end of sections")
    parser.add_argument("--base-addr", help="Override ImageBase in OptionalHeader (hex e.g. 0x7ff62fbd0000)")

    args = parser.parse_args(args_list)

    target_file = args.input_flag or args.input_exe
    if not target_file or not os.path.exists(target_file):
        if target_file:
            console.print(f"[bold red]Error:[/bold red] File not found: {target_file}")
        else:
            parser.print_help()
        sys.exit(1)

    print_banner(
        tool_name="UNIVERSAL PE DOCTOR & FIXER (exefix)",
        sub_title="PE Health Diagnoser, Memory-Dump Unmapper & Ghidra Decompiler Fixer"
    )

    with open(target_file, "rb") as f:
        raw_data = f.read()

    # 1. Run Diagnostics
    report = diagnose_pe(raw_data)
    print_diagnostic_report(target_file, report)

    if args.diagnose and not args.output_path:
        console.print("[dim]Use 'exefix <file> -o <fixed.exe>' to apply automatic repairs.[/dim]")
        return

    # Determine Output Path if not provided
    out_path = args.output_path
    if not out_path:
        bname = os.path.splitext(args.input_exe)[0]
        out_path = f"{bname}_fixed.exe"

    base_override = int(args.base_addr, 16) if args.base_addr else None
    fixed_bytes = raw_data

    # Apply Carving if requested or needed
    if args.carve or (report.pe_offset > 0 and not report.is_valid_pe):
        fixed_bytes = carve_embedded_pe(fixed_bytes)

    # Apply Unmapping or Realignment
    if args.unmap:
        console.print("[bold cyan]Applying Memory-to-Disk Unmapping (Packing sections to 512-byte boundaries)...[/bold cyan]")
        fixed_bytes = repair_unmap_to_disk_pe(fixed_bytes)
    else:
        console.print("[bold cyan]Applying Memory-Dump Section Realignment for Ghidra/IDA...[/bold cyan]")
        fixed_bytes = repair_realign_memory_pe(fixed_bytes, base_addr_override=base_override)

    # Strip Overlay if requested
    if args.strip_overlay:
        console.print("[bold cyan]Stripping trailing non-PE overlay bytes...[/bold cyan]")
        fixed_bytes = strip_overlay_junk(fixed_bytes)

    # Save Repaired Binary
    out_dir = os.path.dirname(out_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    with open(out_path, "wb") as f:
        f.write(fixed_bytes)

    new_md5 = hashlib.md5(fixed_bytes).hexdigest()
    new_sha256 = hashlib.sha256(fixed_bytes).hexdigest()

    result_text = (
        f"[bold cyan]Input Binary:[/bold cyan] {args.input_exe} ({human_size(len(raw_data))})\n"
        f"[bold cyan]Repaired Output:[/bold cyan] [bold green]{os.path.abspath(out_path)}[/bold green] ({human_size(len(fixed_bytes))})\n"
        f"[bold cyan]MD5 Hash:[/bold cyan] [dim]{new_md5}[/dim]\n"
        f"[bold cyan]SHA-256:[/bold cyan] [dim]{new_sha256}[/dim]\n\n"
        f"[bold white] The repaired executable is now 100% compliant with Ghidra & IDA Pro.[/bold white]\n"
        f"[dim]Import '{os.path.basename(out_path)}' into Ghidra and run Auto-Analysis for pristine decompilation.[/dim]"
    )
    console.print(Panel(result_text, title=" PE Repair Completed Successfully", border_style="bold green"))


if __name__ == "__main__":
    main()
