#!/usr/bin/env python3
"""
Comprehensive Steganography & File Integrity Scanner (stegoscan)
Analyzes structural integrity, custom chunks, IHDR height mismatch, trailing overlays, embedded files, and EXIF metadata.
"""

import sys
import os
import struct
import zlib
import re
import argparse
import subprocess
from pathlib import Path

# Add project root to sys.path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree
from rich.markup import escape

from core.banner import print_banner
from core.utils import human_size, calculate_entropy

console = Console(force_terminal=True, legacy_windows=False)

MAGIC_SIGNATURES = [
    (b"PK\x03\x04", "ZIP Archive", ".zip"),
    (b"7z\xbc\xaf'\x1c", "7-Zip Archive", ".7z"),
    (b"Rar!\x1a\x07\x00", "RAR v4 Archive", ".rar"),
    (b"Rar!\x1a\x07\x01\x00", "RAR v5 Archive", ".rar"),
    (b"\x1f\x8b\x08", "GZIP Archive", ".gz"),
    (b"%PDF-", "PDF Document", ".pdf"),
    (b"MZ", "Windows PE Executable", ".exe"),
    (b"\x7fELF", "Linux ELF Executable", ".elf"),
    (b"RIFF", "RIFF Audio/Video", ".wav"),
    (b"\xff\xd8\xff", "JPEG Image", ".jpg"),
    (b"\x89PNG\r\n\x1a\n", "PNG Image", ".png"),
    (b"GIF89a", "GIF89a Animation", ".gif"),
    (b"GIF87a", "GIF87a Image", ".gif"),
]

STANDARD_PNG_CHUNKS = {
    "IHDR", "PLTE", "IDAT", "IEND", "cHRM", "gAMA", "iCCP", "sBIT", "sRGB",
    "bKGD", "hIST", "tRNS", "pHYs", "sPLT", "tIME", "iTXt", "tEXt", "zTXt",
    "eXIf", "acTL", "fcTL", "fdAT"
}

def scan_png(data: bytes, file_path: str, fix_height: bool = False, carve_dir: str = None) -> dict:
    results = {"type": "PNG", "chunks": [], "anomalies": [], "carved": []}
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        results["anomalies"].append("[bold red]Signature mismatch:[/bold red] File does not start with standard PNG magic header.")
        return results

    offset = 8
    total_len = len(data)
    ihdr_found = False
    iend_found = False

    while offset + 12 <= total_len:
        length = struct.unpack(">I", data[offset:offset+4])[0]
        ctype_bytes = data[offset+4:offset+8]
        ctype = ctype_bytes.decode(errors="ignore")
        cdata = data[offset+8:offset+8+length]
        crc = struct.unpack(">I", data[offset+8+length:offset+12+length])[0]
        calc_crc = zlib.crc32(data[offset+4:offset+8+length])
        crc_valid = (crc == calc_crc)

        is_standard = ctype in STANDARD_PNG_CHUNKS
        chunk_info = {
            "type": ctype,
            "length": length,
            "offset": hex(offset),
            "crc": hex(crc),
            "crc_valid": crc_valid,
            "is_standard": is_standard,
            "data": cdata
        }
        results["chunks"].append(chunk_info)

        if not is_standard:
            results["anomalies"].append(f"[bold yellow]Non-Standard Custom Chunk Detected:[/bold yellow] [bold white]{ctype}[/bold white] at offset {hex(offset)} (Length: {length} bytes)")

        if not crc_valid:
            results["anomalies"].append(f"[bold red]CRC Checksum Mismatch in Chunk '{ctype}':[/bold red] Header CRC {hex(crc)} != Calc CRC {hex(calc_crc)}")

        # Check IHDR Height Tampering
        if ctype == "IHDR" and length == 13:
            ihdr_found = True
            width, height, bit_depth, color_type, comp, filt, interlace = struct.unpack(">IIBBBBB", cdata)
            chunk_info["ihdr"] = {
                "width": width,
                "height": height,
                "bit_depth": bit_depth,
                "color_type": color_type
            }

            # If CRC failed on IHDR, bruteforce correct height!
            if not crc_valid:
                results["anomalies"].append(f"[bold yellow]Possible PNG IHDR Height Tampering detected![/bold yellow] Dimensions: {width}x{height}")
                found_h = None
                for candidate_h in range(1, 10000):
                    test_ihdr = struct.pack(">IIBBBBB", width, candidate_h, bit_depth, color_type, comp, filt, interlace)
                    if zlib.crc32(b"IHDR" + test_ihdr) == crc:
                        found_h = candidate_h
                        break
                if found_h:
                    results["anomalies"].append(f"[bold green] Recovered True IHDR Height:[/bold green] [bold white]{found_h}px[/bold white] (Originally disguised as {height}px)")
                    if fix_height:
                        fixed_data = bytearray(data)
                        fixed_data[offset+8+4:offset+8+8] = struct.pack(">I", found_h)
                        out_fixed = file_path.replace(".png", "_fixed_height.png")
                        with open(out_fixed, "wb") as f:
                            f.write(fixed_data)
                        results["carved"].append(f"Fixed image saved to: {out_fixed}")

        if ctype == "IEND":
            iend_found = True
            iend_end_offset = offset + 12
            if iend_end_offset < total_len:
                trailing_len = total_len - iend_end_offset
                trailing_bytes = data[iend_end_offset:]
                results["anomalies"].append(f"[bold red]Trailing Overlay Bytes Detected Past IEND:[/bold red] {trailing_len} bytes at offset {hex(iend_end_offset)}")
                if carve_dir:
                    os.makedirs(carve_dir, exist_ok=True)
                    overlay_path = os.path.join(carve_dir, "trailing_overlay.bin")
                    with open(overlay_path, "wb") as f:
                        f.write(trailing_bytes)
                    results["carved"].append(f"Saved trailing overlay to: {overlay_path}")
            break

        offset += 12 + length

    return results

def scan_jpeg(data: bytes, file_path: str, carve_dir: str = None) -> dict:
    results = {"type": "JPEG", "anomalies": [], "carved": []}
    if not data.startswith(b"\xff\xd8"):
        results["anomalies"].append("[bold red]Signature mismatch:[/bold red] File does not start with standard JPEG magic \\xFF\\xD8.")
        return results

    eoi_idx = data.rfind(b"\xff\xd9")
    if eoi_idx != -1:
        trailing_len = len(data) - (eoi_idx + 2)
        if trailing_len > 0:
            trailing_bytes = data[eoi_idx+2:]
            results["anomalies"].append(f"[bold red]Trailing Overlay Bytes Detected Past EOI (\\xFF\\xD9):[/bold red] {trailing_len} bytes at offset {hex(eoi_idx+2)}")
            if carve_dir:
                os.makedirs(carve_dir, exist_ok=True)
                overlay_path = os.path.join(carve_dir, "trailing_overlay.bin")
                with open(overlay_path, "wb") as f:
                    f.write(trailing_bytes)
                results["carved"].append(f"Saved trailing overlay to: {overlay_path}")
    else:
        results["anomalies"].append("[bold yellow]No EOI Marker (\\xFF\\xD9) found in JPEG file![/bold yellow]")

    return results

def carve_embedded_files(data: bytes, carve_dir: str) -> list:
    carved = []
    if not carve_dir:
        return carved

    os.makedirs(carve_dir, exist_ok=True)
    for magic, desc, ext in MAGIC_SIGNATURES:
        # Ignore match at offset 0 (which is the primary file)
        start = 1
        while True:
            idx = data.find(magic, start)
            if idx == -1:
                break
            out_file = os.path.join(carve_dir, f"carved_0x{idx:X}_{desc.replace(' ', '_')}{ext}")
            with open(out_file, "wb") as f:
                f.write(data[idx:])
            carved.append((idx, desc, out_file))
            start = idx + len(magic)

    return carved

def check_exif_metadata(file_path: str) -> list:
    findings = []
    try:
        out = subprocess.check_output(["exiftool", "-s", file_path], text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                k = k.strip()
                v = v.strip()
                # Check suspicious tags
                if any(w in k.lower() for w in ["comment", "usercomment", "description", "xpcomment", "preservation", "author", "copyright", "artist"]):
                    findings.append((k, v))
                elif re.search(r'([A-Za-z0-9+/]{20,}={0,2})', v):
                    findings.append((f"{k} [Base64-like]", v))
    except Exception:
        pass
    return findings

def main(args=None):
    parser = argparse.ArgumentParser(
        prog="stegoscan",
        description=" Comprehensive Steganography & File Integrity Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  stegoscan image.png
  stegoscan image.png --fix-height
  stegoscan suspicious.jpg --carve ./extracted/
  stegoscan payload.bin --deep
        """
    )
    parser.add_argument("file", help="Target file to analyze (.png, .jpg, .gif, .pdf, .bin)")
    parser.add_argument("--fix-height", action="store_true", help="Auto-fix PNG IHDR height mismatch based on CRC")
    parser.add_argument("--carve", metavar="DIR", help="Directory to save carved embedded files and trailing overlays")
    parser.add_argument("--deep", action="store_true", help="Run zsteg deep analysis on image")

    args = parser.parse_args(args)

    if not os.path.exists(args.file):
        console.print(f"[bold red]Error: File not found: {args.file}[/bold red]")
        sys.exit(1)

    print_banner(tool_name="STEGANOGRAPHY & ARTIFACT SCANNER (stegoscan)", sub_title="Deep Structural, Chunk, & Overlay Triage")

    file_path = os.path.abspath(args.file)
    with open(file_path, "rb") as f:
        raw_data = f.read()

    file_size = len(raw_data)
    entropy = calculate_entropy(raw_data)

    console.print(f"[bold cyan]Target File:[/bold cyan] [bold white]{os.path.basename(file_path)}[/bold white]")
    console.print(f"[bold cyan]File Size:[/bold cyan] {human_size(file_size)} ({file_size} bytes)")
    console.print(f"[bold cyan]Entropy:[/bold cyan] {entropy:.4f} / 8.0000\n")

    # 1. Structural Check
    if raw_data.startswith(b"\x89PNG\r\n\x1a\n"):
        res = scan_png(raw_data, file_path, fix_height=args.fix_height, carve_dir=args.carve)
        chunks = res.get("chunks", [])

        # Display Chunks Table
        table = Table(title=f"PNG Chunks Structure ({len(chunks)} chunks found)", show_header=True, header_style="bold cyan", expand=True)
        table.add_column("Type", style="bold yellow", width=10)
        table.add_column("Offset", style="bold magenta", width=12)
        table.add_column("Length", justify="right", width=12)
        table.add_column("CRC32", style="cyan", width=14)
        table.add_column("Status", width=16)

        for c in chunks:
            status = "[bold green]VALID[/bold green]" if c["crc_valid"] else "[bold red]CRC ERROR[/bold red]"
            if not c["is_standard"]:
                status += " [bold yellow][CUSTOM][/bold yellow]"
            table.add_row(c["type"], c["offset"], f"{c['length']} B", c["crc"], status)
        console.print(table)

    elif raw_data.startswith(b"\xff\xd8"):
        res = scan_jpeg(raw_data, file_path, carve_dir=args.carve)
    else:
        res = {"type": "Generic Binary", "anomalies": [], "carved": []}

    # Display Anomalies
    anomalies = res.get("anomalies", [])
    if anomalies:
        panel_text = "\n".join(f"• {a}" for a in anomalies)
        console.print(Panel(panel_text, title=" Structural Anomalies & Stego Indicators", border_style="bold yellow"))
    else:
        console.print("[bold green] No obvious structural header anomalies detected.[/bold green]\n")

    # 2. Carving Check
    carved_files = carve_embedded_files(raw_data, args.carve)
    if carved_files:
        carve_tree = Tree("[bold green] Embedded Files Carved:[/bold green]")
        for offset, desc, out_path in carved_files:
            carve_tree.add(f"[bold cyan]0x{offset:X}:[/bold cyan] [bold white]{desc}[/bold white] -> [dim]{out_path}[/dim]")
        console.print(carve_tree)
        console.print()
    elif not args.carve:
        # Just scan and report without saving
        embedded_detected = []
        for magic, desc, ext in MAGIC_SIGNATURES:
            start = 1
            while True:
                idx = raw_data.find(magic, start)
                if idx == -1:
                    break
                embedded_detected.append((idx, desc))
                start = idx + len(magic)
        if embedded_detected:
            tree = Tree("[bold yellow] Embedded Binary Signatures Detected (Use --carve <dir> to extract):[/bold yellow]")
            for offset, desc in embedded_detected:
                tree.add(f"[bold magenta]Offset 0x{offset:X}:[/bold magenta] {desc}")
            console.print(tree)
            console.print()

    # 3. EXIF & Metadata
    exif_findings = check_exif_metadata(file_path)
    if exif_findings:
        exif_table = Table(title="EXIF & Suspicious Metadata Tags", show_header=True, header_style="bold cyan")
        exif_table.add_column("Tag Name", style="bold yellow", width=25)
        exif_table.add_column("Value / Content", style="white")
        for tag, val in exif_findings:
            exif_table.add_row(tag, escape(val[:120] + ("..." if len(val) > 120 else "")))
        console.print(exif_table)
        console.print()

    # 4. Deep zsteg
    if args.deep and raw_data.startswith(b"\x89PNG\r\n\x1a\n"):
        console.print("[bold cyan]Running Deep Multi-Plane zsteg Analysis...[/bold cyan]")
        try:
            out = subprocess.check_output(["zsteg", "-a", file_path], text=True, stderr=subprocess.DEVNULL)
            matches = [line for line in out.splitlines() if "text:" in line or "file:" in line]
            if matches:
                ztable = Table(title="zsteg Hidden Data Extracted", show_header=True, header_style="bold cyan")
                ztable.add_column("Payload Stream", style="bold magenta", width=25)
                ztable.add_column("Extracted Data", style="white")
                for m in matches[:15]:
                    parts = m.split("..", 1)
                    if len(parts) == 2:
                        ztable.add_row(parts[0].strip(), escape(parts[1].strip()))
                console.print(ztable)
        except Exception:
            pass

if __name__ == "__main__":
    main()
