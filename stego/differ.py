#!/usr/bin/env python3
"""
2-Image Spatial Differential & Matrix Shift Steganography Analyzer (stegodiff)
Automatically bruteforces 2D pixel alignment shifts (dx, dy), extracts residual arithmetic deltas (+1/+2, XOR), and decodes hidden border/payload bitstreams.
"""

import sys
import os
import argparse
import numpy as np
from PIL import Image

# Add project root to sys.path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree

from core.banner import print_banner
from core.utils import is_ascii_printable

console = Console(force_terminal=True, legacy_windows=False)

def find_optimal_shift(arr1: np.ndarray, arr2: np.ndarray, max_shift: int = 10) -> tuple:
    best_shift = (0, 0)
    best_diff_count = arr1.size
    h1, w1 = arr1.shape[:2]
    h2, w2 = arr2.shape[:2]

    candidates = []
    for dy in range(-max_shift, max_shift + 1):
        for dx in range(-max_shift, max_shift + 1):
            sub1 = arr1[max(0, dy):h1+min(0, dy), max(0, dx):w1+min(0, dx)]
            sub2 = arr2[max(0, -dy):h2+min(0, -dy), max(0, -dx):w2+min(0, -dx)]

            if sub1.shape == sub2.shape and sub1.size > 0:
                diff_count = np.count_nonzero(sub1 != sub2)
                diff_ratio = diff_count / sub1.size
                candidates.append((dx, dy, diff_count, sub1.size, diff_ratio))
                if diff_count < best_diff_count:
                    best_diff_count = diff_count
                    best_shift = (dx, dy)

    candidates.sort(key=lambda x: x[2])
    return best_shift, best_diff_count, candidates[:5]

def analyze_residual_deltas(arr1: np.ndarray, arr2: np.ndarray, dx: int, dy: int) -> dict:
    h1, w1 = arr1.shape[:2]
    h2, w2 = arr2.shape[:2]

    sub1 = arr1[max(0, dy):h1+min(0, dy), max(0, dx):w1+min(0, dx)]
    sub2 = arr2[max(0, -dy):h2+min(0, -dy), max(0, -dx):w2+min(0, -dx)]

    diff_mask = (sub1 != sub2)
    y_idxs, x_idxs, c_idxs = np.where(diff_mask) if sub1.ndim == 3 else (*np.where(diff_mask), [0]*len(np.where(diff_mask)[0]))

    findings = {
        "diff_pixels_count": len(y_idxs),
        "contiguous_deltas": [],
        "decoded_texts": []
    }

    if len(y_idxs) > 0 and len(y_idxs) < 2000:
        # Check if diff values are small integers (+1, +2, etc.)
        for c in range(sub1.shape[2] if sub1.ndim == 3 else 1):
            c_mask = (c_idxs == c)
            if np.count_nonzero(c_mask) > 0:
                c_y = y_idxs[c_mask]
                c_x = x_idxs[c_mask]
                vals1 = sub1[c_y, c_x, c] if sub1.ndim == 3 else sub1[c_y, c_x]
                vals2 = sub2[c_y, c_x, c] if sub2.ndim == 3 else sub2[c_y, c_x]
                deltas = (vals1.astype(int) - vals2.astype(int))

                unique_deltas = sorted(set(deltas))
                if len(unique_deltas) == 2 and set(unique_deltas) in [{1, 2}, {-1, -2}, {0, 1}]:
                    # Binary mapped sequence!
                    min_d = min(unique_deltas)
                    bits = [0 if d == min_d else 1 for d in deltas]
                    # Pack bits into ASCII
                    if len(bits) >= 8:
                        pad = (8 - (len(bits) % 8)) % 8
                        padded_bits = bits + [0] * pad
                        bytes_val = np.packbits(padded_bits).tobytes()
                        if is_ascii_printable(bytes_val[:len(bits)//8]):
                            text = bytes_val[:len(bits)//8].decode(errors="ignore")
                            findings["decoded_texts"].append(f"Channel {c} Binary Delta ({unique_deltas}): '{text}'")

    return findings

def check_border_modulations(arr: np.ndarray) -> list:
    borders = []
    h, w = arr.shape[:2]
    # Check top row y=0
    top_row = arr[0, :, -1] if arr.ndim == 3 else arr[0, :]
    if set(top_row).issubset({0, 1}):
        nonzeros = np.count_nonzero(top_row)
        if 0 < nonzeros < len(top_row):
            bits = top_row[:32].tolist()
            bits_str = ''.join(map(str, bits))
            borders.append(f"Top Row (y=0) Binary Modulation Detected ({nonzeros} bits set): {bits_str}...")

    # Check left col x=0
    left_col = arr[:, 0, -1] if arr.ndim == 3 else arr[:, 0]
    if set(left_col).issubset({0, 1}):
        nonzeros = np.count_nonzero(left_col)
        if 0 < nonzeros < len(left_col):
            bits = left_col[:32].tolist()
            bits_str = ''.join(map(str, bits))
            borders.append(f"Left Column (x=0) Binary Modulation Detected ({nonzeros} bits set): {bits_str}...")

    return borders

def main(args=None):
    parser = argparse.ArgumentParser(
        prog="stegodiff",
        description=" 2-Image Spatial Differential & Matrix Shift Steganography Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  stegodiff scan_042_preview.png scan_042_reference.png
  stegodiff target.png original.png --max-shift 15 --save-diff ./diff_out/
        """
    )
    parser.add_argument("image1", help="First image (Target / Restored derivative)")
    parser.add_argument("image2", help="Second image (Reference / Original baseline)")
    parser.add_argument("--max-shift", type=int, default=10, help="Maximum 2D pixel shift search radius (default: 10)")
    parser.add_argument("--save-diff", metavar="DIR", help="Directory to save visual difference PNG images")

    args = parser.parse_args(args)

    for p in [args.image1, args.image2]:
        if not os.path.exists(p):
            console.print(f"[bold red]Error: File not found: {p}[/bold red]")
            sys.exit(1)

    print_banner(tool_name="SPATIAL DIFFERENTIAL ANALYZER (stegodiff)", sub_title="Matrix Shift, Residual Delta, & Bitstream Triage")

    img1 = Image.open(args.image1)
    img2 = Image.open(args.image2)
    arr1 = np.array(img1)
    arr2 = np.array(img2)

    console.print(f"[bold cyan]Image 1 (Target):[/bold cyan] [bold white]{os.path.basename(args.image1)}[/bold white] ({img1.size[0]}x{img1.size[1]} {img1.mode})")
    console.print(f"[bold cyan]Image 2 (Reference):[/bold cyan] [bold white]{os.path.basename(args.image2)}[/bold white] ({img2.size[0]}x{img2.size[1]} {img2.mode})\n")

    # 1. Unshifted direct difference
    if arr1.shape == arr2.shape:
        direct_diff = np.count_nonzero(arr1 != arr2)
        direct_ratio = direct_diff / arr1.size
        console.print(f"[bold yellow]Direct (Unshifted) Difference:[/bold yellow] {direct_diff} / {arr1.size} bytes differing ({direct_ratio*100:.2f}%)")

    # 2. Bruteforce 2D Shift Alignment
    console.print(f"[bold cyan]Scanning 2D spatial shifts in radius [-{args.max_shift}, +{args.max_shift}]...[/bold cyan]")
    best_shift, best_diff, top_candidates = find_optimal_shift(arr1, arr2, max_shift=args.max_shift)
    dx, dy = best_shift

    shift_table = Table(title="Top Optimal Alignment Shifts (Lowest Difference)", show_header=True, header_style="bold cyan")
    shift_table.add_column("Rank", style="bold yellow", width=6)
    shift_table.add_column("Shift (dx, dy)", style="bold magenta", width=16)
    shift_table.add_column("Diff Pixels", justify="right", width=14)
    shift_table.add_column("Diff Ratio", justify="right", width=12)

    for idx, (cdx, cdy, cdiff, ctotal, cratio) in enumerate(top_candidates):
        is_best = " [bold green] BEST[/bold green]" if idx == 0 else ""
        shift_table.add_row(f"#{idx+1}", f"dx={cdx:+d}, dy={cdy:+d}{is_best}", f"{cdiff} / {ctotal}", f"{cratio*100:.2f}%")
    console.print(shift_table)
    console.print()

    # 3. Analyze Residual Deltas at Best Alignment
    console.print(f"[bold green] Analyzing residual deltas at optimal alignment (dx={dx:+d}, dy={dy:+d})...[/bold green]")
    analysis = analyze_residual_deltas(arr1, arr2, dx, dy)
    decoded_texts = analysis.get("decoded_texts", [])

    if decoded_texts:
        tree = Tree("[bold green] Decoded Hidden Strings from Residual Deltas:[/bold green]")
        for txt in decoded_texts:
            tree.add(f"[bold white]{txt}[/bold white]")
        console.print(tree)
        console.print()
    else:
        console.print(f"[dim]Total differing values at best alignment: {analysis.get('diff_pixels_count')}[/dim]\n")

    # 4. Check Border Modulations
    borders = check_border_modulations(arr1)
    if borders:
        b_tree = Tree("[bold yellow] Border Pixel Modulations Detected in Image 1:[/bold yellow]")
        for b in borders:
            b_tree.add(f"[bold cyan]{b}[/bold cyan]")
        console.print(b_tree)
        console.print()

    # 5. Save Diff Images
    if args.save_diff:
        os.makedirs(args.save_diff, exist_ok=True)
        # Direct XOR
        if arr1.shape == arr2.shape:
            xor_path = os.path.join(args.save_diff, "diff_direct_xor.png")
            Image.fromarray((arr1 ^ arr2).astype(np.uint8)).save(xor_path)
        # Aligned Diff
        h1, w1 = arr1.shape[:2]
        h2, w2 = arr2.shape[:2]
        sub1 = arr1[max(0, dy):h1+min(0, dy), max(0, dx):w1+min(0, dx)]
        sub2 = arr2[max(0, -dy):h2+min(0, -dy), max(0, -dx):w2+min(0, -dx)]
        aligned_path = os.path.join(args.save_diff, "diff_aligned_xor.png")
        Image.fromarray(((sub1 ^ sub2) * 255).astype(np.uint8)).save(aligned_path)
        console.print(f"[bold green] Visual diff images saved to {args.save_diff}[/bold green]\n")

if __name__ == "__main__":
    main()
