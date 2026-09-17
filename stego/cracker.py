#!/usr/bin/env python3
"""
Automated Steganography Password Cracker & Extractor (stegocrack)
High-speed extraction and wordlist bruteforcer for Steghide and OutGuess.
"""

import sys
import os
import argparse
import subprocess
import tempfile
from pathlib import Path

# Add project root to sys.path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

from core.banner import print_banner

console = Console(force_terminal=True, legacy_windows=False)

COMMON_CTF_PASSWORDS = [
    "",  # Blank password
    "password",
    "admin",
    "123456",
    "12345678",
    "flag",
    "stego",
    "secret",
    "hidden",
    "ctf",
    "root",
    "toor",
    "pass",
    "letmein",
    "welcome",
    "access",
    "qwerty",
]

def try_steghide(file_path: str, password: str, output_file: str) -> bool:
    try:
        cmd = ["steghide", "extract", "-sf", file_path, "-p", password, "-xf", output_file, "-f"]
        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res.returncode == 0 and os.path.exists(output_file) and os.path.getsize(output_file) > 0
    except Exception:
        return False

def try_outguess(file_path: str, key: str, output_file: str) -> bool:
    try:
        cmd = ["outguess", "-k", key, "-r", file_path, output_file]
        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res.returncode == 0 and os.path.exists(output_file) and os.path.getsize(output_file) > 0
    except Exception:
        return False

def main(args=None):
    parser = argparse.ArgumentParser(
        prog="stegocrack",
        description=" Automated Steganography Password Cracker & Extractor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  stegocrack target.jpg
  stegocrack target.jpg -w /usr/share/wordlists/rockyou.txt
  stegocrack target.jpg -o ./extracted_secret.bin
        """
    )
    parser.add_argument("file", help="Target stego image (.jpg, .jpeg, .bmp, .wav)")
    parser.add_argument("-w", "--wordlist", help="Path to custom wordlist for dictionary attack")
    parser.add_argument("-o", "--output", help="Destination path for extracted payload (default: ./extracted_<filename>.bin)")

    args = parser.parse_args(args)

    if not os.path.exists(args.file):
        console.print(f"[bold red]Error: File not found: {args.file}[/bold red]")
        sys.exit(1)

    print_banner(tool_name="STEGANOGRAPHY PASSWORD CRACKER (stegocrack)", sub_title="Automated Steghide & OutGuess Extraction")

    file_path = os.path.abspath(args.file)
    base_name = os.path.splitext(os.path.basename(file_path))[0]
    out_file = os.path.abspath(args.output) if args.output else os.path.abspath(f"./extracted_{base_name}.bin")

    console.print(f"[bold cyan]Target File:[/bold cyan] [bold white]{os.path.basename(file_path)}[/bold white]")
    console.print(f"[bold cyan]Output Destination:[/bold cyan] [bold magenta]{out_file}[/bold magenta]\n")

    # Build passwords list
    passwords = list(COMMON_CTF_PASSWORDS)
    passwords.append(base_name)
    passwords.append(base_name.lower())
    passwords.append(base_name.upper())

    if args.wordlist:
        if os.path.exists(args.wordlist):
            console.print(f"[bold cyan]Loading wordlist:[/bold cyan] {args.wordlist}")
            with open(args.wordlist, "r", errors="ignore") as f:
                for line in f:
                    p = line.strip()
                    if p and p not in passwords:
                        passwords.append(p)
        else:
            console.print(f"[bold red]Wordlist not found: {args.wordlist}[/bold red]")

    console.print(f"[bold cyan]Attempting extraction with {len(passwords)} password candidates...[/bold cyan]")

    success = False
    cracked_pass = None
    engine = None

    # 1. Steghide
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), console=console) as prog:
        task = prog.add_task("[yellow]Testing Steghide...", total=len(passwords))
        for pwd in passwords:
            prog.update(task, advance=1, description=f"[yellow]Testing Steghide: '{pwd[:15]}'")
            if try_steghide(file_path, pwd, out_file):
                success = True
                cracked_pass = pwd
                engine = "Steghide"
                break

    # 2. OutGuess fallback
    if not success:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), console=console) as prog:
            task = prog.add_task("[yellow]Testing OutGuess...", total=min(len(passwords), 500))
            for pwd in passwords[:500]:
                prog.update(task, advance=1, description=f"[yellow]Testing OutGuess: '{pwd[:15]}'")
                if try_outguess(file_path, pwd, out_file):
                    success = True
                    cracked_pass = pwd
                    engine = "OutGuess"
                    break

    if success:
        console.print(f"\n[bold green] SUCCESS! Payload extracted via {engine}![/bold green]")
        display_pwd = f"'{cracked_pass}'" if cracked_pass != "" else "[italic](Empty/Blank Password)[/italic]"
        console.print(f"[bold cyan]Password Found:[/bold cyan] [bold white]{display_pwd}[/bold white]")
        console.print(f"[bold cyan]Extracted Payload:[/bold cyan] [bold magenta]{out_file}[/bold magenta] ({os.path.getsize(out_file)} bytes)\n")

        # Preview extracted text
        try:
            with open(out_file, "rb") as f:
                preview = f.read(200)
            console.print(Panel(preview.decode(errors="ignore"), title="Payload Preview", border_style="bold green"))
        except Exception:
            pass
    else:
        console.print(f"\n[bold red][-] Extraction failed. No matching password found in candidate list.[/bold red]")
        console.print("[dim]Tip: Try specifying a larger wordlist with -w /path/to/rockyou.txt[/dim]\n")

if __name__ == "__main__":
    main()
