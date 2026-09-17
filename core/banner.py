"""
Terminal Banners & Visual Styling for DFIR Toolkit
"""
import sys
import io

# Ensure UTF-8 output on Windows terminal
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console(force_terminal=True, legacy_windows=False)

def print_banner(tool_name: str = "DFIR ADVANCED TOOLKIT", sub_title: str = "Digital Forensics & Incident Response Platform"):
    """
    Render a clean modern terminal banner using Rich.
    """
    title_text = Text()
    title_text.append("=================================================================\n", style="bold cyan")
    title_text.append(f" {tool_name.center(63)}\n", style="bold white on blue")
    title_text.append(f" {sub_title.center(63)}\n", style="italic bright_white")
    title_text.append("=================================================================", style="bold cyan")
    
    console.print(title_text)

def print_ad1_banner(module_name: str = "AD1 HISTORY EXTRACTION ENGINE"):
    """
    Render AD1 specific banner.
    """
    panel = Panel(
        Text(f"[+] {module_name} [+]\nAccessData Logical Image (AD1) Multi-Browser Forensics Analyzer", justify="center", style="bold white"),
        border_style="cyan",
        subtitle="[dim]v1.0.0 | DFIR Toolkit[/dim]",
        subtitle_align="right"
    )
    console.print(panel)
