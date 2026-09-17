"""
Unified AD1 CLI Command Line Interface
"""
import os
import sys
import argparse
from rich.console import Console
from rich.tree import Tree
from rich.table import Table
from rich.panel import Panel

from core.banner import print_banner, print_ad1_banner
from core.reporter import (
    print_history_table,
    export_to_csv,
    export_to_json,
    export_to_markdown,
    export_to_html
)
from .parser import AD1Parser
from .browser_history import BrowserHistoryExtractor
from .extractor import AD1Extractor
from .dpapi_bundle import DPAPIBundleExtractor, print_dpapi_triage_panel

console = Console(force_terminal=True, legacy_windows=False)


def cmd_history(args):
    """
    Handler for 'history' command: extracts and analyzes all browser history.
    Also correlates login URLs -> validates 'Login Data' -> auto-extracts DPAPI bundles.
    """
    image_path = args.input
    if not os.path.exists(image_path):
        console.print(f"[bold red]Error:[/bold red] File not found: {image_path}")
        sys.exit(1)

    print_ad1_banner("AD1 BROWSER HISTORY ANALYZER (ad1history)")
    console.print(f"[dim]Opening image container:[/dim] [cyan]{image_path}[/cyan]\n")

    with console.status("[bold cyan]Mounting & scanning AD1 logical image...[/bold cyan]"):
        parser = AD1Parser(image_path)
        extractor = BrowserHistoryExtractor(parser)
        records = extractor.scan_and_extract(browser_filter=args.browser)

    if not records:
        console.print("[bold yellow] No browser history artifacts found in the AD1 image.[/bold yellow]")
        parser.close()
        return

    # Filter keyword if specified
    if args.query:
        q_lower = args.query.lower()
        records = [
            r for r in records
            if q_lower in (r.get("url") or "").lower()
            or q_lower in (r.get("title") or "").lower()
            or q_lower in (r.get("domain") or "").lower()
            or q_lower in (r.get("search_terms") or "").lower()
        ]

    # Filter search queries only if flag provided
    if getattr(args, 'search_only', False):
        records = [r for r in records if r.get("search_terms")]

    # Limit rows for console display
    limit = args.limit if args.limit else 100

    # Display Table in Terminal
    print_history_table(records, max_rows=limit)

    # Automated Login URL -> Login Data -> DPAPI Extraction Check
    auto_extract = not getattr(args, 'no_creds_extract', False)
    creds_dir = getattr(args, 'creds_dir', './extracted_credentials')
    triage_info = {"triggered": False}

    if auto_extract:
        dpapi_extractor = DPAPIBundleExtractor(parser)
        triage_info = dpapi_extractor.correlate_and_triage(records, output_base_dir=creds_dir)
        if triage_info.get("triggered"):
            print_dpapi_triage_panel(triage_info)

            # Check if user requested direct password/NTLM/wordlist decryption
            pwd = getattr(args, 'password', None)
            ntlm = getattr(args, 'ntlm', None)
            wlist = getattr(args, 'wordlist', None)
            auto_sam = getattr(args, 'auto_sam', False)

            if pwd or ntlm or wlist or auto_sam:
                from ad1.dpapi_decrypt import AD1DPAPIDecryptor, print_decrypted_table
                dec = AD1DPAPIDecryptor(parser=parser)
                decrypted_creds = dec.decrypt_bundle(password=pwd, ntlm_hex=ntlm, wordlist_path=wlist)
                print_decrypted_table(decrypted_creds)
                triage_info["decrypted_credentials"] = decrypted_creds

    # Export Handlers
    source_name = os.path.basename(image_path)
    if hasattr(args, 'md') and args.md:
        export_to_markdown(records, args.md, source_name=source_name, dpapi_triage=triage_info)
    if hasattr(args, 'json') and args.json:
        export_to_json(records, args.json, dpapi_triage=triage_info)
    if hasattr(args, 'csv') and args.csv:
        export_to_csv(records, args.csv)
    if hasattr(args, 'html') and args.html:
        export_to_html(records, args.html, source_name=source_name)

    parser.close()


def cmd_info(args):
    """
    Handler for 'info' command: prints image metadata, segment list, data sources.
    """
    image_path = args.input
    if not os.path.exists(image_path):
        console.print(f"[bold red]Error:[/bold red] File not found: {image_path}")
        sys.exit(1)

    parser = AD1Parser(image_path)
    parser.build_tree()

    print_ad1_banner("AD1 IMAGE INFORMATION")

    table = Table(show_header=False, border_style="cyan")
    table.add_column("Property", style="bold yellow", width=25)
    table.add_column("Value", style="white")

    table.add_row("Primary File", os.path.abspath(image_path))
    table.add_row("Total Segments", f"{len(parser.segment_paths)} segment(s)")
    for idx, p in enumerate(parser.segment_paths):
        size_str = human_size(parser.segment_sizes[idx])
        table.add_row(f"  Segment #{idx+1}", f"{os.path.basename(p)} ({size_str})")

    if parser.logical_header:
        table.add_row("Image Version", str(parser.logical_header.image_version))
        table.add_row("Data Source Name", parser.logical_header.data_source_name or "N/A")
        table.add_row("Zlib Chunk Size", human_size(parser.logical_header.zlib_chunk_size))

    table.add_row("Total Files & Folders", str(len(parser.items)))
    
    file_items = [i for i in parser.items if not i.is_dir]
    total_uncompressed = sum(i.decompressed_size for i in file_items)
    table.add_row("Total Uncompressed Size", human_size(total_uncompressed))

    console.print(table)
    parser.close()


def cmd_tree(args):
    """
    Handler for 'tree' command: prints hierarchical tree of items.
    """
    image_path = args.input
    if not os.path.exists(image_path):
        console.print(f"[bold red]Error:[/bold red] File not found: {image_path}")
        sys.exit(1)

    parser = AD1Parser(image_path)
    parser.build_tree()

    print_ad1_banner("AD1 ITEM HIERARCHY TREE")
    root_tree = Tree(f" [bold cyan]{os.path.basename(image_path)}[/bold cyan]")

    def add_children(node, items, depth=0, max_depth=5):
        if depth > max_depth:
            node.add("[dim]... (max depth reached)[/dim]")
            return
        for itm in items:
            if itm.is_dir:
                branch = node.add(f" [bold yellow]{itm.item_name}[/bold yellow]")
                if itm.children:
                    add_children(branch, itm.children, depth + 1, max_depth)
            else:
                size_str = human_size(itm.decompressed_size)
                node.add(f" [white]{itm.item_name}[/white] [dim]({size_str})[/dim]")

    add_children(root_tree, parser.root_items, max_depth=args.max_depth if hasattr(args, 'max_depth') else 5)
    console.print(root_tree)
    parser.close()


def cmd_extract(args):
    """
    Handler for 'extract' command: extracts all or matching files.
    """
    image_path = args.input
    out_dir = args.output or "./extracted"
    os.makedirs(out_dir, exist_ok=True)

    parser = AD1Parser(image_path)
    parser.build_tree()

    extractor = AD1Extractor(parser)

    if args.pattern:
        console.print(f"[cyan]Extracting files matching pattern:[/cyan] '{args.pattern}' -> [green]{out_dir}[/green]")
        extracted = extractor.extract_matching(args.pattern, out_dir)
        console.print(f"[bold green][/bold green] Extracted {len(extracted)} files successfully.")
    else:
        console.print(f"[cyan]Extracting all files[/cyan] -> [green]{out_dir}[/green]")
        count = extractor.extract_all(out_dir)
        console.print(f"[bold green][/bold green] Extracted {count} files successfully.")

    parser.close()
