"""
Interactive & Visual TCP/UDP Stream Follower (pcapstream / pcap/stream_follower.py)
Wireshark-style Follow Stream visualizer and raw stream exporter:
1. Bidirectional Color-Coded Follow Stream (Client  Server in Cyan, Server  Client in Green)
2. Multiple Representation Modes: Formatted Text, Canonical Hex Dump, and Raw Byte Stream
3. Targeted Stream Search & Regex Highlight
4. Payload Splitting & Disk Export (--raw-client, --raw-server, --export-dir)
5. Multi-format Exports (Terminal View, Markdown, Raw Bytes)
"""
import os
import sys
import argparse
import re
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
from pcap.pcap_engine import PCAPEngine, TCPStream

console = Console(force_terminal=True, legacy_windows=False)


def render_hexdump(data: bytes, title: str = "", color_style: str = "white"):
    """Renders a standard 16-byte side-by-side hex dump."""
    if not data:
        console.print(f"[{color_style}]<Empty Payload>[/{color_style}]")
        return

    table = Table(
        title=title if title else None,
        show_header=True,
        header_style="bold yellow",
        border_style="dim cyan",
        expand=True
    )
    table.add_column("Offset", style="bold magenta", width=10, justify="right")
    table.add_column("Hex Bytes (16-byte width)", style=color_style, min_width=50)
    table.add_column("ASCII Preview", style="bright_white", width=20)

    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        hex_str_1 = " ".join(f"{b:02X}" for b in chunk[:8])
        hex_str_2 = " ".join(f"{b:02X}" for b in chunk[8:])
        hex_full = f"{hex_str_1:<23}   {hex_str_2:<23}"

        ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        table.add_row(
            f"0x{i:08X}",
            hex_full,
            escape(ascii_str)
        )

    console.print(table)


def follow_stream(
    stream: TCPStream,
    mode: str = "text",
    search_query: Optional[str] = None,
    side: str = "both"
):
    """
    Renders bidirectional conversation for a TCP stream.
    """
    console.print(Panel(
        f"[bold white]Stream #{stream.stream_id} Conversation[/bold white]\n"
        f"[cyan]Client:[/cyan] {stream.client_ip}:{stream.client_port}  [green]Server:[/green] {stream.server_ip}:{stream.server_port}\n"
        f"[yellow]Protocol:[/yellow] {stream.protocol_name} | [yellow]Packets:[/yellow] {stream.packet_count:,} | [yellow]Total Traffic:[/yellow] {human_size(stream.total_bytes)}",
        title=f" Follow TCP Stream #{stream.stream_id}",
        border_style="bold green"
    ))

    # Reconstruct chronological packet flow
    # Each segment is (seq, payload, is_c2s)
    all_segments = []
    for seq, payload in stream._c2s_segments:
        all_segments.append((seq, payload, True))
    for seq, payload in stream._s2c_segments:
        all_segments.append((seq, payload, False))

    all_segments.sort(key=lambda x: x[0])

    if mode == "hex":
        if side in ("both", "client"):
            render_hexdump(stream.client_payload, f"Client  Server Payload ({human_size(len(stream.client_payload))})", "cyan")
        if side in ("both", "server"):
            render_hexdump(stream.server_payload, f"Server  Client Payload ({human_size(len(stream.server_payload))})", "green")
        return

    # Text mode rendering
    if side == "client":
        c_text = stream.client_payload.decode("latin-1", errors="replace")
        console.print(f"[bold cyan]=== Client Payload ({len(stream.client_payload):,} bytes) ===[/bold cyan]")
        console.print(escape(c_text))
    elif side == "server":
        s_text = stream.server_payload.decode("latin-1", errors="replace")
        console.print(f"[bold green]=== Server Payload ({len(stream.server_payload):,} bytes) ===[/bold green]")
        console.print(escape(s_text))
    else:
        # Interleaved conversation display
        console.print("[dim]─" * 70 + "[/dim]")
        for seq, payload, is_c2s in all_segments:
            text_chunk = payload.decode("latin-1", errors="replace")
            if search_query:
                if not re.search(re.escape(search_query), text_chunk, re.IGNORECASE):
                    continue

            if is_c2s:
                console.print(f"[bold cyan]▶ [{stream.client_ip}:{stream.client_port}  {stream.server_ip}:{stream.server_port} ({len(payload)} B)][/bold cyan]")
                console.print(f"[cyan]{escape(text_chunk)}[/cyan]")
            else:
                console.print(f"[bold green]◀ [{stream.server_ip}:{stream.server_port}  {stream.client_ip}:{stream.client_port} ({len(payload)} B)][/bold green]")
                console.print(f"[green]{escape(text_chunk)}[/green]")
            console.print("[dim]─" * 70 + "[/dim]")


def export_stream_payloads(stream: TCPStream, out_dir: str):
    """Saves raw client, server, and full stream payloads to disk."""
    os.makedirs(out_dir, exist_ok=True)
    c_path = os.path.join(out_dir, f"stream_{stream.stream_id}_client.bin")
    s_path = os.path.join(out_dir, f"stream_{stream.stream_id}_server.bin")
    f_path = os.path.join(out_dir, f"stream_{stream.stream_id}_full.bin")

    with open(c_path, "wb") as f: f.write(stream.client_payload)
    with open(s_path, "wb") as f: f.write(stream.server_payload)
    with open(f_path, "wb") as f: f.write(stream.reassembled_stream)

    console.print(f"[bold green][/bold green] Client Payload: [cyan]{c_path}[/cyan] ({human_size(len(stream.client_payload))})")
    console.print(f"[bold green][/bold green] Server Payload: [cyan]{s_path}[/cyan] ({human_size(len(stream.server_payload))})")
    console.print(f"[bold green][/bold green] Full Stream:    [cyan]{f_path}[/cyan] ({human_size(len(stream.reassembled_stream))})")


def main(args_list=None):
    parser = argparse.ArgumentParser(
        prog="pcapstream",
        description=" Interactive Wireshark-Style TCP/UDP Stream Follower & Dumper",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  pcapstream capture.pcap -s 2
  pcapstream capture.pcap -s 2 --hex
  pcapstream capture.pcap -s 2 --side client
  pcapstream capture.pcap -s 2 -o ./extracted_stream
  pcapstream capture.pcap --search "password"
        """
    )
    parser.add_argument("pcap_file", help="Path to input PCAP or PCAPNG file")
    parser.add_argument("-s", "--stream", type=int, help="Stream ID number to follow (e.g. 1, 2, 3...)")
    parser.add_argument("--hex", action="store_true", help="Display stream payload as hex dump")
    parser.add_argument("--side", choices=["both", "client", "server"], default="both", help="Payload direction filter (default: both)")
    parser.add_argument("--search", help="Search and filter text pattern across stream conversations")
    parser.add_argument("-o", "--out", "--export-dir", dest="out_dir", help="Directory to export raw stream binaries")

    args = parser.parse_args(args_list)

    if not os.path.exists(args.pcap_file):
        console.print(f"[bold red]Error:[/bold red] File not found: {args.pcap_file}")
        sys.exit(1)

    print_banner(
        tool_name="PCAP STREAM FOLLOWER & DUMPER (pcapstream)",
        sub_title="Wireshark-Style TCP/UDP Conversation Follower & Raw Hex Dumper"
    )

    engine = PCAPEngine(args.pcap_file)
    with console.status("[bold cyan]Reassembling TCP conversation streams...[/bold cyan]"):
        engine.analyze()

    streams = list(engine.tcp_streams.values())
    if not streams:
        console.print("[yellow] No TCP conversation streams found in this capture.[/yellow]")
        sys.exit(0)

    # Search mode across all streams
    if args.search and args.stream is None:
        console.print(f"[bold cyan] Searching for pattern '{args.search}' across {len(streams)} streams...[/bold cyan]\n")
        matched = 0
        for s in streams:
            raw_text = s.reassembled_stream.decode("latin-1", errors="replace")
            if re.search(re.escape(args.search), raw_text, re.IGNORECASE):
                matched += 1
                console.print(f"[bold yellow]Found match in Stream #{s.stream_id} ({s.client_ip}:{s.client_port} ⇄ {s.server_ip}:{s.server_port})[/bold yellow]")
                follow_stream(s, mode="hex" if args.hex else "text", search_query=args.search, side=args.side)
                console.print()
        if matched == 0:
            console.print(f"[yellow]No matches found for '{args.search}'.[/yellow]")
        return

    # Follow specific stream
    target_stream = None
    if args.stream is not None:
        for s in streams:
            if s.stream_id == args.stream:
                target_stream = s
                break
        if not target_stream:
            console.print(f"[bold red]Error:[/bold red] Stream ID #{args.stream} not found. (Available streams: 1 to {len(streams)})")
            sys.exit(1)
    else:
        # Default to stream #1 or largest stream
        target_stream = max(streams, key=lambda x: x.total_bytes)
        console.print(f"[dim][i] No stream specified. Automatically selecting Stream #{target_stream.stream_id} (Largest payload: {human_size(target_stream.total_bytes)})[/dim]\n")

    follow_stream(target_stream, mode="hex" if args.hex else "text", search_query=args.search, side=args.side)

    if args.out_dir:
        export_stream_payloads(target_stream, args.out_dir)


if __name__ == "__main__":
    main()
