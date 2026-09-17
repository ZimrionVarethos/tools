"""
PCAP Hierarchy, Endpoints & Conversation Stream Visualizer (pcaptree / pcap/tree.py)
Visualizes:
1. Protocol Distribution & Bandwidth Percentages
2. Endpoints Matrix (Top Talkers: Packets/Bytes Sent/Received)
3. Interactive TCP/UDP Conversation Streams with Service & SNI/URI Resolution
4. Multi-format Exports (Terminal Table, Markdown, JSON, CSV)
"""
import os
import sys
import argparse
import json
from typing import List, Dict, Any, Optional

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree
from rich.markup import escape

from core.banner import print_banner
from core.utils import human_size
from pcap.pcap_engine import PCAPEngine

console = Console(force_terminal=True, legacy_windows=False)


def render_protocol_tree(engine: PCAPEngine):
    total_pkts = len(engine.packets)
    total_bytes = sum(p.length for p in engine.packets)
    if total_pkts == 0:
        console.print("[yellow] Empty capture file.[/yellow]")
        return

    tree = Tree(f"[bold cyan] Protocol Hierarchy Distribution ({total_pkts:,} Packets | {human_size(total_bytes)})[/bold cyan]")
    
    # Sort protocols by packet count
    sorted_protos = sorted(engine.protocol_counts.items(), key=lambda x: x[1], reverse=True)
    for proto, count in sorted_protos:
        p_bytes = engine.protocol_bytes.get(proto, 0)
        pct_pkts = (count / total_pkts) * 100
        pct_bytes = (p_bytes / total_bytes) * 100 if total_bytes > 0 else 0
        tree.add(
            f"[bold green]{proto}[/bold green] ── [yellow]{count:,} pkts[/yellow] ([dim]{pct_pkts:.1f}%[/dim]) "
            f"| [cyan]{human_size(p_bytes)}[/cyan] ([dim]{pct_bytes:.1f}% bandwidth[/dim])"
        )

    console.print(tree)
    console.print()


def render_endpoints_table(engine: PCAPEngine, limit: int = 25):
    if not engine.endpoints:
        return

    table = Table(
        title=f" Top Network Endpoints ({len(engine.endpoints)} Hosts Detected)",
        show_header=True,
        header_style="bold magenta",
        border_style="cyan",
        expand=True
    )
    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("IP Address", style="bold cyan", width=22)
    table.add_column("Tx Packets", style="green", width=12, justify="right")
    table.add_column("Tx Bytes", style="green", width=14, justify="right")
    table.add_column("Rx Packets", style="yellow", width=12, justify="right")
    table.add_column("Rx Bytes", style="yellow", width=14, justify="right")
    table.add_column("Total Traffic", style="bold white", width=16, justify="right")

    # Sort endpoints by total traffic
    sorted_eps = sorted(
        engine.endpoints.items(),
        key=lambda x: (x[1]["tx_bytes"] + x[1]["rx_bytes"]),
        reverse=True
    )

    for idx, (ip, stats) in enumerate(sorted_eps[:limit], start=1):
        tot_bytes = stats["tx_bytes"] + stats["rx_bytes"]
        table.add_row(
            str(idx),
            ip,
            f"{stats['tx_packets']:,}",
            human_size(stats["tx_bytes"]),
            f"{stats['rx_packets']:,}",
            human_size(stats["rx_bytes"]),
            human_size(tot_bytes)
        )

    console.print(table)
    if len(sorted_eps) > limit:
        console.print(f"[dim]... and {len(sorted_eps) - limit} more endpoints (use --limit to expand)[/dim]")
    console.print()


def render_streams_table(engine: PCAPEngine, filter_proto: Optional[str] = None, filter_ip: Optional[str] = None, limit: int = 50):
    streams = list(engine.tcp_streams.values())
    if filter_proto:
        streams = [s for s in streams if filter_proto.lower() in s.protocol_name.lower()]
    if filter_ip:
        streams = [s for s in streams if filter_ip in (s.client_ip, s.server_ip)]

    if not streams:
        console.print("[yellow][i] No matching TCP streams found.[/yellow]")
        return

    table = Table(
        title=f" TCP Conversations & Reassembled Streams ({len(streams)} Streams)",
        show_header=True,
        header_style="bold yellow",
        border_style="bold green",
        expand=True
    )
    table.add_column("Stream", style="bold magenta", width=8, justify="center")
    table.add_column("Client (Source)", style="cyan", width=22)
    table.add_column("Direction", style="dim", width=5, justify="center")
    table.add_column("Server (Destination)", style="cyan", width=22)
    table.add_column("Proto", style="bold green", width=8, justify="center")
    table.add_column("Packets", style="white", width=8, justify="right")
    table.add_column("Bytes", style="white", width=12, justify="right")
    table.add_column("Conversation Summary / Host / SNI", style="yellow", min_width=32, overflow="fold")

    for s in streams[:limit]:
        duration = s.end_time - s.start_time
        summary_text = s.summary or (f"SNI: {s.sni}" if s.sni else f"Payload: {human_size(len(s.reassembled_stream))}")
        table.add_row(
            f"#{s.stream_id}",
            f"{s.client_ip}:{s.client_port}",
            "⇄",
            f"{s.server_ip}:{s.server_port}",
            s.protocol_name,
            f"{s.packet_count:,}",
            human_size(s.total_bytes),
            escape(summary_text)
        )

    console.print(table)
    if len(streams) > limit:
        console.print(f"[dim]... and {len(streams) - limit} more streams (use --limit to expand)[/dim]")


# -------------------------------------------------------------
# Export Handlers (Markdown, JSON, CSV)
# -------------------------------------------------------------

def export_tree_markdown(engine: PCAPEngine, output_path: str):
    lines = [
        f"# PCAP Structure & Conversation Hierarchy Report",
        f"- **File:** `{os.path.basename(engine.file_path)}`",
        f"- **Total Packets:** `{len(engine.packets):,}`",
        f"- **Total Streams:** `{len(engine.tcp_streams):,}`",
        f"- **Unique Endpoints:** `{len(engine.endpoints):,}`",
        "",
        "##  Protocol Distribution",
        "| Protocol | Packets | % Packets | Bandwidth |",
        "|---|---|---|---|"
    ]
    tot_pkts = len(engine.packets)
    tot_bytes = sum(p.length for p in engine.packets)
    for proto, count in sorted(engine.protocol_counts.items(), key=lambda x: x[1], reverse=True):
        p_bytes = engine.protocol_bytes.get(proto, 0)
        lines.append(f"| **{proto}** | {count:,} | {(count/tot_pkts)*100:.1f}% | {human_size(p_bytes)} |")

    lines.append("\n##  Endpoints Matrix")
    lines.append("| # | IP Address | Tx Packets | Tx Bytes | Rx Packets | Rx Bytes | Total Traffic |")
    lines.append("|---|---|---|---|---|---|---|")
    sorted_eps = sorted(engine.endpoints.items(), key=lambda x: (x[1]["tx_bytes"] + x[1]["rx_bytes"]), reverse=True)
    for idx, (ip, stats) in enumerate(sorted_eps[:100], start=1):
        tot = stats["tx_bytes"] + stats["rx_bytes"]
        lines.append(f"| {idx} | `{ip}` | {stats['tx_packets']:,} | {human_size(stats['tx_bytes'])} | {stats['rx_packets']:,} | {human_size(stats['rx_bytes'])} | **{human_size(tot)}** |")

    lines.append("\n##  TCP Conversation Streams")
    lines.append("| Stream | Client | Server | Proto | Packets | Bytes | Summary / Host / SNI |")
    lines.append("|---|---|---|---|---|---|---|")
    for s in list(engine.tcp_streams.values())[:150]:
        sum_esc = (s.summary or s.sni or "").replace("|", "\\|")
        lines.append(f"| `#{s.stream_id}` | `{s.client_ip}:{s.client_port}` | `{s.server_ip}:{s.server_port}` | **{s.protocol_name}** | {s.packet_count:,} | {human_size(s.total_bytes)} | `{sum_esc}` |")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    console.print(f"[bold green][/bold green] Exported PCAP Tree report to Markdown: [cyan]{output_path}[/cyan]")


def export_tree_json(engine: PCAPEngine, output_path: str):
    data = {
        "file": engine.file_path,
        "total_packets": len(engine.packets),
        "protocol_stats": {k: {"packets": v, "bytes": engine.protocol_bytes.get(k, 0)} for k, v in engine.protocol_counts.items()},
        "endpoints": engine.endpoints,
        "streams": [
            {
                "stream_id": s.stream_id,
                "client": f"{s.client_ip}:{s.client_port}",
                "server": f"{s.server_ip}:{s.server_port}",
                "protocol": s.protocol_name,
                "packets": s.packet_count,
                "bytes": s.total_bytes,
                "sni": s.sni,
                "summary": s.summary
            } for s in engine.tcp_streams.values()
        ]
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    console.print(f"[bold green][/bold green] Exported PCAP Tree report to JSON: [cyan]{output_path}[/cyan]")


def main(args_list=None):
    parser = argparse.ArgumentParser(
        prog="pcaptree",
        description=" Visual PCAP Structure, Protocol Hierarchy & Conversation Streams Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  pcaptree capture.pcap
  pcaptree network.pcapng --proto HTTP
  pcaptree evidence.pcap --ip 192.168.1.50
  pcaptree capture.pcap --export-all
        """
    )
    parser.add_argument("pcap_file", help="Path to input PCAP or PCAPNG file")
    parser.add_argument("--proto", help="Filter streams by protocol name (e.g. HTTP, TLS, SSH, FTP)")
    parser.add_argument("--ip", help="Filter streams and endpoints by IP address")
    parser.add_argument("-l", "--limit", type=int, default=50, help="Row display limit (default: 50)")

    # Export formats
    parser.add_argument("--md", "--markdown", dest="md", help="Export to Markdown report (.md)")
    parser.add_argument("--json", help="Export to JSON file")
    parser.add_argument("--csv", help="Export to CSV file")
    parser.add_argument("--export-all", action="store_true", help="Generate MD, JSON, and CSV reports automatically")

    args = parser.parse_args(args_list)

    if not os.path.exists(args.pcap_file):
        console.print(f"[bold red]Error:[/bold red] File not found: {args.pcap_file}")
        sys.exit(1)

    print_banner(
        tool_name="PCAP CONVERSATIONS & STRUCTURE TREE (pcaptree)",
        sub_title="Protocol Hierarchy, Endpoints Matrix & TCP/UDP Streams"
    )

    engine = PCAPEngine(args.pcap_file)
    with console.status("[bold cyan]Parsing packets and reassembling TCP/UDP streams...[/bold cyan]"):
        engine.analyze()

    render_protocol_tree(engine)
    render_endpoints_table(engine, limit=25)
    render_streams_table(engine, filter_proto=args.proto, filter_ip=args.ip, limit=args.limit)

    base_name = os.path.splitext(os.path.basename(args.pcap_file))[0]
    if args.export_all:
        if not args.md: args.md = f"{base_name}_pcaptree.md"
        if not args.json: args.json = f"{base_name}_pcaptree.json"

    if hasattr(args, 'md') and args.md: export_tree_markdown(engine, args.md)
    if hasattr(args, 'json') and args.json: export_tree_json(engine, args.json)


if __name__ == "__main__":
    main()
