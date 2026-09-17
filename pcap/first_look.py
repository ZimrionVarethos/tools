#!/usr/bin/env python3
"""
 PCAP First Look & Macro Triage (pcapfirst / pcap/first_look.py)
Instant Step-1 Reconnaissance Dashboard for Network PCAP/PCAPNG Captures:
1. Capture Overview: File format, size, packet count, capture duration, timestamp range.
2. Protocol Hierarchy Tree (PHS): Exact nested tree structure matching Wireshark/Tshark (eth  ip  tcp  websocket/http/tls).
3. Port Analysis: Standard vs Non-Standard / High-Risk ports breakdown.
4. Top Conversations (Heavy Talkers): 5-tuple traffic rankings with SNI / Hostname resolution.
5. Quick Triage Red Flags: High-volume streams, WebSockets, non-standard services, ICMP exfil hints.
6. Actionable Next Steps: Auto-suggests exact commands (e.g. pcapscanstream) to drill down immediately.
"""
import os
import sys
import argparse
import collections
import subprocess
import re
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple, Set

# Ensure tools directory is on sys.path
TOOLS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if TOOLS_DIR not in sys.path:
    sys.path.insert(0, TOOLS_DIR)

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree
from rich.text import Text
from rich.markup import escape

from core.banner import print_banner
from core.utils import human_size
from pcap.pcap_engine import (
    PCAPReader, PCAPEngine, Packet, TCPStream,
    IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP, IPPROTO_ICMPV6, ETHERTYPE_ARP
)

console = Console(force_terminal=True, legacy_windows=False)

STANDARD_PORTS = {
    80: ("HTTP", "Standard Web (Unencrypted)"),
    443: ("HTTPS/TLS", "Standard Secure Web"),
    53: ("DNS", "Domain Name System"),
    22: ("SSH", "Secure Shell"),
    21: ("FTP", "File Transfer Protocol"),
    20: ("FTP-Data", "FTP Data Transfer"),
    25: ("SMTP", "Simple Mail Transfer"),
    110: ("POP3", "Post Office Protocol"),
    143: ("IMAP", "Internet Message Access Protocol"),
    587: ("SMTP-Sub", "Email Submission"),
    993: ("IMAPS", "Secure IMAP"),
    995: ("POP3S", "Secure POP3"),
    67: ("DHCP", "DHCP Server"),
    68: ("DHCP", "DHCP Client"),
    123: ("NTP", "Network Time Protocol"),
    161: ("SNMP", "Simple Network Management"),
    389: ("LDAP", "Lightweight Directory Access"),
    636: ("LDAPS", "Secure LDAP"),
    3389: ("RDP", "Remote Desktop Protocol"),
    445: ("SMB", "Server Message Block"),
    139: ("NetBIOS", "NetBIOS Session Service"),
    88: ("Kerberos", "Kerberos Authentication"),
    5060: ("SIP", "Session Initiation Protocol (VoIP)"),
    5061: ("SIPS", "Secure SIP (VoIP)")
}


def format_ts(ts: float) -> str:
    if ts <= 0.0:
        return "N/A"
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return "N/A"


def get_tshark_phs_tree(pcap_path: str) -> Optional[List[Dict[str, Any]]]:
    """Extracts exact nested Protocol Hierarchy Tree from tshark."""
    cmd = ["tshark", "-r", pcap_path, "-q", "-z", "io,phs"]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
    except Exception:
        return None

    lines = out.splitlines()
    tree_items = []
    pattern = re.compile(r"^(\s*)([A-Za-z0-9_\-\.\:\+]+)\s+frames:(\d+)\s+bytes:(\d+)")
    
    start_collecting = False
    for line in lines:
        if line.startswith("Filter:") or line.startswith("==="):
            start_collecting = True
            continue
        if not start_collecting or not line.strip():
            continue
            
        m = pattern.match(line)
        if m:
            indent_spaces = len(m.group(1))
            depth = indent_spaces // 2
            proto = m.group(2)
            frames = int(m.group(3))
            num_bytes = int(m.group(4))
            tree_items.append({
                "depth": depth,
                "proto": proto,
                "frames": frames,
                "bytes": num_bytes
            })
    return tree_items if tree_items else None


def render_protocol_tree_table(phs_items: List[Dict[str, Any]], total_bytes: int):
    """Renders visual Protocol Hierarchy Tree table."""
    table = Table(
        title=" Protocol Hierarchy Tree (PHS Dissection)",
        show_header=True,
        header_style="bold yellow",
        border_style="bold blue",
        expand=True
    )
    table.add_column("Protocol Hierarchy (Nested Tree)", style="bright_white", min_width=36)
    table.add_column("Frames", style="bold green", justify="right", width=10)
    table.add_column("Traffic Volume", style="bold magenta", justify="right", width=14)
    table.add_column("Share", style="yellow", justify="right", width=8)

    # Styling colors based on depth / protocol
    depth_colors = ["bold cyan", "cyan", "green", "yellow", "bold magenta", "white"]

    for i, it in enumerate(phs_items):
        depth = it["depth"]
        proto = it["proto"]
        frames = it["frames"]
        num_bytes = it["bytes"]
        pct = (num_bytes / total_bytes * 100.0) if total_bytes > 0 else 0.0

        # Tree branch prefix
        if depth == 0:
            tree_prefix = ""
        else:
            tree_prefix = "  " * (depth - 1) + "└── "

        # Highlight important application protocols
        proto_style = depth_colors[min(depth, len(depth_colors)-1)]
        if proto.lower() in ("websocket", "tls", "http", "dns", "icmp"):
            proto_label = f"[{proto_style}][bold]{proto}[/bold][/{proto_style}]"
        else:
            proto_label = f"[{proto_style}]{proto}[/{proto_style}]"

        display_name = f"{tree_prefix}{proto_label}"
        table.add_row(display_name, f"{frames:,}", human_size(num_bytes), f"{pct:.1f}%")

    console.print(table)
    console.print()


def run_first_look(pcap_path: str, limit: int = 10):
    if not os.path.exists(pcap_path):
        console.print(f"[bold red]Error:[/bold red] File not found: {pcap_path}")
        return

    print_banner("PCAP FIRST LOOK", "Instant Macro Triage & Structure Dashboard")

    file_size = os.path.getsize(pcap_path)
    engine = PCAPEngine(pcap_path)
    engine.analyze()

    total_packets = len(engine.packets)
    if total_packets == 0:
        console.print("[bold red]Capture file contains no readable network packets![/bold red]")
        return

    # Timestamps & Duration
    timestamps = [p.timestamp for p in engine.packets if p.timestamp > 0]
    start_ts = min(timestamps) if timestamps else 0.0
    end_ts = max(timestamps) if timestamps else 0.0
    duration_sec = max(0.0, end_ts - start_ts)

    total_bytes = sum(p.length for p in engine.packets)
    total_streams = len(engine.tcp_streams)

    # -------------------------------------------------------------------------
    # 1. Protocol Hierarchy (PHS Tree from Tshark or Engine)
    # -------------------------------------------------------------------------
    phs_items = get_tshark_phs_tree(pcap_path)

    # Find dominant application layer
    dom_proto = "TCP"
    dom_proto_bytes = 0
    if phs_items:
        # Search for deepest high-volume application layer
        for it in phs_items:
            if it["proto"].lower() in ("websocket", "http", "tls", "dns", "icmp", "tcp", "udp"):
                if it["bytes"] > dom_proto_bytes:
                    dom_proto_bytes = it["bytes"]
                    dom_proto = it["proto"].upper()
    else:
        for proto, p_bytes in engine.protocol_bytes.items():
            if p_bytes > dom_proto_bytes:
                dom_proto_bytes = p_bytes
                dom_proto = proto
    
    dom_pct = (dom_proto_bytes / total_bytes * 100.0) if total_bytes > 0 else 0.0

    # -------------------------------------------------------------------------
    # 2. Macro Overview Header Card
    # -------------------------------------------------------------------------
    header_text = (
        f"[bold cyan] File:[/bold cyan] {os.path.basename(pcap_path)} ({human_size(file_size)}) | "
        f"[bold cyan] Total Packets:[/bold cyan] {total_packets:,} | "
        f"[bold cyan] Total Volume:[/bold cyan] {human_size(total_bytes)}\n"
        f"[bold yellow] Time Span:[/bold yellow] {format_ts(start_ts)}  {format_ts(end_ts)} ([bold green]{duration_sec:.2f}s[/bold green])\n"
        f"[bold magenta] Dominant App Layer:[/bold magenta] [bold white on blue] {dom_proto} [/bold white on blue] ({human_size(dom_proto_bytes)} / {dom_pct:.1f}% traffic) | "
        f"[bold magenta] Total TCP Streams:[/bold magenta] {total_streams}"
    )
    console.print(Panel(header_text, title=" Capture Overview & Metadata", border_style="bold green"))
    console.print()

    # Render Hierarchy Tree
    if phs_items:
        render_protocol_tree_table(phs_items, total_bytes)
    else:
        # Fallback table
        proto_table = Table(title=" Protocol Distribution", show_header=True, header_style="bold yellow", border_style="dim cyan", expand=True)
        proto_table.add_column("Protocol", style="bold cyan", min_width=12)
        proto_table.add_column("Packets", style="green", justify="right", width=9)
        proto_table.add_column("Volume", style="magenta", justify="right", width=10)
        proto_table.add_column("Share", style="yellow", justify="right", width=7)
        for proto, count in sorted(engine.protocol_counts.items(), key=lambda x: x[1], reverse=True):
            b_count = engine.protocol_bytes.get(proto, 0)
            pct = (b_count / total_bytes * 100.0) if total_bytes > 0 else 0.0
            proto_table.add_row(proto, f"{count:,}", human_size(b_count), f"{pct:.1f}%")
        console.print(proto_table)
        console.print()

    # -------------------------------------------------------------------------
    # 3. Port Breakdown & Classification Table
    # -------------------------------------------------------------------------
    port_counts = collections.Counter()
    port_bytes = collections.Counter()
    for pkt in engine.packets:
        if pkt.ip_proto in (IPPROTO_TCP, IPPROTO_UDP):
            srv_port = pkt.dst_port if (pkt.dst_port < 10000 or pkt.src_port >= 10000) else pkt.src_port
            port_counts[srv_port] += 1
            port_bytes[srv_port] += pkt.length

    port_table = Table(
        title=" Top Active Ports & Services",
        show_header=True,
        header_style="bold yellow",
        border_style="dim magenta",
        expand=True
    )
    port_table.add_column("Port", style="bold white", width=8)
    port_table.add_column("Service / Classification", style="cyan", min_width=22)
    port_table.add_column("Packets", style="green", justify="right", width=9)
    port_table.add_column("Volume", style="magenta", justify="right", width=10)

    for port, count in port_counts.most_common(8):
        b_vol = port_bytes[port]
        if port in STANDARD_PORTS:
            srv_name, desc = STANDARD_PORTS[port]
            srv_label = f"[dim cyan]{srv_name}[/dim cyan] [dim]({desc})[/dim]"
        else:
            srv_label = f"[bold white on red] NON-STANDARD [/bold white on red] [yellow]Custom Port / Service[/yellow]"
        port_table.add_row(f"{port}", srv_label, f"{count:,}", human_size(b_vol))

    console.print(port_table)
    console.print()

    # -------------------------------------------------------------------------
    # 4. Top Active Conversations / Streams (Ranked by Traffic)
    # -------------------------------------------------------------------------
    conv_table = Table(
        title=f" Top Conversations & Streams (Ranked by Volume, Top {limit})",
        show_header=True,
        header_style="bold yellow",
        border_style="bold cyan",
        expand=True
    )
    conv_table.add_column("Stream", style="bold magenta", width=8, justify="center")
    conv_table.add_column("Proto", style="cyan", width=10)
    conv_table.add_column("Conversation (Client  Server)", style="bright_white", min_width=32)
    conv_table.add_column("Traffic Volume", style="green", justify="right", width=14)
    conv_table.add_column("Activity / Resolved Metadata", style="yellow", min_width=35)

    sorted_streams = sorted(engine.tcp_streams.values(), key=lambda s: s.total_bytes, reverse=True)
    red_flags: List[str] = []

    for st in sorted_streams[:limit]:
        c2s_len = len(st.client_payload)
        s2c_len = len(st.server_payload)
        vol_str = f"{human_size(st.total_bytes)}\n[dim](C:{human_size(c2s_len)} / S:{human_size(s2c_len)})[/dim]"
        
        meta_parts = []
        if st.sni:
            meta_parts.append(f"SNI: [bold cyan]{st.sni}[/bold cyan]")
        if st.http_requests:
            req = st.http_requests[0]
            meta_parts.append(f"{req['method']} [bright_white]{req['uri'][:35]}[/bright_white]")
            if "host" in req and req["host"]:
                meta_parts.append(f"Host: [dim]{req['host']}[/dim]")
        elif st.summary:
            meta_parts.append(st.summary)

        is_custom_port = (st.server_port not in STANDARD_PORTS and st.client_port not in STANDARD_PORTS)
        if is_custom_port:
            meta_parts.append(f"[bold red] Port {st.server_port}[/bold red]")

        if b"Upgrade: websocket" in st.client_payload or b"Sec-WebSocket" in st.client_payload:
            meta_parts.append("[bold magenta] WebSocket Session[/bold magenta]")
            red_flags.append(f"WebSocket session active on Stream #{st.stream_id} ({st.server_ip}:{st.server_port})")

        if is_custom_port and st.total_bytes >= 50_000:
            red_flags.append(f"Large data transfer ({human_size(st.total_bytes)}) on Stream #{st.stream_id} (Port {st.server_port})")

        if not meta_parts:
            meta_parts.append("[dim]Raw TCP Transmission[/dim]")

        meta_str = " | ".join(meta_parts)
        conv_table.add_row(
            f"#{st.stream_id}",
            st.protocol_name,
            f"{st.client_ip}:{st.client_port} \n{st.server_ip}:{st.server_port}",
            vol_str,
            meta_str
        )

    console.print(conv_table)
    console.print()

    # -------------------------------------------------------------------------
    # 5. Quick Triage Red Flags & Recommendations
    # -------------------------------------------------------------------------
    if engine.icmp_packets:
        red_flags.append(f"ICMP Echo Packets detected ({len(engine.icmp_packets)} packets with payload data - potential covert channel)")

    if engine.dns_records:
        txt_records = [r for r in engine.dns_records if any(a.get("type") == 16 for a in r.get("answers", []))]
        if txt_records:
            red_flags.append(f"DNS TXT records detected ({len(txt_records)} queries - potential DNS tunneling/exfil)")

    red_flags_text = ""
    if red_flags:
        red_flags_text = "\n".join(f"  •  [bold red]{rf}[/bold red]" for rf in red_flags[:5])
    else:
        red_flags_text = "  • [green]No glaring macroscopic anomalies detected. Proceed to deep stream inspection.[/green]"

    recom_text = (
        f"[bold yellow] Macroscopic Triage Highlights:[/bold yellow]\n"
        f"{red_flags_text}\n\n"
        f"[bold cyan] Recommended Next Actions:[/bold cyan]\n"
        f"  1. Deep Scan Non-Standard & App Streams:\n"
        f"     [bold green]pcapscanstream {pcap_path} -tcp --non-standard[/bold green]\n"
        f"  2. Deep Scan All Suspicious Payloads (Entropy & Magic):\n"
        f"     [bold green]pcapscanstream {pcap_path} -tcp --only-sus[/bold green]\n"
        f"  3. Extract and Carve Network Files:\n"
        f"     [bold green]pcapfile {pcap_path} -o ./extracted_files[/bold green]"
    )
    console.print(Panel(recom_text, title=" Triage Summary & Next Steps", border_style="bold yellow"))


def main(custom_args: Optional[List[str]] = None):
    parser = argparse.ArgumentParser(
        prog="pcapfirst",
        description=" PCAP First Look - Instant Macro Triage & Structure Dashboard"
    )
    parser.add_argument("pcap_file", help="Path to .pcap or .pcapng network capture file")
    parser.add_argument("-l", "--limit", type=int, default=10, help="Number of top conversations to display (Default: 10)")
    
    args = parser.parse_args(custom_args if custom_args is not None else sys.argv[1:])
    run_first_look(args.pcap_file, limit=args.limit)


if __name__ == "__main__":
    main()
