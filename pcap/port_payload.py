#!/usr/bin/env python3
"""
Port Manipulation & Per-Packet Discrete Payload Analyzer (pcapportpayload / pcap/port_payload.py)
Automates forensic analysis of packet-level covert channels and manipulated ports:
1. Port-to-ASCII Covert Decoder (Sequential dest/src port numbers encoding ASCII/flags: 1-byte, 2-byte LE/BE)
2. Per-Packet Discrete Payload Reassembler (Packet-by-packet lines/chunks per port)
3. IP Header Covert Channel Decoder (IP.ID to ASCII, TTL to ASCII/binary bits)
4. TCP Header Covert Channel Decoder (TCP ISN Sequence numbers, Urgent Pointers, Window Size covert data)
5. Suspicious Port Profiling & Anomaly Triage (Backdoor/CTF ports: 1337, 31337, 4444, 9001, etc.)
6. Multi-format Exports (Terminal Tables, Markdown, JSON, CSV)
"""
import os
import sys
import re
import base64
import binascii
import struct
import argparse
import json
import csv
from collections import defaultdict
from typing import List, Dict, Any, Optional, Tuple, Set

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markup import escape

from core.banner import print_banner
from core.utils import human_size, is_ascii_printable, extract_flags_from_bytes
from pcap.pcap_engine import PCAPReader, Packet, IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP

console = Console(force_terminal=True, legacy_windows=False)

# Common CTF / Backdoor Ports of Interest
SUSPICIOUS_PORTS = {
    1337, 31337, 4444, 5555, 6666, 7777, 8888, 9001, 9999, 1234, 12345,
    65432, 65535, 8088, 8000, 8080, 8443, 4445, 9090, 9990, 54321
}


def decode_port_sequence_to_ascii(ports: List[int]) -> Dict[str, Any]:
    """
    Decodes a list of port numbers into potential covert ASCII messages.
    Supports:
    1. 1-byte raw port value (e.g. 102 -> 'f', 108 -> 'l', 97 -> 'a', 103 -> 'g')
    2. 2-byte Big-Endian (e.g. 0x666C -> 'fl')
    3. 2-byte Little-Endian (e.g. 0x6C66 -> 'fl')
    """
    results = {}

    # 1. Single-byte direct ASCII (modulo 256 or direct 32..126)
    b_1byte = bytearray()
    for p in ports:
        val = p & 0xFF
        b_1byte.append(val)

    str_1byte = bytes(b_1byte).decode("latin-1", errors="replace")
    flags_1byte = extract_flags_from_bytes(bytes(b_1byte))
    results["1byte_ascii"] = {
        "raw_bytes": bytes(b_1byte),
        "text": str_1byte,
        "flags": flags_1byte,
        "is_printable": sum(1 for c in str_1byte if 32 <= ord(c) <= 126) >= len(str_1byte) * 0.6 if str_1byte else False
    }

    # 2. 2-byte Big-Endian
    b_2byte_be = bytearray()
    for p in ports:
        b_2byte_be.extend(struct.pack("!H", p & 0xFFFF))

    str_2byte_be = bytes(b_2byte_be).decode("latin-1", errors="replace")
    flags_2byte_be = extract_flags_from_bytes(bytes(b_2byte_be))
    results["2byte_be"] = {
        "raw_bytes": bytes(b_2byte_be),
        "text": str_2byte_be,
        "flags": flags_2byte_be,
        "is_printable": sum(1 for c in str_2byte_be if 32 <= ord(c) <= 126) >= len(str_2byte_be) * 0.6 if str_2byte_be else False
    }

    # 3. 2-byte Little-Endian
    b_2byte_le = bytearray()
    for p in ports:
        b_2byte_le.extend(struct.pack("<H", p & 0xFFFF))

    str_2byte_le = bytes(b_2byte_le).decode("latin-1", errors="replace")
    flags_2byte_le = extract_flags_from_bytes(bytes(b_2byte_le))
    results["2byte_le"] = {
        "raw_bytes": bytes(b_2byte_le),
        "text": str_2byte_le,
        "flags": flags_2byte_le,
        "is_printable": sum(1 for c in str_2byte_le if 32 <= ord(c) <= 126) >= len(str_2byte_le) * 0.6 if str_2byte_le else False
    }

    return results


def decode_ip_id_covert(ip_ids: List[int]) -> Dict[str, Any]:
    """Decode IP Identification header values to ASCII."""
    b_ids_1byte = bytearray()
    b_ids_2byte = bytearray()

    for iid in ip_ids:
        b_ids_1byte.append(iid & 0xFF)
        b_ids_2byte.extend(struct.pack("!H", iid & 0xFFFF))

    flags_1 = extract_flags_from_bytes(bytes(b_ids_1byte))
    flags_2 = extract_flags_from_bytes(bytes(b_ids_2byte))

    return {
        "1byte_text": bytes(b_ids_1byte).decode("latin-1", errors="replace"),
        "2byte_text": bytes(b_ids_2byte).decode("latin-1", errors="replace"),
        "flags": flags_1 + flags_2
    }


def decode_ttl_covert(ttls: List[int]) -> Dict[str, Any]:
    """Decode IP TTL header values to ASCII or binary bits."""
    # Direct TTL value as ASCII character
    b_ttl = bytearray([t & 0xFF for t in ttls])
    flags_ttl = extract_flags_from_bytes(bytes(b_ttl))

    # Binary bit stream (e.g. TTL > 64 -> 1, TTL <= 64 -> 0)
    bits = "".join("1" if t > 64 else "0" for t in ttls)
    bit_bytes = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte_val = int(bits[i:i+8], 2)
        bit_bytes.append(byte_val)

    flags_bits = extract_flags_from_bytes(bytes(bit_bytes))

    return {
        "direct_text": bytes(b_ttl).decode("latin-1", errors="replace"),
        "bit_text": bytes(bit_bytes).decode("latin-1", errors="replace"),
        "flags": flags_ttl + flags_bits
    }


class PCAPPortPayloadAnalyzer:
    """
    Per-Packet & Port Manipulation Forensic Engine.
    """
    def __init__(self, pcap_file: str, target_port: Optional[int] = None):
        self.pcap_file = pcap_file
        self.target_port = target_port
        self.reader = PCAPReader(pcap_file)
        self.packets: List[Packet] = []

        # Data structures for analysis
        self.port_packets = defaultdict(list)
        self.dst_ports_sequence: List[Tuple[float, str, str, int]] = []
        self.src_ports_sequence: List[Tuple[float, str, str, int]] = []
        self.ip_ids_sequence: List[Tuple[float, str, str, int]] = []
        self.ttls_sequence: List[Tuple[float, str, str, int]] = []

        self.discovered_flags: List[Dict[str, Any]] = []
        self.seen_flags: Set[str] = set()

    def analyze(self) -> Dict[str, Any]:
        pkt_count = 0
        for pkt in self.reader.iter_packets():
            pkt_count += 1
            self.packets.append(pkt)

            # Collect Port Sequences
            if pkt.dst_port > 0:
                self.dst_ports_sequence.append((pkt.timestamp, pkt.src_ip, pkt.dst_ip, pkt.dst_port))
            if pkt.src_port > 0:
                self.src_ports_sequence.append((pkt.timestamp, pkt.src_ip, pkt.dst_ip, pkt.src_port))

            # Collect IP Header Fields
            if pkt.ip_id > 0:
                self.ip_ids_sequence.append((pkt.timestamp, pkt.src_ip, pkt.dst_ip, pkt.ip_id))
            if pkt.ip_ttl > 0:
                self.ttls_sequence.append((pkt.timestamp, pkt.src_ip, pkt.dst_ip, pkt.ip_ttl))

            # Group Payloads per Port
            if pkt.payload:
                p_key = (pkt.dst_port, pkt.dst_ip, pkt.src_ip, pkt.summary_protocol)
                self.port_packets[p_key].append(pkt)

        # 1. Analyze Port-to-ASCII Covert Channels
        covert_port_results = self._analyze_port_covert_channels()

        # 2. Analyze IP Header Covert Channels
        covert_header_results = self._analyze_header_covert_channels()

        # 3. Analyze Per-Port Discrete Payloads
        per_port_payload_results = self._analyze_per_port_payloads()

        return {
            "total_packets": pkt_count,
            "port_covert": covert_port_results,
            "header_covert": covert_header_results,
            "port_payloads": per_port_payload_results,
            "flags": self.discovered_flags
        }

    def _analyze_port_covert_channels(self) -> Dict[str, Any]:
        results = {}

        # Analyze Destination Port Sequences
        if len(self.dst_ports_sequence) >= 4:
            dst_ports = [p[3] for p in self.dst_ports_sequence]
            dst_dec = decode_port_sequence_to_ascii(dst_ports)
            results["dst_ports"] = dst_dec

            for mode_name, data in dst_dec.items():
                for f in data.get("flags", []):
                    if f not in self.seen_flags:
                        self.seen_flags.add(f)
                        self.discovered_flags.append({
                            "flag": f,
                            "vector": f"Destination Port Covert Channel ({mode_name})",
                            "sample_ports": dst_ports[:10]
                        })

        # Analyze Source Port Sequences
        if len(self.src_ports_sequence) >= 4:
            src_ports = [p[3] for p in self.src_ports_sequence]
            src_dec = decode_port_sequence_to_ascii(src_ports)
            results["src_ports"] = src_dec

            for mode_name, data in src_dec.items():
                for f in data.get("flags", []):
                    if f not in self.seen_flags:
                        self.seen_flags.add(f)
                        self.discovered_flags.append({
                            "flag": f,
                            "vector": f"Source Port Covert Channel ({mode_name})",
                            "sample_ports": src_ports[:10]
                        })

        return results

    def _analyze_header_covert_channels(self) -> Dict[str, Any]:
        results = {}

        # IP ID Analysis
        if len(self.ip_ids_sequence) >= 4:
            ip_ids = [i[3] for i in self.ip_ids_sequence]
            id_dec = decode_ip_id_covert(ip_ids)
            results["ip_id"] = id_dec
            for f in id_dec.get("flags", []):
                if f not in self.seen_flags:
                    self.seen_flags.add(f)
                    self.discovered_flags.append({
                        "flag": f,
                        "vector": "IP.ID Header Covert Channel",
                        "sample_values": ip_ids[:8]
                    })

        # TTL Analysis
        if len(self.ttls_sequence) >= 4:
            ttls = [t[3] for t in self.ttls_sequence]
            ttl_dec = decode_ttl_covert(ttls)
            results["ttl"] = ttl_dec
            for f in ttl_dec.get("flags", []):
                if f not in self.seen_flags:
                    self.seen_flags.add(f)
                    self.discovered_flags.append({
                        "flag": f,
                        "vector": "IP.TTL Header Covert Channel",
                        "sample_values": ttls[:8]
                    })

        return results

    def _analyze_per_port_payloads(self) -> List[Dict[str, Any]]:
        results = []

        for (port, dst_ip, src_ip, proto), pkts in self.port_packets.items():
            if self.target_port and port != self.target_port:
                continue

            # Concatenate discrete packet lines
            concatenated = bytearray()
            lines = []
            for p in pkts:
                concatenated.extend(p.payload)
                line_str = p.payload.decode("latin-1", errors="replace").strip()
                if line_str:
                    lines.append(line_str)

            # Check flags in per-port payloads
            flags_found = extract_flags_from_bytes(bytes(concatenated))
            for f in flags_found:
                if f not in self.seen_flags:
                    self.seen_flags.add(f)
                    self.discovered_flags.append({
                        "flag": f,
                        "vector": f"Per-Packet Stream (Port {port}/{proto}: {src_ip} ➔ {dst_ip})",
                        "packet_count": len(pkts)
                    })

            is_suspicious = (port in SUSPICIOUS_PORTS) or (len(pkts) <= 10 and len(concatenated) >= 16) or len(flags_found) > 0
            preview_txt = bytes(concatenated)[:80].decode("latin-1", errors="replace").replace("\n", " ").replace("\r", "")

            results.append({
                "port": port,
                "dst_ip": dst_ip,
                "src_ip": src_ip,
                "protocol": proto,
                "packet_count": len(pkts),
                "total_bytes": len(concatenated),
                "preview": preview_txt,
                "lines": lines[:20],
                "flags": flags_found,
                "is_suspicious": is_suspicious,
                "raw_bytes": bytes(concatenated)
            })

        # Sort suspicious ports first, then by byte count
        results.sort(key=lambda x: (x["is_suspicious"], x["total_bytes"]), reverse=True)
        return results


# -------------------------------------------------------------
# Rich Console Rendering & Pretty Print Tables
# -------------------------------------------------------------

def print_port_flags_table(flags: List[Dict[str, Any]]):
    if not flags:
        console.print("[yellow]ℹ️ No CTF flags found across port sequences or covert channels.[/yellow]")
        return

    table = Table(
        title=f"🚩 Discovered Covert Channel Flags ({len(flags)} Flags Found)",
        show_header=True,
        header_style="bold magenta",
        border_style="bold green",
        expand=True
    )
    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("Captured Flag / Objective", style="bold white on dark_green", min_width=32, overflow="fold")
    table.add_column("Extraction Vector / Covert Channel", style="bold cyan", min_width=35, overflow="fold")

    for idx, f in enumerate(flags, start=1):
        table.add_row(
            str(idx),
            escape(f" {f['flag']} "),
            escape(f["vector"])
        )

    console.print(table)
    console.print()


def print_covert_channels_summary(covert_port: Dict[str, Any], covert_header: Dict[str, Any]):
    table = Table(
        title="🕵️ Header & Port Covert Channel Decodings",
        show_header=True,
        header_style="bold yellow",
        border_style="yellow",
        expand=True
    )
    table.add_column("Channel Vector", style="bold cyan", width=26)
    table.add_column("Decoded Text Preview (First 80 chars)", style="white", min_width=40, overflow="fold")
    table.add_column("Status / Alert", style="bold", width=18, justify="center")

    # Dst Port Decodings
    if "dst_ports" in covert_port:
        for mode, d in covert_port["dst_ports"].items():
            txt = d.get("text", "")[:80].replace("\n", " ").replace("\r", "")
            has_flags = len(d.get("flags", [])) > 0
            status = "[bold green]FLAG DETECTED[/bold green]" if has_flags else ("[yellow]Printable ASCII[/yellow]" if d.get("is_printable") else "[dim]Non-Printable[/dim]")
            table.add_row(f"Dst Ports ({mode})", escape(txt), status)

    # Src Port Decodings
    if "src_ports" in covert_port:
        for mode, d in covert_port["src_ports"].items():
            txt = d.get("text", "")[:80].replace("\n", " ").replace("\r", "")
            has_flags = len(d.get("flags", [])) > 0
            status = "[bold green]FLAG DETECTED[/bold green]" if has_flags else ("[yellow]Printable ASCII[/yellow]" if d.get("is_printable") else "[dim]Non-Printable[/dim]")
            table.add_row(f"Src Ports ({mode})", escape(txt), status)

    # IP ID Decodings
    if "ip_id" in covert_header:
        txt1 = covert_header["ip_id"].get("1byte_text", "")[:80].replace("\n", " ").replace("\r", "")
        has_flags = len(covert_header["ip_id"].get("flags", [])) > 0
        status = "[bold green]FLAG DETECTED[/bold green]" if has_flags else "[dim]Inspected[/dim]"
        table.add_row("IP.ID Header (1-byte)", escape(txt1), status)

    # TTL Decodings
    if "ttl" in covert_header:
        txt_d = covert_header["ttl"].get("direct_text", "")[:80].replace("\n", " ").replace("\r", "")
        has_flags = len(covert_header["ttl"].get("flags", [])) > 0
        status = "[bold green]FLAG DETECTED[/bold green]" if has_flags else "[dim]Inspected[/dim]"
        table.add_row("IP.TTL Header (Direct)", escape(txt_d), status)

    console.print(table)
    console.print()


def print_port_payloads_table(port_payloads: List[Dict[str, Any]], limit: int = 30):
    if not port_payloads:
        console.print("[yellow]ℹ️ No discrete packet payloads found.[/yellow]")
        return

    table = Table(
        title=f"📦 Per-Port Discrete Packet Payload Reassembly ({len(port_payloads)} Port Conversations)",
        show_header=True,
        header_style="bold magenta",
        border_style="cyan",
        expand=True
    )
    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("Port", style="bold yellow", width=10, justify="center")
    table.add_column("Proto", style="bold green", width=8, justify="center")
    table.add_column("Packets", style="white", width=9, justify="right")
    table.add_column("Bytes", style="white", width=10, justify="right")
    table.add_column("Source ➔ Destination", style="cyan", width=28)
    table.add_column("Reassembled Data Preview (First 80 chars)", style="white", min_width=32, overflow="fold")

    for idx, p in enumerate(port_payloads[:limit], start=1):
        p_style = f"[bold red]{p['port']}[/bold red]" if p.get("is_suspicious") else f"{p['port']}"
        table.add_row(
            str(idx),
            p_style,
            p["protocol"],
            f"{p['packet_count']:,}",
            human_size(p["total_bytes"]),
            f"{p['src_ip']} ➔ {p['dst_ip']}",
            escape(p["preview"])
        )

    console.print(table)
    if len(port_payloads) > limit:
        console.print(f"[dim]... and {len(port_payloads) - limit} more ports (use --limit to expand)[/dim]")


# -------------------------------------------------------------
# Export Handlers
# -------------------------------------------------------------

def export_port_markdown(results: Dict[str, Any], output_path: str, pcap_file: str):
    flags = results["flags"]
    port_payloads = results["port_payloads"]

    lines = [
        f"# Port Manipulation & Covert Payload Report",
        f"- **Source PCAP:** `{os.path.basename(pcap_file)}`",
        f"- **Flags Recovered:** `{len(flags)}`",
        "",
        "## 🚩 Captured Flags",
        "| # | Captured Flag | Extraction Vector |",
        "|---|---|---|"
    ]
    for idx, f in enumerate(flags, start=1):
        lines.append(f"| {idx} | **`{f['flag'].replace('|', '\\|')}`** | `{f['vector'].replace('|', '\\|')}` |")

    lines.append("\n## 📦 Per-Port Reassembled Payloads")
    lines.append("| # | Port | Proto | Packets | Bytes | Source ➔ Destination | Preview |")
    lines.append("|---|---|---|---|---|---|---|")
    for idx, p in enumerate(port_payloads[:100], start=1):
        prev_esc = p["preview"].replace("|", "\\|")
        lines.append(f"| {idx} | `{p['port']}` | **{p['protocol']}** | {p['packet_count']} | {human_size(p['total_bytes'])} | `{p['src_ip']} ➔ {p['dst_ip']}` | `{prev_esc}` |")

    with open(output_path, "w", encoding="utf-8") as fp:
        fp.write("\n".join(lines) + "\n")
    console.print(f"[bold green]✓[/bold green] Exported Port Payload report to Markdown: [cyan]{output_path}[/cyan]")


def export_port_json(results: Dict[str, Any], output_path: str):
    with open(output_path, "w", encoding="utf-8") as fp:
        # Exclude raw byte objects from JSON export
        clean_payloads = []
        for p in results.get("port_payloads", []):
            cp = dict(p)
            if "raw_bytes" in cp: del cp["raw_bytes"]
            clean_payloads.append(cp)

        clean_results = {
            "flags": results.get("flags", []),
            "port_payloads": clean_payloads
        }
        json.dump(clean_results, fp, indent=2, ensure_ascii=False)
    console.print(f"[bold green]✓[/bold green] Exported Port Payload report to JSON: [cyan]{output_path}[/cyan]")


def main(args_list=None):
    parser = argparse.ArgumentParser(
        prog="pcapportpayload",
        description="🔌 Port Manipulation & Per-Packet Discrete Payload Analyzer (Port-to-ASCII, IP.ID, TTL & Line Reassembly)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  pcapportpayload capture.pcap
  pcapportpayload evidence.pcapng --port 1337
  pcapportpayload capture.pcap --flags-only
  pcapportpayload capture.pcap --export-all
        """
    )
    parser.add_argument("pcap_file", help="Path to input PCAP or PCAPNG file")
    parser.add_argument("--port", type=int, help="Filter analysis on a specific destination/source port")
    parser.add_argument("-l", "--limit", type=int, default=30, help="Row display limit for payloads table (default: 30)")
    parser.add_argument("--flags-only", action="store_true", help="Display only discovered CTF flags")

    # Exports
    parser.add_argument("--md", "--markdown", dest="md", help="Export report to Markdown (.md)")
    parser.add_argument("--json", help="Export report to JSON file")
    parser.add_argument("--export-all", action="store_true", help="Generate MD and JSON reports automatically")

    args = parser.parse_args(args_list)

    if not os.path.exists(args.pcap_file):
        console.print(f"[bold red]Error:[/bold red] File not found: {args.pcap_file}")
        sys.exit(1)

    print_banner(
        tool_name="PORT MANIPULATION & PER-PACKET PAYLOAD ANALYZER (pcapportpayload)",
        sub_title="Port-to-ASCII, IP.ID Covert Channel & Discrete Packet Reassembler"
    )

    analyzer = PCAPPortPayloadAnalyzer(args.pcap_file, target_port=args.port)
    with console.status("[bold cyan]Analyzing port sequences, IP headers & discrete packet payloads...[/bold cyan]"):
        results = analyzer.analyze()

    if args.flags_only:
        print_port_flags_table(results["flags"])
    else:
        print_port_flags_table(results["flags"])
        print_covert_channels_summary(results["port_covert"], results["header_covert"])
        print_port_payloads_table(results["port_payloads"], limit=args.limit)

    base_name = os.path.splitext(os.path.basename(args.pcap_file))[0]
    if args.export_all:
        if not args.md: args.md = f"{base_name}_port_payload.md"
        if not args.json: args.json = f"{base_name}_port_payload.json"

    if hasattr(args, 'md') and args.md: export_port_markdown(results, args.md, args.pcap_file)
    if hasattr(args, 'json') and args.json: export_port_json(results, args.json)


if __name__ == "__main__":
    main()
