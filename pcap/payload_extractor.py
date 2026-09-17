#!/usr/bin/env python3
"""
Packet Payload Reassembler & Fragmented Stream Extractor (pcappayload)
Extracts packet-by-packet payloads, displays dedicated Hex/Raw & ASCII columns, exports structured table.xml/CSV/JSON, and reassembles DNS/ICMP/UDP exfiltration streams.
"""

import sys
import os
import re
import base64
import binascii
import urllib.parse
import argparse
import csv
import json
import xml.etree.ElementTree as ET
from xml.dom import minidom
from typing import List, Dict, Any, Optional

# Add project root to sys.path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from pcap.pcap_engine import PCAPReader, Packet, IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP
from core.banner import print_banner
from core.utils import human_size, is_ascii_printable, extract_flags_from_bytes
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree
from rich.markup import escape

console = Console(force_terminal=True, legacy_windows=False)


def try_auto_decode(raw_text: str) -> List[Dict[str, str]]:
    """Try decoding raw concatenated string with Hex, Base64, Base32, URL decode."""
    results = []
    cleaned = raw_text.strip().replace("\n", "").replace("\r", "").replace(" ", "")

    # 1. Hex Decode
    if re.fullmatch(r"[0-9a-fA-F]+", cleaned) and len(cleaned) % 2 == 0 and len(cleaned) >= 4:
        try:
            hex_bytes = bytes.fromhex(cleaned)
            preview = hex_bytes.decode(errors="replace")
            flags = extract_flags_from_bytes(hex_bytes)
            results.append({
                "type": "Hexadecimal (Base16)",
                "decoded_bytes": hex_bytes,
                "preview": preview,
                "flags": flags
            })
        except Exception:
            pass

    # 2. Base64 Decode
    b64_cand = cleaned.rstrip("=")
    if re.fullmatch(r"[A-Za-z0-9+/_-]+", b64_cand) and len(b64_cand) >= 4:
        pad = (4 - (len(b64_cand) % 4)) % 4
        padded = b64_cand + ("=" * pad)
        try:
            padded_std = padded.replace("-", "+").replace("_", "/")
            b64_bytes = base64.b64decode(padded_std)
            if len(b64_bytes) > 0 and (is_ascii_printable(b64_bytes) or len(extract_flags_from_bytes(b64_bytes)) > 0):
                preview = b64_bytes.decode(errors="replace")
                flags = extract_flags_from_bytes(b64_bytes)
                results.append({
                    "type": "Base64",
                    "decoded_bytes": b64_bytes,
                    "preview": preview,
                    "flags": flags
                })
        except Exception:
            pass

    # 3. Base32 Decode
    if re.fullmatch(r"[A-Za-z2-7=]+", cleaned) and len(cleaned) >= 8:
        try:
            b32_bytes = base64.b32decode(cleaned.upper())
            if len(b32_bytes) > 0 and (is_ascii_printable(b32_bytes) or len(extract_flags_from_bytes(b32_bytes)) > 0):
                preview = b32_bytes.decode(errors="replace")
                flags = extract_flags_from_bytes(b32_bytes)
                results.append({
                    "type": "Base32",
                    "decoded_bytes": b32_bytes,
                    "preview": preview,
                    "flags": flags
                })
        except Exception:
            pass

    # 4. URL Decode
    if "%" in raw_text:
        try:
            url_decoded = urllib.parse.unquote(raw_text)
            if url_decoded != raw_text:
                results.append({
                    "type": "URL Decoded",
                    "decoded_bytes": url_decoded.encode(errors="replace"),
                    "preview": url_decoded,
                    "flags": extract_flags_from_bytes(url_decoded.encode(errors="replace"))
                })
        except Exception:
            pass

    return results


def extract_dns_queries(packets: List[Packet], base_domain: Optional[str] = None) -> List[str]:
    """Extract DNS query subdomain chunks."""
    queries = []
    for pkt in packets:
        if pkt.ip_proto == IPPROTO_UDP and (pkt.src_port == 53 or pkt.dst_port == 53):
            payload = pkt.payload
            if len(payload) >= 12:
                idx = 12
                labels = []
                while idx < len(payload):
                    length = payload[idx]
                    if length == 0:
                        break
                    if length > 63 or idx + 1 + length > len(payload):
                        break
                    label = payload[idx+1:idx+1+length].decode(errors="ignore")
                    labels.append(label)
                    idx += 1 + length

                if labels:
                    domain = ".".join(labels)
                    if base_domain:
                        b_dom = base_domain.lstrip(".")
                        if domain.lower().endswith("." + b_dom.lower()):
                            sub = domain[:-(len(b_dom) + 1)]
                            queries.append(sub)
                        elif domain.lower() == b_dom.lower():
                            continue
                        else:
                            queries.append(domain)
                    else:
                        queries.append(domain)
    return queries


def extract_icmp_payloads(packets: List[Packet]) -> List[bytes]:
    """Extract ICMP data payloads."""
    payloads = []
    for pkt in packets:
        if pkt.ip_proto == IPPROTO_ICMP and len(pkt.payload) > 0:
            payloads.append(pkt.payload)
    return payloads


def build_table_data(packets: List[Packet], unique: bool = False) -> List[Dict[str, Any]]:
    """Build unified structured table records with both Hex and ASCII representations."""
    rows = []
    last_payload = None
    for idx, pkt in enumerate(packets, 1):
        if unique and pkt.payload == last_payload:
            continue
        last_payload = pkt.payload

        proto_str = "TCP" if pkt.ip_proto == IPPROTO_TCP else "UDP" if pkt.ip_proto == IPPROTO_UDP else "ICMP" if pkt.ip_proto == IPPROTO_ICMP else f"IP-{pkt.ip_proto}"
        src_str = f"{pkt.src_ip}:{pkt.src_port}" if pkt.src_port else pkt.src_ip
        dst_str = f"{pkt.dst_ip}:{pkt.dst_port}" if pkt.dst_port else pkt.dst_ip

        raw_hex = pkt.payload.hex()
        hex_spaced = " ".join(re.findall(r"..", raw_hex))
        raw_s = pkt.payload.decode(errors="replace")
        ascii_clean = "".join(c if (32 <= ord(c) <= 126) else "." for c in raw_s)

        rows.append({
            "index": idx,
            "proto": proto_str,
            "src": src_str,
            "dst": dst_str,
            "length": len(pkt.payload),
            "hex": raw_hex,
            "hex_spaced": hex_spaced,
            "ascii": ascii_clean,
            "raw_bytes": pkt.payload
        })
    return rows


def export_to_xml(rows: List[Dict[str, Any]], filename: str, capture_file: str):
    """Export table data to structured XML (table.xml format)."""
    root = ET.Element("PacketPayloadTable", {
        "total_packets": str(len(rows)),
        "capture_file": os.path.basename(capture_file)
    })

    for r in rows:
        pkt_elem = ET.SubElement(root, "Packet", {
            "index": str(r["index"]),
            "proto": r["proto"],
            "src": r["src"],
            "dst": r["dst"],
            "length": str(r["length"])
        })
        hex_elem = ET.SubElement(pkt_elem, "Hex")
        hex_elem.text = r["hex"]
        
        hex_spaced_elem = ET.SubElement(pkt_elem, "HexFormatted")
        hex_spaced_elem.text = r["hex_spaced"]

        ascii_elem = ET.SubElement(pkt_elem, "Ascii")
        ascii_elem.text = r["ascii"]

    xml_str = ET.tostring(root, encoding="utf-8")
    pretty_xml = minidom.parseString(xml_str).toprettyxml(indent="  ")

    with open(filename, "w", encoding="utf-8") as f:
        f.write(pretty_xml)


def export_to_csv(rows: List[Dict[str, Any]], filename: str):
    """Export table data to CSV."""
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Index", "Proto", "Source", "Destination", "Length", "Hex", "ASCII"])
        for r in rows:
            writer.writerow([r["index"], r["proto"], r["src"], r["dst"], r["length"], r["hex"], r["ascii"]])


def export_to_json(rows: List[Dict[str, Any]], filename: str, capture_file: str):
    """Export table data to JSON."""
    clean_rows = [{
        "index": r["index"],
        "proto": r["proto"],
        "src": r["src"],
        "dst": r["dst"],
        "length": r["length"],
        "hex": r["hex"],
        "ascii": r["ascii"]
    } for r in rows]

    data = {
        "capture_file": os.path.basename(capture_file),
        "total_packets": len(clean_rows),
        "packets": clean_rows
    }
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def export_to_txt_table(rows: List[Dict[str, Any]], filename: str):
    """Export formatted text table."""
    with open(filename, "w", encoding="utf-8") as f:
        f.write(f"{'Pkt #':<7} | {'Proto':<6} | {'Source -> Destination':<34} | {'Len':<6} | {'Hex (Raw)':<32} | {'ASCII Preview'}\n")
        f.write("-" * 120 + "\n")
        for r in rows:
            sd = f"{r['src']} -> {r['dst']}"
            hex_prev = r["hex"][:30] + (".." if len(r["hex"]) > 30 else "")
            ascii_prev = r["ascii"][:40] + (".." if len(r["ascii"]) > 40 else "")
            f.write(f"#{r['index']:<6} | {r['proto']:<6} | {sd:<34} | {r['length']:<5}B | {hex_prev:<32} | {ascii_prev}\n")


def main(args=None):
    parser = argparse.ArgumentParser(
        prog="pcappayload",
        description=" Packet Payload Reassembler & Structured Table XML Extractor (DNS, ICMP, TCP, UDP)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Extraction & Export Modes:
  lines    : Display payload table with both Hex/Raw & ASCII columns (Default)
  concat   : Reassemble & concatenate all payloads into a single continuous stream
  dns      : Auto-extract DNS query subdomains, strip suffix & decode exfiltration
  icmp     : Extract ICMP echo data payloads sequence
  raw      : Output raw binary payload directly to stdout or file

Structured Output Options:
  --xml [file.xml]   : Export structured table to XML format (Default: table.xml)
  --csv [file.csv]   : Export structured table to CSV format
  --json [file.json] : Export structured table to JSON format
  -o, --output <file>: Save output (auto-detects .xml, .csv, .json, .bin, .txt)
  -a, --all          : Display all packets in console without limit truncation

Examples:
  # 1. View table with Hex & ASCII columns (no truncation):
  pcappayload capture.pcap --port 4444 -a

  # 2. Export exact structured table to table.xml:
  pcappayload capture.pcap --xml table.xml

  # 3. Extract and concatenate exfiltrated DNS subdomains:
  pcappayload exfil.pcap --dns --domain evil.corp

  # 4. Extract and reassemble ICMP ping data to binary:
  pcappayload ping.pcap --icmp -c -o ./extracted_icmp.bin

  # 5. Filter by IP and decode concatenated Base64/Hex payload:
  pcappayload capture.pcap --ip 10.0.0.5 -c -d
        """
    )
    parser.add_argument("file", help="Path to packet capture file (.pcap, .pcapng)")
    parser.add_argument("-m", "--mode", choices=["lines", "concat", "dns", "icmp", "raw"], default="lines",
                        help="Payload extraction mode (default: lines)")
    parser.add_argument("-c", "--concat", action="store_true", help="Shortcut for --mode concat")
    parser.add_argument("--dns", action="store_true", help="Shortcut for --mode dns")
    parser.add_argument("--icmp", action="store_true", help="Shortcut for --mode icmp")
    parser.add_argument("--raw", action="store_true", help="Output raw binary stream")

    # Filters
    parser.add_argument("--proto", choices=["all", "tcp", "udp", "icmp", "dns", "http"], default="all", help="Protocol filter")
    parser.add_argument("--ip", help="Filter by Source or Destination IP")
    parser.add_argument("--src-ip", help="Filter by Source IP")
    parser.add_argument("--dst-ip", help="Filter by Destination IP")
    parser.add_argument("--port", type=int, help="Filter by Source or Destination Port")
    parser.add_argument("--domain", help="Base domain suffix to strip in DNS mode (e.g. evil.corp)")
    parser.add_argument("--unique", action="store_true", help="Deduplicate identical consecutive payload lines")
    parser.add_argument("--min-len", type=int, default=1, help="Minimum payload length in bytes (default: 1)")

    # Display & Export
    parser.add_argument("-l", "--limit", type=int, default=100, help="Max rows to display in terminal (0 for unlimited, default: 100)")
    parser.add_argument("-a", "--all", action="store_true", help="Display all rows in terminal without truncation")
    parser.add_argument("-d", "--decode", action="store_true", help="Auto-decode concatenated payload (Hex, Base64, Base32, URL)")
    parser.add_argument("--xml", nargs="?", const="table.xml", help="Export structured table to XML (default: table.xml)")
    parser.add_argument("--csv", nargs="?", const="table.csv", help="Export structured table to CSV (default: table.csv)")
    parser.add_argument("--json", nargs="?", const="table.json", help="Export structured table to JSON (default: table.json)")
    parser.add_argument("-o", "--output", help="Save extracted payload / table to file (.xml, .csv, .json, .bin, .txt)")

    parsed_args = parser.parse_args(args)

    if not os.path.exists(parsed_args.file):
        console.print(f"[bold red]Error: File not found: {parsed_args.file}[/bold red]")
        sys.exit(1)

    # Determine mode
    mode = parsed_args.mode
    if parsed_args.concat:
        mode = "concat"
    elif parsed_args.dns:
        mode = "dns"
    elif parsed_args.icmp:
        mode = "icmp"
    elif parsed_args.raw:
        mode = "raw"

    # Read PCAP
    try:
        reader = PCAPReader(parsed_args.file)
        packets = list(reader.iter_packets())
    except Exception as e:
        console.print(f"[bold red]Error reading PCAP file:[/bold red] {e}")
        sys.exit(1)

    # Apply Filters
    filtered_packets = []
    for pkt in packets:
        if len(pkt.payload) < parsed_args.min_len and mode != "dns":
            continue

        if parsed_args.proto == "tcp" and pkt.ip_proto != IPPROTO_TCP:
            continue
        elif parsed_args.proto == "udp" and pkt.ip_proto != IPPROTO_UDP:
            continue
        elif parsed_args.proto == "icmp" and pkt.ip_proto != IPPROTO_ICMP:
            continue
        elif parsed_args.proto == "dns" and not (pkt.ip_proto == IPPROTO_UDP and (pkt.src_port == 53 or pkt.dst_port == 53)):
            continue

        if parsed_args.ip and parsed_args.ip not in (pkt.src_ip, pkt.dst_ip):
            continue
        if parsed_args.src_ip and pkt.src_ip != parsed_args.src_ip:
            continue
        if parsed_args.dst_ip and pkt.dst_ip != parsed_args.dst_ip:
            continue

        if parsed_args.port and parsed_args.port not in (pkt.src_port, pkt.dst_port):
            continue

        filtered_packets.append(pkt)

    # Build Structured Table Records
    table_rows = build_table_data(filtered_packets, unique=parsed_args.unique)

    # If raw mode to stdout, suppress banner
    if mode != "raw" or (parsed_args.output and not parsed_args.output.endswith(".bin")):
        print_banner("PCAP PAYLOAD & STRUCTURED TABLE EXTRACTOR (pcappayload)", "Fragmented Stream, Hex/ASCII Table & XML Export")
        console.print(f"[bold cyan]Capture File:[/bold cyan] [bold white]{os.path.basename(parsed_args.file)}[/bold white] ({len(packets)} total packets, {len(table_rows)} matching payloads)")
        console.print(f"[bold cyan]Extraction Mode:[/bold cyan] [bold magenta]{mode.upper()}[/bold magenta]\n")

    # 1. DNS Mode
    if mode == "dns":
        queries = extract_dns_queries(filtered_packets, parsed_args.domain)
        if parsed_args.unique:
            dedup = []
            for q in queries:
                if not dedup or dedup[-1] != q:
                    dedup.append(q)
            queries = dedup

        if not queries:
            console.print("[bold yellow]No DNS queries found matching filter criteria.[/bold yellow]")
            return

        table = Table(title=f"Extracted DNS Query Subdomains ({len(queries)} chunks)", show_header=True, header_style="bold cyan")
        table.add_column("Index", style="bold yellow", width=8)
        table.add_column("Query Subdomain Chunk", style="bold white")

        for idx, q in enumerate(queries[:50], 1):
            table.add_row(f"#{idx}", escape(q))
        if len(queries) > 50:
            table.add_row("...", f"... and {len(queries)-50} more queries")
        console.print(table)
        console.print()

        concatenated_str = "".join(queries).replace(".", "")
        console.print(Panel(escape(concatenated_str[:400] + ("..." if len(concatenated_str) > 400 else "")),
                            title=f"Concatenated DNS Data Stream ({len(concatenated_str)} chars)", border_style="bold green"))
        console.print()

        dec_results = try_auto_decode(concatenated_str)
        if dec_results:
            tree = Tree("[bold green] Auto-Decoded Payload Candidates:[/bold green]")
            for dec in dec_results:
                b_branch = tree.add(f"[bold cyan]Format: {dec['type']}[/bold cyan] ({len(dec['decoded_bytes'])} bytes)")
                b_branch.add(f"[bold white]Preview:[/bold white] {escape(dec['preview'][:200])}")
                if dec['flags']:
                    for flg in dec['flags']:
                        b_branch.add(f"[bold yellow] Captured Flag:[/bold yellow] [bold green]{flg}[/bold green]")
            console.print(tree)
            console.print()

        if parsed_args.output:
            with open(parsed_args.output, "w") as f:
                f.write(concatenated_str + "\n")
            console.print(f"[bold green] Concatenated DNS stream saved to {parsed_args.output}[/bold green]\n")

    # 2. ICMP Mode
    elif mode == "icmp":
        icmp_chunks = extract_icmp_payloads(filtered_packets)
        if not icmp_chunks:
            console.print("[bold yellow]No ICMP payloads found matching filter criteria.[/bold yellow]")
            return

        table = Table(title=f"Extracted ICMP Payloads ({len(icmp_chunks)} packets)", show_header=True, header_style="bold cyan")
        table.add_column("Pkt #", style="bold yellow", width=8)
        table.add_column("Size", justify="right", width=10)
        table.add_column("Hex / ASCII Preview", style="white")

        for idx, chunk in enumerate(icmp_chunks[:30], 1):
            prev = chunk.decode(errors="replace")
            clean_prev = "".join(c if c.isprintable() else "." for c in prev)
            table.add_row(f"#{idx}", f"{len(chunk)} B", escape(clean_prev[:60]))
        if len(icmp_chunks) > 30:
            table.add_row("...", "", f"... and {len(icmp_chunks)-30} more ICMP packets")
        console.print(table)
        console.print()

        concat_bytes = b"".join(icmp_chunks)
        flags = extract_flags_from_bytes(concat_bytes)
        if flags:
            f_panel = "\n".join(f"• [bold green]{flg}[/bold green]" for flg in flags)
            console.print(Panel(f_panel, title=" Flag Matches in ICMP Stream", border_style="bold green"))
            console.print()

        if parsed_args.output:
            with open(parsed_args.output, "wb") as f:
                f.write(concat_bytes)
            console.print(f"[bold green] Assembled ICMP payload saved to {parsed_args.output} ({len(concat_bytes)} bytes)[/bold green]\n")

    # 3. Concat Mode
    elif mode == "concat":
        all_payloads = [p.payload for p in filtered_packets]
        if parsed_args.unique:
            dedup = []
            for pl in all_payloads:
                if not dedup or dedup[-1] != pl:
                    dedup.append(pl)
            all_payloads = dedup

        concat_bytes = b"".join(all_payloads)
        console.print(f"[bold cyan]Reassembled {len(all_payloads)} packets -> Total Size: {len(concat_bytes)} bytes ({human_size(len(concat_bytes))})[/bold cyan]\n")

        ascii_text = concat_bytes.decode(errors="replace")
        preview = "".join(c if c.isprintable() or c in "\n\r\t" else "." for c in ascii_text[:500])
        console.print(Panel(escape(preview), title="Reassembled Payload Stream Preview", border_style="bold cyan"))
        console.print()

        flags = extract_flags_from_bytes(concat_bytes)
        if flags:
            f_panel = "\n".join(f"• [bold green]{flg}[/bold green]" for flg in flags)
            console.print(Panel(f_panel, title=" Captured Flags in Reassembled Stream", border_style="bold green"))
            console.print()

        if parsed_args.decode:
            dec_results = try_auto_decode(ascii_text)
            if dec_results:
                tree = Tree("[bold green] Auto-Decoded Payload Candidates:[/bold green]")
                for dec in dec_results:
                    b_branch = tree.add(f"[bold cyan]Format: {dec['type']}[/bold cyan] ({len(dec['decoded_bytes'])} bytes)")
                    b_branch.add(f"[bold white]Preview:[/bold white] {escape(dec['preview'][:200])}")
                    if dec['flags']:
                        for flg in dec['flags']:
                            b_branch.add(f"[bold yellow] Captured Flag:[/bold yellow] [bold green]{flg}[/bold green]")
                console.print(tree)
                console.print()

        if parsed_args.output:
            with open(parsed_args.output, "wb") as f:
                f.write(concat_bytes)
            console.print(f"[bold green] Reassembled payload stream saved to {parsed_args.output}[/bold green]\n")

    # 4. Raw Output Mode
    elif mode == "raw":
        concat_bytes = b"".join(p.payload for p in filtered_packets)
        if parsed_args.output:
            with open(parsed_args.output, "wb") as f:
                f.write(concat_bytes)
        else:
            sys.stdout.buffer.write(concat_bytes)

    # 5. Lines Mode (Default Table with Hex & ASCII Columns)
    else:
        limit = 0 if (parsed_args.all or parsed_args.limit == 0) else parsed_args.limit

        table = Table(title=f"Packet Payloads Table ({len(table_rows)} packets)", show_header=True, header_style="bold cyan", expand=True)
        table.add_column("Pkt #", style="bold yellow", width=7)
        table.add_column("Proto", style="bold magenta", width=6)
        table.add_column("Source -> Destination", style="cyan", width=32)
        table.add_column("Len", justify="right", width=6)
        table.add_column("Hex / Raw Bytes", style="bold green", width=28)
        table.add_column("ASCII Preview", style="white")

        display_rows = table_rows if limit == 0 else table_rows[:limit]
        for r in display_rows:
            sd_str = f"{r['src']} -> {r['dst']}"
            hex_disp = r["hex"][:24] + (".." if len(r["hex"]) > 24 else "")
            ascii_disp = r["ascii"][:35] + (".." if len(r["ascii"]) > 35 else "")
            table.add_row(f"#{r['index']}", r["proto"], sd_str, f"{r['length']}B", hex_disp, escape(ascii_disp))

        if limit > 0 and len(table_rows) > limit:
            table.add_row("...", "", "", "", f"... and {len(table_rows)-limit} more packets", "(Use -a or -l 0 for all, or --xml table.xml to export)")

        console.print(table)
        console.print()

    # Handle Exports (XML, CSV, JSON, TXT, Raw)
    xml_out = parsed_args.xml
    csv_out = parsed_args.csv
    json_out = parsed_args.json

    if parsed_args.output:
        out_lower = parsed_args.output.lower()
        if out_lower.endswith(".xml"):
            xml_out = parsed_args.output
        elif out_lower.endswith(".csv"):
            csv_out = parsed_args.output
        elif out_lower.endswith(".json"):
            json_out = parsed_args.output
        elif out_lower.endswith((".txt", ".log")):
            export_to_txt_table(table_rows, parsed_args.output)
            console.print(f"[bold green] Structured text table saved to {parsed_args.output}[/bold green]\n")
        elif mode not in ["concat", "dns", "icmp", "raw"]:
            # Default text dump
            export_to_txt_table(table_rows, parsed_args.output)
            console.print(f"[bold green] Dumped payload table to {parsed_args.output}[/bold green]\n")

    if xml_out:
        export_to_xml(table_rows, xml_out, parsed_args.file)
        console.print(f"[bold green] Structured XML Table exported to:[/bold green] [bold magenta]{xml_out}[/bold magenta] ({len(table_rows)} packets with Hex & ASCII)\n")

    if csv_out:
        export_to_csv(table_rows, csv_out)
        console.print(f"[bold green] Structured CSV Table exported to:[/bold green] [bold magenta]{csv_out}[/bold magenta]\n")

    if json_out:
        export_to_json(table_rows, json_out, parsed_args.file)
        console.print(f"[bold green] Structured JSON Table exported to:[/bold green] [bold magenta]{json_out}[/bold magenta]\n")


if __name__ == "__main__":
    main()
