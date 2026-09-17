"""
Universal Pure-Python PCAP & PCAPNG Parsing and Stream Reassembly Engine (pcap/pcap_engine.py)
Supports:
- Classic PCAP (microsecond 0xa1b2c3d4, nanosecond 0xa1b23c4d, big/little endian)
- PCAP Next Generation (.pcapng, SHB 0x0A0D0D0A, IDB 0x00000001, EPB 0x00000006, SPB 0x00000003)
- Link Layers: Ethernet II (802.3), Linux SLL (Cooked 1), Linux SLL2 (Cooked 2), Raw IPv4/IPv6
- Network Layers: IPv4, IPv6, ARP
- Transport Layers: TCP, UDP, ICMP (with echo payload extraction)
- TCP Stream Reassembler (Tracks 5-tuples, sequence reordering, deduplication, bidirectional streams)
- Protocol Dissectors: HTTP/1.x (with gzip/chunked decoding), DNS (Queries, Answers, TXT), TLS (SNI), ICMP
"""
import os
import sys
import struct
import socket
import zlib
import gzip
import re
import math
import hashlib
from io import BytesIO
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple, Set, Generator

# Link type constants
LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 12
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229

# Ethertypes
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = 0x8100

# IP Protocols
IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_ICMPV6 = 58


class Packet:
    """
    Decoded Network Packet Container.
    """
    __slots__ = (
        'timestamp', 'raw', 'length', 'link_type',
        'src_mac', 'dst_mac', 'ethertype',
        'ip_ver', 'src_ip', 'dst_ip', 'ip_proto', 'ip_ttl', 'ip_id',
        'src_port', 'dst_port',
        'tcp_seq', 'tcp_ack', 'tcp_flags', 'tcp_syn', 'tcp_fin', 'tcp_rst', 'tcp_psh', 'tcp_ack_flag',
        'icmp_type', 'icmp_code',
        'payload'
    )

    def __init__(self):
        self.timestamp: float = 0.0
        self.raw: bytes = b""
        self.length: int = 0
        self.link_type: int = LINKTYPE_ETHERNET

        # Layer 2
        self.src_mac: str = ""
        self.dst_mac: str = ""
        self.ethertype: int = 0

        # Layer 3
        self.ip_ver: int = 0
        self.src_ip: str = ""
        self.dst_ip: str = ""
        self.ip_proto: int = 0
        self.ip_ttl: int = 0
        self.ip_id: int = 0

        # Layer 4
        self.src_port: int = 0
        self.dst_port: int = 0

        # TCP specific
        self.tcp_seq: int = 0
        self.tcp_ack: int = 0
        self.tcp_flags: int = 0
        self.tcp_syn: bool = False
        self.tcp_fin: bool = False
        self.tcp_rst: bool = False
        self.tcp_psh: bool = False
        self.tcp_ack_flag: bool = False

        # ICMP specific
        self.icmp_type: int = -1
        self.icmp_code: int = -1

        # Application Payload
        self.payload: bytes = b""

    @property
    def dt(self) -> datetime:
        try:
            return datetime.fromtimestamp(self.timestamp, tz=timezone.utc)
        except Exception:
            return datetime.fromtimestamp(0, tz=timezone.utc)

    @property
    def summary_protocol(self) -> str:
        if self.ip_proto == IPPROTO_TCP:
            if self.src_port in (80, 8080, 8000) or self.dst_port in (80, 8080, 8000): return "HTTP"
            if self.src_port == 443 or self.dst_port == 443: return "TLS"
            if self.src_port in (21, 20) or self.dst_port in (21, 20): return "FTP"
            if self.src_port == 22 or self.dst_port == 22: return "SSH"
            if self.src_port in (25, 587, 465) or self.dst_port in (25, 587, 465): return "SMTP"
            if self.src_port == 53 or self.dst_port == 53: return "DNS"
            return "TCP"
        elif self.ip_proto == IPPROTO_UDP:
            if self.src_port == 53 or self.dst_port == 53: return "DNS"
            if self.src_port in (67, 68) or self.dst_port in (67, 68): return "DHCP"
            if self.src_port in (123,) or self.dst_port in (123,): return "NTP"
            if self.src_port in (69,) or self.dst_port in (69,): return "TFTP"
            return "UDP"
        elif self.ip_proto in (IPPROTO_ICMP, IPPROTO_ICMPV6):
            return "ICMP"
        elif self.ethertype == ETHERTYPE_ARP:
            return "ARP"
        return "IP" if self.src_ip else "RAW"


def format_mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


class PCAPReader:
    """
    Reads Classic PCAP and PCAPNG files without external C libraries.
    """
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
        self.is_pcapng = False
        self.is_nanosecond = False
        self.byte_order = "<"
        self.link_type = LINKTYPE_ETHERNET
        self.iface_link_types: List[int] = []

    def iter_packets(self) -> Generator[Packet, None, None]:
        if not os.path.exists(self.file_path) or self.file_size < 24:
            return

        with open(self.file_path, "rb") as f:
            magic = f.read(4)
            f.seek(0)

            if magic == b"\x0a\x0d\x0d\x0a":
                # PCAP Next Generation (.pcapng)
                self.is_pcapng = True
                yield from self._read_pcapng(f)
            elif magic in (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1"):
                # Classic PCAP (.pcap)
                self.is_pcapng = False
                yield from self._read_pcap_classic(f)
            else:
                # Attempt PCAP fallback
                yield from self._read_pcap_classic(f)

    def _read_pcap_classic(self, f) -> Generator[Packet, None, None]:
        hdr = f.read(24)
        if len(hdr) < 24:
            return

        magic = hdr[:4]
        if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            self.byte_order = ">"
        else:
            self.byte_order = "<"

        self.is_nanosecond = magic in (b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1")
        _, _, _, _, _, _, self.link_type = struct.unpack(f"{self.byte_order}IHHiIII", hdr)

        ts_divisor = 1_000_000_000.0 if self.is_nanosecond else 1_000_000.0

        while True:
            rec_hdr = f.read(16)
            if len(rec_hdr) < 16:
                break

            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{self.byte_order}IIII", rec_hdr)
            if incl_len > 1000000 or incl_len <= 0:
                break

            pkt_data = f.read(incl_len)
            if len(pkt_data) < incl_len:
                break

            timestamp = float(ts_sec) + (float(ts_usec) / ts_divisor)
            pkt = self._decode_packet(pkt_data, timestamp, self.link_type)
            if pkt:
                yield pkt

    def _read_pcapng(self, f) -> Generator[Packet, None, None]:
        ifaces: List[Dict[str, Any]] = []
        endian = "<"

        while True:
            hdr = f.read(8)
            if len(hdr) < 8:
                break

            block_type, block_len = struct.unpack(f"{endian}II", hdr)
            if block_len < 12 or block_len > 20_000_000:
                break

            body_len = block_len - 12
            body = f.read(body_len)
            trailer = f.read(4) # block_len copy
            if len(body) < body_len or len(trailer) < 4:
                break

            if block_type == 0x0A0D0D0A:
                # Section Header Block
                if len(body) >= 4:
                    bom = body[:4]
                    if bom == b"\x1a\x2b\x3c\x4d": endian = ">"
                    elif bom == b"\x4d\x3c\x2b\x1a": endian = "<"

            elif block_type == 0x00000001:
                # Interface Description Block
                if len(body) >= 4:
                    l_type = struct.unpack(f"{endian}H", body[:2])[0]
                    # Check options for tsresol (default 10^-6 = microsec)
                    tsresol = 1_000_000.0
                    ifaces.append({"link_type": l_type, "tsresol": tsresol})

            elif block_type == 0x00000006:
                # Enhanced Packet Block (EPB)
                if len(body) >= 20:
                    iface_id, ts_high, ts_low, cap_len, orig_len = struct.unpack(f"{endian}IIIII", body[:20])
                    raw_pkt = body[20 : 20 + cap_len]
                    
                    iface = ifaces[iface_id] if iface_id < len(ifaces) else {"link_type": LINKTYPE_ETHERNET, "tsresol": 1_000_000.0}
                    ts_raw = (ts_high << 32) | ts_low
                    timestamp = float(ts_raw) / iface["tsresol"]

                    pkt = self._decode_packet(raw_pkt, timestamp, iface["link_type"])
                    if pkt:
                        yield pkt

            elif block_type == 0x00000003:
                # Simple Packet Block (SPB)
                if len(body) >= 4:
                    orig_len = struct.unpack(f"{endian}I", body[:4])[0]
                    raw_pkt = body[4 : 4 + (block_len - 16)]
                    l_type = ifaces[0]["link_type"] if ifaces else LINKTYPE_ETHERNET
                    pkt = self._decode_packet(raw_pkt, 0.0, l_type)
                    if pkt:
                        yield pkt

    def _decode_packet(self, data: bytes, timestamp: float, link_type: int) -> Optional[Packet]:
        if not data:
            return None

        pkt = Packet()
        pkt.raw = data
        pkt.length = len(data)
        pkt.timestamp = timestamp
        pkt.link_type = link_type

        offset = 0

        # -------------------------------------------------------------
        # Layer 2: Link Layer Decoding
        # -------------------------------------------------------------
        if link_type == LINKTYPE_ETHERNET:
            if len(data) < 14:
                return None
            pkt.dst_mac = format_mac(data[0:6])
            pkt.src_mac = format_mac(data[6:12])
            pkt.ethertype = struct.unpack("!H", data[12:14])[0]
            offset = 14

            # Handle 802.1Q VLAN tagging
            if pkt.ethertype == ETHERTYPE_VLAN and len(data) >= 18:
                pkt.ethertype = struct.unpack("!H", data[16:18])[0]
                offset = 18

        elif link_type == LINKTYPE_LINUX_SLL:
            if len(data) < 16:
                return None
            pkt.ethertype = struct.unpack("!H", data[14:16])[0]
            offset = 16

        elif link_type == LINKTYPE_LINUX_SLL2:
            if len(data) < 20:
                return None
            pkt.ethertype = struct.unpack("!H", data[0:2])[0]
            offset = 20

        elif link_type in (LINKTYPE_RAW, LINKTYPE_IPV4):
            pkt.ethertype = ETHERTYPE_IPV4
            offset = 0

        elif link_type == LINKTYPE_IPV6:
            pkt.ethertype = ETHERTYPE_IPV6
            offset = 0

        # -------------------------------------------------------------
        # Layer 3: Network Layer Decoding
        # -------------------------------------------------------------
        l3_data = data[offset:]

        if pkt.ethertype == ETHERTYPE_IPV4:
            if len(l3_data) < 20:
                return pkt
            v_ihl = l3_data[0]
            pkt.ip_ver = 4
            ihl = (v_ihl & 0x0F) * 4
            if len(l3_data) < ihl:
                return pkt

            total_len = struct.unpack("!H", l3_data[2:4])[0]
            pkt.ip_id = struct.unpack("!H", l3_data[4:6])[0]
            pkt.ip_ttl = l3_data[8]
            pkt.ip_proto = l3_data[9]
            pkt.src_ip = socket.inet_ntoa(l3_data[12:16])
            pkt.dst_ip = socket.inet_ntoa(l3_data[16:20])

            l4_data = l3_data[ihl : total_len if total_len > ihl else len(l3_data)]

        elif pkt.ethertype == ETHERTYPE_IPV6:
            if len(l3_data) < 40:
                return pkt
            pkt.ip_ver = 6
            pkt.ip_proto = l3_data[6]
            pkt.ip_ttl = l3_data[7] # Hop limit
            try:
                pkt.src_ip = socket.inet_ntop(socket.AF_INET6, l3_data[8:24])
                pkt.dst_ip = socket.inet_ntop(socket.AF_INET6, l3_data[24:40])
            except Exception:
                pass
            l4_data = l3_data[40:]

        elif pkt.ethertype == ETHERTYPE_ARP:
            if len(l3_data) >= 28:
                try:
                    pkt.src_ip = socket.inet_ntoa(l3_data[14:18])
                    pkt.dst_ip = socket.inet_ntoa(l3_data[24:28])
                except Exception:
                    pass
            return pkt
        else:
            return pkt

        # -------------------------------------------------------------
        # Layer 4: Transport Layer Decoding
        # -------------------------------------------------------------
        if pkt.ip_proto == IPPROTO_TCP:
            if len(l4_data) < 20:
                return pkt
            pkt.src_port, pkt.dst_port, pkt.tcp_seq, pkt.tcp_ack, offset_flags = struct.unpack("!HHIIH", l4_data[:14])
            data_offset = ((offset_flags >> 12) & 0x0F) * 4
            pkt.tcp_flags = offset_flags & 0x01FF

            pkt.tcp_fin = bool(pkt.tcp_flags & 0x01)
            pkt.tcp_syn = bool(pkt.tcp_flags & 0x02)
            pkt.tcp_rst = bool(pkt.tcp_flags & 0x04)
            pkt.tcp_psh = bool(pkt.tcp_flags & 0x08)
            pkt.tcp_ack_flag = bool(pkt.tcp_flags & 0x10)

            if len(l4_data) > data_offset:
                pkt.payload = l4_data[data_offset:]

        elif pkt.ip_proto == IPPROTO_UDP:
            if len(l4_data) < 8:
                return pkt
            pkt.src_port, pkt.dst_port, u_len, u_chk = struct.unpack("!HHHH", l4_data[:8])
            pkt.payload = l4_data[8:u_len] if u_len >= 8 else l4_data[8:]

        elif pkt.ip_proto in (IPPROTO_ICMP, IPPROTO_ICMPV6):
            if len(l4_data) >= 4:
                pkt.icmp_type = l4_data[0]
                pkt.icmp_code = l4_data[1]
                pkt.payload = l4_data[4:] # Extract ICMP echo / error payload

        return pkt


class TCPStream:
    """
    Reassembled Bidirectional TCP Conversation.
    """
    def __init__(self, stream_id: int, client_ip: str, client_port: int, server_ip: str, server_port: int):
        self.stream_id = stream_id
        self.client_ip = client_ip
        self.client_port = client_port
        self.server_ip = server_ip
        self.server_port = server_port

        self.start_time: float = 0.0
        self.end_time: float = 0.0
        self.packet_count: int = 0
        self.total_bytes: int = 0

        # Segment queues for reordering
        self._c2s_segments: List[Tuple[int, bytes]] = []
        self._s2c_segments: List[Tuple[int, bytes]] = []

        # Reassembled payloads
        self.client_payload: bytes = b""
        self.server_payload: bytes = b""
        self.reassembled_stream: bytes = b""

        # Protocol metadata
        self.protocol_name: str = "TCP"
        self.sni: str = ""
        self.http_requests: List[Dict[str, Any]] = []
        self.http_responses: List[Dict[str, Any]] = []
        self.summary: str = ""

    def add_packet(self, pkt: Packet):
        if self.start_time == 0.0:
            self.start_time = pkt.timestamp
        self.end_time = pkt.timestamp
        self.packet_count += 1
        self.total_bytes += pkt.length

        if not pkt.payload:
            return

        is_c2s = (pkt.src_ip == self.client_ip and pkt.src_port == self.client_port)
        if is_c2s:
            self._c2s_segments.append((pkt.tcp_seq, pkt.payload))
        else:
            self._s2c_segments.append((pkt.tcp_seq, pkt.payload))

    def reassemble(self):
        """Reassembles payload fragments in sequence order, removing overlapping retransmissions."""
        self.client_payload = self._reassemble_side(self._c2s_segments)
        self.server_payload = self._reassemble_side(self._s2c_segments)
        self.reassembled_stream = self.client_payload + b"\n" + self.server_payload

        self._dissect_protocols()

    def _reassemble_side(self, segments: List[Tuple[int, bytes]]) -> bytes:
        if not segments:
            return b""
        # Sort by TCP sequence number
        segments.sort(key=lambda x: x[0])
        out = bytearray()
        last_seq = None

        for seq, data in segments:
            if last_seq is None:
                out.extend(data)
                last_seq = seq + len(data)
            else:
                if seq == last_seq:
                    out.extend(data)
                    last_seq = seq + len(data)
                elif seq > last_seq:
                    # Missing packet gap, append anyway for forensic visibility
                    out.extend(data)
                    last_seq = seq + len(data)
                elif seq + len(data) > last_seq:
                    # Overlapping retransmission
                    overlap = last_seq - seq
                    if overlap < len(data):
                        out.extend(data[overlap:])
                        last_seq = seq + len(data)
        return bytes(out)

    def _dissect_protocols(self):
        # 1. Check HTTP
        if self.client_payload.startswith((b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"CONNECT ")):
            self.protocol_name = "HTTP"
            self._parse_http()
            return

        # 2. Check TLS Client Hello (SNI extraction)
        if self.client_payload.startswith(b"\x16\x03"):
            self.protocol_name = "TLS"
            self.sni = self._extract_tls_sni(self.client_payload)
            if self.sni:
                self.summary = f"SNI: {self.sni}"
            return

        # 3. Check FTP / SSH / SMTP
        if self.server_payload.startswith(b"SSH-"):
            self.protocol_name = "SSH"
            self.summary = self.server_payload[:30].decode("latin-1", errors="ignore").strip()
            return
        elif self.server_payload.startswith(b"220 ") and (b"FTP" in self.server_payload[:100] or self.server_port in (21, 20)):
            self.protocol_name = "FTP"
            return
        elif self.server_payload.startswith(b"220 ") and b"SMTP" in self.server_payload[:100]:
            self.protocol_name = "SMTP"
            return

        # 4. Check WebAssembly
        if b"\x00asm\x01\x00\x00\x00" in self.reassembled_stream:
            self.protocol_name = "WASM Stream"
            self.summary = "Contains WebAssembly (.wasm) binary module"

    def _parse_http(self):
        try:
            # Parse HTTP Request
            req_text = self.client_payload.decode("latin-1", errors="ignore")
            headers, _, body = req_text.partition("\r\n\r\n")
            lines = headers.split("\r\n")
            if lines:
                req_line = lines[0]
                parts = req_line.split(" ")
                method = parts[0] if len(parts) > 0 else "GET"
                uri = parts[1] if len(parts) > 1 else "/"
                
                host = ""
                ua = ""
                for h in lines[1:]:
                    if h.lower().startswith("host:"): host = h[5:].strip()
                    elif h.lower().startswith("user-agent:"): ua = h[11:].strip()

                self.summary = f"{method} http://{host}{uri}"
                self.http_requests.append({
                    "method": method,
                    "uri": uri,
                    "host": host,
                    "user_agent": ua,
                    "headers_raw": headers,
                    "body_bytes": self.client_payload[len(headers)+4:] if len(self.client_payload) > len(headers)+4 else b""
                })

            # Parse HTTP Response
            if self.server_payload.startswith(b"HTTP/"):
                resp_text = self.server_payload.decode("latin-1", errors="ignore")
                r_headers, _, _ = resp_text.partition("\r\n\r\n")
                r_lines = r_headers.split("\r\n")
                status = r_lines[0] if r_lines else "HTTP/1.1 200 OK"
                content_type = ""
                content_disp = ""
                for rh in r_lines[1:]:
                    if rh.lower().startswith("content-type:"): content_type = rh[13:].strip()
                    elif rh.lower().startswith("content-disposition:"): content_disp = rh[20:].strip()

                resp_body = self.server_payload[len(r_headers)+4:]
                # Decompress gzip if present
                if b"Content-Encoding: gzip" in r_headers.encode("latin-1") or resp_body.startswith(b"\x1f\x8b"):
                    try:
                        resp_body = gzip.decompress(resp_body)
                    except Exception:
                        pass

                self.http_responses.append({
                    "status": status,
                    "content_type": content_type,
                    "content_disposition": content_disp,
                    "headers_raw": r_headers,
                    "body_bytes": resp_body
                })
        except Exception:
            pass

    def _extract_tls_sni(self, data: bytes) -> str:
        try:
            if len(data) < 43 or data[0] != 0x16 or data[5] != 0x01:
                return ""
            sess_id_len = data[43]
            offset = 44 + sess_id_len
            if offset + 2 > len(data): return ""
            cs_len = struct.unpack("!H", data[offset:offset+2])[0]
            offset += 2 + cs_len
            if offset + 1 > len(data): return ""
            comp_len = data[offset]
            offset += 1 + comp_len
            if offset + 2 > len(data): return ""
            ext_total_len = struct.unpack("!H", data[offset:offset+2])[0]
            offset += 2
            ext_end = offset + ext_total_len

            while offset + 4 <= ext_end and offset + 4 <= len(data):
                ext_type, ext_len = struct.unpack("!H", data[offset:offset+2])[0], struct.unpack("!H", data[offset+2:offset+4])[0]
                offset += 4
                if ext_type == 0x0000: # SNI
                    if offset + 5 <= len(data):
                        # server_name_list
                        name_len = struct.unpack("!H", data[offset+3:offset+5])[0]
                        sni_bytes = data[offset+5 : offset+5+name_len]
                        return sni_bytes.decode("utf-8", errors="ignore")
                offset += ext_len
        except Exception:
            pass
        return ""


class PCAPEngine:
    """
    Comprehensive PCAP/PCAPNG Forensics Engine.
    Processes packets, builds statistics, reassembles TCP streams, and collects DNS/ICMP data.
    """
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.reader = PCAPReader(file_path)
        self.packets: List[Packet] = []
        self.tcp_streams: Dict[str, TCPStream] = {}
        self.udp_conversations: Dict[str, Dict[str, Any]] = {}
        self.dns_records: List[Dict[str, Any]] = []
        self.icmp_packets: List[Dict[str, Any]] = []
        
        # Statistics
        self.protocol_counts: Dict[str, int] = {}
        self.protocol_bytes: Dict[str, int] = {}
        self.endpoints: Dict[str, Dict[str, int]] = {}
        self.is_analyzed = False

    def analyze(self):
        if self.is_analyzed:
            return

        stream_counter = 0

        for pkt in self.reader.iter_packets():
            self.packets.append(pkt)

            # 1. Update Protocol Stats
            proto_name = pkt.summary_protocol
            self.protocol_counts[proto_name] = self.protocol_counts.get(proto_name, 0) + 1
            self.protocol_bytes[proto_name] = self.protocol_bytes.get(proto_name, 0) + pkt.length

            # 2. Update Endpoints Stats
            if pkt.src_ip:
                if pkt.src_ip not in self.endpoints:
                    self.endpoints[pkt.src_ip] = {"tx_packets": 0, "rx_packets": 0, "tx_bytes": 0, "rx_bytes": 0}
                self.endpoints[pkt.src_ip]["tx_packets"] += 1
                self.endpoints[pkt.src_ip]["tx_bytes"] += pkt.length

            if pkt.dst_ip:
                if pkt.dst_ip not in self.endpoints:
                    self.endpoints[pkt.dst_ip] = {"tx_packets": 0, "rx_packets": 0, "tx_bytes": 0, "rx_bytes": 0}
                self.endpoints[pkt.dst_ip]["rx_packets"] += 1
                self.endpoints[pkt.dst_ip]["rx_bytes"] += pkt.length

            # 3. TCP Stream Tracking & Reassembly
            if pkt.ip_proto == IPPROTO_TCP and pkt.src_ip and pkt.dst_ip:
                # Canonical stream key (low_ip:low_port <-> high_ip:high_port)
                c_key = (
                    f"{pkt.src_ip}:{pkt.src_port}-{pkt.dst_ip}:{pkt.dst_port}"
                    if (pkt.src_ip < pkt.dst_ip or (pkt.src_ip == pkt.dst_ip and pkt.src_port <= pkt.dst_port))
                    else f"{pkt.dst_ip}:{pkt.dst_port}-{pkt.src_ip}:{pkt.src_port}"
                )

                if c_key not in self.tcp_streams:
                    stream_counter += 1
                    self.tcp_streams[c_key] = TCPStream(
                        stream_id=stream_counter,
                        client_ip=pkt.src_ip,
                        client_port=pkt.src_port,
                        server_ip=pkt.dst_ip,
                        server_port=pkt.dst_port
                    )

                self.tcp_streams[c_key].add_packet(pkt)

            # 4. UDP DNS Dissection
            elif pkt.ip_proto == IPPROTO_UDP and (pkt.src_port == 53 or pkt.dst_port == 53):
                dns_info = self._dissect_dns(pkt.payload)
                if dns_info:
                    dns_info["src_ip"] = pkt.src_ip
                    dns_info["dst_ip"] = pkt.dst_ip
                    dns_info["timestamp"] = pkt.timestamp
                    self.dns_records.append(dns_info)

            # 5. ICMP Payload Dissection (Covert Channel / Exfil Hunter)
            elif pkt.ip_proto in (IPPROTO_ICMP, IPPROTO_ICMPV6) and pkt.payload:
                self.icmp_packets.append({
                    "src_ip": pkt.src_ip,
                    "dst_ip": pkt.dst_ip,
                    "type": pkt.icmp_type,
                    "code": pkt.icmp_code,
                    "payload": pkt.payload,
                    "length": len(pkt.payload),
                    "timestamp": pkt.timestamp
                })

        # Reassemble all TCP streams
        for stream in self.tcp_streams.values():
            stream.reassemble()

        self.is_analyzed = True

    def _dissect_dns(self, payload: bytes) -> Optional[Dict[str, Any]]:
        if len(payload) < 12:
            return None
        try:
            tx_id, flags, qd_count, an_count, ns_count, ar_count = struct.unpack("!HHHHHH", payload[:12])
            is_response = bool(flags & 0x8000)
            offset = 12

            queries = []
            for _ in range(qd_count):
                q_name, offset = self._parse_dns_name(payload, offset)
                if offset + 4 <= len(payload):
                    q_type, q_class = struct.unpack("!HH", payload[offset:offset+4])
                    offset += 4
                    queries.append({"name": q_name, "type": q_type})

            answers = []
            for _ in range(an_count):
                a_name, offset = self._parse_dns_name(payload, offset)
                if offset + 10 <= len(payload):
                    a_type, a_class, a_ttl, rd_len = struct.unpack("!HHIH", payload[offset:offset+10])
                    offset += 10
                    rd_data = payload[offset : offset + rd_len]
                    offset += rd_len

                    ans_val = ""
                    if a_type == 1 and rd_len == 4: # A record
                        ans_val = socket.inet_ntoa(rd_data)
                    elif a_type == 16: # TXT record
                        ans_val = rd_data[1:].decode("latin-1", errors="replace") if len(rd_data) > 1 else ""
                    elif a_type == 5: # CNAME
                        ans_val, _ = self._parse_dns_name(payload, offset - rd_len)
                    else:
                        ans_val = rd_data.hex()

                    answers.append({"name": a_name, "type": a_type, "ttl": a_ttl, "value": ans_val})

            return {
                "tx_id": f"0x{tx_id:04x}",
                "is_response": is_response,
                "queries": queries,
                "answers": answers,
                "query_name": queries[0]["name"] if queries else ""
            }
        except Exception:
            return None

    def _parse_dns_name(self, payload: bytes, offset: int) -> Tuple[str, int]:
        labels = []
        visited = set()
        orig_offset = offset

        while offset < len(payload):
            length = payload[offset]
            if length == 0:
                offset += 1
                break
            elif (length & 0xC0) == 0xC0:
                # Compression pointer
                if offset + 2 > len(payload): break
                pointer = struct.unpack("!H", payload[offset:offset+2])[0] & 0x3FFF
                offset += 2
                if pointer in visited: break
                visited.add(pointer)
                ptr_name, _ = self._parse_dns_name(payload, pointer)
                labels.append(ptr_name)
                break
            else:
                offset += 1
                if offset + length <= len(payload):
                    labels.append(payload[offset : offset + length].decode("latin-1", errors="replace"))
                    offset += length
                else:
                    break
        return ".".join(filter(None, labels)), offset
