"""
Synthetic PCAP Generator for Testing CaRT carving, Unknown header carving, and pcapportpayload covert channels.
"""
import struct
import socket
import os

def create_pcap(filename: str):
    f = open(filename, "wb")

    # Global PCAP Header (24 bytes)
    # Magic: 0xa1b2c3d4, v2.4, snaplen=65535, linktype=1 (Ethernet)
    f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))

    base_time = 1725500000.0

    def write_packet(raw_eth_pkt, t_offset):
        ts = base_time + t_offset
        ts_sec = int(ts)
        ts_usec = int((ts - ts_sec) * 1_000_000)
        p_len = len(raw_eth_pkt)
        f.write(struct.pack("<IIII", ts_sec, ts_usec, p_len, p_len))
        f.write(raw_eth_pkt)

    def build_ipv4_tcp_pkt(src_ip, src_port, dst_ip, dst_port, seq, ack, flags, payload, ip_id=0x1234, ip_ttl=64):
        eth = b"\x00\x0c\x29\x11\x22\x33" + b"\x00\x50\x56\xaa\xbb\xcc" + b"\x08\x00"
        tcp_hdr = struct.pack("!HHIIH", src_port, dst_port, seq, ack, (5 << 12) | flags) + struct.pack("!HHH", 8192, 0, 0)
        ip_total_len = 20 + 20 + len(payload)
        ip_hdr = struct.pack("!BBHHHBBH", 0x45, 0, ip_total_len, ip_id, 0x4000, ip_ttl, 6, 0)
        ip_hdr += socket.inet_aton(src_ip) + socket.inet_aton(dst_ip)
        return eth + ip_hdr + tcp_hdr + payload

    def build_ipv4_udp_pkt(src_ip, src_port, dst_ip, dst_port, payload, ip_id=0x5678, ip_ttl=64):
        eth = b"\x00\x0c\x29\x11\x22\x33" + b"\x00\x50\x56\xaa\xbb\xcc" + b"\x08\x00"
        udp_len = 8 + len(payload)
        udp_hdr = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)
        ip_total = 20 + udp_len
        ip_hdr = struct.pack("!BBHHHBBH", 0x45, 0, ip_total, ip_id, 0, ip_ttl, 17, 0)
        ip_hdr += socket.inet_aton(src_ip) + socket.inet_aton(dst_ip)
        return eth + ip_hdr + udp_hdr + payload

    # =========================================================================
    # Test 1: CaRT file transfer in TCP stream
    # =========================================================================
    cart_header = b"CART\x01\x00\x00\x00" + b"{\"name\": \"malware_sample.exe\", \"hash\": \"12345\"}\n"
    cart_payload = cart_header + b"MZ\x90\x00\x03\x00\x00\x00CaRT_Encrypted_Payload_Block_flag{cart_file_successfully_carved_2026}"
    write_packet(build_ipv4_tcp_pkt("192.168.1.100", 50001, "10.0.0.10", 8080, 1000, 1, 0x18, cart_payload), 0.1)

    # =========================================================================
    # Test 2: Custom / Unknown Header container (e.g. C2PK)
    # =========================================================================
    unknown_container = b"C2PK\x00\x01\x00\x08" + b"FLAG_BLOCK:flag{custom_c2pk_header_carved_9999}\x00\x00\x00\x00"
    write_packet(build_ipv4_tcp_pkt("192.168.1.100", 50002, "10.0.0.20", 9001, 2000, 1, 0x18, unknown_container), 0.2)

    # =========================================================================
    # Test 3: Port-to-ASCII Covert Channel (Sequential Destination Ports)
    # Target string: "flag{p0rt_c0v3rt_ch4nn3l}"
    # =========================================================================
    target_flag = "flag{p0rt_c0v3rt_ch4nn3l}"
    for idx, ch in enumerate(target_flag):
        dest_port = ord(ch) # e.g. 102 ('f'), 108 ('l'), ...
        write_packet(build_ipv4_udp_pkt("192.168.1.100", 40000 + idx, "10.0.0.30", dest_port, b"PING"), 0.5 + idx * 0.05)

    # =========================================================================
    # Test 4: Per-Packet Discrete Payload Lines on Port 1337
    # =========================================================================
    discrete_lines = [
        b"[PACKET 1] Initializing covert line transfer...\n",
        b"[PACKET 2] Target authenticated.\n",
        b"[PACKET 3] Payload data: flag{discrete_per_packet_line_inserted_1337}\n",
        b"[PACKET 4] Session terminated.\n"
    ]
    for idx, line in enumerate(discrete_lines):
        write_packet(build_ipv4_udp_pkt("192.168.1.100", 49999, "10.0.0.40", 1337, line), 2.0 + idx * 0.1)

    # =========================================================================
    # Test 5: IP.ID Covert Channel
    # Sequence of IP IDs encoding ASCII: "flag{ip_id_covert_flag}"
    # =========================================================================
    ipid_flag = "flag{ip_id_covert_flag}"
    for idx, ch in enumerate(ipid_flag):
        write_packet(build_ipv4_tcp_pkt("192.168.1.100", 55555, "10.0.0.50", 80, 5000 + idx * 10, 1, 0x02, b"", ip_id=ord(ch)), 3.0 + idx * 0.05)

    f.close()
    print(f"[✓] Generated covert test PCAP: {filename} ({os.path.getsize(filename)} bytes)")

if __name__ == "__main__":
    out_path = os.path.join(os.path.dirname(__file__), "covert_traffic.pcap")
    create_pcap(out_path)
