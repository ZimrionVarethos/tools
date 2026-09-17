"""
Synthetic DMP / Binary File Generator for Testing globalscan
"""
import struct
import base64
import os

def create_mock_dmp(output_path: str):
    data = bytearray()
    
    # MiniDump Header (MDMP signature)
    data.extend(b"MDMP\x93\xa7\x00\x00")
    data.extend(struct.pack("<IIII", 10, 0x20, 0, 0)) # Stream count, offset, etc.
    data.extend(b"\x00" * 256)

    # 1. Plaintext Standard Flag
    data.extend(b"\n[DEBUG] Memory dump captured at process 0x1404\n")
    data.extend(b"User Objective Flag: flag{m3m0ry_dump_str1ngs_succ3ss_2026}\n")

    # 2. Flag with spaces & special characters
    data.extend(b"System Environment Config: {CTF_flag with spaces and special @#$ symbols}\n")

    # 3. Base64 Encoded Flag
    b64_flag = base64.b64encode(b"flag{base64_decoded_flag_1234}").decode("ascii")
    data.extend(f"Cached Token Payload: {b64_flag}\n".encode("utf-8"))

    # 4. Single-byte XOR encoded flag (XOR key 0x42)
    xor_key = 0x42
    xor_flag = bytes([c ^ xor_key for c in b"flag{x0r_single_byte_carved_flag_999}"])
    data.extend(b"\n--- Obfuscated Memory Buffer ---\n")
    data.extend(xor_flag)
    data.extend(b"\n--- End Buffer ---\n")

    # 5. Sensitive credentials & API keys
    data.extend(b"DB Connection: password = 'SuperAdminPasswordSecret!'\n")
    data.extend(b"AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE\n")
    data.extend(b"Discord C2: https://discord.com/api/webhooks/999888777/xyz123abc456\n")
    data.extend(b"Privilege command: sudo /bin/bash\n")
    data.extend(b"Cryptographic algorithm: XOR cipher rot13\n")

    # Fill some padding binary data
    data.extend(os.urandom(2048))

    with open(output_path, "wb") as f:
        f.write(data)

    print(f"[] Created synthetic DMP file: {output_path} ({len(data)} bytes)")

if __name__ == "__main__":
    out_file = os.path.join(os.path.dirname(__file__), "cute.DMP")
    create_mock_dmp(out_file)
