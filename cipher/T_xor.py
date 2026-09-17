#!/usr/bin/env python3
"""
Template XOR Decryptor & Cracker (cipher/T_xor.py)
Supports:
- Single-Byte XOR Brute-Force (0x00 - 0xFF)
- Repeating Multi-Byte XOR
- Incremental / Rolling Seed XOR (NimPlant / Malware deobfuscation style)
- Known-Plaintext XOR Key Recovery
"""
import sys
import os
import base64
import argparse

def parse_input_bytes(text_or_path: str) -> bytes:
    if os.path.exists(text_or_path):
        with open(text_or_path, "rb") as f:
            return f.read()
    s = text_or_path.strip()
    try:
        if len(s) % 4 == 0 and len(s) > 4:
            return base64.b64decode(s)
    except Exception:
        pass
    try:
        clean_hex = s.replace(" ", "").replace("0x", "")
        if len(clean_hex) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in clean_hex):
            return bytes.fromhex(clean_hex)
    except Exception:
        pass
    return s.encode("latin-1")

def repeating_xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def rolling_xor(data: bytes, seed: int) -> bytes:
    out = bytearray()
    curr_seed = seed
    for b in data:
        b0 = curr_seed & 0xFF
        b1 = (curr_seed >> 8) & 0xFF
        b2 = (curr_seed >> 16) & 0xFF
        b3 = (curr_seed >> 24) & 0xFF
        out.append(b ^ b0 ^ b1 ^ b2 ^ b3)
        curr_seed = (curr_seed + 1) & 0xFFFFFFFF
    return bytes(out)

def single_byte_brute(data: bytes, flag_prefix: str = "flag{"):
    print(f"[*] Scanning all 256 single-byte XOR keys...")
    matches = []
    for k in range(256):
        dec = bytes(b ^ k for b in data)
        # Check printable
        printable = sum(1 for b in dec if 32 <= b <= 126 or b in (9, 10, 13))
        score = printable / len(dec)
        if flag_prefix.lower().encode() in dec.lower():
            print(f"\n[ FLAG DETECTED!] Key: 0x{k:02X} ({k})")
            print(f"Result: {dec}")
            matches.append((k, dec))
        elif score >= 0.90:
            print(f"[+] High ASCII Score ({score*100:.0f}%) | Key: 0x{k:02X} -> {dec[:80]}")
            matches.append((k, dec))
    return matches

def main():
    parser = argparse.ArgumentParser(description=" Universal XOR Decryption & Cracker Template")
    parser.add_argument("-i", "--input", required=True, help="Ciphertext string, hex, base64, or file path")
    parser.add_argument("-k", "--key", help="XOR Key (string, hex, or int e.g. 0x3386dd90)")
    parser.add_argument("--brute", action="store_true", help="Brute-force all 256 single-byte XOR keys")
    parser.add_argument("--rolling", action="store_true", help="Use 4-byte incremental rolling seed XOR")
    parser.add_argument("-o", "--out", help="Save output to file")

    args = parser.parse_args()
    data = parse_input_bytes(args.input)

    if args.brute or not args.key:
        single_byte_brute(data)
        return

    # Parse key
    k_str = args.key.strip()
    if k_str.startswith("0x") or k_str.isdigit():
        int_key = int(k_str, 16) if k_str.startswith("0x") else int(k_str)
        if args.rolling:
            print(f"[*] Rolling Seed XOR with seed: 0x{int_key:08X}")
            out = rolling_xor(data, int_key)
        else:
            # Multi-byte hex key
            key_bytes = int_key.to_bytes((int_key.bit_length() + 7) // 8 or 1, byteorder="little")
            print(f"[*] Multi-byte XOR with key bytes: {key_bytes.hex()}")
            out = repeating_xor(data, key_bytes)
    else:
        key_bytes = k_str.encode("latin-1")
        print(f"[*] Repeating XOR with key string: {k_str}")
        out = repeating_xor(data, key_bytes)

    print(f"\n[] Result Length: {len(out)} bytes")
    try:
        print(f"[] Plaintext Preview:\n{out[:200].decode('utf-8')}")
    except Exception:
        print(f"[] Raw Preview:\n{out[:100]}")

    if args.out:
        with open(args.out, "wb") as f:
            f.write(out)
        print(f"[] Saved to: {args.out}")

if __name__ == "__main__":
    main()
