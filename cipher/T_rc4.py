#!/usr/bin/env python3
"""
Template RC4 / ARC4 Stream Cipher Decryptor & Encryptor (cipher/T_rc4.py)
"""
import sys
import os
import base64
import argparse
from Crypto.Cipher import ARC4

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

def main():
    parser = argparse.ArgumentParser(description=" RC4 / ARC4 Stream Cipher Template")
    parser.add_argument("-k", "--key", required=True, help="RC4 Key (string or hex)")
    parser.add_argument("-i", "--input", required=True, help="Ciphertext string, hex, base64, or file path")
    parser.add_argument("-o", "--out", help="Save output to file")

    args = parser.parse_args()

    k_str = args.key.strip()
    if k_str.startswith("0x"):
        key_bytes = bytes.fromhex(k_str[2:])
    else:
        key_bytes = k_str.encode("latin-1")

    data = parse_input_bytes(args.input)

    print(f"[*] RC4 Key: {key_bytes}")
    print(f"[*] Input Data: {len(data)} bytes")

    cipher = ARC4.new(key_bytes)
    out = cipher.decrypt(data)

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
