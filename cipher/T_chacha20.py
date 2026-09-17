#!/usr/bin/env python3
"""
Template ChaCha20 & Poly1305 Decryptor & Encryptor (cipher/T_chacha20.py)
"""
import sys
import os
import base64
import argparse
from Crypto.Cipher import ChaCha20

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
    parser = argparse.ArgumentParser(description=" ChaCha20 Decryptor / Encryptor")
    parser.add_argument("-k", "--key", required=True, help="ChaCha20 Key (32 bytes / 64 hex chars)")
    parser.add_argument("-i", "--input", required=True, help="Ciphertext string, hex, base64, or file path")
    parser.add_argument("--nonce", help="Nonce (8, 12, or 24 bytes). If omitted, uses first 8/12 bytes of input")
    parser.add_argument("-o", "--out", help="Save output to file")

    args = parser.parse_args()

    k_str = args.key.strip()
    if len(k_str) == 64 and all(c in "0123456789abcdefABCDEF" for c in k_str):
        key_bytes = bytes.fromhex(k_str)
    else:
        key_bytes = k_str.encode("latin-1").ljust(32, b"\x00")[:32]

    data = parse_input_bytes(args.input)

    if args.nonce:
        nonce = bytes.fromhex(args.nonce) if len(args.nonce) in (16, 24) else args.nonce.encode("latin-1")
        ct = data
    else:
        # Default 8 or 12 bytes nonce prefix
        nonce = data[:8] if len(data) > 8 else b"\x00" * 8
        ct = data[8:]

    print(f"[*] ChaCha20 Key ({len(key_bytes)}B): {key_bytes.hex()}")
    print(f"[*] Nonce ({len(nonce)}B): {nonce.hex()}")

    cipher = ChaCha20.new(key=key_bytes, nonce=nonce)
    out = cipher.decrypt(ct)

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
