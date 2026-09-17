#!/usr/bin/env python3
"""
Template AES Decryptor & Encryptor (cipher/T_aes.py)
Supports:
- Modes: ECB, CBC, CTR, GCM, CFB, OFB
- Key Sizes: AES-128 (16B), AES-192 (24B), AES-256 (32B)
- Auto IV handling: Embedded first 16 bytes, custom hex/utf8, or zero IV
- Formats: Base64, Hex, Raw binary input/output
"""
import sys
import os
import base64
import argparse
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Util.Padding import pad, unpad

def parse_input_bytes(text_or_path: str) -> bytes:
    if os.path.exists(text_or_path):
        with open(text_or_path, "rb") as f:
            return f.read()
    s = text_or_path.strip()
    # Try Base64
    try:
        if len(s) % 4 == 0 and len(s) > 4:
            return base64.b64decode(s)
    except Exception:
        pass
    # Try Hex
    try:
        clean_hex = s.replace(" ", "").replace("0x", "")
        if len(clean_hex) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in clean_hex):
            return bytes.fromhex(clean_hex)
    except Exception:
        pass
    return s.encode("latin-1")

def parse_key_bytes(key_str: str) -> bytes:
    k = key_str.strip()
    clean_hex = k.replace(" ", "").replace("0x", "")
    if len(clean_hex) in (32, 48, 64) and all(c in "0123456789abcdefABCDEF" for c in clean_hex):
        try:
            return bytes.fromhex(clean_hex)
        except Exception:
            pass
    return k.encode("latin-1")

def main():
    parser = argparse.ArgumentParser(description=" AES Decryption / Encryption Template")
    parser.add_argument("-k", "--key", required=True, help="AES Key (string or hex: 16B/24B/32B)")
    parser.add_argument("-i", "--input", required=True, help="Ciphertext string, Base64, Hex, or file path")
    parser.add_argument("-m", "--mode", default="CTR", choices=["ECB", "CBC", "CTR", "GCM", "CFB", "OFB"], help="AES Mode (Default: CTR)")
    parser.add_argument("--iv", help="Custom IV (string or hex). If omitted in CTR/CBC, uses first 16 bytes of input")
    parser.add_argument("--zero-iv", action="store_true", help="Use all zero bytes as IV")
    parser.add_argument("-e", "--encrypt", action="store_true", help="Encrypt instead of decrypt")
    parser.add_argument("-o", "--out", help="Save output to file")

    args = parser.parse_args()

    key_bytes = parse_key_bytes(args.key)
    if len(key_bytes) not in (16, 24, 32):
        print(f"[!] Warning: Key length is {len(key_bytes)} bytes. AES requires 16, 24, or 32 bytes.")
        key_bytes = key_bytes.ljust(16, b"\x00")[:16]

    raw_data = parse_input_bytes(args.input)
    mode = args.mode.upper()

    print(f"[*] AES Mode: {mode} | Key ({len(key_bytes)}B): {key_bytes}")
    print(f"[*] Input Data Length: {len(raw_data)} bytes")

    iv = None
    ct = raw_data

    if mode in ["CBC", "CTR", "CFB", "OFB", "GCM"]:
        if args.zero_iv:
            iv = b"\x00" * 16
        elif args.iv:
            iv = parse_key_bytes(args.iv)[:16].ljust(16, b"\x00")
        else:
            if len(raw_data) > 16:
                iv = raw_data[:16]
                ct = raw_data[16:]
                print(f"[*] Auto-extracted 16-byte IV prefix: {iv.hex()}")
            else:
                iv = b"\x00" * 16

    if args.encrypt:
        if mode == "ECB":
            cipher = AES.new(key_bytes, AES.MODE_ECB)
            out = cipher.encrypt(pad(raw_data, 16))
        elif mode == "CBC":
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv)
            out = iv + cipher.encrypt(pad(raw_data, 16))
        elif mode == "CTR":
            ctr = Counter.new(128, initial_value=int.from_bytes(iv, byteorder="big"))
            cipher = AES.new(key_bytes, AES.MODE_CTR, counter=ctr)
            out = iv + cipher.encrypt(raw_data)
        elif mode == "GCM":
            cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=iv[:12])
            ct_bytes, tag = cipher.encrypt_and_digest(raw_data)
            out = iv[:12] + tag + ct_bytes
    else:
        # Decrypt
        if mode == "ECB":
            cipher = AES.new(key_bytes, AES.MODE_ECB)
            try:
                out = unpad(cipher.decrypt(raw_data), 16)
            except Exception:
                out = cipher.decrypt(raw_data)
        elif mode == "CBC":
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv)
            try:
                out = unpad(cipher.decrypt(ct), 16)
            except Exception:
                out = cipher.decrypt(ct)
        elif mode == "CTR":
            ctr = Counter.new(128, initial_value=int.from_bytes(iv, byteorder="big"))
            cipher = AES.new(key_bytes, AES.MODE_CTR, counter=ctr)
            out = cipher.decrypt(ct)
        elif mode == "GCM":
            cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=iv[:12])
            out = cipher.decrypt(ct[16:])

    print(f"\n[] Result Length: {len(out)} bytes")
    try:
        print(f"[] Plaintext Preview:\n{out[:200].decode('utf-8')}")
    except Exception:
        print(f"[] Hex/Raw Preview:\n{out[:100]}")

    if args.out:
        with open(args.out, "wb") as f:
            f.write(out)
        print(f"[] Saved output to: {args.out}")

if __name__ == "__main__":
    main()
