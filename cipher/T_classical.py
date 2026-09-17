#!/usr/bin/env python3
"""
Template Classical Ciphers Solver (cipher/T_classical.py)
Supports:
- Caesar / ROT (All 26 rotations)
- Vigenere Cipher (Encrypt & Decrypt)
- Atbash Cipher
- Rail Fence (Transposition Cipher)
- Affine Cipher
"""
import sys
import argparse

def caesar_all(text: str):
    print("=== Caesar / ROT 1 - 25 ===")
    for shift in range(1, 26):
        res = []
        for ch in text:
            if ch.isalpha():
                base = ord('A') if ch.isupper() else ord('a')
                res.append(chr((ord(ch) - base + shift) % 26 + base))
            else:
                res.append(ch)
        out = "".join(res)
        flag_mark = "  [FLAG!]" if "flag" in out.lower() or "ctf" in out.lower() else ""
        print(f"ROT-{shift:02d}: {out}{flag_mark}")

def vigenere(text: str, key: str, decrypt: bool = True) -> str:
    res = []
    key = key.upper()
    k_idx = 0
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            k_shift = ord(key[k_idx % len(key)]) - ord('A')
            if decrypt:
                res.append(chr((ord(ch) - base - k_shift) % 26 + base))
            else:
                res.append(chr((ord(ch) - base + k_shift) % 26 + base))
            k_idx += 1
        else:
            res.append(ch)
    return "".join(res)

def atbash(text: str) -> str:
    res = []
    for ch in text:
        if ch.isupper():
            res.append(chr(ord('Z') - (ord(ch) - ord('A'))))
        elif ch.islower():
            res.append(chr(ord('z') - (ord(ch) - ord('a'))))
        else:
            res.append(ch)
    return "".join(res)

def rail_fence_decrypt(cipher: str, rails: int) -> str:
    fence = [['\n' for _ in range(len(cipher))] for _ in range(rails)]
    row, col = 0, 0
    dir_down = None

    for i in range(len(cipher)):
        if row == 0:
            dir_down = True
        if row == rails - 1:
            dir_down = False
        fence[row][col] = '*'
        col += 1
        row += 1 if dir_down else -1

    idx = 0
    for i in range(rails):
        for j in range(len(cipher)):
            if fence[i][j] == '*' and idx < len(cipher):
                fence[i][j] = cipher[idx]
                idx += 1

    result = []
    row, col = 0, 0
    for i in range(len(cipher)):
        if row == 0:
            dir_down = True
        if row == rails - 1:
            dir_down = False
        if fence[row][col] != '*':
            result.append(fence[row][col])
            col += 1
        row += 1 if dir_down else -1
    return "".join(result)

def main():
    parser = argparse.ArgumentParser(description=" Classical Ciphers Solver")
    parser.add_argument("-t", "--text", required=True, help="Ciphertext string")
    parser.add_argument("--caesar", action="store_true", help="Brute-force all Caesar ROT shifts")
    parser.add_argument("--vigenere", help="Decrypt using Vigenere key")
    parser.add_argument("--atbash", action="store_true", help="Apply Atbash substitution")
    parser.add_argument("--railfence", type=int, help="Decrypt using Rail Fence with N rails")

    args = parser.parse_args()

    if args.caesar:
        caesar_all(args.text)
    elif args.vigenere:
        print(f"[] Vigenere Decrypted: {vigenere(args.text, args.vigenere)}")
    elif args.atbash:
        print(f"[] Atbash Decrypted: {atbash(args.text)}")
    elif args.railfence:
        print(f"[] Rail Fence ({args.railfence} rails): {rail_fence_decrypt(args.text, args.railfence)}")
    else:
        # Run all basic checks
        caesar_all(args.text)
        print(f"\n[] Atbash: {atbash(args.text)}")

if __name__ == "__main__":
    main()
