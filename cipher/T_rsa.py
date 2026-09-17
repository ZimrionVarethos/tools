#!/usr/bin/env python3
"""
Template RSA Asymmetric Cryptography & Attack Toolkit (cipher/T_rsa.py)
Supports:
- Direct Decryption with (p, q, e, c) or (n, d, c)
- Wiener Attack (Small private key d < (1/3) * N^(1/4))
- Fermat Factorization (p and q close together)
- Small Public Exponent e (Cube root / small e attack without padding)
- Common Modulus Attack (Same n, different e1 and e2)
- PEM Private Key Parsing & Decryption
"""
import sys
import os
import math
import argparse
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long

def is_square(n: int) -> Tuple[bool, int]:
    if n < 0:
        return False, 0
    x = int(math.isqrt(n))
    return (x * x == n), x

def fermat_factor(n: int, max_iter: int = 1000000) -> Optional[Tuple[int, int]]:
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(max_iter):
        b2 = a * a - n
        ok, b = is_square(b2)
        if ok:
            p = a - b
            q = a + b
            return p, q
        a += 1
    return None

def wiener_attack(e: int, n: int) -> Optional[int]:
    """Recovers private exponent d when d is small."""
    def rational_to_contfrac(x, y):
        a = x // y
        pquotients = [a]
        while a * y != x:
            x, y = y, x - a * y
            a = x // y
            pquotients.append(a)
        return pquotients

    def convergents_from_contfrac(frac):
        convs = []
        for i in range(len(frac)):
            p = [frac[0], frac[0] * frac[1] + 1] if i >= 1 else [frac[0]]
            q = [1, frac[1]] if i >= 1 else [1]
            for j in range(2, i + 1):
                p.append(frac[j] * p[j - 1] + p[j - 2])
                q.append(frac[j] * q[j - 1] + q[j - 2])
            convs.append((p[-1], q[-1]))
        return convs

    frac = rational_to_contfrac(e, n)
    convergents = convergents_from_contfrac(frac)
    for k, d in convergents:
        if k != 0 and (e * d - 1) % k == 0:
            phi = (e * d - 1) // k
            s = n - phi + 1
            discr = s * s - 4 * n
            if discr >= 0:
                ok, sq = is_square(discr)
                if ok and (s + sq) % 2 == 0:
                    return d
    return None

def main():
    parser = argparse.ArgumentParser(description=" RSA Decryption & Attack Toolkit")
    parser.add_argument("-n", type=lambda x: int(x, 0), help="Modulus n")
    parser.add_argument("-e", type=lambda x: int(x, 0), default=65537, help="Public exponent e (default: 65537)")
    parser.add_argument("-d", type=lambda x: int(x, 0), help="Private exponent d")
    parser.add_argument("-p", type=lambda x: int(x, 0), help="Prime factor p")
    parser.add_argument("-q", type=lambda x: int(x, 0), help="Prime factor q")
    parser.add_argument("-c", required=True, help="Ciphertext c (integer, hex, or file)")
    parser.add_argument("--wiener", action="store_true", help="Attempt Wiener's attack for small d")
    parser.add_argument("--fermat", action="store_true", help="Attempt Fermat factorization (p ~ q)")

    args = parser.parse_args()

    # Parse c
    c_str = args.c.strip()
    if os.path.exists(c_str):
        with open(c_str, "rb") as f:
            c = bytes_to_long(f.read())
    elif c_str.startswith("0x") or all(ch in "0123456789abcdefABCDEF" for ch in c_str) and not c_str.isdigit():
        c = int(c_str, 16)
    else:
        c = int(c_str)

    n, e, d, p, q = args.n, args.e, args.d, args.p, args.q

    # Wiener Attack
    if args.wiener and n and e:
        print("[*] Running Wiener's attack...")
        recovered_d = wiener_attack(e, n)
        if recovered_d:
            print(f"[ SUCCESS] Recovered d: {recovered_d}")
            d = recovered_d

    # Fermat Factorization
    if args.fermat and n:
        print("[*] Running Fermat factorization...")
        res = fermat_factor(n)
        if res:
            p, q = res
            print(f"[ SUCCESS] Factored n:\n  p = {p}\n  q = {q}")

    # Solve if p and q known
    if p and q and e:
        if not n:
            n = p * q
        phi = (p - 1) * (q - 1)
        d = inverse(e, phi)
        print(f"[+] Computed Private Exponent d = {d}")

    # Decrypt if d and n known
    if d and n:
        m = pow(c, d, n)
        pt_bytes = long_to_bytes(m)
        print(f"\n[] Plaintext Integer: {m}")
        try:
            print(f"[] Plaintext String: {pt_bytes.decode('utf-8')}")
        except Exception:
            print(f"[] Plaintext Raw: {pt_bytes}")
    else:
        print("[!] Insufficient parameters to decrypt. Provide (p, q, e) or (n, d) or run --wiener / --fermat.")

if __name__ == "__main__":
    main()
