#!/usr/bin/env python3
"""
Advanced Cryptographic Key, Nonce, Constant & Struct Harvester (cipher/cryptohunt.py)
Alias: cryptohunt, keyhunt, keyfind, cryptoparse
"""

import sys, os, math, struct, base64, argparse, json, re
from typing import List, Dict, Any, Tuple, Optional

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.markup import escape

from core.banner import print_banner
from core.utils import human_size

console = Console(force_terminal=True, legacy_windows=False)

CRYPTO_SIGNATURES = [
    {
        "name": "ChaCha20 / Salsa20 Constant (32-byte key)",
        "algo": "ChaCha20-32",
        "pattern": b"expand 32-byte k",
        "desc": "ChaCha20 state matrix 16-byte sigma constant (0x61707865, 0x3320646e, 0x79622d32, 0x6b206574)"
    },
    {
        "name": "ChaCha20 / Salsa20 Constant (16-byte key)",
        "algo": "ChaCha20-16",
        "pattern": b"expand 16-byte k",
        "desc": "ChaCha20 state matrix 16-byte tau constant"
    },
    {
        "name": "AES Forward S-Box (Initial 16 bytes)",
        "algo": "AES",
        "pattern": bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76]),
        "desc": "Standard Rijndael Substitution Box (SubBytes lookup table)"
    },
    {
        "name": "AES Inverse S-Box (Initial 16 bytes)",
        "algo": "AES",
        "pattern": bytes([0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb]),
        "desc": "Standard Rijndael Inverse Substitution Box (InvSubBytes lookup table)"
    },
    {
        "name": "AES Rcon (Round Constants)",
        "algo": "AES",
        "pattern": bytes([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]),
        "desc": "AES Key Expansion Round Constants"
    },
    {
        "name": "SHA-256 Initial Hash State (H0-H7)",
        "algo": "SHA-256",
        "pattern": bytes.fromhex("6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19"),
        "desc": "SHA-256 fractional parts of square roots of first 8 primes (Big Endian)"
    },
    {
        "name": "SHA-256 Initial Hash State (Little Endian)",
        "algo": "SHA-256",
        "pattern": bytes.fromhex("67e6096a85ae67bb72f36e3c3af54fa57f520e518c68059babd9831f19cde05b"),
        "desc": "SHA-256 initial vector (x86/x64 Little Endian binary layout)"
    },
    {
        "name": "MD5 Initial State (A, B, C, D)",
        "algo": "MD5",
        "pattern": bytes.fromhex("0123456789abcdeffedcba9876543210"),
        "desc": "MD5 standard initialization constants (Little Endian)"
    },
    {
        "name": "SM4 Forward S-Box (Initial 16 bytes)",
        "algo": "SM4",
        "pattern": bytes([0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05]),
        "desc": "Chinese Commercial Cryptography SM4 Block Cipher S-Box"
    },
    {
        "name": "DES Initial Permutation (IP) Table",
        "algo": "DES",
        "pattern": bytes([58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4]),
        "desc": "Data Encryption Standard Initial Bit Permutation Table"
    }
]
def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    length = len(data)
    counts = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def is_candidate_key(data: bytes, min_entropy: float = 3.0, min_distinct: int = 6) -> bool:
    """Filter out non-random, repeating, null, or pure ASCII text buffers."""
    if not data:
        return False
    if data == b"\x00" * len(data) or data == b"\xff" * len(data):
        return False
    distinct = len(set(data))
    if distinct < min_distinct:
        return False
    ent = calculate_entropy(data)
    if ent < min_entropy:
        return False
    
    # If entropy is high (>= 3.9), it is pseudo-random crypto key data (even if it contains 0x00)
    if ent >= 3.9:
        return True

    # Filter out text strings and symbol tables (low entropy + mostly ASCII)
    printable_count = sum(1 for b in data if 32 <= b <= 126)
    if (printable_count / len(data)) >= 0.70:
        if not re.match(r"^[0-9a-fA-F]{16,}$", data.decode("ascii", errors="ignore")):
            return False
    return True

def parse_elf_sections(data: bytes) -> List[Dict[str, Any]]:
    sections = []
    if len(data) < 64 or not data.startswith(b"\x7fELF"):
        return sections
    
    is_64 = data[4] == 2
    is_le = data[5] == 1
    endian = "<"
    if not is_le:
        endian = ">"
    
    try:
        if is_64:
            e_shoff = struct.unpack_from(f"{endian}Q", data, 40)[0]
            e_shentsize = struct.unpack_from(f"{endian}H", data, 58)[0]
            e_shnum = struct.unpack_from(f"{endian}H", data, 60)[0]
            e_shstrndx = struct.unpack_from(f"{endian}H", data, 62)[0]
        else:
            e_shoff = struct.unpack_from(f"{endian}I", data, 32)[0]
            e_shentsize = struct.unpack_from(f"{endian}H", data, 46)[0]
            e_shnum = struct.unpack_from(f"{endian}H", data, 48)[0]
            e_shstrndx = struct.unpack_from(f"{endian}H", data, 50)[0]

        if e_shoff == 0 or e_shnum == 0 or e_shoff + e_shnum * e_shentsize > len(data):
            return sections

        shstr_entry = e_shoff + e_shstrndx * e_shentsize
        if is_64:
            shstr_offset = struct.unpack_from(f"{endian}Q", data, shstr_entry + 24)[0]
        else:
            shstr_offset = struct.unpack_from(f"{endian}I", data, shstr_entry + 16)[0]
        
        strtab = data[shstr_offset:]

        for i in range(e_shnum):
            s_offset = e_shoff + i * e_shentsize
            if is_64:
                sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size = struct.unpack_from(f"{endian}IIQQQQ", data, s_offset)
            else:
                sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size = struct.unpack_from(f"{endian}IIIIII", data, s_offset)

            name_end = strtab.find(b"\x00", sh_name)
            name = strtab[sh_name:name_end].decode("ascii", errors="ignore") if name_end != -1 else f"sec_{i}"
            
            if sh_size > 0:
                sections.append({
                    "name": name,
                    "type": sh_type,
                    "vaddr": sh_addr,
                    "offset": sh_offset,
                    "size": sh_size
                })
    except Exception:
        pass
    return sections

def parse_pe_sections(data: bytes) -> List[Dict[str, Any]]:
    sections = []
    if len(data) < 64 or not data.startswith(b"MZ"):
        return sections
    try:
        e_lfanew = struct.unpack_from("<I", data, 60)[0]
        if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew+4] != b"PE\0\0":
            return sections
        
        num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
        opt_hdr_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
        sec_table_offset = e_lfanew + 24 + opt_hdr_size

        for i in range(num_sections):
            entry_off = sec_table_offset + i * 40
            if entry_off + 40 > len(data):
                break
            sec_name = data[entry_off:entry_off+8].rstrip(b"\0").decode("ascii", errors="ignore")
            vsize, vaddr, raw_size, raw_offset = struct.unpack_from("<IIII", data, entry_off + 8)
            
            if raw_size > 0:
                sections.append({
                    "name": sec_name,
                    "vaddr": vaddr,
                    "offset": raw_offset,
                    "size": raw_size
                })
    except Exception:
        pass
    return sections

def check_plaintext_validity(pt: bytes, expected_prefix: bytes = None) -> bool:
    if not pt:
        return False
    if expected_prefix and expected_prefix in pt:
        return True
    if not expected_prefix:
        printable = sum(1 for b in pt if 32 <= b <= 126 or b in (10, 13, 9))
        return (printable / len(pt)) >= 0.95
    return False

def test_decryption_candidate(key: bytes, nonce: bytes, ct: bytes, expected_prefix: bytes = None) -> Optional[Dict[str, Any]]:
    from Crypto.Cipher import ChaCha20, AES, ARC4

    if len(key) == 32 and len(nonce) in (8, 12):
        try:
            c1 = ChaCha20.new(key=key, nonce=nonce)
            c1.decrypt(b"\x00" * 64)
            pt = c1.decrypt(ct)
            if check_plaintext_validity(pt, expected_prefix):
                return {"algo": "ChaCha20 (IETF Counter=1)", "plaintext": pt}
        except Exception:
            pass

        try:
            c0 = ChaCha20.new(key=key, nonce=nonce)
            pt = c0.decrypt(ct)
            if check_plaintext_validity(pt, expected_prefix):
                return {"algo": "ChaCha20 (Block Counter=0)", "plaintext": pt}
        except Exception:
            pass

    if len(key) in (16, 24, 32) and len(nonce) in (12, 16):
        try:
            if len(ct) > 16:
                tag = ct[-16:]
                enc_data = ct[:-16]
                aes_gcm = AES.new(key, AES.MODE_GCM, nonce=nonce)
                pt = aes_gcm.decrypt_and_verify(enc_data, tag)
                if check_plaintext_validity(pt, expected_prefix):
                    return {"algo": f"AES-{len(key)*8}-GCM", "plaintext": pt}
        except Exception:
            pass

    if len(key) in (16, 24, 32) and len(nonce) == 16:
        try:
            if len(ct) % 16 == 0:
                aes_cbc = AES.new(key, AES.MODE_CBC, iv=nonce)
                pt = aes_cbc.decrypt(ct)
                pad_len = pt[-1]
                if 1 <= pad_len <= 16 and pt.endswith(bytes([pad_len]) * pad_len):
                    pt_unpad = pt[:-pad_len]
                else:
                    pt_unpad = pt
                if check_plaintext_validity(pt_unpad, expected_prefix):
                    return {"algo": f"AES-{len(key)*8}-CBC", "plaintext": pt_unpad}
        except Exception:
            pass

    if len(key) in (8, 16, 24, 32):
        try:
            rc4 = ARC4.new(key)
            pt = rc4.decrypt(ct)
            if check_plaintext_validity(pt, expected_prefix):
                return {"algo": f"RC4-{len(key)*8}", "plaintext": pt}
        except Exception:
            pass

    return None

def is_noise_or_pointer(data: bytes) -> bool:
    """Filter out 64-bit kernel/userspace pointers, ASCII names, and non-crypto noise."""
    if not data:
        return True
    # 64-bit kernel pointer or sign-extension (0xffffffff or 0x00000000)
    if b"\xff\xff\xff\xff" in data or b"\x00\x00\x00\x00" in data:
        return True
    # Userspace 64-bit stack/heap pointers (e.g. 0x7fXXXXXXXXXX or 0x55XXXXXXXXXX / 0x56XXXXXXXXXX)
    if re.search(rb"\x7f[\x00-\xff]\xff\xff", data) or re.search(rb"\xff\xff[\x00-\xff]\x7f", data):
        return True
    if re.search(rb"\x55\x55\x55\x55", data) or re.search(rb"\x56\x56\x56\x56", data):
        return True
    # Repeated single byte >= 4 times (e.g. AAAA, \x90\x90\x90\x90)
    for i in range(len(data) - 3):
        if data[i] == data[i+1] == data[i+2] == data[i+3]:
            return True
    # ASCII text words (e.g. kworker, strings, symbol names)
    printable = sum(1 for x in data if 32 <= x <= 126)
    if (printable / len(data)) >= 0.55:
        return True
    return False

def compute_crypto_quality(data: bytes, target_size: int, lead_nulls: int = 0, trail_nulls: int = 0, offset: int = 0) -> float:
    """
    Compute a normalized Forensic Quality Score (0.0 to 100.0) for a candidate buffer.
    High scores indicate authentic cryptographic keys/nonces.
    """
    if not data or is_noise_or_pointer(data):
        return 0.0

    ent = calculate_entropy(data)
    distinct = len(set(data))
    max_ent = math.log2(len(data)) if len(data) > 1 else 1.0
    norm_ent = min(1.0, ent / max_ent)

    # Base score from entropy and byte diversity
    score = (norm_ent * 50.0) + ((distinct / len(data)) * 30.0)

    # 16-byte alignment bonus (GCC/Clang/Rust aligns struct fields to 8B/16B)
    if offset % 16 == 0:
        score += 10.0
    elif offset % 8 == 0:
        score += 5.0

    # Surrounding null padding bonus (indicates struct member or static variable in .data/.rodata)
    if lead_nulls >= 4 or trail_nulls >= 4:
        score += 10.0
    elif lead_nulls >= 1 or trail_nulls >= 1:
        score += 5.0

    return round(score, 2)

def scan_file_crypto_anchors_streaming(target_path: str, chunk_size: int = 32 * 1024 * 1024) -> List[Dict[str, Any]]:
    """
    Memory-efficient streaming scanner for discovering known cryptographic constants in large dumps (>2GB).
    """
    anchors = []
    file_size = os.path.getsize(target_path)
    overlap = 65536

    with open(target_path, "rb") as f:
        curr_offset = 0
        while curr_offset < file_size:
            f.seek(curr_offset)
            chunk = f.read(chunk_size)
            if not chunk:
                break

            for sig in CRYPTO_SIGNATURES:
                pat = sig["pattern"]
                pos = 0
                while True:
                    pos = chunk.find(pat, pos)
                    if pos == -1:
                        break
                    abs_off = curr_offset + pos
                    anchors.append({
                        "algo": sig["algo"],
                        "name": sig["name"],
                        "desc": sig["desc"],
                        "offset": abs_off,
                        "hex": pat.hex()
                    })
                    pos += 1

            if len(chunk) < chunk_size:
                break
            curr_offset += chunk_size - overlap

    return anchors

def scan_crypto_constants(data: bytes, base_offset: int = 0) -> List[Dict[str, Any]]:
    found = []
    for sig in CRYPTO_SIGNATURES:
        pos = 0
        pat = sig["pattern"]
        while True:
            pos = data.find(pat, pos)
            if pos == -1:
                break
            found.append({
                "name": sig["name"],
                "algo": sig["algo"],
                "offset": base_offset + pos,
                "desc": sig["desc"],
                "hex": pat.hex()
            })
            pos += 1
    return found

def harvest_contiguous_runs(
    data: bytes,
    min_run_len: int = 4,
    max_run_len: int = 1024,
    near_offset: Optional[int] = None,
    max_distance: int = 65536,
    filter_pointers: bool = True
) -> List[Dict[str, Any]]:
    """
    Harvest all contiguous non-zero byte runs (islands bounded by null bytes 0x00).
    In Ghidra/binary memory, structs and buffers are separated by null bytes.
    """
    runs = []
    buf_len = len(data)

    start_scan = 0
    end_scan = buf_len
    if near_offset is not None:
        start_scan = max(0, near_offset - max_distance)
        end_scan = min(buf_len, near_offset + max_distance)

    slice_data = data[start_scan:end_scan]
    for m in re.finditer(rb"[^\x00]+", slice_data):
        r_start = start_scan + m.start()
        r_end = start_scan + m.end()
        raw_chunk = m.group(0)
        r_len = len(raw_chunk)

        if r_len < min_run_len or r_len > max_run_len:
            continue

        if filter_pointers and is_noise_or_pointer(raw_chunk):
            continue

        lead_nulls = 0
        p = r_start - 1
        while p >= 0 and data[p] == 0 and lead_nulls < 64:
            lead_nulls += 1
            p -= 1

        trail_nulls = 0
        p = r_end
        while p < buf_len and data[p] == 0 and trail_nulls < 64:
            trail_nulls += 1
            p += 1

        ent = calculate_entropy(raw_chunk)
        distinct = len(set(raw_chunk))
        q_score = compute_crypto_quality(raw_chunk, r_len, lead_nulls, trail_nulls, r_start)

        printable_count = sum(1 for b in raw_chunk if 32 <= b <= 126)
        is_ascii = (printable_count / r_len) >= 0.70

        tag = "Binary Array"
        if r_len == 32 and ent >= 3.8:
            tag = "Key-32 (AES-256 / ChaCha20)"
        elif r_len == 16 and ent >= 3.2:
            tag = "Key-16 / IV (AES-128)"
        elif r_len == 12 and ent >= 3.0:
            tag = "Nonce-12 (ChaCha20 / GCM)"
        elif r_len == 8:
            tag = "Nonce-8 / Seed"
        elif is_ascii:
            tag = "ASCII String"
        elif ent >= 3.8:
            tag = f"High-Entropy Run ({r_len}B)"
        else:
            tag = f"Contiguous Run ({r_len}B)"

        runs.append({
            "start": r_start,
            "end": r_end,
            "length": r_len,
            "entropy": round(ent, 3),
            "distinct": distinct,
            "quality": q_score,
            "hex": raw_chunk.hex(),
            "raw": raw_chunk,
            "tag": tag,
            "lead_nulls": lead_nulls,
            "trail_nulls": trail_nulls,
            "is_ascii": is_ascii
        })

    if near_offset is not None:
        runs.sort(key=lambda x: (abs(x["start"] - near_offset), -x["quality"], -x["entropy"]))
    else:
        runs.sort(key=lambda x: (-x["quality"], -x["entropy"]))

    return runs

def harvest_key_candidates(data: bytes, target_sizes: List[int] = [32, 16, 12, 8], step: int = 16, min_entropy: float = 3.0, near_offset: int = None, max_distance: int = 65536) -> List[Dict[str, Any]]:
    candidates = []
    buf_len = len(data)

    start_idx = 0
    end_idx = buf_len
    if near_offset is not None:
        start_idx = max(0, near_offset - max_distance)
        end_idx = min(buf_len, near_offset + max_distance)

    for sz in target_sizes:
        min_dist = 8 if sz >= 32 else (6 if sz >= 16 else 3)
        sz_end = min(end_idx, buf_len - sz + 1)
        for i in range(start_idx, sz_end, step):
            chunk = data[i : i + sz]
            if is_noise_or_pointer(chunk):
                continue
            if is_candidate_key(chunk, min_entropy=min_entropy, min_distinct=min_dist):
                ent = calculate_entropy(chunk)
                q_score = compute_crypto_quality(chunk, sz, 0, 0, i)
                
                tag = "Key" if sz in (32, 24, 16) else ("Nonce/IV" if sz in (12, 16, 8) else "Buffer")
                if sz == 32:
                    tag = "Key-32 (AES-256 / ChaCha20)"
                elif sz == 16:
                    tag = "Key-16 / IV (AES-128)"
                elif sz == 12:
                    tag = "Nonce-12 (ChaCha20 / GCM)"
                elif sz == 8:
                    tag = "Nonce-8 / Key-8 (DES / Seed)"

                candidates.append({
                    "offset": i,
                    "size": sz,
                    "tag": tag,
                    "entropy": round(ent, 3),
                    "distinct": len(set(chunk)),
                    "quality": q_score,
                    "hex": chunk.hex(),
                    "raw": chunk
                })

    if near_offset is not None:
        candidates.sort(key=lambda x: (abs(x["offset"] - near_offset), -x["quality"], -x["entropy"]))
    else:
        candidates.sort(key=lambda x: (-x["quality"], -x["entropy"]))

    return candidates

def harvest_paired_structs(data: bytes, step: int = 16, near_offset: int = None, max_distance: int = 65536) -> List[Dict[str, Any]]:
    pairs = []
    buf_len = len(data)

    start_idx = 0
    end_idx = buf_len - 32
    if near_offset is not None:
        start_idx = max(0, near_offset - max_distance)
        end_idx = min(buf_len - 32, near_offset + max_distance)

    for i in range(start_idx, end_idx, step):
        cand_key = data[i : i + 32]
        if is_noise_or_pointer(cand_key):
            continue
        if not is_candidate_key(cand_key, min_entropy=3.3, min_distinct=8):
            continue

        probe_offsets = [
            (i - 32, 12, "Preceding Nonce (32B alignment / 20B pad)"),
            (i - 16, 12, "Preceding Nonce (16B alignment / 4B pad)"),
            (i - 12, 12, "Contiguous Preceding Nonce (Packed struct)"),
            (i + 32, 12, "Contiguous Following Nonce (Key, Nonce)"),
            (i + 40, 12, "Following Nonce (8B padding)"),
            (i + 48, 12, "Following Nonce (16B padding)"),
            (i - 16, 16, "Preceding 16B IV/Key"),
            (i + 32, 16, "Following 16B IV/Key")
        ]

        for n_off, n_sz, desc in probe_offsets:
            if 0 <= n_off <= buf_len - n_sz:
                cand_nonce = data[n_off : n_off + n_sz]
                if is_noise_or_pointer(cand_nonce):
                    continue
                if is_candidate_key(cand_nonce, min_entropy=2.8, min_distinct=4):
                    k_ent = calculate_entropy(cand_key)
                    n_ent = calculate_entropy(cand_nonce)
                    pairs.append({
                        "key_offset": i,
                        "key_hex": cand_key.hex(),
                        "key_raw": cand_key,
                        "nonce_offset": n_off,
                        "nonce_size": n_sz,
                        "nonce_hex": cand_nonce.hex(),
                        "nonce_raw": cand_nonce,
                        "layout_desc": desc,
                        "distance": abs(i - n_off),
                        "combined_entropy": round((k_ent + n_ent) / 2, 3)
                    })

    if near_offset is not None:
        pairs.sort(key=lambda x: (abs(x["key_offset"] - near_offset), -x["combined_entropy"]))
    else:
        pairs.sort(key=lambda x: -x["combined_entropy"])
    return pairs

def render_hexdump_preview(data: bytes, start_offset: int, length: int = 64, highlight_range: Tuple[int, int] = None) -> Text:
    chunk = data[start_offset : start_offset + length]
    t = Text()
    for row_i in range(0, len(chunk), 16):
        row = chunk[row_i : row_i + 16]
        curr_addr = start_offset + row_i
        t.append(f"0x{curr_addr:08X}  ", style="bold cyan")
        
        for bi, b in enumerate(row):
            byte_addr = curr_addr + bi
            style = "bold yellow"
            if highlight_range and highlight_range[0] <= byte_addr < highlight_range[1]:
                style = "bold white on green"
            elif b == 0:
                style = "dim"
            t.append(f"{b:02X} ", style=style)
        
        if len(row) < 16:
            t.append("   " * (16 - len(row)))
        
        t.append(" |", style="dim")
        for bi, b in enumerate(row):
            byte_addr = curr_addr + bi
            ch = chr(b) if 32 <= b <= 126 else "."
            style = "bold white" if 32 <= b <= 126 else "dim"
            if highlight_range and highlight_range[0] <= byte_addr < highlight_range[1]:
                style = "bold white on green"
            t.append(ch, style=style)
        t.append("|\n", style="dim")
    return t

def main(args=None):
    if args is None:
        args = sys.argv[1:]

    # Pre-process dynamic size flags like --32byte, --40byte, --12byte, --16b, --20bytes
    custom_sizes = []
    clean_args = []
    for a in args:
        m = re.match(r"^--?(\d+)(?:bytes?|b)?$", a, re.IGNORECASE)
        if m:
            custom_sizes.append(int(m.group(1)))
        else:
            clean_args.append(a)

    parser = argparse.ArgumentParser(
        prog="cryptohunt",
        description=" Advanced Cryptographic Key, Nonce, Contiguous Run & Struct Harvester",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands & Dynamic Syntax:
  cryptohunt <file> --32byte                 Cari semua deretan bytes tepat 32-byte (Keys)
  cryptohunt <file> --40byte                 Cari deretan bytes 40-byte (Custom Buffer)
  cryptohunt <file> --12byte --32byte --pair Cari Nonce (12B) & Key (32B) serta pasangan struct-nya
  cryptohunt <file> --near flag.txt          Cari di sekitar keyword atau alamat memori
  cryptohunt <file> --test-decrypt <ct>      Auto-uji dekripsi ChaCha20/AES/RC4 dengan kandidat key

Examples:
  cryptohunt elf_51767488.bin --32byte --pair --test-decrypt "KEVt/ztn..." --prefix "GEMASTIK"
  cryptohunt memory.lime --near 0x0315E8C0 --range 65536 --32byte
  cryptohunt sample.bin --40byte --min-entropy 3.0 --json output.json
        """
    )
    parser.add_argument("target", help="Path to target file (ELF, PE, raw memory dump, firmware, .lime, .bin)")
    parser.add_argument("--size", "-s", default="32,16,12,8", help="Target byte sizes to scan (comma separated, default: 32,16,12,8)")
    parser.add_argument("--step", type=int, default=16, help="Byte step alignment for sliding window (default: 16 bytes)")
    parser.add_argument("--min-entropy", type=float, default=3.0, help="Minimum Shannon entropy score (default: 3.0)")
    parser.add_argument("--near", help="Search near target string, symbol, or hex address (e.g. --near flag.txt or --near 0xc100)")
    parser.add_argument("--range", type=int, default=65536, help="Max search distance in bytes when using --near (default: 64KB)")
    parser.add_argument("--pair", action="store_true", help="Auto-detect and extract paired crypto structs {Nonce, Key}")
    parser.add_argument("--runs", action="store_true", help="Display all contiguous non-zero runs regardless of target size")
    parser.add_argument("--test-decrypt", dest="ciphertext", help="Ciphertext (Base64 or Hex) to auto-test against harvested keys")
    parser.add_argument("--prefix", default="", help="Expected plaintext prefix for validation (e.g. GEMASTIK, flag{, CTF{)")
    parser.add_argument("--json", dest="json_out", help="Export findings to JSON file")
    parser.add_argument("--limit", type=int, default=30, help="Maximum candidate rows to display (default: 30)")

    parsed_args = parser.parse_args(clean_args)

    if custom_sizes:
        parsed_args.size = ",".join(str(s) for s in sorted(list(set(custom_sizes))))

    print_banner(tool_name="CRYPTO & KEY HARVESTER (cryptohunt)", sub_title="Binary & Memory Cryptographic Artifact Engine")

    if not os.path.exists(parsed_args.target):
        console.print(f"[bold red][-] Target file not found: {parsed_args.target}[/bold red]")
        sys.exit(1)

    file_size = os.path.getsize(parsed_args.target)
    console.print(f"[bold cyan] Target File :[/bold cyan] [bold white]{parsed_args.target}[/bold white] ({human_size(file_size)})")

    try:
        target_sizes = [int(s.strip()) for s in parsed_args.size.split(",") if s.strip().isdigit()]
    except Exception:
        target_sizes = [32, 16, 12, 8]

    console.print(f"[bold cyan] Target Byte Sizes :[/bold cyan] [bold yellow]{', '.join(f'{s}B' for s in target_sizes)}[/bold yellow] (Alignment Step: {parsed_args.step}B)")

    near_offset = None
    if parsed_args.near:
        if parsed_args.near.startswith("0x") or parsed_args.near.startswith("0X"):
            near_offset = int(parsed_args.near, 16)
            console.print(f"[bold magenta] Near Proximity Target Address :[/bold magenta] 0x{near_offset:X}")
        else:
            near_kw = parsed_args.near.encode("utf-8")
            # Search keyword using streaming if file is large
            if file_size > 30 * 1024 * 1024:
                with open(parsed_args.target, "rb") as f:
                    curr = 0
                    while curr < file_size:
                        f.seek(curr)
                        chk = f.read(32 * 1024 * 1024)
                        pos = chk.find(near_kw)
                        if pos != -1:
                            near_offset = curr + pos
                            console.print(f"[bold magenta] Found Keyword '{parsed_args.near}' @ Offset :[/bold magenta] 0x{near_offset:X} ({near_offset})")
                            break
                        curr += 32 * 1024 * 1024 - 1024
            else:
                with open(parsed_args.target, "rb") as f:
                    data_full = f.read()
                pos = data_full.find(near_kw)
                if pos != -1:
                    near_offset = pos
                    console.print(f"[bold magenta] Found Keyword '{parsed_args.near}' @ Offset :[/bold magenta] 0x{near_offset:X} ({near_offset})")

    # If file is large (> 30MB) and no explicit near offset, auto-discover crypto anchors
    constants = []
    base_file_offset = 0
    if file_size > 30 * 1024 * 1024:
        console.print("[bold yellow] Large File / Memory Dump Detected (>30MB). Activating Fast Streaming Anchor Discovery...[/bold yellow]")
        constants = scan_file_crypto_anchors_streaming(parsed_args.target)
    else:
        with open(parsed_args.target, "rb") as f:
            raw_data_head = f.read()
        constants = scan_crypto_constants(raw_data_head)

    scan_windows = []
    if near_offset is not None:
        scan_windows.append((near_offset, f"Specified Near Target (0x{near_offset:X})"))
    elif constants:
        for c in constants:
            scan_windows.append((c["offset"], f"Anchor '{c['name']}' (0x{c['offset']:X})"))
    else:
        scan_windows.append((0, "File Head (0x0)"))

    elf_secs = []
    pe_secs = []

    # 1. SCAN CRYPTOGRAPHIC CONSTANTS
    console.print("\n[bold cyan]=== 1. KNOWN CRYPTOGRAPHIC CONSTANTS & ALGORITHMS ===[/bold cyan]")
    if constants:
        t_const = Table(show_header=True, header_style="bold magenta", expand=True)
        t_const.add_column("Algorithm", style="bold green", width=16)
        t_const.add_column("Offset", style="bold cyan", width=14)
        t_const.add_column("Signature Name", style="bold white", width=32)
        t_const.add_column("Description / Purpose", style="white")

        for c in constants:
            t_const.add_row(c["algo"], f"0x{c['offset']:08X}", c["name"], c["desc"])
        console.print(t_const)
    else:
        console.print("[dim]No hardcoded standard S-Box or sigma constants found in target.[/dim]")

    # 2. AGGREGATE RUNS, PAIRS & CANDIDATES ACROSS ALL SCAN WINDOWS
    all_runs = []
    all_pairs = []
    all_candidates = []
    all_harvested_keys = []

    for win_center, win_label in scan_windows:
        win_size = max(parsed_args.range * 2, 256 * 1024)
        base_file_offset = max(0, win_center - parsed_args.range)
        with open(parsed_args.target, "rb") as f:
            f.seek(base_file_offset)
            raw_data = f.read(win_size)

        if not elf_secs and not pe_secs:
            elf_secs = parse_elf_sections(raw_data)
            pe_secs = parse_pe_sections(raw_data)

        local_near = win_center - base_file_offset

        # Runs
        w_runs = harvest_contiguous_runs(
            raw_data,
            min_run_len=4,
            max_run_len=512,
            near_offset=local_near,
            max_distance=parsed_args.range,
            filter_pointers=True
        )
        for r in w_runs:
            r["start"] += base_file_offset
            r["end"] += base_file_offset
            all_runs.append(r)

        # Pairs
        w_pairs = harvest_paired_structs(raw_data, step=parsed_args.step, near_offset=local_near, max_distance=parsed_args.range)
        for p in w_pairs:
            p["key_offset"] += base_file_offset
            p["nonce_offset"] += base_file_offset
            all_pairs.append(p)

        # Candidates
        w_cands = harvest_key_candidates(
            raw_data,
            target_sizes=target_sizes,
            step=parsed_args.step,
            min_entropy=parsed_args.min_entropy,
            near_offset=local_near,
            max_distance=parsed_args.range
        )
        for c in w_cands:
            c["offset"] += base_file_offset
            all_candidates.append(c)

    # Deduplicate runs by (start, end)
    seen_runs = set()
    runs = []
    for r in all_runs:
        if (r["start"], r["end"]) not in seen_runs:
            seen_runs.add((r["start"], r["end"]))
            runs.append(r)
    runs.sort(key=lambda x: (-x["quality"], -x["entropy"]))

    # Deduplicate pairs by (key_offset, nonce_offset)
    seen_pairs = set()
    pairs = []
    for p in all_pairs:
        if (p["key_offset"], p["nonce_offset"]) not in seen_pairs:
            seen_pairs.add((p["key_offset"], p["nonce_offset"]))
            pairs.append(p)
    pairs.sort(key=lambda x: -x["combined_entropy"])

    # Deduplicate candidates by (offset, size)
    seen_cands = set()
    candidates = []
    for c in all_candidates:
        if (c["offset"], c["size"]) not in seen_cands:
            seen_cands.add((c["offset"], c["size"]))
            candidates.append(c)
    candidates.sort(key=lambda x: (-x["quality"], -x["entropy"]))

    # 2. CONTIGUOUS NON-ZERO RUNS (ISLANDS)
    console.print("\n[bold cyan]=== 2. CONTIGUOUS NON-ZERO BYTE RUNS (GHIDRA-STYLE ISLANDS) ===[/bold cyan]")
    for sz in target_sizes:
        exact_runs = [r for r in runs if r["length"] == sz]
        sub_runs = [r for r in runs if r["length"] > sz and r["entropy"] >= parsed_args.min_entropy]
        closest_runs = [r for r in runs if r["length"] != sz and abs(r["length"] - sz) <= 16 and not r["is_ascii"]]

        console.print(f"\n[bold yellow]─── Target Run Size: {sz} Bytes ───[/bold yellow]")

        if exact_runs:
            t_exact = Table(title=f" Exact Contiguous Runs ({sz} Bytes)", show_header=True, header_style="bold green", expand=True)
            t_exact.add_column("Offset Range", style="bold cyan", width=25)
            t_exact.add_column("Length", style="bold white", width=8, justify="right")
            t_exact.add_column("Entropy", style="bold yellow", width=9, justify="right")
            t_exact.add_column("Surrounding Null Pad", style="bold magenta", width=22)
            t_exact.add_column("Tag / Type", style="bold green", width=28)
            t_exact.add_column("Hex Content", style="white")

            for r in exact_runs[:parsed_args.limit]:
                pad_info = f"{r['lead_nulls']}B [dim]00[/dim] | {r['trail_nulls']}B [dim]00[/dim]"
                hex_disp = r["hex"]
                if len(hex_disp) > 40:
                    hex_disp = hex_disp[:40] + "..."
                t_exact.add_row(
                    f"0x{r['start']:08X} - 0x{r['end']:08X}",
                    f"{r['length']} B",
                    f"{r['entropy']:.2f}",
                    pad_info,
                    r["tag"],
                    hex_disp
                )
                all_harvested_keys.append({
                    "offset": r["start"],
                    "size": r["length"],
                    "entropy": r["entropy"],
                    "hex": r["hex"],
                    "raw": r["raw"]
                })
            console.print(t_exact)
        else:
            console.print(f"[bold yellow] Tidak ditemukan Exact {sz}-Byte Contiguous Run pada pencarian ini.[/bold yellow]")
            
            if closest_runs:
                closest_runs.sort(key=lambda x: (abs(x["length"] - sz), -x["entropy"]))
                t_close = Table(title=f" Kandidat Terdekat ke {sz} Bytes (Closest Length Fallback)", show_header=True, header_style="bold yellow", expand=True)
                t_close.add_column("Offset Range", style="bold cyan", width=25)
                t_close.add_column("Length", style="bold yellow", width=10, justify="right")
                t_close.add_column("Delta", style="bold red", width=8, justify="right")
                t_close.add_column("Entropy", style="bold yellow", width=9, justify="right")
                t_close.add_column("Null Padding", style="bold magenta", width=20)
                t_close.add_column("Hex Preview", style="white")

                for r in closest_runs[:10]:
                    delta = r["length"] - sz
                    delta_str = f"+{delta}B" if delta > 0 else f"{delta}B"
                    pad_info = f"{r['lead_nulls']}B / {r['trail_nulls']}B"
                    hex_disp = r["hex"]
                    if len(hex_disp) > 36:
                        hex_disp = hex_disp[:36] + "..."
                    t_close.add_row(
                        f"0x{r['start']:08X} - 0x{r['end']:08X}",
                        f"{r['length']} B",
                        delta_str,
                        f"{r['entropy']:.2f}",
                        pad_info,
                        hex_disp
                    )
                console.print(t_close)
                console.print(
                    "[dim][i] Catatan Forensik: Jika key sesungguhnya mengandung byte 0x00 di tengahnya atau compiler alignment berbeda, "
                    "silakan periksa kandidat terdekat di atas atau gunakan mode sliding-window (--step 16 / --step 1).[/dim]"
                )

        if sub_runs and len(exact_runs) < 5:
            t_sub = Table(title=f" Sub-Slices dari Buffer Lebih Besar (> {sz} Bytes)", show_header=True, header_style="bold blue", expand=True)
            t_sub.add_column("Buffer Range", style="bold cyan", width=25)
            t_sub.add_column("Total Len", style="bold white", width=10, justify="right")
            t_sub.add_column("Extracted Slice (Hex)", style="white")
            t_sub.add_column("Entropy", style="bold yellow", width=9, justify="right")

            for r in sub_runs[:5]:
                slice_head = r["raw"][:sz]
                t_sub.add_row(
                    f"0x{r['start']:08X} - 0x{r['end']:08X}",
                    f"{r['length']} B",
                    slice_head.hex()[:40] + "...",
                    f"{calculate_entropy(slice_head):.2f}"
                )
                all_harvested_keys.append({
                    "offset": r["start"],
                    "size": sz,
                    "entropy": calculate_entropy(slice_head),
                    "hex": slice_head.hex(),
                    "raw": slice_head
                })
            console.print(t_sub)

    # 3. SCAN PAIRED CRYPTO STRUCTS
    if pairs:
        console.print("\n[bold cyan]=== 3. DETECTED PAIRED STRUCTS { Nonce / IV, Key } ===[/bold cyan]")
        t_pairs = Table(show_header=True, header_style="bold yellow", expand=True)
        t_pairs.add_column("Key Offset", style="bold cyan", width=14)
        t_pairs.add_column("Key Hex (32 Bytes)", style="bold green", width=36)
        t_pairs.add_column("Nonce Offset", style="bold cyan", width=14)
        t_pairs.add_column("Nonce Hex", style="bold magenta", width=28)
        t_pairs.add_column("Entropy", style="bold yellow", width=10, justify="right")
        t_pairs.add_column("Memory Layout & Padding", style="white")

        for p in pairs[:parsed_args.limit]:
            t_pairs.add_row(
                f"0x{p['key_offset']:08X}",
                p["key_hex"][:32] + "...",
                f"0x{p['nonce_offset']:08X}",
                p["nonce_hex"],
                f"{p['combined_entropy']:.2f}",
                p["layout_desc"]
            )
        console.print(t_pairs)

    # 4. SLIDING WINDOW FIXED-SIZE CANDIDATES
    console.print("\n[bold cyan]=== 4. SLIDING-WINDOW ALIGNED CANDIDATE BUFFERS ===[/bold cyan]")
    if candidates:
        t_cand = Table(show_header=True, header_style="bold cyan", expand=True)
        t_cand.add_column("Offset", style="bold magenta", width=14)
        t_cand.add_column("Size", style="bold white", width=8, justify="right")
        t_cand.add_column("Entropy", style="bold yellow", width=10, justify="right")
        t_cand.add_column("Type / Tag", style="bold green", width=28)
        t_cand.add_column("Hex Preview", style="white")

        for row in candidates[:parsed_args.limit]:
            hex_disp = row["hex"]
            if len(hex_disp) > 48:
                hex_disp = hex_disp[:48] + "..."
            t_cand.add_row(
                f"0x{row['offset']:08X}",
                f"{row['size']} B",
                f"{row['entropy']:.2f}",
                row["tag"],
                hex_disp
            )
        console.print(t_cand)
        if len(candidates) > parsed_args.limit:
            console.print(f"[dim]... and {len(candidates) - parsed_args.limit} more candidate buffers. Use --limit to view all.[/dim]")
    else:
        console.print("[dim]No high-entropy candidates matching criteria found.[/dim]")

    # 5. AUTO-DECRYPTION TESTING
    winning_pair = None
    if parsed_args.ciphertext:
        console.print("\n[bold cyan]=== 5. AUTO-DECRYPTOR & CIPHER VERIFICATION PIPELINE ===[/bold cyan]")
        ct_raw = None
        try:
            ct_raw = base64.b64decode(parsed_args.ciphertext)
        except Exception:
            pass
        if not ct_raw:
            try:
                ct_raw = bytes.fromhex(parsed_args.ciphertext)
            except Exception:
                pass

        if not ct_raw:
            console.print("[bold red][-] Failed to parse ciphertext as Base64 or Hex.[/bold red]")
        else:
            console.print(f"[bold white]Target Ciphertext Length :[/bold white] {len(ct_raw)} bytes")
            prefix_bytes = parsed_args.prefix.encode("utf-8") if parsed_args.prefix else None
            decrypted_found = False

            for p in pairs:
                res = test_decryption_candidate(p["key_raw"], p["nonce_raw"], ct_raw, prefix_bytes)
                if res:
                    pt = res["plaintext"]
                    console.print(Panel(
                        f"[bold green] SUCCESSFUL DECRYPTION MATCH FOUND![/bold green]\n\n"
                        f"[bold cyan]Algorithm      :[/bold cyan] {res['algo']}\n"
                        f"[bold cyan]Key Offset     :[/bold cyan] 0x{p['key_offset']:08X}\n"
                        f"[bold cyan]Key (Hex)      :[/bold cyan] {p['key_hex']}\n"
                        f"[bold cyan]Nonce Offset   :[/bold cyan] 0x{p['nonce_offset']:08X}\n"
                        f"[bold cyan]Nonce (Hex)    :[/bold cyan] {p['nonce_hex']}\n"
                        f"[bold cyan]Decrypted Text :[/bold cyan] [bold white on blue]{pt.decode('utf-8', errors='replace')}[/bold white on blue]",
                        title=" MATCH CONFIRMED",
                        border_style="bold green"
                    ))
                    decrypted_found = True
                    winning_pair = p
                    break

            if not decrypted_found:
                keys32 = [r for r in runs if r["length"] == 32] + [c for c in candidates if c["size"] == 32]
                nonces12 = [r for r in runs if r["length"] in (12, 16, 8)] + [c for c in candidates if c["size"] in (12, 16, 8)]
                
                for k in keys32:
                    k_raw = k["raw"]
                    k_off = k["start"] if "start" in k else k["offset"]
                    k_hex = k["hex"]
                    for n in nonces12:
                        n_raw = n["raw"]
                        n_off = n["start"] if "start" in n else n["offset"]
                        n_hex = n["hex"]
                        res = test_decryption_candidate(k_raw, n_raw, ct_raw, prefix_bytes)
                        if res:
                            pt = res["plaintext"]
                            console.print(Panel(
                                f"[bold green] SUCCESSFUL DECRYPTION MATCH FOUND![/bold green]\n\n"
                                f"[bold cyan]Algorithm      :[/bold cyan] {res['algo']}\n"
                                f"[bold cyan]Key Offset     :[/bold cyan] 0x{k_off:08X}\n"
                                f"[bold cyan]Key (Hex)      :[/bold cyan] {k_hex}\n"
                                f"[bold cyan]Nonce Offset   :[/bold cyan] 0x{n_off:08X}\n"
                                f"[bold cyan]Nonce (Hex)    :[/bold cyan] {n_hex}\n"
                                f"[bold cyan]Decrypted Text :[/bold cyan] [bold white on blue]{pt.decode('utf-8', errors='replace')}[/bold white on blue]",
                                title=" MATCH CONFIRMED",
                                border_style="bold green"
                            ))
                            decrypted_found = True
                            winning_pair = {
                                "key_offset": k_off,
                                "nonce_offset": n_off,
                                "key_raw": k_raw,
                                "nonce_raw": n_raw
                            }
                            break
                    if decrypted_found:
                        break

            if not decrypted_found:
                console.print("[bold yellow][!] No harvested Key/Nonce pair decrypted the ciphertext successfully.[/bold yellow]")

    # 6. HEXDUMP PREVIEW
    target_pair = winning_pair if winning_pair else (pairs[0] if pairs else None)
    if target_pair:
        k_off = target_pair["key_offset"]
        n_off = target_pair["nonce_offset"]
        start_dump = max(0, min(n_off, k_off) - 16)
        console.print(f"\n[bold cyan]=== 6. HEXDUMP PREVIEW AROUND STRUCT (0x{start_dump:08X}) ===[/bold cyan]")
        with open(parsed_args.target, "rb") as f:
            f.seek(start_dump)
            dump_bytes = f.read(96)
        dump_text = render_hexdump_preview(
            dump_bytes,
            start_dump,
            length=96,
            highlight_range=(k_off, k_off + 32)
        )
        console.print(dump_text)
    elif runs:
        top_run = runs[0]
        start_dump = max(0, top_run["start"] - 16)
        console.print(f"\n[bold cyan]=== 6. HEXDUMP PREVIEW AROUND TOP CONTIGUOUS RUN (0x{start_dump:08X}) ===[/bold cyan]")
        with open(parsed_args.target, "rb") as f:
            f.seek(start_dump)
            dump_bytes = f.read(96)
        dump_text = render_hexdump_preview(
            dump_bytes,
            start_dump,
            length=96,
            highlight_range=(top_run["start"], top_run["end"])
        )
        console.print(dump_text)

    # 7. JSON EXPORT
    if parsed_args.json_out:
        out_dict = {
            "file": parsed_args.target,
            "size": file_size,
            "constants": constants,
            "contiguous_runs": [{k: v for k, v in r.items() if not k.endswith("_raw")} for r in runs[:100]],
            "pairs": [{k: v for k, v in p.items() if not k.endswith("_raw")} for p in pairs],
            "candidates": [{k: v for k, v in c.items() if not k.endswith("_raw")} for c in candidates]
        }
        with open(parsed_args.json_out, "w") as jf:
            json.dump(out_dict, jf, indent=2)
        console.print(f"\n[bold green] Findings exported to JSON:[/bold green] {parsed_args.json_out}")

if __name__ == "__main__":
    main()
