"""
Pure Python LevelDB & SSTable (.ldb / .log) Forensic Parser
Engineered specifically for Digital Forensics & Incident Response (DFIR).

Features:
- Parses LevelDB WAL (.log) chunks: Full, First, Middle, Last record frames & WriteBatches.
- Parses LevelDB SSTable (.ldb / .sst) block structures, footers, index handles, and restart arrays.
- Handles uncompacted, compacted, and corrupted records without crashing.
- Custom pure-Python byte-level stream carver for strings, JSON payloads, tokens, and cookies.
- Zero C++ / plyvel dependencies. Works natively across Linux/WSL and Windows.
"""
import struct
import io
import re
import json
from typing import List, Dict, Tuple, Any, Optional


def read_varint(stream_or_bytes, offset: int = 0) -> Tuple[int, int]:
    """
    Decodes a standard LevelDB unsigned varint.
    Returns: (value, bytes_consumed)
    """
    if isinstance(stream_or_bytes, (bytes, bytearray)):
        data = stream_or_bytes
        pos = offset
        res = 0
        shift = 0
        while pos < len(data):
            byte = data[pos]
            pos += 1
            res |= (byte & 0x7F) << shift
            if not (byte & 0x80):
                return res, pos - offset
            shift += 7
            if shift >= 64:
                break
        return 0, 0
    else:
        res = 0
        shift = 0
        consumed = 0
        while True:
            b = stream_or_bytes.read(1)
            if not b:
                return res, consumed
            consumed += 1
            byte = b[0]
            res |= (byte & 0x7F) << shift
            if not (byte & 0x80):
                return res, consumed
            shift += 7
            if shift >= 64:
                break
        return 0, consumed


class LevelDBLogParser:
    """
    Parses LevelDB Write-Ahead Log (.log) files.
    Format:
    Record: CRC32 (4 bytes), Length (2 bytes, little endian), RecordType (1 byte), Payload (Length bytes)
    Types: 1 = FULL, 2 = FIRST, 3 = MIDDLE, 4 = LAST
    """
    RECORD_FULL = 1
    RECORD_FIRST = 2
    RECORD_MIDDLE = 3
    RECORD_LAST = 4

    @staticmethod
    def parse_log(data: bytes) -> List[Tuple[bytes, bytes]]:
        """
        Parses WAL log and extracts (key, value) tuples from WriteBatches.
        """
        entries = []
        pos = 0
        current_payload = bytearray()

        while pos + 7 <= len(data):
            # Check 32KB block boundary
            block_offset = pos % 32768
            if block_offset > 32768 - 7:
                # Pad bytes at the end of 32KB block
                pos += (32768 - block_offset)
                continue

            crc, length, r_type = struct.unpack("<IHB", data[pos:pos + 7])
            pos += 7

            if pos + length > len(data):
                # Truncated record
                break

            payload = data[pos:pos + length]
            pos += length

            if r_type == LevelDBLogParser.RECORD_FULL:
                LevelDBLogParser._parse_write_batch(payload, entries)
            elif r_type == LevelDBLogParser.RECORD_FIRST:
                current_payload = bytearray(payload)
            elif r_type == LevelDBLogParser.RECORD_MIDDLE:
                current_payload.extend(payload)
            elif r_type == LevelDBLogParser.RECORD_LAST:
                current_payload.extend(payload)
                LevelDBLogParser._parse_write_batch(bytes(current_payload), entries)
                current_payload = bytearray()

        return entries

    @staticmethod
    def _parse_write_batch(batch_data: bytes, entries: list):
        if len(batch_data) < 12:
            return

        seq_number, count = struct.unpack("<QI", batch_data[:12])
        offset = 12

        for _ in range(count):
            if offset >= len(batch_data):
                break

            val_type = batch_data[offset]
            offset += 1

            if val_type == 1:  # Value (kTypeValue)
                k_len, v_bytes = read_varint(batch_data, offset)
                offset += v_bytes
                if offset + k_len > len(batch_data):
                    break
                key = batch_data[offset:offset + k_len]
                offset += k_len

                v_len, v_bytes = read_varint(batch_data, offset)
                offset += v_bytes
                if offset + v_len > len(batch_data):
                    break
                val = batch_data[offset:offset + v_len]
                offset += v_len

                entries.append((key, val))

            elif val_type == 0:  # Deletion (kTypeDeletion)
                k_len, v_bytes = read_varint(batch_data, offset)
                offset += v_bytes
                if offset + k_len > len(batch_data):
                    break
                key = batch_data[offset:offset + k_len]
                offset += k_len
                # Record deletion key with empty value
                entries.append((key, b""))
            else:
                break


class LevelDBTableParser:
    """
    Parses LevelDB SSTable (.ldb / .sst) files.
    Footer is 48 bytes at the end of the file.
    Magic number: 0xdb4775248b80fb57 (\x57\xfb\x80\x8b\x24\x75\x47\xdb)
    """
    SST_MAGIC = 0xdb4775248b80fb57
    SST_MAGIC_BYTES = b"\x57\xfb\x80\x8b\x24\x75\x47\xdb"

    @staticmethod
    def parse_ldb(data: bytes) -> List[Tuple[bytes, bytes]]:
        entries = []
        if len(data) < 48:
            return entries

        # Check footer magic
        magic = struct.unpack("<Q", data[-8:])[0]
        if magic != LevelDBTableParser.SST_MAGIC and LevelDBTableParser.SST_MAGIC_BYTES not in data[-16:]:
            # Not standard SSTable footer, fallback to block scanning
            return LevelDBTableParser._scan_blocks_heuristic(data)

        # Parse Footer: metaindex_handle (varint offset & size), index_handle (varint offset & size)
        footer = data[-48:]
        off = 0
        meta_off, n1 = read_varint(footer, off); off += n1
        meta_sz, n2 = read_varint(footer, off); off += n2
        idx_off, n3 = read_varint(footer, off); off += n3
        idx_sz, n4 = read_varint(footer, off); off += n4

        # Read index block to find data block handles
        data_block_handles = []
        if idx_off > 0 and idx_off + idx_sz <= len(data):
            idx_block_data = data[idx_off:idx_off + idx_sz]
            idx_entries = LevelDBTableParser._parse_block(idx_block_data)
            for _, val_handle in idx_entries:
                b_off, n_a = read_varint(val_handle, 0)
                b_sz, n_b = read_varint(val_handle, n_a)
                if b_off + b_sz <= len(data):
                    data_block_handles.append((b_off, b_sz))

        # Parse each data block
        if data_block_handles:
            for b_off, b_sz in data_block_handles:
                # 1 byte compression type + 4 bytes CRC follows block
                block_data = data[b_off:b_off + b_sz]
                comp_type = data[b_off + b_sz] if b_off + b_sz < len(data) else 0

                decompressed = LevelDBTableParser._decompress_block(block_data, comp_type)
                if decompressed:
                    b_entries = LevelDBTableParser._parse_block(decompressed)
                    entries.extend(b_entries)
        else:
            entries = LevelDBTableParser._scan_blocks_heuristic(data)

        return entries

    @staticmethod
    def _decompress_block(block_bytes: bytes, comp_type: int) -> bytes:
        if comp_type == 0:  # No compression
            return block_bytes
        elif comp_type == 1:  # Snappy compression
            try:
                import snappy
                return snappy.uncompress(block_bytes)
            except Exception:
                try:
                    import cramjam
                    return cramjam.snappy.decompress(block_bytes)
                except Exception:
                    # Decompressor not installed, return raw for string carving
                    return block_bytes
        return block_bytes

    @staticmethod
    def _parse_block(block: bytes) -> List[Tuple[bytes, bytes]]:
        """
        Parses a single uncompressed LevelDB block with restart array.
        """
        entries = []
        if len(block) < 4:
            return entries

        num_restarts = struct.unpack("<I", block[-4:])[0]
        restarts_offset = len(block) - (4 + num_restarts * 4)
        if restarts_offset < 0 or restarts_offset > len(block):
            restarts_offset = len(block) - 4

        pos = 0
        last_key = bytearray()

        while pos < restarts_offset:
            shared, n1 = read_varint(block, pos); pos += n1
            unshared, n2 = read_varint(block, pos); pos += n2
            val_len, n3 = read_varint(block, pos); pos += n3

            if n1 == 0 or n2 == 0 or n3 == 0:
                break

            if pos + unshared > restarts_offset:
                break
            key_delta = block[pos:pos + unshared]
            pos += unshared

            key = bytes(last_key[:shared] + key_delta)
            last_key = bytearray(key)

            if pos + val_len > restarts_offset:
                val = block[pos:restarts_offset]
                entries.append((key, val))
                break

            val = block[pos:pos + val_len]
            pos += val_len

            entries.append((key, val))

        return entries

    @staticmethod
    def _scan_blocks_heuristic(data: bytes) -> List[Tuple[bytes, bytes]]:
        """
        Heuristic stream scanner when index block is missing or damaged.
        """
        entries = []
        # Look for typical LevelDB key/value sequences
        pos = 0
        while pos < len(data) - 10:
            shared, n1 = read_varint(data, pos)
            if shared == 0 and 0 < n1 <= 2:
                unshared, n2 = read_varint(data, pos + n1)
                val_len, n3 = read_varint(data, pos + n1 + n2)
                
                # Check realistic key and value lengths
                if 1 <= unshared <= 256 and 0 <= val_len <= 65536:
                    k_start = pos + n1 + n2 + n3
                    k_end = k_start + unshared
                    v_end = k_end + val_len

                    if v_end <= len(data):
                        key = data[k_start:k_end]
                        # Verify key is mostly printable or valid ASCII/utf-8
                        if any(c in key for c in [b"_", b":", b"-", b".", b"/"]) or key.isalnum():
                            val = data[k_end:v_end]
                            entries.append((key, val))
                            pos = v_end
                            continue
            pos += 1
        return entries


class LevelDBForensicCarver:
    """
    Deep forensic carver for strings, JSON objects, Discord webhooks, Telegram tokens,
    and session cookies from raw LevelDB streams.
    """
    # High-signal IoC Regex Patterns
    RE_DISCORD_WEBHOOK = re.compile(r"https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/(\d+)/([\w-]+)", re.IGNORECASE)
    RE_TELEGRAM_BOT = re.compile(r"(?:api\.telegram\.org/bot|telegram\.me/|t\.me/)([0-9]{8,10}:[a-zA-Z0-9_-]{35})", re.IGNORECASE)
    RE_GENERIC_URL = re.compile(r"https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{8,200}")
    RE_IP_PORT = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{2,5}\b")
    
    # High-Value Cookie / Token Keys
    COOKIE_PATTERNS = [
        "c_user", "xs", "datr", "sb", "sessionid", "ds_user_id", "auth_token", "twid",
        "li_at", "connect.sid", "PHPSESSID", "JSESSIONID", "__Secure-3PSID", "bearer", "token", "jwt"
    ]

    @classmethod
    def scan_for_iocs(cls, raw_data: bytes) -> Dict[str, List[str]]:
        """
        Scans binary bytes for high-signal forensic IoCs.
        """
        text = raw_data.decode("latin-1", errors="replace")
        iocs = {
            "discord_webhooks": [],
            "telegram_bots": [],
            "suspicious_urls": [],
            "ip_endpoints": [],
            "cookie_keys": [],
            "extracted_json": []
        }

        # 1. Discord Webhooks
        for m in cls.RE_DISCORD_WEBHOOK.finditer(text):
            full_url = m.group(0)
            if full_url not in iocs["discord_webhooks"]:
                iocs["discord_webhooks"].append(full_url)

        # 2. Telegram Bot API
        for m in cls.RE_TELEGRAM_BOT.finditer(text):
            tok = m.group(0)
            if tok not in iocs["telegram_bots"]:
                iocs["telegram_bots"].append(tok)

        # 3. IP Endpoints
        for m in cls.RE_IP_PORT.finditer(text):
            ip = m.group(0)
            if not ip.startswith("127.0.0.1") and not ip.startswith("0.0.0.0"):
                if ip not in iocs["ip_endpoints"]:
                    iocs["ip_endpoints"].append(ip)

        # 4. URLs (Excluding standard Google/Chromium telemetry)
        for m in cls.RE_GENERIC_URL.finditer(text):
            url = m.group(0)
            u_low = url.lower()
            if not any(b in u_low for b in [
                "google.com", "gstatic.com", "googleapis.com", "chromium.org",
                "schema.org", "w3.org", "mozilla.org", "microsoft.com", "github.com"
            ]):
                if url not in iocs["suspicious_urls"] and len(url) < 150:
                    iocs["suspicious_urls"].append(url)

        # 5. Cookie Keys
        text_lower = text.lower()
        for k in cls.COOKIE_PATTERNS:
            if f'"{k}"' in text_lower or f"'{k}'" in text_lower or f"{k}=" in text_lower:
                if k not in iocs["cookie_keys"]:
                    iocs["cookie_keys"].append(k)

        # 6. JSON Carving
        for m in re.finditer(r"\{[\s\S]{10,2000}?\}", text):
            candidate = m.group(0)
            try:
                parsed = json.loads(candidate)
                if isinstance(parsed, dict) and len(parsed) >= 2:
                    # Check if contains interesting keys
                    keys = [str(k).lower() for k in parsed.keys()]
                    if any(interesting in keys for interesting in ["cookie", "token", "session", "url", "user", "pass", "key", "auth"]):
                        iocs["extracted_json"].append(candidate)
            except Exception:
                pass

        return iocs


def parse_extension_leveldb_files(files_dict: Dict[str, bytes]) -> Tuple[List[Dict[str, Any]], Dict[str, List[str]]]:
    """
    Parses all .ldb and .log files for an extension directory and correlates
    key-values and carved IoCs.
    """
    all_kvs = []
    combined_raw = bytearray()

    for file_name, file_bytes in files_dict.items():
        combined_raw.extend(file_bytes)
        name_low = file_name.lower()

        if name_low.endswith(".log"):
            entries = LevelDBLogParser.parse_log(file_bytes)
            for k, v in entries:
                k_str = k.decode("latin-1", errors="replace")
                v_str = v.decode("latin-1", errors="replace")
                all_kvs.append({"key": k_str, "value": v_str, "source_file": file_name})

        elif name_low.endswith(".ldb") or name_low.endswith(".sst"):
            entries = LevelDBTableParser.parse_ldb(file_bytes)
            for k, v in entries:
                k_str = k.decode("latin-1", errors="replace")
                v_str = v.decode("latin-1", errors="replace")
                all_kvs.append({"key": k_str, "value": v_str, "source_file": file_name})

    # Deep carve IoCs
    iocs = LevelDBForensicCarver.scan_for_iocs(bytes(combined_raw))

    return all_kvs, iocs
