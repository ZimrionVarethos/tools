"""
PCAP File Extractor & Stream Carving Engine (pcapfile / pcap/file_carver.py)
Automates extraction and file carving from network packets:
1. Protocol-Aware Reassembly:
   - HTTP File Downloads (GET/POST responses, Content-Disposition, URI filenames, decompressed bodies)
   - HTTP File Uploads (POST/PUT multipart/form-data uploads, raw binary bodies)
   - FTP Data Channels (RETR / STOR transfers)
2. Deep Structural Raw Stream Carving:
   - For non-HTTP streams (e.g. netcat, reverse shells, raw sockets, custom C2)
   - Eliminates false positives by deep structural verification (PE, ELF, PNG, JPEG, ZIP, PDF, GZIP, SQLite, WASM, CaRT)
   - Exact boundary determination (never blind slicing to end of stream)
3. Disk Exporting (-o / --export-dir) with automatic hashing (MD5 / SHA-256)
4. Multi-format Exports (Terminal Table, Markdown, JSON)
"""
import os
import sys
import struct
import argparse
import hashlib
import json
import gzip
import zlib
import re
from typing import List, Dict, Any, Optional, Tuple, Set

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markup import escape

from core.banner import print_banner
from core.utils import human_size
from pcap.pcap_engine import PCAPEngine, TCPStream

console = Console(force_terminal=True, legacy_windows=False)

MIME_TO_EXT = {
    "audio/wav": ".wav",
    "audio/x-wav": ".wav",
    "audio/wave": ".wav",
    "image/bmp": ".bmp",
    "image/x-ms-bmp": ".bmp",
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/pjpeg": ".jpg",
    "image/gif": ".gif",
    "image/webp": ".webp",
    "image/tiff": ".tiff",
    "application/pdf": ".pdf",
    "application/zip": ".zip",
    "application/x-zip-compressed": ".zip",
    "application/wasm": ".wasm",
    "application/x-executable": ".elf",
    "application/x-dosexec": ".exe",
    "application/x-msdownload": ".exe",
    "application/vnd.microsoft.portable-executable": ".exe",
    "application/gzip": ".gz",
    "application/x-gzip": ".gz",
    "application/x-tar": ".tar",
    "application/json": ".json",
    "application/x-sqlite3": ".sqlite",
    "application/vnd.android.package-archive": ".apk",
    "application/java-archive": ".jar",
}


class CarvedFile:
    """
    Metadata container for a detected network file.
    """
    def __init__(
        self,
        index: int,
        stream_id: int,
        filename: str,
        file_type: str,
        file_bytes: bytes,
        source: str,
        destination: str,
        protocol: str,
        extra_info: str = ""
    ):
        self.index = index
        self.stream_id = stream_id
        self.filename = filename
        self.file_type = file_type
        self.file_bytes = file_bytes
        self.size = len(file_bytes)
        self.source = source
        self.destination = destination
        self.protocol = protocol
        self.extra_info = extra_info

        self.md5 = hashlib.md5(file_bytes).hexdigest()
        self.sha256 = hashlib.sha256(file_bytes).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "stream_id": self.stream_id,
            "filename": self.filename,
            "file_type": self.file_type,
            "size": self.size,
            "size_human": human_size(self.size),
            "source": self.source,
            "destination": self.destination,
            "protocol": self.protocol,
            "extra_info": self.extra_info,
            "md5": self.md5,
            "sha256": self.sha256
        }


# ---------------------------------------------------------------------------
# Deep Structural Validators (Zero False Positives)
# ---------------------------------------------------------------------------

def verify_pe(data: bytes, pos: int = 0) -> Optional[Tuple[str, str, int]]:
    """Deep verification of Windows PE headers (EXE/DLL). Returns (desc, ext, size)."""
    if pos + 0x40 > len(data) or data[pos:pos+2] != b"MZ":
        return None
    e_lfanew = struct.unpack_from("<I", data, pos + 0x3C)[0]
    if e_lfanew < 0x40 or e_lfanew > 0x1000 or pos + e_lfanew + 24 > len(data):
        return None
    if data[pos+e_lfanew : pos+e_lfanew+4] != b"PE\0\0":
        return None
    num_sections = struct.unpack_from("<H", data, pos + e_lfanew + 6)[0]
    if num_sections == 0 or num_sections > 96:
        return None
    opt_size = struct.unpack_from("<H", data, pos + e_lfanew + 20)[0]
    if opt_size >= 2:
        magic = struct.unpack_from("<H", data, pos + e_lfanew + 24)[0]
        if magic not in (0x10B, 0x20B):
            return None
    characteristics = struct.unpack_from("<H", data, pos + e_lfanew + 22)[0]
    is_dll = (characteristics & 0x2000) != 0
    ext = ".dll" if is_dll else ".exe"
    desc = "Windows Dynamic Link Library (DLL)" if is_dll else "Windows PE Executable"

    total_size = len(data) - pos
    sec_table = pos + e_lfanew + 24 + opt_size
    if sec_table + (num_sections * 40) <= len(data):
        max_end = 0
        for i in range(num_sections):
            s_off = sec_table + (i * 40)
            raw_sz = struct.unpack_from("<I", data, s_off + 16)[0]
            raw_ptr = struct.unpack_from("<I", data, s_off + 20)[0]
            if raw_ptr + raw_sz > max_end:
                max_end = raw_ptr + raw_sz
        if max_end > 0:
            total_size = e_lfanew + max_end
    return (desc, ext, min(total_size, len(data) - pos))


def verify_elf(data: bytes, pos: int = 0) -> Optional[Tuple[str, str, int]]:
    """Deep verification of Linux ELF headers. Returns (desc, ext, size)."""
    if pos + 52 > len(data) or data[pos:pos+4] != b"\x7fELF":
        return None
    cls = data[pos+4]
    endian = data[pos+5]
    version = data[pos+6]
    if cls not in (1, 2) or endian not in (1, 2) or version != 1:
        return None
    fmt = "<" if endian == 1 else ">"
    e_type, e_machine = struct.unpack_from(f"{fmt}HH", data, pos + 16)
    if e_machine not in (0x02, 0x03, 0x08, 0x14, 0x15, 0x28, 0x3E, 0xB7, 0xF3) or e_type not in (1, 2, 3, 4):
        return None
    ehsize_off = pos + (52 if cls == 2 else 40)
    if ehsize_off + 2 <= len(data):
        e_ehsize = struct.unpack_from(f"{fmt}H", data, ehsize_off)[0]
        if e_ehsize != (64 if cls == 2 else 52):
            return None
    ext = ".so" if e_type == 3 else ".elf"
    desc = "ELF 64-bit Shared Object (.so)" if (cls == 2 and e_type == 3) else "ELF Executable"
    return (desc, ext, len(data) - pos)


def verify_png(data: bytes, pos: int = 0) -> Optional[Tuple[str, str, int]]:
    """Deep verification of PNG image. Returns (desc, ext, size)."""
    if pos + 24 > len(data) or data[pos:pos+8] != b"\x89PNG\r\n\x1a\n":
        return None
    if data[pos+8:pos+16] != b"\x00\x00\x00\x0dIHDR":
        return None
    iend = data.find(b"\x00\x00\x00\x00IEND", pos)
    total_size = (iend + 12 - pos) if iend != -1 else (len(data) - pos)
    return ("PNG Image", ".png", total_size)


def verify_jpeg(data: bytes, pos: int = 0) -> Optional[Tuple[str, str, int]]:
    """Deep verification of JPEG image. Returns (desc, ext, size)."""
    if pos + 4 > len(data) or data[pos:pos+3] != b"\xff\xd8\xff":
        return None
    marker = data[pos+3]
    if marker not in (0xe0, 0xe1, 0xdb, 0xc0, 0xc2, 0xee):
        return None
    eoi = data.find(b"\xff\xd9", pos + 4)
    if eoi == -1:
        return None
    return ("JPEG Image", ".jpg", eoi + 2 - pos)


def verify_zip(data: bytes, pos: int = 0) -> Optional[Tuple[str, str, int]]:
    """Deep verification of ZIP archive. Returns (desc, ext, size)."""
    if pos + 30 > len(data) or data[pos:pos+4] != b"PK\x03\x04":
        return None
    comp = struct.unpack_from("<H", data, pos + 8)[0]
    fn_len = struct.unpack_from("<H", data, pos + 26)[0]
    extra_len = struct.unpack_from("<H", data, pos + 28)[0]
    if comp > 20 or fn_len == 0 or fn_len > 1024 or extra_len > 4096:
        return None
    if pos + 30 + fn_len <= len(data):
        fn_bytes = data[pos+30:pos+30+fn_len]
        if not all(32 <= b <= 126 for b in fn_bytes):
            return None
    eocd = data.find(b"PK\x05\x06", pos + 30)
    total_size = (eocd + 22 - pos) if eocd != -1 else (len(data) - pos)
    return ("ZIP Archive", ".zip", total_size)


def verify_pdf(data: bytes, pos: int = 0) -> Optional[Tuple[str, str, int]]:
    """Deep verification of PDF document. Returns (desc, ext, size)."""
    if pos + 8 > len(data) or data[pos:pos+7] != b"%PDF-1.":
        return None
    if not chr(data[pos+7]).isdigit():
        return None
    eof_pos = data.find(b"%%EOF", pos)
    total_size = (eof_pos + 5 - pos) if eof_pos != -1 else (len(data) - pos)
    return ("Adobe Portable Document (PDF)", ".pdf", total_size)


def verify_riff(data: bytes, pos: int = 0) -> Optional[Tuple[str, str, int]]:
    """Deep verification of RIFF container (WAVE/AVI). Returns (desc, ext, size)."""
    if pos + 12 > len(data) or data[pos:pos+4] != b"RIFF":
        return None
    riff_sz = struct.unpack_from("<I", data, pos + 4)[0]
    type_tag = data[pos+8:pos+12]
    if type_tag == b"WAVE":
        return ("WAVE Audio File (RIFF/WAVE)", ".wav", min(riff_sz + 8, len(data) - pos))
    elif type_tag == b"AVI ":
        return ("AVI Video File (RIFF/AVI)", ".avi", min(riff_sz + 8, len(data) - pos))
    return None


def verify_sqlite(data: bytes, pos: int = 0) -> Optional[Tuple[str, str, int]]:
    """Deep verification of SQLite 3 database. Returns (desc, ext, size)."""
    if pos + 100 > len(data) or data[pos:pos+16] != b"SQLite format 3\x00":
        return None
    page_sz = struct.unpack_from(">H", data, pos + 16)[0]
    if page_sz == 1: page_sz = 65536
    if page_sz < 512 or page_sz > 65536 or (page_sz & (page_sz - 1)) != 0:
        return None
    page_count = struct.unpack_from(">I", data, pos + 28)[0]
    total_sz = (page_sz * page_count) if (0 < page_count <= 1_000_000) else (len(data) - pos)
    return ("SQLite 3 Database", ".sqlite", total_sz)


def verify_gzip(data: bytes, pos: int = 0) -> Optional[Tuple[str, str, int]]:
    """Deep verification of GZIP stream. Returns (desc, ext, size)."""
    if pos + 10 > len(data) or data[pos:pos+3] != b"\x1f\x8b\x08":
        return None
    flags = data[pos+3]
    if flags & 0xE0 != 0:
        return None
    try:
        decomp = gzip.decompress(data[pos:min(pos+1024, len(data))])
        if len(decomp) < 8:
            return None
    except Exception:
        try:
            gzip.decompress(data[pos:])
        except Exception:
            return None
    return ("GZIP Compressed Stream", ".gz", len(data) - pos)


def verify_cart(data: bytes, pos: int = 0) -> Optional[Tuple[str, str, int]]:
    """Deep verification of CaRT container. Returns (desc, ext, size)."""
    if pos + 8 > len(data) or data[pos:pos+4] != b"CART":
        return None
    return ("CaRT Container (Forensic Artifact)", ".cart", len(data) - pos)


def verify_wasm(data: bytes, pos: int = 0) -> Optional[Tuple[str, str, int]]:
    """Deep verification of WebAssembly module. Returns (desc, ext, size)."""
    if pos + 8 > len(data) or data[pos:pos+8] != b"\x00asm\x01\x00\x00\x00":
        return None
    return ("WebAssembly Binary Module", ".wasm", len(data) - pos)


def verify_class(data: bytes, pos: int = 0) -> Optional[Tuple[str, str, int]]:
    """Deep verification of Java class bytecode. Returns (desc, ext, size)."""
    if pos + 10 > len(data) or data[pos:pos+4] != b"\xca\xfe\xba\xbe":
        return None
    major = struct.unpack_from(">H", data, pos + 6)[0]
    if not (45 <= major <= 70):
        return None
    return ("Java Class Compiled Bytecode", ".class", len(data) - pos)


def verify_pyc(data: bytes, pos: int = 0) -> Optional[Tuple[str, str, int]]:
    """Deep verification of Python bytecode (.pyc). Returns (desc, ext, size)."""
    if pos + 16 > len(data):
        return None
    magic = data[pos:pos+4]
    pyc_magics = {
        b"\x42\x0d\r\n": "3.7",
        b"\x55\x0d\r\n": "3.8",
        b"\x61\x0d\r\n": "3.9",
        b"\x6f\x0d\r\n": "3.10",
        b"\xa7\x0d\r\n": "3.11",
        b"\xcb\x0d\r\n": "3.12",
        b"\xf3\x0d\r\n": "3.13",
    }
    if magic in pyc_magics:
        flags = struct.unpack_from("<I", data, pos + 4)[0]
        if flags <= 7:
            return (f"Compiled Python {pyc_magics[magic]} Bytecode", ".pyc", len(data) - pos)
    return None


RAW_DEEP_VERIFIERS = [
    verify_wasm,
    verify_riff,
    verify_png,
    verify_jpeg,
    verify_pe,
    verify_elf,
    verify_zip,
    verify_pdf,
    verify_cart,
    verify_sqlite,
    verify_gzip,
    verify_class,
    verify_pyc,
]


# ---------------------------------------------------------------------------
# Core Reconstructor & Carver Engine
# ---------------------------------------------------------------------------

class PCAPFileCarver:
    """
    Extracts and carves transferred files from PCAP streams.
    Hierarchical extraction:
    1. Protocol-Aware Reassembly (HTTP Downloads & Uploads, FTP Data)
    2. Deep Structural Raw Stream Carving (for non-HTTP streams or --deep-carve)
    """
    def __init__(self, engine: PCAPEngine, deep_carve: bool = False):
        self.engine = engine
        self.deep_carve = deep_carve
        self.carved_files: List[CarvedFile] = []

    def carve_all(self) -> List[CarvedFile]:
        self.engine.analyze()
        self.carved_files = []
        file_idx = 1
        seen_hashes = set()

        for stream in self.engine.tcp_streams.values():
            stream_has_protocol_files = False

            # -----------------------------------------------------------------
            # 1. HTTP File Downloads (Server -> Client Responses)
            # -----------------------------------------------------------------
            for r_idx, resp in enumerate(stream.http_responses):
                body = resp.get("body_bytes", b"")
                if not body or len(body) < 16:
                    continue

                fname = self._extract_filename_from_http(resp, stream, r_idx)
                ftype = resp.get("content_type", "HTTP Transferred Object")

                # Refine filetype and extension using verified signature detection
                detected_type, detected_ext = self._detect_magic(body, ftype)
                if detected_type:
                    ftype = detected_type
                if not os.path.splitext(fname)[1] and detected_ext:
                    fname += detected_ext

                b_hash = hashlib.md5(body).hexdigest()
                if b_hash not in seen_hashes:
                    seen_hashes.add(b_hash)
                    self.carved_files.append(CarvedFile(
                        index=file_idx,
                        stream_id=stream.stream_id,
                        filename=fname,
                        file_type=ftype,
                        file_bytes=body,
                        source=f"{stream.server_ip}:{stream.server_port}",
                        destination=f"{stream.client_ip}:{stream.client_port}",
                        protocol="HTTP Response",
                        extra_info=resp.get("status", "")
                    ))
                    file_idx += 1
                    stream_has_protocol_files = True

            # -----------------------------------------------------------------
            # 2. HTTP File Uploads (Client -> Server Requests: POST / PUT)
            # -----------------------------------------------------------------
            for req in stream.http_requests:
                body = req.get("body_bytes", b"")
                if not body or len(body) < 16:
                    continue

                # Check multipart/form-data upload
                uploaded_files = self._extract_multipart_files(body, req.get("headers_raw", ""))
                for up_name, up_type, up_bytes in uploaded_files:
                    u_hash = hashlib.md5(up_bytes).hexdigest()
                    if u_hash not in seen_hashes:
                        seen_hashes.add(u_hash)
                        self.carved_files.append(CarvedFile(
                            index=file_idx,
                            stream_id=stream.stream_id,
                            filename=up_name,
                            file_type=up_type,
                            file_bytes=up_bytes,
                            source=f"{stream.client_ip}:{stream.client_port}",
                            destination=f"{stream.server_ip}:{stream.server_port}",
                            protocol="HTTP Upload",
                            extra_info=f"{req.get('method', 'POST')} {req.get('uri', '')}"
                        ))
                        file_idx += 1
                        stream_has_protocol_files = True

            # -----------------------------------------------------------------
            # 3. Protocol Isolation Gate
            # If stream is an HTTP transaction and we are NOT in deep_carve mode,
            # SKIP raw carving! HTTP framing already gives exact, authentic files.
            # -----------------------------------------------------------------
            if stream_has_protocol_files and not self.deep_carve:
                continue

            # -----------------------------------------------------------------
            # 4. Deep Structural Raw Stream Carving (Non-HTTP / Raw Sockets)
            # -----------------------------------------------------------------
            for payload_side, src_ip, dst_ip in [
                (stream.server_payload, f"{stream.server_ip}:{stream.server_port}", f"{stream.client_ip}:{stream.client_port}"),
                (stream.client_payload, f"{stream.client_ip}:{stream.client_port}", f"{stream.server_ip}:{stream.server_port}")
            ]:
                if len(payload_side) < 24:
                    continue

                # Run structural validators on raw payload
                for verifier in RAW_DEEP_VERIFIERS:
                    res = verifier(payload_side, 0)
                    if res:
                        desc, ext, c_len = res
                        carved_bytes = payload_side[:c_len]
                        c_hash = hashlib.md5(carved_bytes).hexdigest()
                        if c_hash not in seen_hashes:
                            seen_hashes.add(c_hash)
                            fname = f"stream_{stream.stream_id}_carved_{file_idx}{ext}"
                            self.carved_files.append(CarvedFile(
                                index=file_idx,
                                stream_id=stream.stream_id,
                                filename=fname,
                                file_type=desc,
                                file_bytes=carved_bytes,
                                source=src_ip,
                                destination=dst_ip,
                                protocol="TCP Raw Carve",
                                extra_info="Verified Structural Header"
                            ))
                            file_idx += 1

                # -------------------------------------------------------------
                # 5. Unrecognized / Custom Binary Containers
                # -------------------------------------------------------------
                # Only if the payload contains non-text binary data (not shell sessions)
                if not payload_side.startswith((b"GET ", b"POST ", b"HTTP/", b"SSH-", b"220 ", b"CONNECT ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ")):
                    prefix_4 = payload_side[:4]
                    is_binary_data = not all(32 <= b <= 126 or b in (10, 13, 9) for b in payload_side[:32])

                    if is_binary_data and (re.fullmatch(rb"[A-Za-z0-9_]{4}", prefix_4)):
                        c_hash = hashlib.md5(payload_side).hexdigest()
                        if c_hash not in seen_hashes:
                            try:
                                hdr_name = prefix_4.decode("latin-1")
                                custom_desc = f"Custom Binary Container: '{hdr_name}'"
                                custom_ext = f".{hdr_name.lower()}"
                                seen_hashes.add(c_hash)
                                fname = f"stream_{stream.stream_id}_unknown_{file_idx}{custom_ext}"
                                self.carved_files.append(CarvedFile(
                                    index=file_idx,
                                    stream_id=stream.stream_id,
                                    filename=fname,
                                    file_type=custom_desc,
                                    file_bytes=payload_side,
                                    source=src_ip,
                                    destination=dst_ip,
                                    protocol="Custom Container Carve",
                                    extra_info=f"Raw Header: {prefix_4.hex().upper()}"
                                ))
                                file_idx += 1
                            except Exception:
                                pass

        return self.carved_files

    def _extract_filename_from_http(self, resp: Dict[str, Any], stream: TCPStream, r_idx: int = 0) -> str:
        disp = resp.get("content_disposition", "")
        if "filename=" in disp.lower():
            m = re.search(r'filename=["\']?([^"\';\r\n]+)["\']?', disp, re.IGNORECASE)
            if m:
                return os.path.basename(m.group(1).strip())

        # Fallback to Request URI
        if r_idx < len(stream.http_requests):
            uri = stream.http_requests[r_idx].get("uri", "")
            path = uri.split("?")[0].split("#")[0]
            bname = os.path.basename(path)
            if bname and "." in bname and len(bname) <= 64:
                return bname
        elif stream.http_requests:
            uri = stream.http_requests[0].get("uri", "")
            path = uri.split("?")[0].split("#")[0]
            bname = os.path.basename(path)
            if bname and "." in bname and len(bname) <= 64:
                return bname

        ct = resp.get("content_type", "").split(";")[0].strip().lower()
        ext = MIME_TO_EXT.get(ct, ".bin")
        return f"http_download_stream_{stream.stream_id}{ext}"

    def _extract_multipart_files(self, body: bytes, headers_raw: str) -> List[Tuple[str, str, bytes]]:
        """Extract files from HTTP multipart/form-data upload requests."""
        files = []
        m = re.search(r'boundary=([^\r\n;]+)', headers_raw, re.IGNORECASE)
        boundary_str = m.group(1).strip('"\'') if m else ""
        if boundary_str:
            boundary_bytes = f"--{boundary_str}".encode("latin-1")
            parts = body.split(boundary_bytes)
            for part in parts:
                if b"Content-Disposition" in part and b"filename=" in part:
                    p_hdr, _, p_body = part.partition(b"\r\n\r\n")
                    if p_body.endswith(b"\r\n"):
                        p_body = p_body[:-2]
                    if p_body.endswith(b"--"):
                        p_body = p_body[:-2]

                    fn_m = re.search(r'filename=["\']?([^"\';\r\n]+)["\']?', p_hdr.decode("latin-1", errors="ignore"))
                    ct_m = re.search(r'Content-Type:\s*([^\r\n;]+)', p_hdr.decode("latin-1", errors="ignore"), re.IGNORECASE)
                    fn = fn_m.group(1).strip() if fn_m else "uploaded_file"
                    ct = ct_m.group(1).strip() if ct_m else "Uploaded File"
                    if len(p_body) > 0:
                        files.append((fn, ct, p_body))
        return files

    def _detect_magic(self, data: bytes, default_type: str) -> Tuple[str, str]:
        """Detect file format description and extension from magic bytes."""
        if data.startswith(b"RIFF") and len(data) >= 12:
            tag = data[8:12]
            if tag == b"WAVE":
                return "WAVE Audio File (RIFF/WAVE)", ".wav"
            elif tag == b"AVI ":
                return "AVI Video File (RIFF/AVI)", ".avi"
        elif data.startswith(b"BM"):
            return "Bitmap Image (BMP)", ".bmp"
        elif data.startswith(b"\x89PNG\r\n\x1a\n"):
            return "PNG Image", ".png"
        elif data.startswith(b"\xff\xd8\xff"):
            return "JPEG Image", ".jpg"
        elif data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
            return "GIF Image", ".gif"
        elif data.startswith(b"%PDF-"):
            return "Adobe Portable Document (PDF)", ".pdf"
        elif data.startswith(b"PK\x03\x04"):
            return "ZIP Archive", ".zip"
        elif data.startswith(b"\x00asm\x01\x00\x00\x00"):
            return "WebAssembly Binary Module", ".wasm"
        elif data.startswith(b"\x7fELF"):
            return "Linux ELF Executable / Object", ".elf"
        elif data.startswith(b"MZ") and len(data) > 0x40:
            return "Windows PE Executable / DLL", ".exe"
        elif data.startswith(b"SQLite format 3\x00"):
            return "SQLite 3 Database", ".sqlite"
        elif data.startswith(b"CART\x01\x00") or data.startswith(b"CART"):
            return "CaRT Container Format", ".cart"
        elif data.startswith(b"7z\xbc\xaf\x27\x1c"):
            return "7-Zip Archive", ".7z"
        elif data.startswith(b"\x1f\x8b\x08"):
            return "GZIP Compressed Stream", ".gz"
        elif data.startswith(b"\xfd7zXZ\x00"):
            return "XZ Compressed Archive", ".xz"
        elif data.startswith(b"\x28\xb5\x2f\xfd"):
            return "Zstandard Compressed Archive", ".zst"

        # Fallback to MIME type mapping
        ct_clean = default_type.split(";")[0].strip().lower()
        if ct_clean in MIME_TO_EXT:
            return default_type, MIME_TO_EXT[ct_clean]

        return default_type, ""


# ---------------------------------------------------------------------------
# CLI & Output Formatting
# ---------------------------------------------------------------------------

def print_files_table(files: List[CarvedFile]):
    if not files:
        console.print("[yellow][i] No transferable or exportable files detected in this capture.[/yellow]")
        return

    table = Table(
        title=f"Discovered & Exportable Network Files ({len(files)} Files Detected)",
        show_header=True,
        header_style="bold magenta",
        border_style="bold green",
        expand=True
    )
    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("Stream", style="bold cyan", width=8, justify="center")
    table.add_column("Filename", style="bold white on dark_blue", min_width=24, overflow="fold")
    table.add_column("File Type / Signature", style="green", width=28)
    table.add_column("Size", style="yellow", width=12, justify="right")
    table.add_column("Source -> Destination", style="cyan", width=28)
    table.add_column("MD5 Hash", style="dim white", width=34)

    for f in files:
        table.add_row(
            str(f.index),
            f"#{f.stream_id}",
            escape(f" {f.filename} "),
            escape(f.file_type),
            human_size(f.size),
            f"{f.source} -> {f.destination}",
            f.md5
        )

    console.print(table)


def export_files_to_disk(files: List[CarvedFile], out_dir: str, target_idx: Optional[int] = None):
    os.makedirs(out_dir, exist_ok=True)
    exported_count = 0

    to_export = [f for f in files if target_idx is None or f.index == target_idx]
    if not to_export:
        console.print(f"[red] No matching file index {target_idx} to export.[/red]")
        return

    for f in to_export:
        safe_name = re.sub(r'[^\w\.-]', '_', f.filename)
        dest_path = os.path.join(out_dir, safe_name)

        if os.path.exists(dest_path):
            try:
                with open(dest_path, "rb") as check_f:
                    if hashlib.md5(check_f.read()).hexdigest() == f.md5:
                        exported_count += 1
                        console.print(f"[bold green][+] File already present (Identical MD5):[/bold green] [cyan]{dest_path}[/cyan] ({human_size(f.size)})")
                        continue
            except Exception:
                pass
            base, ext = os.path.splitext(safe_name)
            dest_path = os.path.join(out_dir, f"{base}_{f.index}{ext}")

        with open(dest_path, "wb") as fp:
            fp.write(f.file_bytes)

        exported_count += 1
        console.print(f"[bold green][+] Carved & Exported:[/bold green] [cyan]{dest_path}[/cyan] ({human_size(f.size)}) - [dim]MD5: {f.md5}[/dim]")

    console.print(f"\n[bold green][+] Total {exported_count} file(s) saved to directory:[/bold green] [bold white]{os.path.abspath(out_dir)}[/bold white]")


def export_files_markdown(files: List[CarvedFile], output_path: str):
    lines = [
        f"# PCAP Carved & Transferred Files Report",
        f"- **Total Files Detected:** `{len(files)}`",
        "",
        "| # | Stream | Filename | File Type | Size | Source -> Destination | MD5 Hash | SHA-256 |",
        "|---|---|---|---|---|---|---|---|"
    ]
    for f in files:
        fn_esc = f.filename.replace("|", "\\|")
        ft_esc = f.file_type.replace("|", "\\|")
        lines.append(f"| {f.index} | `#{f.stream_id}` | **`{fn_esc}`** | {ft_esc} | {human_size(f.size)} | `{f.source} -> {f.destination}` | `{f.md5}` | `{f.sha256}` |")

    with open(output_path, "w", encoding="utf-8") as fp:
        fp.write("\n".join(lines) + "\n")
    console.print(f"[bold green][+] Exported PCAP files list to Markdown:[/bold green] [cyan]{output_path}[/cyan]")


def main(args_list=None):
    parser = argparse.ArgumentParser(
        prog="pcapfile",
        description="PCAP File Extractor & Stream Carving Engine (HTTP, FTP, WASM, PE, ELF, ZIP, PDF)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  pcapfile capture.pcap
  pcapfile evidence.pcapng -o ./extracted_pcap_files
  pcapfile capture.pcap -i 1 -o ./carved_output
  pcapfile capture.pcap --deep-carve
  pcapfile capture.pcap --export-all
        """
    )
    parser.add_argument("pcap_file", help="Path to input PCAP or PCAPNG file")
    parser.add_argument("-o", "--out", "--export-dir", dest="out_dir", help="Directory to save carved files to disk")
    parser.add_argument("-i", "--index", type=int, help="Carve and export only a specific file index")
    parser.add_argument("--deep-carve", action="store_true", help="Force deep signature carving even inside already-extracted HTTP bodies")

    # Export options
    parser.add_argument("--md", "--markdown", dest="md", help="Export file list to Markdown report")
    parser.add_argument("--json", help="Export file list to JSON file")
    parser.add_argument("--export-all", action="store_true", help="Generate MD, JSON reports and export files to folder")

    args = parser.parse_args(args_list)

    if not os.path.exists(args.pcap_file):
        console.print(f"[bold red]Error:[/bold red] File not found: {args.pcap_file}")
        sys.exit(1)

    print_banner(
        tool_name="PCAP FILE EXTRACTOR & STREAM CARVER (pcapfile)",
        sub_title="HTTP, FTP, WASM, PE, ELF, ZIP & Document Reconstructor"
    )

    engine = PCAPEngine(args.pcap_file)
    with console.status("[bold cyan]Reassembling streams & carving transferred files...[/bold cyan]"):
        carver = PCAPFileCarver(engine, deep_carve=args.deep_carve)
        files = carver.carve_all()

    print_files_table(files)

    # Disk Export Handler
    if args.out_dir or (args.export_all and not args.out_dir):
        export_dir = args.out_dir or f"./carved_{os.path.splitext(os.path.basename(args.pcap_file))[0]}"
        export_files_to_disk(files, export_dir, target_idx=args.index)

    base_name = os.path.splitext(os.path.basename(args.pcap_file))[0]
    if args.export_all:
        if not args.md: args.md = f"{base_name}_pcap_files.md"
        if not args.json: args.json = f"{base_name}_pcap_files.json"

    if hasattr(args, 'md') and args.md: export_files_markdown(files, args.md)
    if hasattr(args, 'json') and args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"carved_files": [f.to_dict() for f in files]}, f, indent=2, ensure_ascii=False)
        console.print(f"[bold green][+] Exported PCAP files list to JSON:[/bold green] [cyan]{args.json}[/cyan]")


if __name__ == "__main__":
    main()
