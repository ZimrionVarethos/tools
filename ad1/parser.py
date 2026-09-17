"""
High Performance Pure Python AccessData Logical Image (AD1) Parser
"""
import os
import struct
import zlib
import glob
from typing import List, Dict, Optional, Tuple, Generator, BinaryIO
from .models import (
    SegmentHeader, LogicalHeader, AD1Metadata, AD1Item,
    AD1_LOGICAL_MARGIN, AD1_FOLDER_SIGNATURE,
    ITEM_TYPE_REGULAR_FILE, ITEM_TYPE_REGULAR_FOLDER
)


class AD1Parser:
    """
    Parser for AccessData AD1 logical forensic container format.
    Supports multi-segment files (.ad1, .ad2, .ad3, etc.) and on-the-fly zlib decompression.
    """
    def __init__(self, primary_file_path: str):
        self.primary_path = os.path.abspath(primary_file_path)
        self.segment_paths: List[str] = []
        self.segment_files: List[BinaryIO] = []
        self.segment_sizes: List[int] = []
        self.segment_header: Optional[SegmentHeader] = None
        self.logical_header: Optional[LogicalHeader] = None
        self.items: List[AD1Item] = []
        self.items_by_addr: Dict[int, AD1Item] = {}
        self.root_items: List[AD1Item] = []
        
        self._discover_and_open_segments()
        self._read_headers()

    def _discover_and_open_segments(self):
        """
        Discover all associated segment files (.ad1, .ad2, ... or .001, .002, ...)
        """
        base_dir = os.path.dirname(self.primary_path)
        base_name = os.path.basename(self.primary_path)
        root, ext = os.path.splitext(self.primary_path)

        # Check standard AD1 naming: file.ad1, file.ad2, file.ad3...
        candidates = []
        if ext.lower() == ".ad1":
            pattern = os.path.join(base_dir, f"{os.path.splitext(base_name)[0]}.ad*")
            found = glob.glob(pattern)
            # Sort by extension number (.ad1, .ad2, .ad10, etc.)
            def get_ad_idx(p):
                ext_part = os.path.splitext(p)[1].lower()
                if ext_part.startswith(".ad") and ext_part[3:].isdigit():
                    return int(ext_part[3:])
                return 1
            candidates = sorted(found, key=get_ad_idx)
        else:
            candidates = [self.primary_path]

        if not candidates:
            candidates = [self.primary_path]

        self.segment_paths = candidates
        for path in self.segment_paths:
            f = open(path, "rb")
            self.segment_files.append(f)
            f.seek(0, os.SEEK_END)
            self.segment_sizes.append(f.tell())
            f.seek(0)

    def close(self):
        """Close all opened segment file handles."""
        for f in self.segment_files:
            try:
                f.close()
            except Exception:
                pass
        self.segment_files = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def arbitrary_read(self, offset: int, length: int) -> bytes:
        """
        Read arbitrary binary data across segmented AD1 image files.
        """
        if length <= 0:
            return b""

        if not self.segment_header:
            raise ValueError("Segment header not loaded")

        frag_size = self.segment_header.fragments_size
        capacity_per_seg = (frag_size * 65536) - AD1_LOGICAL_MARGIN
        if capacity_per_seg <= 0:
            capacity_per_seg = self.segment_sizes[0] - AD1_LOGICAL_MARGIN

        file_idx = int(offset // capacity_per_seg)
        data_cursor = int(offset - (capacity_per_seg * file_idx))
        
        result = bytearray()
        to_read = length

        while to_read > 0 and file_idx < len(self.segment_files):
            seg_file = self.segment_files[file_idx]
            seg_size = self.segment_sizes[file_idx]
            
            # Physical offset in current segment file
            phys_offset = data_cursor + AD1_LOGICAL_MARGIN
            bytes_available_in_seg = seg_size - phys_offset
            
            if bytes_available_in_seg <= 0:
                file_idx += 1
                data_cursor = 0
                continue

            chunk_len = min(to_read, bytes_available_in_seg)
            seg_file.seek(phys_offset)
            data = seg_file.read(chunk_len)
            if not data:
                break

            result.extend(data)
            to_read -= len(data)
            data_cursor = 0
            file_idx += 1

        return bytes(result)

    def _read_uint16_le(self, offset: int) -> int:
        data = self.arbitrary_read(offset, 2)
        return struct.unpack("<H", data)[0] if len(data) == 2 else 0

    def _read_uint32_le(self, offset: int) -> int:
        data = self.arbitrary_read(offset, 4)
        return struct.unpack("<I", data)[0] if len(data) == 4 else 0

    def _read_uint64_le(self, offset: int) -> int:
        data = self.arbitrary_read(offset, 8)
        return struct.unpack("<Q", data)[0] if len(data) == 8 else 0

    def _read_headers(self):
        """
        Parse AD1 Segment Header & Logical Image Header.
        """
        if not self.segment_files:
            raise FileNotFoundError("No segment files available")

        # Read segment header from first segment
        f0 = self.segment_files[0]
        f0.seek(0)
        sig = f0.read(16)
        if not sig.startswith(b"ADSEGMENTEDFILE"):
            raise ValueError(f"Invalid AD1 segment signature: {sig}")

        f0.seek(0x18)
        seg_index = struct.unpack("<I", f0.read(4))[0]
        seg_number = struct.unpack("<I", f0.read(4))[0]
        f0.seek(0x22)
        fragments_size = struct.unpack("<I", f0.read(4))[0]
        f0.seek(0x28)
        header_size = struct.unpack("<I", f0.read(4))[0]

        self.segment_header = SegmentHeader(
            signature=sig,
            segment_index=seg_index,
            segment_number=seg_number,
            fragments_size=fragments_size,
            header_size=header_size
        )

        # Read logical header (at logical offset 0 = physical offset 512 in seg 0)
        sig_bytes = self.arbitrary_read(0, 16)
        sig_str = sig_bytes.split(b"\x00")[0].decode("latin-1", errors="ignore")
        if not sig_str.startswith("ADLOGICALIMAGE"):
            # Some versions might differ slightly in header name, but signature usually starts with AD
            pass

        img_version = self._read_uint32_le(0x10) # relative to 0x200
        zlib_chunk_size = self._read_uint32_le(0x18)
        logical_meta_addr = self._read_uint64_le(0x1c)
        first_item_addr = self._read_uint64_le(0x24)
        ds_name_len = self._read_uint32_le(0x2c)
        
        ad_sig = self.arbitrary_read(0x30, 3).decode("latin-1", errors="ignore")
        ds_name_addr = self._read_uint64_le(0x34)
        attrguid_addr = self._read_uint64_le(0x3c)
        locsguid_addr = self._read_uint64_le(0x4c)
        
        ds_name = ""
        if ds_name_len > 0:
            ds_name_raw = self.arbitrary_read(0x5c, ds_name_len)
            ds_name = ds_name_raw.decode("utf-8", errors="replace")

        self.logical_header = LogicalHeader(
            signature=sig_str,
            image_version=img_version,
            zlib_chunk_size=zlib_chunk_size,
            logical_metadata_addr=logical_meta_addr,
            first_item_addr=first_item_addr,
            data_source_name_length=ds_name_len,
            ad_signature=ad_sig,
            data_source_name_addr=ds_name_addr,
            attrguid_footer_addr=attrguid_addr,
            locsguid_footer_addr=locsguid_addr,
            data_source_name=ds_name
        )

    def _read_metadata_chain(self, first_addr: int) -> List[AD1Metadata]:
        """
        Traverse linked list of metadata entries for an item.
        """
        results = []
        curr_addr = first_addr
        visited = set()

        while curr_addr != 0 and curr_addr not in visited:
            visited.add(curr_addr)
            next_addr = self._read_uint64_le(curr_addr)
            category = self._read_uint32_le(curr_addr + 0x08)
            key = self._read_uint32_le(curr_addr + 0x0c)
            data_len = self._read_uint32_le(curr_addr + 0x10)
            
            raw_data = self.arbitrary_read(curr_addr + 0x14, data_len) if data_len > 0 else b""
            text_val = ""
            try:
                text_val = raw_data.decode("utf-8").strip("\x00")
            except Exception:
                text_val = raw_data.hex()

            meta = AD1Metadata(
                next_metadata_addr=next_addr,
                category=category,
                key=key,
                data_length=data_len,
                raw_data=raw_data,
                text_data=text_val
            )
            results.append(meta)
            curr_addr = next_addr

        return results

    def _read_item_at(self, offset: int) -> Optional[AD1Item]:
        """
        Read single AD1 Item Header structure at given logical offset.
        """
        if offset == 0:
            return None

        next_item_addr = self._read_uint64_le(offset)
        first_child_addr = self._read_uint64_le(offset + 0x08)
        first_metadata_addr = self._read_uint64_le(offset + 0x10)
        zlib_metadata_addr = self._read_uint64_le(offset + 0x18)
        decompressed_size = self._read_uint64_le(offset + 0x20)
        item_type = self._read_uint32_le(offset + 0x28)
        name_len = self._read_uint32_le(offset + 0x2c)

        if name_len > 2048:
            # Sanity check to avoid reading corrupted buffers
            name_len = 256

        raw_name = self.arbitrary_read(offset + 0x30, name_len)
        name = raw_name.decode("utf-8", errors="replace").rstrip("\x00")

        # Sanitize slashes in filenames
        name = name.replace("/", "_").replace("\\", "_")

        parent_folder_addr = self._read_uint64_le(offset + 0x30 + name_len)

        item = AD1Item(
            address=offset,
            next_item_addr=next_item_addr,
            first_child_addr=first_child_addr,
            first_metadata_addr=first_metadata_addr,
            zlib_metadata_addr=zlib_metadata_addr,
            decompressed_size=decompressed_size,
            item_type=item_type,
            item_name_length=name_len,
            item_name=name,
            parent_folder_addr=parent_folder_addr
        )

        # Parse metadata
        if first_metadata_addr != 0:
            meta_list = self._read_metadata_chain(first_metadata_addr)
            for m in meta_list:
                item.metadata.setdefault(m.category, []).append(m)
                
                # Category 1 = Hashes (0x5001 = MD5, 0x5002 = SHA1)
                if m.category == 1:
                    if m.key == 0x5001:
                        item.md5 = m.text_data or m.raw_data.hex()
                    elif m.key == 0x5002:
                        item.sha1 = m.text_data or m.raw_data.hex()
                # Category 5 = Timestamps (0x07 = Access, 0x08 = Modified, 0x09 = Change/Created)
                elif m.category == 5:
                    if m.key == 0x07:
                        item.accessed_time = m.text_data
                    elif m.key == 0x08:
                        item.modified_time = m.text_data
                    elif m.key == 0x09:
                        item.created_time = m.text_data

        return item

    def build_tree(self) -> List[AD1Item]:
        """
        Build the entire file tree hierarchy from the AD1 image.
        Returns list of root-level items.
        """
        if not self.logical_header or self.logical_header.first_item_addr == 0:
            return []

        self.items = []
        self.items_by_addr = {}
        self.root_items = []

        def traverse_items(offset: int, parent: Optional[AD1Item] = None) -> Optional[AD1Item]:
            curr_addr = offset
            first_in_level: Optional[AD1Item] = None
            prev_item: Optional[AD1Item] = None

            while curr_addr != 0:
                if curr_addr in self.items_by_addr:
                    break

                item = self._read_item_at(curr_addr)
                if not item:
                    break

                item.parent = parent
                self.items.append(item)
                self.items_by_addr[curr_addr] = item

                if first_in_level is None:
                    first_in_level = item

                if prev_item:
                    prev_item.next_item = item
                prev_item = item

                # Recurse children if any
                if item.first_child_addr != 0:
                    child = traverse_items(item.first_child_addr, parent=item)
                    # Collect all siblings under this child
                    c = child
                    while c:
                        item.children.append(c)
                        c = c.next_item

                curr_addr = item.next_item_addr

            return first_in_level

        first_root = traverse_items(self.logical_header.first_item_addr, parent=None)
        curr = first_root
        while curr:
            self.root_items.append(curr)
            curr = curr.next_item

        return self.root_items

    def read_file_bytes(self, item: AD1Item) -> bytes:
        """
        Decompress and read all data bytes for an AD1 file item.
        """
        if item.decompressed_size == 0 or item.zlib_metadata_addr == 0:
            return b""

        chunk_count = self._read_uint64_le(item.zlib_metadata_addr)
        if chunk_count == 0 or chunk_count > 500_000:
            return b""

        # Read chunk address pointers
        addresses = []
        for i in range(chunk_count + 1):
            addr = self._read_uint64_le(item.zlib_metadata_addr + ((i + 1) * 8))
            addresses.append(addr)

        result = bytearray()
        for i in range(chunk_count):
            chunk_start = addresses[i]
            chunk_end = addresses[i + 1]
            chunk_len = chunk_end - chunk_start
            
            if chunk_len <= 0 or chunk_len > (16 * 1024 * 1024):
                continue

            compressed_bytes = self.arbitrary_read(chunk_start, chunk_len)
            if not compressed_bytes:
                continue

            try:
                decomp = zlib.decompress(compressed_bytes)
                result.extend(decomp)
            except Exception:
                # Fallback for raw / uncompressed or zlib errors
                try:
                    decomp = zlib.decompress(compressed_bytes, -15)
                    result.extend(decomp)
                except Exception:
                    pass

        return bytes(result[:item.decompressed_size])

    def find_items_by_name(self, target_filename: str) -> List[AD1Item]:
        """
        Find items matching specific filename (case-insensitive).
        """
        target_lower = target_filename.lower()
        return [item for item in self.items if item.item_name.lower() == target_lower]

    def find_items_by_pattern(self, pattern: str) -> List[AD1Item]:
        """
        Find items whose full path or name contains substring or glob.
        """
        import fnmatch
        pat_lower = pattern.lower()
        matches = []
        for item in self.items:
            path_lower = item.full_path.lower()
            name_lower = item.item_name.lower()
            if pat_lower in path_lower or pat_lower in name_lower or fnmatch.fnmatch(name_lower, pat_lower) or fnmatch.fnmatch(path_lower, pat_lower):
                matches.append(item)
        return matches
