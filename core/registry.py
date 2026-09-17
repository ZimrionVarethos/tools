"""
Pure Python Windows Registry (REGF) Hive Parser
Compatible with Amcache.hve, NTUSER.DAT, SYSTEM, SOFTWARE, SAM
Does not require external C dependencies.
"""
import struct
import io
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Tuple, Generator
from .utils import filetime_to_datetime, format_datetime

# Value Type Constants
REG_NONE = 0
REG_SZ = 1
REG_EXPAND_SZ = 2
REG_BINARY = 3
REG_DWORD = 4
REG_DWORD_BIG_ENDIAN = 5
REG_LINK = 6
REG_MULTI_SZ = 7
REG_RESOURCE_LIST = 8
REG_FULL_RESOURCE_DESCRIPTOR = 9
REG_RESOURCE_REQUIREMENTS_LIST = 10
REG_QWORD = 11


class RegValue:
    """Represents a Registry Value (vk record)"""
    def __init__(self, name: str, val_type: int, raw_data: bytes, parsed_value: Any):
        self.name = name
        self.type = val_type
        self.raw_data = raw_data
        self.value = parsed_value

    def __repr__(self):
        return f"<RegValue {self.name}: {self.value}>"


class RegKey:
    """Represents a Registry Key (nk record)"""
    def __init__(self, name: str, path: str, timestamp: Optional[datetime] = None):
        self.name = name
        self.path = path
        self.timestamp = timestamp
        self.values: Dict[str, RegValue] = {}
        self.subkeys: Dict[str, 'RegKey'] = {}

    def get_value(self, name: str, default=None):
        v = self.values.get(name)
        return v.value if v is not None else default

    def get_subkey(self, name: str) -> Optional['RegKey']:
        for k_name, key in self.subkeys.items():
            if k_name.lower() == name.lower():
                return key
        return None

    def __repr__(self):
        return f"<RegKey {self.path}>"


class RegistryHive:
    """
    Pure Python REGF parser. Reads in-memory bytes of any Windows Registry Hive.
    """
    def __init__(self, hive_bytes: bytes):
        self.data = hive_bytes
        self.root: Optional[RegKey] = None
        self._parse()

    def _parse(self):
        if len(self.data) < 4096 or self.data[:4] != b"regf":
            # Try python-registry if available
            try:
                from Registry import Registry
                reg = Registry.Registry(io.BytesIO(self.data))
                self.root = self._convert_python_registry(reg.root())
                return
            except Exception:
                return

        # Pure python parse of standard REGF
        try:
            root_cell_offset = struct.unpack("<I", self.data[0x24:0x28])[0]
            # Offsets in REGF are relative to hive bins start (0x1000 = 4096)
            self.root = self._parse_nk_cell(root_cell_offset, "")
        except Exception:
            # Fallback to python-registry
            try:
                from Registry import Registry
                reg = Registry.Registry(io.BytesIO(self.data))
                self.root = self._convert_python_registry(reg.root())
            except Exception:
                pass

    def _convert_python_registry(self, py_key, parent_path="") -> RegKey:
        path = f"{parent_path}\\{py_key.name()}" if parent_path else py_key.name()
        ts = None
        try:
            ts = py_key.timestamp()
            if ts and ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
        except Exception:
            pass

        key = RegKey(name=py_key.name(), path=path, timestamp=ts)

        for v in py_key.values():
            try:
                v_name = v.name()
                v_type = v.value_type()
                v_val = v.value()
                v_raw = v.raw_data()
                key.values[v_name] = RegValue(v_name, v_type, v_raw, v_val)
            except Exception:
                pass

        for sub in py_key.subkeys():
            try:
                sub_key = self._convert_python_registry(sub, path)
                key.subkeys[sub_key.name] = sub_key
            except Exception:
                pass

        return key

    def _get_cell_data(self, cell_offset: int) -> Tuple[int, bytes]:
        abs_offset = 0x1000 + cell_offset
        if abs_offset < 0 or abs_offset + 4 > len(self.data):
            return 0, b""
        size = struct.unpack("<i", self.data[abs_offset:abs_offset + 4])[0]
        # size is negative for allocated cells
        actual_size = abs(size) - 4
        return abs_offset + 4, self.data[abs_offset + 4:abs_offset + 4 + actual_size]

    def _parse_nk_cell(self, cell_offset: int, parent_path: str) -> Optional[RegKey]:
        data_offset, cell_data = self._get_cell_data(cell_offset)
        if len(cell_data) < 0x48 or cell_data[:2] != b"nk":
            return None

        flags, ft_raw = struct.unpack("<HQ", cell_data[2:12])
        timestamp = filetime_to_datetime(ft_raw)

        subkey_count = struct.unpack("<I", cell_data[0x14:0x18])[0]
        subkey_list_offset = struct.unpack("<I", cell_data[0x1c:0x20])[0]

        values_count = struct.unpack("<I", cell_data[0x24:0x28])[0]
        values_list_offset = struct.unpack("<I", cell_data[0x28:0x2c])[0]

        name_len = struct.unpack("<H", cell_data[0x48:0x4a])[0]
        name_raw = cell_data[0x4c:0x4c + name_len]
        
        # Flags & 0x0020 means ASCII, otherwise UTF-16LE
        is_ascii = bool(flags & 0x0020)
        try:
            key_name = name_raw.decode("latin-1" if is_ascii else "utf-16-le", errors="replace")
        except Exception:
            key_name = name_raw.decode("latin-1", errors="replace")

        full_path = f"{parent_path}\\{key_name}" if parent_path else key_name
        key = RegKey(name=key_name, path=full_path, timestamp=timestamp)

        # Parse Values
        if values_count > 0 and values_list_offset != 0xFFFFFFFF:
            _, vlist_data = self._get_cell_data(values_list_offset)
            for i in range(values_count):
                if (i + 1) * 4 > len(vlist_data):
                    break
                vk_offset = struct.unpack("<I", vlist_data[i * 4:(i + 1) * 4])[0]
                val = self._parse_vk_cell(vk_offset)
                if val:
                    key.values[val.name] = val

        # Parse Subkeys
        if subkey_count > 0 and subkey_list_offset != 0xFFFFFFFF:
            sub_offsets = self._parse_subkey_list(subkey_list_offset)
            for s_off in sub_offsets:
                sub_key = self._parse_nk_cell(s_off, full_path)
                if sub_key:
                    key.subkeys[sub_key.name] = sub_key

        return key

    def _parse_vk_cell(self, cell_offset: int) -> Optional[RegValue]:
        _, cell_data = self._get_cell_data(cell_offset)
        if len(cell_data) < 0x14 or cell_data[:2] != b"vk":
            return None

        name_len, data_len = struct.unpack("<HI", cell_data[2:8])
        data_offset = struct.unpack("<I", cell_data[8:12])[0]
        val_type, flags = struct.unpack("<IH", cell_data[12:18])

        is_ascii = bool(flags & 0x0001)
        name_raw = cell_data[0x14:0x14 + name_len] if name_len > 0 else b""
        
        if name_len == 0:
            val_name = ""
        else:
            try:
                val_name = name_raw.decode("latin-1" if is_ascii else "utf-16-le", errors="replace")
            except Exception:
                val_name = name_raw.decode("latin-1", errors="replace")

        # Extract data
        # If high bit of data_len is set (data_len & 0x80000000), data is stored inline in data_offset
        if data_len & 0x80000000:
            actual_len = data_len & 0x7FFFFFFF
            raw_bytes = struct.pack("<I", data_offset)[:actual_len]
        else:
            _, raw_bytes = self._get_cell_data(data_offset)
            raw_bytes = raw_bytes[:data_len]

        parsed_val = self._decode_value(val_type, raw_bytes)
        return RegValue(name=val_name, val_type=val_type, raw_data=raw_bytes, parsed_value=parsed_val)

    def _decode_value(self, val_type: int, raw_bytes: bytes) -> Any:
        try:
            if val_type in [REG_SZ, REG_EXPAND_SZ]:
                return raw_bytes.decode("utf-16-le", errors="replace").rstrip("\x00")
            elif val_type == REG_MULTI_SZ:
                text = raw_bytes.decode("utf-16-le", errors="replace")
                return [s for s in text.split("\x00") if s]
            elif val_type == REG_DWORD:
                return struct.unpack("<I", raw_bytes[:4])[0] if len(raw_bytes) >= 4 else 0
            elif val_type == REG_QWORD:
                return struct.unpack("<Q", raw_bytes[:8])[0] if len(raw_bytes) >= 8 else 0
            elif val_type == REG_BINARY:
                return raw_bytes
            else:
                return raw_bytes
        except Exception:
            return raw_bytes

    def _parse_subkey_list(self, list_offset: int) -> List[int]:
        offsets = []
        _, cell_data = self._get_cell_data(list_offset)
        if len(cell_data) < 4:
            return offsets

        sig = cell_data[:2]
        count = struct.unpack("<H", cell_data[2:4])[0]

        if sig in [b"lf", b"lh"]:
            # Fast index elements are (offset 4 bytes, hash 4 bytes)
            for i in range(count):
                pos = 4 + (i * 8)
                if pos + 4 <= len(cell_data):
                    off = struct.unpack("<I", cell_data[pos:pos + 4])[0]
                    offsets.append(off)
        elif sig == b"li":
            for i in range(count):
                pos = 4 + (i * 4)
                if pos + 4 <= len(cell_data):
                    off = struct.unpack("<I", cell_data[pos:pos + 4])[0]
                    offsets.append(off)
        elif sig == b"ri":
            # List of sublists
            for i in range(count):
                pos = 4 + (i * 4)
                if pos + 4 <= len(cell_data):
                    sublist_off = struct.unpack("<I", cell_data[pos:pos + 4])[0]
                    offsets.extend(self._parse_subkey_list(sublist_off))

        return offsets

    def open_key(self, path: str) -> Optional[RegKey]:
        """
        Traverse and return key by relative path (e.g. 'Root\\InventoryApplicationFile' or 'Software\\Microsoft\\...')
        """
        if not self.root:
            return None

        clean_path = path.replace("/", "\\").strip("\\")
        parts = [p for p in clean_path.split("\\") if p]

        curr = self.root
        # Skip root name if match
        if parts and parts[0].lower() == curr.name.lower():
            parts = parts[1:]

        for part in parts:
            next_key = curr.get_subkey(part)
            if not next_key:
                return None
            curr = next_key

        return curr

    def iter_keys(self) -> Generator[RegKey, None, None]:
        """
        Walk all keys in registry hive.
        """
        if not self.root:
            return

        def walk(k: RegKey):
            yield k
            for sub in k.subkeys.values():
                yield from walk(sub)

        yield from walk(self.root)
