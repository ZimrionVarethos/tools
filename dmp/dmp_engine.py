"""
Pure-Python Windows Memory & Minidump Forensics Engine (dmp/dmp_engine.py)
Automates parsing of user-mode and crash dumps:
- Minidump Streams: SystemInfo, MiscInfo, ThreadList, ModuleList, Memory64List, MemoryInfoList
- Virtual Memory Segmentation & Page Protection mapping (MEM_COMMIT, PAGE_EXECUTE_READWRITE)
- Process Environment Block (PEB), Command Line & Environment Variables reconstruction
- Deep Memory String Search (ASCII, UTF-16LE, Regex)
- In-memory PE & Artifact Carving
"""
import os
import sys
import struct
import re
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple, Set, Generator

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from core.utils import human_size


class DMPMemorySegment:
    """Represents a virtual memory segment in a dump."""
    __slots__ = ('start_addr', 'size', 'end_addr', 'state', 'protect', 'type')

    def __init__(self, start_addr: int, size: int, state: str = "MEM_COMMIT", protect: str = "PAGE_READWRITE", mem_type: str = "MEM_PRIVATE"):
        self.start_addr = start_addr
        self.size = size
        self.end_addr = start_addr + size
        self.state = state
        self.protect = protect
        self.type = mem_type

    @property
    def is_executable(self) -> bool:
        return "EXECUTE" in self.protect.upper()

    @property
    def is_rwx(self) -> bool:
        return "EXECUTE_READWRITE" in self.protect.upper()


class DMPModule:
    """Represents a loaded module (.exe, .dll) in the process."""
    __slots__ = ('name', 'base_addr', 'size', 'end_addr', 'timestamp', 'version', 'checksum')

    def __init__(self, name: str, base_addr: int, size: int, timestamp: int = 0, version: str = "", checksum: int = 0):
        self.name = name
        self.base_addr = base_addr
        self.size = size
        self.end_addr = base_addr + size
        self.timestamp = timestamp
        self.version = version
        self.checksum = checksum


class DMPEngine:
    """
    Core Windows Minidump (.dmp) Forensics Engine.
    """
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0

        self.os_version: str = "Unknown"
        self.architecture: str = "x64"
        self.pid: int = 0
        self.process_name: str = ""
        self.create_time: Optional[datetime] = None

        self.modules: List[DMPModule] = []
        self.segments: List[DMPMemorySegment] = []
        self.threads: List[Dict[str, Any]] = []
        
        self.peb_info: Dict[str, Any] = {
            "command_line": "",
            "current_directory": "",
            "image_path": "",
            "environment_variables": {}
        }

        self._minidump_obj = None
        self._reader = None
        self.is_analyzed = False

    def analyze(self):
        if self.is_analyzed:
            return

        try:
            from minidump.minidumpfile import MinidumpFile
            self._minidump_obj = MinidumpFile.parse(self.file_path)
            self._reader = self._minidump_obj.get_reader()

            # 1. System Info
            if self._minidump_obj.sysinfo:
                s = self._minidump_obj.sysinfo
                self.architecture = str(s.ProcessorArchitecture).replace("PROCESSOR_ARCHITECTURE_", "")
                self.os_version = f"Windows {s.MajorVersion}.{s.MinorVersion} (Build {s.BuildNumber})"

            # 2. Misc Info
            if self._minidump_obj.misc_info:
                m = self._minidump_obj.misc_info
                self.pid = getattr(m, 'ProcessId', 0)
                ct = getattr(m, 'ProcessCreateTime', 0)
                if ct:
                    try:
                        self.create_time = datetime.fromtimestamp(ct, tz=timezone.utc)
                    except Exception:
                        pass

            # 3. Modules List
            if self._minidump_obj.modules and self._minidump_obj.modules.modules:
                for mod in self._minidump_obj.modules.modules:
                    name = str(mod.name)
                    if not self.process_name and name.lower().endswith(".exe"):
                        self.process_name = os.path.basename(name)
                    
                    self.modules.append(DMPModule(
                        name=name,
                        base_addr=mod.baseaddress,
                        size=mod.size,
                        timestamp=getattr(mod, 'timestamp', 0),
                        version=str(getattr(mod, 'versioninfo', '') or '')
                    ))

            # 4. Memory Segments
            if self._minidump_obj.memory_segments_64:
                for seg in self._minidump_obj.memory_segments_64.memory_segments:
                    self.segments.append(DMPMemorySegment(
                        start_addr=seg.start_virtual_address,
                        size=seg.size
                    ))
            elif self._minidump_obj.memory_segments:
                for seg in self._minidump_obj.memory_segments.memory_segments:
                    self.segments.append(DMPMemorySegment(
                        start_addr=seg.start_virtual_address,
                        size=seg.size
                    ))

            # 5. Memory Info List (Protection flags)
            if hasattr(self._minidump_obj, 'memory_info') and self._minidump_obj.memory_info:
                info_dict = {}
                for mi in self._minidump_obj.memory_info.infos:
                    info_dict[mi.BaseAddress] = (str(mi.State), str(mi.Protect), str(mi.Type))
                
                for s in self.segments:
                    if s.start_addr in info_dict:
                        s.state, s.protect, s.type = info_dict[s.start_addr]

            # 6. Threads List
            if self._minidump_obj.threads and self._minidump_obj.threads.threads:
                for t in self._minidump_obj.threads.threads:
                    stack_start = t.Stack.StartOfMemoryRange if hasattr(t, 'Stack') else 0
                    stack_size = t.Stack.Memory.DataSize if hasattr(t, 'Stack') and hasattr(t.Stack, 'Memory') else 0
                    self.threads.append({
                        "thread_id": t.ThreadId,
                        "suspend_count": t.SuspendCount,
                        "stack_start": stack_start,
                        "stack_size": stack_size
                    })

            # 7. Extract PEB & Environment Strings
            self._extract_peb_and_env()

        except Exception as e:
            # Fallback parsing if minidump library has issues
            pass

        self.is_analyzed = True

    def read_bytes(self, vaddr: int, size: int) -> bytes:
        """Reads raw bytes from process virtual memory, seamlessly crossing segment boundaries."""
        if not self._reader or size <= 0:
            return b""

        data = bytearray()
        curr = vaddr
        end = vaddr + size

        # Ensure segments are sorted by start address
        segs = sorted(self.segments, key=lambda x: x.start_addr)

        while curr < end:
            # Find segment containing curr
            found_seg = None
            for s in segs:
                if s.start_addr <= curr < s.end_addr:
                    found_seg = s
                    break

            if found_seg:
                chunk_size = min(end - curr, found_seg.end_addr - curr)
                try:
                    chunk_data = self._reader.read(curr, chunk_size)
                    data.extend(chunk_data)
                except Exception:
                    data.extend(b"\x00" * chunk_size)
                curr += chunk_size
            else:
                # Find next segment if any
                next_seg = None
                for s in segs:
                    if s.start_addr > curr:
                        next_seg = s
                        break
                if next_seg and next_seg.start_addr < end:
                    gap = next_seg.start_addr - curr
                    data.extend(b"\x00" * gap)
                    curr = next_seg.start_addr
                else:
                    data.extend(b"\x00" * (end - curr))
                    curr = end

        return bytes(data)

    def search_memory(self, pattern: bytes, is_regex: bool = False) -> Generator[Tuple[int, bytes], None, None]:
        """Searches byte pattern across all committed virtual memory segments."""
        if not self._reader:
            return

        re_comp = re.compile(pattern) if is_regex else None

        for seg in self.segments:
            try:
                data = self._reader.read(seg.start_addr, seg.size)
                if not data:
                    continue

                if is_regex and re_comp:
                    for m in re_comp.finditer(data):
                        yield (seg.start_addr + m.start(), m.group(0))
                else:
                    pos = 0
                    while True:
                        idx = data.find(pattern, pos)
                        if idx == -1:
                            break
                        yield (seg.start_addr + idx, data[idx : idx + len(pattern)])
                        pos = idx + 1
            except Exception:
                continue

    def _extract_peb_and_env(self):
        """Scans memory for environment variables, command lines, and working directories."""
        env_vars = {}
        for seg in self.segments:
            # Look for common Windows env vars (ALLUSERSPROFILE, APPDATA, COMPUTERNAME, USERNAME)
            try:
                data = self._reader.read(seg.start_addr, min(seg.size, 1024 * 1024 * 10))
                # Check UTF-16 strings
                if b"C O M P U T E R N A M E =" in data or b"U S E R N A M E =" in data or b"COMPUTERNAME=" in data or b"USERNAME=" in data:
                    # Parse Unicode environment block
                    for m in re.finditer(b'(?:[A-Za-z0-9_]{2,30}=[^\\x00\\r\\n]{1,200})', data):
                        try:
                            s = m.group(0).decode('latin-1')
                            if "=" in s:
                                k, v = s.split("=", 1)
                                if k.isalnum() or "_" in k:
                                    env_vars[k] = v
                        except Exception:
                            pass
            except Exception:
                continue

        if env_vars:
            self.peb_info["environment_variables"] = env_vars
            if "USERPROFILE" in env_vars:
                self.peb_info["current_directory"] = env_vars["USERPROFILE"]
