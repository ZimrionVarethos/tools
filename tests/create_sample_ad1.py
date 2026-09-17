"""
Enhanced Synthetic AD1 Image Generator
Builds a realistic AD1 forensic evidence container with:
- Browser History (Google Chrome SQLite & Mozilla Firefox places.sqlite)
- Amcache.hve (Windows 10/11 InventoryApplicationFile & Win7 File execution artifacts)
- NTUSER.DAT (UserAssist ROT13 executions, TypedPaths, RunMRU Win+R, RecentDocs)
- Windows Recent Items (.lnk shortcut binary files)
"""
import os
import struct
import zlib
import sqlite3
import tempfile
import time
import codecs
import json
import base64
from typing import Tuple


def create_mock_chrome_history(db_path: str):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE urls (
        id INTEGER PRIMARY KEY,
        url LONGVARCHAR,
        title LONGVARCHAR,
        visit_count INTEGER DEFAULT 0,
        typed_count INTEGER DEFAULT 0,
        last_visit_time INTEGER NOT NULL,
        hidden INTEGER DEFAULT 0
    );
    """)
    cur.execute("""
    CREATE TABLE visits (
        id INTEGER PRIMARY KEY,
        url INTEGER NOT NULL,
        visit_time INTEGER NOT NULL,
        from_visit INTEGER,
        transition INTEGER DEFAULT 0,
        segment_id INTEGER,
        visit_duration INTEGER DEFAULT 0
    );
    """)

    base_ts = 13430845800 * 1000000
    test_data = [
        (1, "https://www.google.com/search?q=kali+linux+download", "kali linux download - Google Search", 5, 2, base_ts),
        (2, "https://github.com/torvalds/linux", "torvalds/linux: Linux kernel source tree", 12, 1, base_ts + 3600_000_000),
        (3, "https://duckduckgo.com/?q=digital+forensics+dfir+tools", "digital forensics dfir tools at DuckDuckGo", 3, 0, base_ts + 7200_000_000),
        (4, "https://www.youtube.com/results?search_query=malware+analysis+tutorial", "malware analysis tutorial - YouTube", 8, 1, base_ts + 10800_000_000),
        (5, "https://news.ycombinator.com/", "Hacker News", 25, 4, base_ts + 14400_000_000),
        (6, "https://portal.bank.com/auth/login", "Secure Banking Portal - Sign In", 4, 2, base_ts + 18000_000_000),
    ]

    for row in test_data:
        cur.execute("INSERT INTO urls VALUES (?, ?, ?, ?, ?, ?, 0)", row)
        cur.execute("INSERT INTO visits (url, visit_time, transition) VALUES (?, ?, ?)", (row[0], row[5], 1))

    conn.commit()
    conn.close()


def create_mock_login_data(db_path: str):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE logins (
        origin_url VARCHAR NOT NULL,
        action_url VARCHAR,
        username_element VARCHAR,
        username_value VARCHAR,
        password_element VARCHAR,
        password_value BLOB,
        submit_element VARCHAR,
        signon_realm VARCHAR NOT NULL,
        date_created INTEGER NOT NULL,
        blacklisted_by_user INTEGER NOT NULL,
        scheme INTEGER NOT NULL,
        password_type INTEGER,
        times_used INTEGER,
        form_data BLOB,
        date_synced INTEGER,
        display_name VARCHAR,
        icon_url VARCHAR,
        federation_url VARCHAR,
        skip_zero_click INTEGER,
        generation_upload_status INTEGER,
        possible_username_pairs BLOB,
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        date_last_used INTEGER NOT NULL DEFAULT 0,
        moving_blocked_for BLOB,
        date_password_modified INTEGER NOT NULL DEFAULT 0
    );
    """)
    pwd_blob = b"v10\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12encrypted_aes_payload_bytes_for_auth"
    cur.execute("""
    INSERT INTO logins (origin_url, action_url, username_element, username_value, password_element, password_value, signon_realm, date_created, blacklisted_by_user, scheme, times_used)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 5)
    """, ("https://portal.bank.com/auth/login", "https://portal.bank.com/api/v1/auth", "username", "alice.investigator@protonmail.com", "password", pwd_blob, "https://portal.bank.com/", 13430845800 * 1000000))
    conn.commit()
    conn.close()


def create_mock_firefox_places(db_path: str):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE moz_places (
        id INTEGER PRIMARY KEY,
        url LONGVARCHAR,
        title LONGVARCHAR,
        visit_count INTEGER DEFAULT 0,
        typed INTEGER DEFAULT 0,
        last_visit_date INTEGER
    );
    """)
    cur.execute("""
    CREATE TABLE moz_historyvisits (
        id INTEGER PRIMARY KEY,
        place_id INTEGER,
        visit_date INTEGER,
        visit_type INTEGER
    );
    """)

    base_ts = 1786438800 * 1000000
    test_data = [
        (1, "https://www.google.com/search?q=ghidra+reverse+engineering+cheatsheet", "ghidra reverse engineering cheatsheet - Google Search", 7, base_ts),
        (2, "https://www.wireshark.org/download.html", "Wireshark · Go Deep", 2, base_ts + 1800_000_000),
        (3, "https://bing.com/search?q=threat+hunting+sigma+rules", "threat hunting sigma rules - Bing", 4, base_ts + 3600_000_000),
    ]

    for row in test_data:
        cur.execute("INSERT INTO moz_places VALUES (?, ?, ?, ?, 1, ?)", row)
        cur.execute("INSERT INTO moz_historyvisits VALUES (?, ?, ?, 1)", (row[0], row[0], row[4]))

    conn.commit()
    conn.close()


def create_mock_lnk_file(target_path: str, size: int = 1048576) -> bytes:
    """
    Build a valid Windows Shell Link (.lnk) binary structure.
    """
    buf = bytearray(0x4C)
    struct.pack_into("<I", buf, 0, 0x4C) # HeaderSize
    # CLSID
    buf[4:20] = bytes.fromhex("0114020000000000c000000000000046")
    # LinkFlags: HasLinkInfo (0x02) | HasRelativePath (0x08) | IsUnicode (0x80)
    struct.pack_into("<I", buf, 0x14, 0x02 | 0x08 | 0x80)
    struct.pack_into("<I", buf, 0x18, 0x20) # FileAttributes
    
    # Target Timestamps (2026-08-12 11:00:00 UTC)
    ft = 13431005600 * 10000000
    struct.pack_into("<Q", buf, 0x1C, ft) # Creation
    struct.pack_into("<Q", buf, 0x24, ft + 36000000000) # Access
    struct.pack_into("<Q", buf, 0x2C, ft + 18000000000) # Write
    struct.pack_into("<I", buf, 0x34, size) # FileSize

    # LinkInfo section
    link_info = bytearray()
    local_path_ascii = target_path.encode("latin-1", errors="replace") + b"\x00"
    header_size = 0x1C
    local_base_offset = header_size
    info_size = header_size + len(local_path_ascii)

    link_info.extend(struct.pack("<IIIIIII", info_size, header_size, 0x01, local_base_offset, 0, 0, 0))
    link_info.extend(local_path_ascii)

    buf.extend(link_info)

    # Relative path string
    rel_path = f".\\{os.path.basename(target_path)}".encode("utf-16-le")
    buf.extend(struct.pack("<H", len(rel_path) // 2))
    buf.extend(rel_path)

    return bytes(buf)


def build_synthetic_regf_hive(hive_type: str = "amcache") -> bytes:
    """
    Build a clean, valid REGF hive structure with binary cell records.
    """
    data = bytearray(0x4000) # 16KB hive
    # REGF Header
    data[0:4] = b"regf"
    struct.pack_into("<I", data, 0x24, 0x20) # Root Cell Offset (relative to 0x1000)
    struct.pack_into("<I", data, 0x28, 0x3000) # Hive Bins Data Size

    # HBIN at 0x1000
    hbin_off = 0x1000
    data[hbin_off:hbin_off + 4] = b"hbin"
    struct.pack_into("<I", data, hbin_off + 4, 0) # Offset from 1st hbin
    struct.pack_into("<I", data, hbin_off + 8, 0x3000) # HBIN Size

    cursor = hbin_off + 0x20

    # Helper to allocate cell
    def alloc_cell(raw_bytes: bytes) -> int:
        nonlocal cursor
        cell_rel = cursor - 0x1000
        size = len(raw_bytes) + 4
        # Pad to 8 bytes
        if size % 8 != 0:
            size += 8 - (size % 8)
        
        # Negative size for allocated cell
        struct.pack_into("<i", data, cursor, -size)
        data[cursor + 4:cursor + 4 + len(raw_bytes)] = raw_bytes
        cursor += size
        return cell_rel

    # Helper to build vk (value) cell
    def make_vk(name: str, val_type: int, val_bytes: bytes) -> int:
        name_ascii = name.encode("latin-1")
        vk_data = bytearray(0x14 + len(name_ascii))
        vk_data[0:2] = b"vk"
        struct.pack_into("<HI", vk_data, 2, len(name_ascii), len(val_bytes))
        
        # Check inline data
        if len(val_bytes) <= 4:
            inline_val = struct.unpack("<I", val_bytes.ljust(4, b"\x00"))[0]
            struct.pack_into("<I", vk_data, 8, inline_val)
            struct.pack_into("<I", vk_data, 12, val_type)
            struct.pack_into("<H", vk_data, 16, 0x0001) # ASCII name flag
            struct.pack_into("<I", vk_data, 4, len(val_bytes) | 0x80000000) # High bit
        else:
            # Separate data cell
            data_cell_off = alloc_cell(val_bytes)
            struct.pack_into("<I", vk_data, 8, data_cell_off)
            struct.pack_into("<I", vk_data, 12, val_type)
            struct.pack_into("<H", vk_data, 16, 0x0001)

        vk_data[0x14:0x14 + len(name_ascii)] = name_ascii
        return alloc_cell(vk_data)

    # Helper to build nk (key) cell
    def make_nk(name: str, subkey_offsets: list, val_offsets: list, ft: int = 13431005600 * 10000000) -> int:
        name_ascii = name.encode("latin-1")
        nk_data = bytearray(0x4C + len(name_ascii))
        nk_data[0:2] = b"nk"
        # Flags (0x0020 = ASCII), Timestamp
        struct.pack_into("<HQ", nk_data, 2, 0x0020, ft)
        
        # Subkeys list cell
        if subkey_offsets:
            lf_data = bytearray(4 + len(subkey_offsets) * 8)
            lf_data[0:2] = b"lh"
            struct.pack_into("<H", lf_data, 2, len(subkey_offsets))
            for i, so in enumerate(subkey_offsets):
                struct.pack_into("<II", lf_data, 4 + i * 8, so, 0)
            sub_list_off = alloc_cell(lf_data)
            struct.pack_into("<I", nk_data, 0x14, len(subkey_offsets))
            struct.pack_into("<I", nk_data, 0x1C, sub_list_off)
        else:
            struct.pack_into("<I", nk_data, 0x14, 0)
            struct.pack_into("<I", nk_data, 0x1C, 0xFFFFFFFF)

        # Values list cell
        if val_offsets:
            vlist_data = bytearray(len(val_offsets) * 4)
            for i, vo in enumerate(val_offsets):
                struct.pack_into("<I", vlist_data, i * 4, vo)
            val_list_off = alloc_cell(vlist_data)
            struct.pack_into("<I", nk_data, 0x24, len(val_offsets))
            struct.pack_into("<I", nk_data, 0x28, val_list_off)
        else:
            struct.pack_into("<I", nk_data, 0x24, 0)
            struct.pack_into("<I", nk_data, 0x28, 0xFFFFFFFF)

        struct.pack_into("<H", nk_data, 0x48, len(name_ascii))
        nk_data[0x4C:0x4C + len(name_ascii)] = name_ascii
        return alloc_cell(nk_data)

    if hive_type == "amcache":
        # Amcache Win10/11 InventoryApplicationFile structure:
        # Root -> InventoryApplicationFile -> [FileKeys...]
        file_keys = []
        
        # Entry 1: mimikatz.exe (in Temp!)
        vk1 = make_vk("LowerCaseLongPath", 1, "c:\\users\\alice\\appdata\\local\\temp\\mimikatz.exe\x00".encode("utf-16-le"))
        vk2 = make_vk("FileId", 1, "0000a1b2c3d4e5f60718293a4b5c6d7e8f9012345678\x00".encode("utf-16-le"))
        vk3 = make_vk("Size", 4, struct.pack("<I", 1254400))
        vk4 = make_vk("Publisher", 1, "gentilkiwi\x00".encode("utf-16-le"))
        vk5 = make_vk("Name", 1, "mimikatz.exe\x00".encode("utf-16-le"))
        file_keys.append(make_nk("0000a1b2c3d4e5f60718293a4b5c6d7e8f9012345678", [], [vk1, vk2, vk3, vk4, vk5]))

        # Entry 2: powershell.exe
        vk_ps1 = make_vk("LowerCaseLongPath", 1, "c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe\x00".encode("utf-16-le"))
        vk_ps2 = make_vk("FileId", 1, "00009876543210fedcba0987654321fedcba09876543\x00".encode("utf-16-le"))
        vk_ps3 = make_vk("Size", 4, struct.pack("<I", 450560))
        vk_ps4 = make_vk("Publisher", 1, "Microsoft Corporation\x00".encode("utf-16-le"))
        vk_ps5 = make_vk("Name", 1, "powershell.exe\x00".encode("utf-16-le"))
        file_keys.append(make_nk("00009876543210fedcba0987654321fedcba09876543", [], [vk_ps1, vk_ps2, vk_ps3, vk_ps4, vk_ps5]))

        inv_file_key_off = make_nk("InventoryApplicationFile", file_keys, [])
        root_key_off = make_nk("Root", [inv_file_key_off], [])

    else:
        # NTUSER.DAT Hive structure:
        # Root -> Software -> Microsoft -> Windows -> CurrentVersion -> Explorer -> [UserAssist, TypedPaths, RunMRU]
        
        # 1. UserAssist ROT-13: notepad.exe -> abgrcnq.rkr
        rot_cmd = codecs.encode("C:\\Windows\\System32\\cmd.exe", "rot_13")
        rot_notepad = codecs.encode("C:\\Windows\\System32\\notepad.exe", "rot_13")
        
        # UserAssist 72-byte binary structure (run count = 15, focus count = 8)
        ua_raw = bytearray(72)
        struct.pack_into("<III", ua_raw, 4, 15, 8, 45000) # run=15, focus=8, focus_time=45s
        struct.pack_into("<Q", ua_raw, 60, 13431005600 * 10000000) # last exec
        
        vk_ua1 = make_vk(rot_cmd, 3, bytes(ua_raw))
        vk_ua2 = make_vk(rot_notepad, 3, bytes(ua_raw))
        count_key_off = make_nk("Count", [], [vk_ua1, vk_ua2])
        guid_key_off = make_nk("{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}", [count_key_off], [])
        user_assist_off = make_nk("UserAssist", [guid_key_off], [])

        # 2. TypedPaths
        vk_tp1 = make_vk("url1", 1, "C:\\Users\\Alice\\Downloads\x00".encode("utf-16-le"))
        vk_tp2 = make_vk("url2", 1, "\\\\192.168.1.100\\share\x00".encode("utf-16-le"))
        typed_paths_off = make_nk("TypedPaths", [], [vk_tp1, vk_tp2])

        # 3. RunMRU (Win + R commands)
        vk_r1 = make_vk("a", 1, "powershell.exe -ExecutionPolicy Bypass\\1\x00".encode("utf-16-le"))
        vk_r2 = make_vk("b", 1, "regedit.exe\\1\x00".encode("utf-16-le"))
        vk_r3 = make_vk("MRUList", 1, "ab\x00".encode("utf-16-le"))
        run_mru_off = make_nk("RunMRU", [], [vk_r1, vk_r2, vk_r3])

        # Tree assembly
        explorer_off = make_nk("Explorer", [user_assist_off, typed_paths_off, run_mru_off], [])
        cur_ver_off = make_nk("CurrentVersion", [explorer_off], [])
        win_off = make_nk("Windows", [cur_ver_off], [])
        ms_off = make_nk("Microsoft", [win_off], [])
        soft_off = make_nk("Software", [ms_off], [])
        root_key_off = make_nk("Root", [soft_off], [])

    # Write root cell offset to REGF header
    struct.pack_into("<I", data, 0x24, root_key_off)

    return bytes(data)


def build_full_ad1_image(output_ad1_path: str):
    with tempfile.TemporaryDirectory() as tmpdir:
        chrome_hist = os.path.join(tmpdir, "History")
        ff_places = os.path.join(tmpdir, "places.sqlite")
        create_mock_chrome_history(chrome_hist)
        create_mock_firefox_places(ff_places)

        with open(chrome_hist, "rb") as f: chrome_bytes = f.read()
        with open(ff_places, "rb") as f: firefox_bytes = f.read()

        amcache_bytes = build_synthetic_regf_hive("amcache")
        ntuser_bytes = build_synthetic_regf_hive("ntuser")
        lnk1_bytes = create_mock_lnk_file("C:\\Users\\Alice\\Documents\\passwords.xlsx", 524288)
        lnk2_bytes = create_mock_lnk_file("C:\\Users\\Alice\\AppData\\Local\\Temp\\mimikatz.exe", 1254400)

        stream = bytearray()
        
        # 1. Segment Header (512 bytes)
        seg_hdr = bytearray(512)
        seg_hdr[0:16] = b"ADSEGMENTEDFILE\x00"
        struct.pack_into("<I", seg_hdr, 0x18, 1)
        struct.pack_into("<I", seg_hdr, 0x1c, 1)
        struct.pack_into("<I", seg_hdr, 0x22, 1000)
        struct.pack_into("<I", seg_hdr, 0x28, 512)
        stream.extend(seg_hdr)

        # 2. Logical Header
        log_hdr = bytearray(512)
        log_hdr[0:16] = b"ADLOGICALIMAGE\x00\x00"
        struct.pack_into("<I", log_hdr, 0x10, 2)
        struct.pack_into("<I", log_hdr, 0x18, 65536)
        struct.pack_into("<I", log_hdr, 0x2c, 15)
        log_hdr[0x30:0x33] = b"AD\x00"
        log_hdr[0x5c:0x5c+15] = b"CompleteEvidence"

        logical_data = bytearray(log_hdr)

        def write_compressed(raw: bytes) -> Tuple[int, int]:
            comp = zlib.compress(raw)
            comp_off = len(logical_data)
            logical_data.extend(comp)
            meta_off = len(logical_data)
            logical_data.extend(struct.pack("<QQQ", 1, comp_off, comp_off + len(comp)))
            return meta_off, len(raw)

        z_chrome, s_chrome = write_compressed(chrome_bytes)
        z_ff, s_ff = write_compressed(firefox_bytes)
        z_amcache, s_amcache = write_compressed(amcache_bytes)
        z_ntuser, s_ntuser = write_compressed(ntuser_bytes)
        z_lnk1, s_lnk1 = write_compressed(lnk1_bytes)
        z_lnk2, s_lnk2 = write_compressed(lnk2_bytes)

        def create_item(name: str, item_type: int, size: int = 0, zlib_meta: int = 0) -> int:
            addr = len(logical_data)
            name_bytes = name.encode("utf-8")
            name_len = len(name_bytes)
            buf = bytearray(0x30 + name_len + 8)
            struct.pack_into("<QQQQQII", buf, 0, 0, 0, 0, zlib_meta, size, item_type, name_len)
            buf[0x30:0x30 + name_len] = name_bytes
            logical_data.extend(buf)
            return addr

        # Items Layout:
        # Root: Users
        #   Child: Alice
        #     Child: NTUSER.DAT (file) -> sibling: AppData
        #       AppData -> Local -> [Google/Chrome/User Data/Default/History, Temp]
        #       AppData -> Roaming -> Microsoft -> Windows -> Recent -> [passwords.xlsx.lnk, mimikatz.exe.lnk]
        #   Sibling of Users: Windows
        #     Windows -> appcompat -> Programs -> Amcache.hve (file)

        # Alice Recent
        addr_lnk2 = create_item("mimikatz.exe.lnk", 0x31, s_lnk2, z_lnk2)
        addr_lnk1 = create_item("passwords.xlsx.lnk", 0x31, s_lnk1, z_lnk1)
        struct.pack_into("<Q", logical_data, addr_lnk1 + 0x00, addr_lnk2) # sibling
        
        addr_recent = create_item("Recent", 0x05)
        struct.pack_into("<Q", logical_data, addr_recent + 0x08, addr_lnk1)

        addr_win_rec = create_item("Windows", 0x05)
        struct.pack_into("<Q", logical_data, addr_win_rec + 0x08, addr_recent)

        addr_ms_rec = create_item("Microsoft", 0x05)
        struct.pack_into("<Q", logical_data, addr_ms_rec + 0x08, addr_win_rec)

        addr_roaming_alice = create_item("Roaming", 0x05)
        struct.pack_into("<Q", logical_data, addr_roaming_alice + 0x08, addr_ms_rec)

        # Alice Chrome Preferences JSON
        pref_data = {
            "extensions": {
                "settings": {
                    "ghbmnnjooekpmoecnnnilnnbdlolhkhi": {
                        "manifest": {
                            "name": "Google Docs Offline",
                            "version": "1.4"
                        },
                        "was_installed_by_default": True,
                        "from_webstore": True
                    },
                    "kcljodffpfpnjkggjjdbldmhkdhhceoe": {
                        "manifest": {
                            "name": "QuickSessionSync",
                            "version": "1.0.2",
                            "permissions": ["cookies", "<all_urls>", "webRequest", "storage"]
                        },
                        "was_installed_by_default": False,
                        "from_webstore": False,
                        "location": 4,
                        "install_time": "13431005600000000"
                    }
                }
            }
        }
        pref_bytes = json.dumps(pref_data, indent=2).encode("utf-8")

        # Mock LevelDB WAL log for rogue extension (containing stolen cookie tokens and discord webhook)
        ldb_data = bytearray()
        # Write-batch with cookie payload
        payload_cookie = '{"c_user": "1000849281729", "xs": "27:AbCdEf12345", "sessionid": "1984279184_auth", "discord_c2": "https://discord.com/api/webhooks/1234567890/abcdefghijklmnopqrstuvwxyz"}'.encode("utf-8")
        batch = bytearray(12)
        struct.pack_into("<QI", batch, 0, 100, 1) # seq=100, count=1
        batch.append(1) # Value type
        # Key: "exfiltrated_cookies"
        k_name = b"exfiltrated_cookies"
        batch.extend(bytes([len(k_name)]))
        batch.extend(k_name)
        # Value
        batch.extend(bytes([len(payload_cookie)]))
        batch.extend(payload_cookie)

        # LevelDB log frame
        ldb_log = bytearray()
        crc = 0x12345678
        ldb_log.extend(struct.pack("<IHB", crc, len(batch), 1)) # Full chunk
        ldb_log.extend(batch)
        leveldb_bytes = bytes(ldb_log)

        # ---------------------------------------------
        # Real Cryptographic DPAPI Test Construction
        # ---------------------------------------------
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.backends import default_backend
        import hashlib, hmac

        # 1. MasterKey with password "Password123"
        raw_masterkey = b"M" * 64
        mk_salt = b"0123456789ABCDEF"
        mk_rounds = 8000
        derived_mk_key = hashlib.pbkdf2_hmac("sha512", "Password123".encode("utf-16le"), mk_salt, mk_rounds, dklen=32)
        iv_zero = b"\x00" * 16
        c_mk = Cipher(algorithms.AES(derived_mk_key), modes.CBC(iv_zero), backend=default_backend())
        enc_mk_payload = c_mk.encryptor().update(raw_masterkey) + c_mk.encryptor().finalize()

        # Build MasterKey file buffer
        mk_hmac = hmac.new(derived_mk_key, enc_mk_payload, hashlib.sha512).digest()
        mk_buf = bytearray()
        mk_buf.extend(struct.pack("<I", 2)) # Version
        mk_buf.extend(b"\x00" * 76) # Guid / Header
        # MasterKey struct marker
        mk_buf.extend(struct.pack("<I", 2)) # Sub-version
        mk_buf.extend(mk_salt) # Salt 16B
        mk_buf.extend(struct.pack("<III", mk_rounds, 0x800e, 0x6610)) # Rounds, SHA512, AES256
        mk_buf.extend(enc_mk_payload) # 64B
        mk_buf.extend(mk_hmac) # 64B HMAC
        dpapi_key_bytes = bytes(mk_buf)

        # 2. Local State with Chrome AES-256 key
        chrome_aes_key = b"\x11\x22\x33\x44" * 8 # 32 bytes
        blob_salt = b"FEDCBA9876543210" # 16B
        sym_key = hmac.new(raw_masterkey, blob_salt, hashlib.sha512).digest()[:32]
        c_blob = Cipher(algorithms.AES(sym_key), modes.CBC(iv_zero), backend=default_backend())
        enc_chrome_key = c_blob.encryptor().update(chrome_aes_key) + c_blob.encryptor().finalize()

        # CryptProtectData Blob
        blob_buf = bytearray()
        blob_buf.extend(struct.pack("<I", 1)) # Version
        blob_buf.extend(b"\x00" * 16) # Provider GUID
        blob_buf.extend(struct.pack("<I", 1)) # MasterKey version
        blob_buf.extend(b"a1b2c3d4e5f67890") # MasterKey GUID
        blob_buf.extend(struct.pack("<II", 0, 0)) # Flags, Description length (0)
        blob_buf.extend(struct.pack("<II", 0x6610, 0x800e)) # CALG_AES_256, CALG_SHA_512
        blob_buf.extend(struct.pack("<I", len(blob_salt))) # Salt length
        blob_buf.extend(blob_salt) # Salt
        blob_buf.extend(struct.pack("<I", len(enc_chrome_key))) # Cipher length
        blob_buf.extend(enc_chrome_key) # Ciphertext
        blob_buf.extend(struct.pack("<I", 64)) # Sign len
        blob_buf.extend(b"\x00" * 64) # Signature

        local_state_b64 = base64.b64encode(b"DPAPI" + bytes(blob_buf)).decode("ascii")
        local_state_data = {
            "os_crypt": {
                "encrypted_key": local_state_b64
            }
        }
        local_state_bytes = json.dumps(local_state_data, indent=2).encode("utf-8")

        # 3. Login Data encrypted with chrome_aes_key
        # Plaintext password = "SuperSecretBankPassword2026!"
        nonce = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12" # 12 bytes
        aesgcm = AESGCM(chrome_aes_key)
        encrypted_pwd = b"v10" + nonce + aesgcm.encrypt(nonce, b"SuperSecretBankPassword2026!", None)

        with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as tf:
            tf.close()
            conn = sqlite3.connect(tf.name)
            cur = conn.cursor()
            cur.execute("""
            CREATE TABLE logins (
                origin_url VARCHAR NOT NULL,
                action_url VARCHAR,
                username_element VARCHAR,
                username_value VARCHAR,
                password_element VARCHAR,
                password_value BLOB,
                submit_element VARCHAR,
                signon_realm VARCHAR NOT NULL,
                date_created INTEGER NOT NULL,
                blacklisted_by_user INTEGER NOT NULL,
                scheme INTEGER NOT NULL,
                password_type INTEGER,
                times_used INTEGER,
                form_data BLOB,
                date_synced INTEGER,
                display_name VARCHAR,
                icon_url VARCHAR,
                federation_url VARCHAR,
                skip_zero_click INTEGER,
                generation_upload_status INTEGER,
                possible_username_pairs BLOB,
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date_last_used INTEGER NOT NULL DEFAULT 0,
                moving_blocked_for BLOB,
                date_password_modified INTEGER NOT NULL DEFAULT 0
            );
            """)
            cur.execute("""
            INSERT INTO logins (origin_url, action_url, username_element, username_value, password_element, password_value, signon_realm, date_created, blacklisted_by_user, scheme, times_used)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 5)
            """, ("https://portal.bank.com/auth/login", "https://portal.bank.com/api/v1/auth", "username", "alice.investigator@protonmail.com", "password", encrypted_pwd, "https://portal.bank.com/", 13430845800 * 1000000))
            conn.commit()
            conn.close()

            with open(tf.name, "rb") as f:
                login_data_bytes = f.read()
            os.remove(tf.name)

        # Mock SAM & SYSTEM hives
        sam_bytes = b"regf\x00\x00\x00\x00synthetic_sam_hive"
        system_bytes = b"regf\x00\x00\x00\x00synthetic_system_hive"

        z_pref, s_pref = write_compressed(pref_bytes)
        z_ldb, s_ldb = write_compressed(leveldb_bytes)
        z_ldata, s_ldata = write_compressed(login_data_bytes)
        z_lstate, s_lstate = write_compressed(local_state_bytes)
        z_sam, s_sam = write_compressed(sam_bytes)
        z_sys, s_sys = write_compressed(system_bytes)
        z_dpapi, s_dpapi = write_compressed(dpapi_key_bytes)

        # DPAPI Protect Folder inside Roaming:
        # Roaming -> Microsoft -> Protect -> S-1-5-21-123456789-1001 -> a1b2c3d4-e5f6-7890-abcd-ef0123456789
        addr_dpapi_file = create_item("a1b2c3d4-e5f6-7890-abcd-ef0123456789", 0x31, s_dpapi, z_dpapi)
        addr_sid_folder = create_item("S-1-5-21-123456789-1001", 0x05)
        struct.pack_into("<Q", logical_data, addr_sid_folder + 0x08, addr_dpapi_file)

        addr_protect = create_item("Protect", 0x05)
        struct.pack_into("<Q", logical_data, addr_protect + 0x08, addr_sid_folder)

        # Microsoft children: Windows -> Protect
        struct.pack_into("<Q", logical_data, addr_win_rec + 0x00, addr_protect) # Windows sibling -> Protect

        # Alice Chrome Items Hierarchy:
        # Default -> [History -> Login Data -> Preferences -> Local Extension Settings]
        addr_ldb_file = create_item("000003.log", 0x31, s_ldb, z_ldb)
        addr_ext_id_folder = create_item("kcljodffpfpnjkggjjdbldmhkdhhceoe", 0x05)
        struct.pack_into("<Q", logical_data, addr_ext_id_folder + 0x08, addr_ldb_file)

        addr_local_ext_set = create_item("Local Extension Settings", 0x05)
        struct.pack_into("<Q", logical_data, addr_local_ext_set + 0x08, addr_ext_id_folder)

        addr_pref = create_item("Preferences", 0x31, s_pref, z_pref)
        struct.pack_into("<Q", logical_data, addr_pref + 0x00, addr_local_ext_set) # sibling

        addr_login_data = create_item("Login Data", 0x31, s_ldata, z_ldata)
        struct.pack_into("<Q", logical_data, addr_login_data + 0x00, addr_pref) # sibling

        addr_hist = create_item("History", 0x31, s_chrome, z_chrome)
        struct.pack_into("<Q", logical_data, addr_hist + 0x00, addr_login_data) # sibling

        addr_default = create_item("Default", 0x05)
        struct.pack_into("<Q", logical_data, addr_default + 0x08, addr_hist)

        addr_local_state = create_item("Local State", 0x31, s_lstate, z_lstate)
        struct.pack_into("<Q", logical_data, addr_default + 0x00, addr_local_state) # Default sibling -> Local State

        addr_userdata = create_item("User Data", 0x05)
        struct.pack_into("<Q", logical_data, addr_userdata + 0x08, addr_default)

        addr_chrome = create_item("Chrome", 0x05)
        struct.pack_into("<Q", logical_data, addr_chrome + 0x08, addr_userdata)

        addr_google = create_item("Google", 0x05)
        struct.pack_into("<Q", logical_data, addr_google + 0x08, addr_chrome)

        addr_local = create_item("Local", 0x05)
        struct.pack_into("<Q", logical_data, addr_local + 0x08, addr_google)
        # Sibling Local -> Roaming
        struct.pack_into("<Q", logical_data, addr_local + 0x00, addr_roaming_alice)

        addr_appdata_alice = create_item("AppData", 0x05)
        struct.pack_into("<Q", logical_data, addr_appdata_alice + 0x08, addr_local)

        # Alice Sensitive Artifacts
        flag_txt = b"Congratulations forensic investigator!\nHere is your objective:\nFLAG{4dv4nc3d_df1r_ad1_p4rs3r_succ3ss}\nKeep this secret!\n"
        aws_env = b"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nPORT=8080\n"
        ssh_key = b"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n-----END OPENSSH PRIVATE KEY-----\n"
        b64_zip = b"PK\x03\x04synthetic_zip_content"

        z_flag, s_flag = write_compressed(flag_txt)
        z_aws, s_aws = write_compressed(aws_env)
        z_ssh, s_ssh = write_compressed(ssh_key)
        z_zip, s_zip = write_compressed(b64_zip)

        addr_flag_file = create_item("secret_flag.txt", 0x31, s_flag, z_flag)
        addr_desktop = create_item("Desktop", 0x05)
        struct.pack_into("<Q", logical_data, addr_desktop + 0x08, addr_flag_file)

        addr_aws_file = create_item("aws_credentials.env", 0x31, s_aws, z_aws)
        addr_documents = create_item("Documents", 0x05)
        struct.pack_into("<Q", logical_data, addr_documents + 0x08, addr_aws_file)

        addr_zip_file = create_item("backup_ZmxhZ3tzZWNyZXRfZGF0YX0=.zip", 0x31, s_zip, z_zip)
        addr_downloads = create_item("Downloads", 0x05)
        struct.pack_into("<Q", logical_data, addr_downloads + 0x08, addr_zip_file)

        addr_ssh_file = create_item("id_rsa", 0x31, s_ssh, z_ssh)
        addr_ssh_dir = create_item(".ssh", 0x05)
        struct.pack_into("<Q", logical_data, addr_ssh_dir + 0x08, addr_ssh_file)

        # Pictures & Music for Alice
        pic_bytes = b"\x89PNG\r\n\x1a\nprofile_photo_bytes"
        music_bytes = b"ID3\x03\x00\x00\x00podcast_episode_bytes"
        z_pic, s_pic = write_compressed(pic_bytes)
        z_mus, s_mus = write_compressed(music_bytes)

        addr_pic_file = create_item("profile_photo.png", 0x31, s_pic, z_pic)
        addr_pictures = create_item("Pictures", 0x05)
        struct.pack_into("<Q", logical_data, addr_pictures + 0x08, addr_pic_file)

        addr_mus_file = create_item("podcast_ep1.mp3", 0x31, s_mus, z_mus)
        addr_music = create_item("Music", 0x05)
        struct.pack_into("<Q", logical_data, addr_music + 0x08, addr_mus_file)

        # Connect Alice folders: AppData -> Desktop -> Documents -> Downloads -> Pictures -> Music -> .ssh
        struct.pack_into("<Q", logical_data, addr_music + 0x00, addr_ssh_dir) # Music -> .ssh
        struct.pack_into("<Q", logical_data, addr_pictures + 0x00, addr_music) # Pictures -> Music
        struct.pack_into("<Q", logical_data, addr_downloads + 0x00, addr_pictures) # Downloads -> Pictures
        struct.pack_into("<Q", logical_data, addr_documents + 0x00, addr_downloads) # Documents -> Downloads
        struct.pack_into("<Q", logical_data, addr_desktop + 0x00, addr_documents) # Desktop -> Documents
        struct.pack_into("<Q", logical_data, addr_appdata_alice + 0x00, addr_desktop) # AppData -> Desktop

        # Alice NTUSER.DAT
        addr_ntuser = create_item("NTUSER.DAT", 0x31, s_ntuser, z_ntuser)
        struct.pack_into("<Q", logical_data, addr_ntuser + 0x00, addr_appdata_alice)

        addr_alice = create_item("Alice", 0x05)
        struct.pack_into("<Q", logical_data, addr_alice + 0x08, addr_ntuser)

        # ---------------------------------------------
        # User SERV Items
        # ---------------------------------------------
        serv_notes = b"Server notes for SERV administrator:\nDatabase host: 10.0.0.5:5432\nBackup schedule: Daily 02:00 UTC\n"
        serv_sql = b"CREATE TABLE users (id INT, username VARCHAR(50));\nINSERT INTO users VALUES (1, 'admin');\n"
        serv_topo = b"\xff\xd8\xff\xe0\x00\x10JFIFnetwork_topology_jpg"

        z_snotes, s_snotes = write_compressed(serv_notes)
        z_ssql, s_ssql = write_compressed(serv_sql)
        z_stopo, s_stopo = write_compressed(serv_topo)

        addr_snotes_file = create_item("server_notes.txt", 0x31, s_snotes, z_snotes)
        addr_sdesk = create_item("Desktop", 0x05)
        struct.pack_into("<Q", logical_data, addr_sdesk + 0x08, addr_snotes_file)

        addr_ssql_file = create_item("database_backup.sql", 0x31, s_ssql, z_ssql)
        addr_sdoc = create_item("Documents", 0x05)
        struct.pack_into("<Q", logical_data, addr_sdoc + 0x08, addr_ssql_file)

        addr_stopo_file = create_item("network_topology.jpg", 0x31, s_stopo, z_stopo)
        addr_spic = create_item("Pictures", 0x05)
        struct.pack_into("<Q", logical_data, addr_spic + 0x08, addr_stopo_file)

        # SERV folder siblings: Desktop -> Documents -> Pictures
        struct.pack_into("<Q", logical_data, addr_sdoc + 0x00, addr_spic)
        struct.pack_into("<Q", logical_data, addr_sdesk + 0x00, addr_sdoc)

        addr_serv = create_item("SERV", 0x05)
        struct.pack_into("<Q", logical_data, addr_serv + 0x08, addr_sdesk)

        # Alice sibling -> SERV
        struct.pack_into("<Q", logical_data, addr_alice + 0x00, addr_serv)

        # Users folder
        addr_users = create_item("Users", 0x05)
        struct.pack_into("<Q", logical_data, addr_users + 0x08, addr_alice)

        # Windows -> System32 -> config -> [SAM, SYSTEM]
        addr_sam_file = create_item("SAM", 0x31, s_sam, z_sam)
        addr_sys_file = create_item("SYSTEM", 0x31, s_sys, z_sys)
        struct.pack_into("<Q", logical_data, addr_sam_file + 0x00, addr_sys_file) # SAM sibling -> SYSTEM

        addr_config = create_item("config", 0x05)
        struct.pack_into("<Q", logical_data, addr_config + 0x08, addr_sam_file)

        addr_sys32 = create_item("System32", 0x05)
        struct.pack_into("<Q", logical_data, addr_sys32 + 0x08, addr_config)

        # Windows -> appcompat -> Programs -> Amcache.hve
        addr_amcache = create_item("Amcache.hve", 0x31, s_amcache, z_amcache)
        addr_prog = create_item("Programs", 0x05)
        struct.pack_into("<Q", logical_data, addr_prog + 0x08, addr_amcache)

        addr_appcompat = create_item("appcompat", 0x05)
        struct.pack_into("<Q", logical_data, addr_appcompat + 0x08, addr_prog)

        # appcompat sibling -> System32
        struct.pack_into("<Q", logical_data, addr_appcompat + 0x00, addr_sys32)

        addr_windows = create_item("Windows", 0x05)
        struct.pack_into("<Q", logical_data, addr_windows + 0x08, addr_appcompat)

        # Users Sibling -> Windows
        struct.pack_into("<Q", logical_data, addr_users + 0x00, addr_windows)

        # First root item = Users
        struct.pack_into("<Q", logical_data, 0x24, addr_users)

        stream.extend(logical_data)

        os.makedirs(os.path.dirname(os.path.abspath(output_ad1_path)), exist_ok=True)
        with open(output_ad1_path, "wb") as f:
            f.write(stream)

    print(f"Generated comprehensive synthetic AD1 image: {output_ad1_path} ({len(stream)} bytes)")


if __name__ == "__main__":
    out_file = os.path.join(os.path.dirname(__file__), "sample_evidence.ad1")
    build_full_ad1_image(out_file)
