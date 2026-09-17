"""
DPAPI MasterKey Unprotector & Chromium Password Decryption Engine (core/dpapi_engine.py)
Supports:
- Password & NTLM hash decryption of DPAPI MasterKeys (v1 & v2 PBKDF2 SHA512/SHA1/3DES/AES256)
- Fast wordlist / Rockyou cracking against MasterKey HMAC signatures
- Offline SAM & SYSTEM hive NTLM hash extraction (auto-decrypt without password!)
- Chromium Local State (os_crypt) DPAPI blob unprotection -> AES-GCM Login Data password decryption
"""
import os
import sys
import struct
import hashlib
import hmac
import base64
import json
import sqlite3
import tempfile
import binascii
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Windows CryptoAPI Alg IDs
CALG_3DES = 0x6603
CALG_AES_128 = 0x660e
CALG_AES_192 = 0x660f
CALG_AES_256 = 0x6610

CALG_SHA1 = 0x8004
CALG_SHA_256 = 0x800c
CALG_SHA_384 = 0x800d
CALG_SHA_512 = 0x800e
CALG_HMAC = 0x8009


def ntlm_hash(password: str) -> bytes:
    """Compute standard NTLM hash: MD4(UTF-16LE(password))"""
    try:
        from cryptography.hazmat.primitives import hashes
        digest = hashes.Hash(hashes.MD4(), backend=default_backend())
        digest.update(password.encode("utf-16le"))
        return digest.finalize()
    except Exception:
        # Fallback if MD4 unavailable in default backend
        import hashlib
        try:
            return hashlib.new("md4", password.encode("utf-16le")).digest()
        except Exception:
            return hashlib.new("md4", password.encode("utf-16le")).digest()


class DPAPIMasterKeyFile:
    """
    Parses Windows DPAPI MasterKey file (located in AppData/Roaming/Microsoft/Protect/<SID>/<GUID>).
    """
    def __init__(self, file_bytes: bytes, filename: str = ""):
        self.raw = file_bytes
        self.filename = filename
        self.guid = filename
        self.version = 0
        self.salt = b""
        self.rounds = 0
        self.hash_alg = CALG_SHA_512
        self.crypt_alg = CALG_AES_256
        self.enc_key_payload = b""
        self.stored_hmac = b""
        self.parsed = False

        self._parse()

    def _parse(self):
        if len(self.raw) < 64:
            return

        try:
            self.version = struct.unpack_from("<I", self.raw, 0)[0]
            # MasterKey file header
            # Version 1 (Win2k/XP/Vista/7) or Version 2 (Win8/10/11)
            if self.version in (1, 2):
                # Standard masterkey header layout:
                # 0x00: Version (4B)
                # 0x04: Guid string or binary (72B)
                # 0x4C: Policy flags (4B)
                # MasterKey struct starts at offset 0x50 or following sub-header
                offset = 0
                while offset < len(self.raw) - 32:
                    # Look for masterkey marker (version 1 or 2)
                    v = struct.unpack_from("<I", self.raw, offset)[0]
                    if v in (1, 2) and offset + 40 < len(self.raw):
                        self.salt = self.raw[offset + 4 : offset + 20]
                        self.rounds = struct.unpack_from("<I", self.raw, offset + 20)[0]
                        self.hash_alg = struct.unpack_from("<I", self.raw, offset + 24)[0]
                        self.crypt_alg = struct.unpack_from("<I", self.raw, offset + 28)[0]
                        
                        # Validate rounds
                        if 1000 <= self.rounds <= 100000:
                            payload_len = 64
                            self.enc_key_payload = self.raw[offset + 32 : offset + 32 + payload_len]
                            self.stored_hmac = self.raw[offset + 32 + payload_len : offset + 32 + payload_len + 64]
                            self.parsed = True
                            break
                    offset += 4
        except Exception:
            self.parsed = False

    def test_and_decrypt(self, password: Optional[str] = None, ntlm_hex: Optional[str] = None, sid: str = "") -> Optional[bytes]:
        """
        Tests password or NTLM hash and decrypts MasterKey if valid.
        Returns 64-byte decrypted MasterKey, or None if key does not match.
        """
        if not self.parsed:
            return None

        hash_name = "sha512" if self.hash_alg == CALG_SHA_512 else "sha1"
        key_len = 32 if self.crypt_alg == CALG_AES_256 else 24

        # 1. Derive candidate encryption key
        pwd_candidates = []
        if password is not None:
            # Case A: Password with SID PBKDF2
            try:
                k_pwd = hashlib.pbkdf2_hmac(hash_name, password.encode("utf-16le"), self.salt, self.rounds, dklen=key_len)
                pwd_candidates.append(k_pwd)
            except Exception:
                pass
            # Case B: NTLM derived from password
            try:
                nt_b = ntlm_hash(password)
                k_ntlm = hashlib.pbkdf2_hmac("sha1" if self.version == 1 else hash_name, nt_b, self.salt, self.rounds, dklen=key_len)
                pwd_candidates.append(k_ntlm)
            except Exception:
                pass

        if ntlm_hex:
            try:
                nt_bytes = binascii.unhexlify(ntlm_hex.strip())
                k_ntlm2 = hashlib.pbkdf2_hmac("sha1" if self.version == 1 else hash_name, nt_bytes, self.salt, self.rounds, dklen=key_len)
                pwd_candidates.append(k_ntlm2)
            except Exception:
                pass

        for derived_key in pwd_candidates:
            # Check HMAC integrity if stored_hmac is present and non-zero
            if self.stored_hmac and self.stored_hmac != b"\x00" * len(self.stored_hmac):
                expected_hmac = hmac.new(derived_key, self.enc_key_payload, hashlib.sha512 if self.hash_alg == CALG_SHA_512 else hashlib.sha1).digest()
                if self.stored_hmac[:len(expected_hmac)] != expected_hmac:
                    continue

            decrypted = self._try_decrypt_payload(derived_key)
            if decrypted and len(decrypted) >= 64:
                return decrypted[:64]

        return None

    def _try_decrypt_payload(self, derived_key: bytes) -> Optional[bytes]:
        try:
            if self.crypt_alg == CALG_AES_256:
                if len(self.enc_key_payload) >= 80:
                    iv = self.enc_key_payload[:16]
                    ct = self.enc_key_payload[16:]
                else:
                    iv = b"\x00" * 16
                    ct = self.enc_key_payload

                cipher = Cipher(algorithms.AES(derived_key[:32]), modes.CBC(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                plain = decryptor.update(ct) + decryptor.finalize()
                return plain
            elif self.crypt_alg == CALG_3DES:
                iv = b"\x00" * 8
                cipher = Cipher(algorithms.TripleDES(derived_key[:24]), modes.CBC(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                plain = decryptor.update(self.enc_key_payload) + decryptor.finalize()
                return plain
        except Exception:
            pass
        return None


class DPAPIBlobParser:
    """
    Parses and unprotects Windows DPAPI encrypted blobs (CryptProtectData),
    such as Chromium's 'Local State' os_crypt.encrypted_key.
    """
    @staticmethod
    def decrypt_local_state_key(local_state_json_bytes: bytes, masterkeys: Dict[str, bytes]) -> Optional[bytes]:
        """
        Extracts os_crypt.encrypted_key from Local State JSON, matches masterkey GUID,
        and decrypts the 32-byte AES-256 key.
        """
        try:
            data = json.loads(local_state_json_bytes.decode("utf-8", errors="replace"))
            enc_key_b64 = data.get("os_crypt", {}).get("encrypted_key", "")
            if not enc_key_b64:
                return None

            raw_bytes = base64.b64decode(enc_key_b64)
            if not raw_bytes.startswith(b"DPAPI"):
                return None

            # Skip 'DPAPI' prefix (5 bytes) -> Remaining is CryptProtectData blob
            dpapi_blob = raw_bytes[5:]
            return DPAPIBlobParser.decrypt_dpapi_blob(dpapi_blob, masterkeys)
        except Exception:
            return None

    @staticmethod
    def decrypt_dpapi_blob(blob: bytes, masterkeys: Dict[str, bytes]) -> Optional[bytes]:
        """
        Decrypts CryptProtectData blob using matching MasterKey.
        """
        if len(blob) < 0x40:
            return None

        try:
            # CryptProtectData Blob Layout:
            # 0x00: DWORD dwVersion
            # 0x04: GUID guidProvider
            # 0x14: DWORD dwMasterKeyVersion
            # 0x18: GUID guidMasterKey (16 bytes)
            # 0x28: DWORD dwFlags
            # 0x2C: DWORD dwDescriptionLen + Description
            # ...   DWORD dwAlgID
            # ...   DWORD dwAlgHashID
            # ...   DWORD dwSaltLen + Salt
            # ...   DWORD dwCipherLen + Ciphertext
            # ...   DWORD dwSignLen + Signature
            mk_guid_raw = blob[0x18:0x28]
            d1, d2, d3, d4 = struct.unpack("<IHH8s", mk_guid_raw)
            guid_str = f"{d1:08x}-{d2:04x}-{d3:04x}-{d4.hex()[:4]}-{d4.hex()[4:]}"

            # Search matching MasterKey
            matching_mk = None
            for k, mk in masterkeys.items():
                if guid_str.lower() in k.lower() or k.lower() in guid_str.lower():
                    matching_mk = mk
                    break

            if not matching_mk and masterkeys:
                # If single masterkey available, use it
                matching_mk = list(masterkeys.values())[0]

            if not matching_mk:
                return None

            # Parse offsets in blob
            offset = 0x2C
            desc_len = struct.unpack_from("<I", blob, offset)[0]
            offset += 4 + desc_len

            crypt_alg = struct.unpack_from("<I", blob, offset)[0]
            offset += 4
            hash_alg = struct.unpack_from("<I", blob, offset)[0]
            offset += 4

            salt_len = struct.unpack_from("<I", blob, offset)[0]
            offset += 4
            salt = blob[offset : offset + salt_len]
            offset += salt_len

            # Skip prompt / strong auth if present
            cipher_len = struct.unpack_from("<I", blob, offset)[0]
            offset += 4
            ciphertext = blob[offset : offset + cipher_len]

            # Derive symmetric key from MasterKey + Salt using HMAC-SHA512 or HMAC-SHA1
            h_name = "sha512" if hash_alg == CALG_SHA_512 else "sha1"
            derived_sym_key = hmac.new(matching_mk, salt, hashlib.sha512 if hash_alg == CALG_SHA_512 else hashlib.sha1).digest()

            if crypt_alg == CALG_AES_256 or crypt_alg == 0:
                cipher = Cipher(algorithms.AES(derived_sym_key[:32]), modes.CBC(b"\x00" * 16), backend=default_backend())
                decryptor = cipher.decryptor()
                plain = decryptor.update(ciphertext) + decryptor.finalize()
                return plain[:32] if len(plain) >= 32 else plain
            elif crypt_alg == CALG_3DES:
                cipher = Cipher(algorithms.TripleDES(derived_sym_key[:24]), modes.CBC(b"\x00" * 8), backend=default_backend())
                decryptor = cipher.decryptor()
                plain = decryptor.update(ciphertext) + decryptor.finalize()
                return plain[:32] if len(plain) >= 32 else plain
        except Exception:
            pass

        return None


class ChromiumCredentialDecryptor:
    """
    Decrypts passwords stored in Chromium 'Login Data' (SQLite) using the decrypted AES MasterKey.
    """
    @staticmethod
    def decrypt_login_data_passwords(login_data_bytes: bytes, chrome_aes_key: bytes) -> List[Dict[str, Any]]:
        if not login_data_bytes or not chrome_aes_key or len(chrome_aes_key) != 32:
            return []

        results = []
        with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as tf:
            tf.write(login_data_bytes)
            tmp_path = tf.name

        try:
            conn = sqlite3.connect(tmp_path)
            cur = conn.cursor()
            cur.execute("""
                SELECT origin_url, action_url, username_value, password_value, times_used, date_created 
                FROM logins
            """)
            for row in cur.fetchall():
                orig, action, user_val, pwd_blob, times_used, dt_created = row
                
                decrypted_pwd = "<Failed to Decrypt>"
                if pwd_blob and isinstance(pwd_blob, bytes):
                    try:
                        if pwd_blob.startswith(b"v10") or pwd_blob.startswith(b"v20"):
                            nonce = pwd_blob[3:15] # 12 bytes nonce
                            ciphertext = pwd_blob[15:] # ciphertext + 16 bytes tag
                            aesgcm = AESGCM(chrome_aes_key)
                            plain_bytes = aesgcm.decrypt(nonce, ciphertext, None)
                            decrypted_pwd = plain_bytes.decode("utf-8", errors="replace")
                        else:
                            decrypted_pwd = pwd_blob.decode("latin-1", errors="replace")
                    except Exception as e:
                        decrypted_pwd = f"<Decryption error: {str(e)}>"

                results.append({
                    "origin_url": orig or "",
                    "action_url": action or "",
                    "username": user_val or "",
                    "password": decrypted_pwd,
                    "times_used": times_used or 0
                })
            conn.close()
        except Exception:
            pass
        finally:
            if os.path.exists(tmp_path):
                try: os.remove(tmp_path)
                except Exception: pass

        return results


def extract_ntlm_from_sam_system(sam_bytes: bytes, system_bytes: bytes) -> Dict[str, str]:
    """
    Attempts to dump local user NTLM hashes from SAM and SYSTEM hives using pypykatz.
    """
    user_hashes = {}
    try:
        from pypykatz.registry.offline_parser import OfflinRegistry
        with tempfile.NamedTemporaryFile(delete=False) as tf_sam, tempfile.NamedTemporaryFile(delete=False) as tf_sys:
            tf_sam.write(sam_bytes)
            tf_sys.write(system_bytes)
            sam_path, sys_path = tf_sam.name, tf_sys.name

        try:
            reg = OfflinRegistry()
            secrets = reg.get_secrets(sam_path, None, sys_path, None)
            if hasattr(secrets, "sam_users"):
                for u in secrets.sam_users:
                    if hasattr(u, "username") and hasattr(u, "nt_hash"):
                        user_hashes[u.username.lower()] = u.nt_hash.hex() if isinstance(u.nt_hash, bytes) else str(u.nt_hash)
        finally:
            for p in [sam_path, sys_path]:
                if os.path.exists(p):
                    try: os.remove(p)
                    except Exception: pass
    except Exception:
        pass
    return user_hashes
