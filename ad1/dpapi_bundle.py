"""
AD1 DPAPI & Chromium Credential Triage and Auto-Extractor (ad1/dpapi_bundle.py)
Correlates Browser History Login Events -> Validates Login Data -> Auto-extracts DPAPI Artifacts (SAM, SYSTEM, Protect/SID, Local State, Login Data).
"""
import os
import sys
import re
import json
import sqlite3
import base64
import tempfile
from typing import List, Dict, Any, Optional, Tuple

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from ad1.parser import AD1Parser
from ad1.models import AD1Item
from core.utils import human_size, webkit_timestamp_to_datetime, format_datetime

console = Console(force_terminal=True, legacy_windows=False)

# Keywords indicating login / authentication actions in URL
LOGIN_URL_PATTERNS = [
    re.compile(r"(?:login|signin|sign-in|auth|oauth|session|sso|idp|portal|account|authenticate|wp-login|admin/login|log-in|webmail|cpanel)", re.IGNORECASE),
    re.compile(r"(?:accounts\.google\.com|login\.live\.com|login\.microsoftonline\.com|github\.com/login|appleid\.apple\.com|auth0\.com)", re.IGNORECASE)
]


def is_login_url(url: str) -> bool:
    if not url:
        return False
    return any(p.search(url) for p in LOGIN_URL_PATTERNS)


class DPAPIBundleExtractor:
    """
    Handles intelligent correlation:
    If Login URLs found -> Verify 'Login Data' -> Extract SAM, SYSTEM, Protect/<SID>, Local State, Login Data.
    """
    def __init__(self, parser: AD1Parser):
        self.parser = parser

    def correlate_and_triage(self, history_records: List[Dict[str, Any]], output_base_dir: str = "./extracted_credentials") -> Dict[str, Any]:
        """
        Main triage entrypoint:
        1. Identifies profiles with login URL activity.
        2. Checks for presence of 'Login Data' in those profiles.
        3. If both exist, extracts the DPAPI masterkey decrypt bundle.
        """
        if not self.parser.items:
            self.parser.build_tree()

        # Group login history by (user, browser, profile_path)
        login_events_by_profile: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = {}

        for rec in history_records:
            url = rec.get("url", "")
            if is_login_url(url):
                user = rec.get("user") or rec.get("user_name") or "UnknownUser"
                browser = rec.get("browser") or rec.get("browser_type") or "UnknownBrowser"
                source_path = rec.get("source_file") or rec.get("source_path") or ""
                # Get directory of history file (profile directory)
                prof_dir = os.path.dirname(source_path).replace("\\", "/")

                key = (user, browser, prof_dir)
                if key not in login_events_by_profile:
                    login_events_by_profile[key] = []
                login_events_by_profile[key].append(rec)

        if not login_events_by_profile:
            return {"triggered": False, "reason": "No login activity detected in browser history.", "profiles": []}

        # For each profile with login activity, verify if 'Login Data' exists
        triage_results = []

        for (user, browser, prof_dir), login_recs in login_events_by_profile.items():
            login_data_item = self._find_login_data_item(prof_dir)
            if not login_data_item:
                # No Login Data exists -> skip extraction to avoid noise!
                continue

            # We have Login URLs AND Login Data! Proceed with full DPAPI bundle extraction
            bundle_info = self._extract_profile_bundle(
                user=user,
                browser=browser,
                prof_dir=prof_dir,
                login_data_item=login_data_item,
                login_records=login_recs,
                output_base_dir=output_base_dir
            )
            triage_results.append(bundle_info)

        if not triage_results:
            return {
                "triggered": False,
                "reason": "Login URLs found but no 'Login Data' databases present (no saved credentials).",
                "profiles": []
            }

        return {
            "triggered": True,
            "profile_count": len(triage_results),
            "profiles": triage_results
        }

    def _find_login_data_item(self, prof_dir: str) -> Optional[AD1Item]:
        prof_lower = prof_dir.lower().rstrip("/")
        for item in self.parser.items:
            if item.is_dir or item.decompressed_size == 0:
                continue
            path_norm = item.full_path.replace("\\", "/").lower()
            if path_norm.startswith(prof_lower) and item.item_name.lower() in ["login data", "login data for account"]:
                return item
        return None

    def _extract_profile_bundle(
        self,
        user: str,
        browser: str,
        prof_dir: str,
        login_data_item: AD1Item,
        login_records: List[Dict[str, Any]],
        output_base_dir: str
    ) -> Dict[str, Any]:
        # Target extraction folder: ./extracted_credentials/<User>_<Browser>
        clean_browser = browser.replace(" ", "_")
        target_dir = os.path.join(output_base_dir, f"{user}_{clean_browser}")
        os.makedirs(target_dir, exist_ok=True)

        extracted_files = []

        # 1. Extract Login Data
        login_data_bytes = self.parser.read_file_bytes(login_data_item)
        login_data_out = os.path.join(target_dir, "Login Data")
        if login_data_bytes:
            with open(login_data_out, "wb") as f:
                f.write(login_data_bytes)
            extracted_files.append({"type": "Login Data", "path": login_data_out, "size": len(login_data_bytes)})

        # Parse stored credentials inside Login Data SQLite
        stored_credentials = self._parse_login_data(login_data_bytes)

        # 2. Extract Local State (contains os_crypt encrypted key)
        local_state_item = self._find_local_state_item(prof_dir)
        local_state_info = {}
        if local_state_item:
            ls_bytes = self.parser.read_file_bytes(local_state_item)
            if ls_bytes:
                ls_out = os.path.join(target_dir, "Local State")
                with open(ls_out, "wb") as f:
                    f.write(ls_bytes)
                extracted_files.append({"type": "Local State", "path": ls_out, "size": len(ls_bytes)})
                local_state_info = self._parse_local_state(ls_bytes)

        # 3. Extract Protect / SID DPAPI MasterKeys
        protect_items = self._find_user_protect_items(user)
        protect_extracted = []
        for p_item in protect_items:
            p_bytes = self.parser.read_file_bytes(p_item)
            if p_bytes:
                # Preserve relative folder structure inside Protect/
                rel_p = p_item.full_path.replace("\\", "/")
                idx = rel_p.lower().find("/protect/")
                sub_path = rel_p[idx+1:] if idx != -1 else os.path.basename(rel_p)
                p_out = os.path.join(target_dir, sub_path)
                os.makedirs(os.path.dirname(p_out), exist_ok=True)
                with open(p_out, "wb") as f:
                    f.write(p_bytes)
                protect_extracted.append(p_out)
                extracted_files.append({"type": "DPAPI MasterKey", "path": p_out, "size": len(p_bytes)})

        # 4. Extract SAM & SYSTEM hives
        system_hives = self._find_system_hives()
        for hive_name, h_item in system_hives.items():
            h_bytes = self.parser.read_file_bytes(h_item)
            if h_bytes:
                h_out = os.path.join(target_dir, hive_name.upper())
                with open(h_out, "wb") as f:
                    f.write(h_bytes)
                extracted_files.append({"type": f"Registry Hive ({hive_name.upper()})", "path": h_out, "size": len(h_bytes)})

        # 5. Extract NTUSER.DAT for user
        ntuser_item = self._find_ntuser_item(user)
        if ntuser_item:
            nt_bytes = self.parser.read_file_bytes(ntuser_item)
            if nt_bytes:
                nt_out = os.path.join(target_dir, "NTUSER.DAT")
                with open(nt_out, "wb") as f:
                    f.write(nt_bytes)
                extracted_files.append({"type": "User Registry (NTUSER.DAT)", "path": nt_out, "size": len(nt_bytes)})

        # Generate DPAPI Triage JSON summary inside target dir
        summary_payload = {
            "user": user,
            "browser": browser,
            "profile_directory": prof_dir,
            "trigger_login_urls": [r.get("url") for r in login_records[:10]],
            "stored_credentials_count": len(stored_credentials),
            "stored_credentials": stored_credentials,
            "local_state_info": local_state_info,
            "extracted_artifacts": extracted_files,
            "dpapi_ready": bool(local_state_item and (protect_items or "sam" in system_hives))
        }

        with open(os.path.join(target_dir, "dpapi_triage_manifest.json"), "w", encoding="utf-8") as f:
            json.dump(summary_payload, f, indent=2, ensure_ascii=False)

        return {
            "user": user,
            "browser": browser,
            "profile_directory": prof_dir,
            "target_dir": target_dir,
            "trigger_login_urls": login_records,
            "stored_credentials": stored_credentials,
            "local_state_info": local_state_info,
            "extracted_files": extracted_files,
            "protect_count": len(protect_extracted),
            "has_sam_system": ("sam" in system_hives and "system" in system_hives),
            "dpapi_ready": bool(local_state_item and (protect_items or "sam" in system_hives))
        }

    def _parse_login_data(self, data_bytes: Optional[bytes]) -> List[Dict[str, Any]]:
        if not data_bytes or not data_bytes.startswith(b"SQLite format 3\x00"):
            return []

        records = []
        with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as tf:
            tf.write(data_bytes)
            tmp_name = tf.name

        try:
            conn = sqlite3.connect(tmp_name)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='logins'")
            if cursor.fetchone():
                cursor.execute("""
                    SELECT origin_url, action_url, username_element, username_value, 
                           password_element, password_value, date_created, times_used 
                    FROM logins
                """)
                for row in cursor.fetchall():
                    origin, action, u_elem, u_val, p_elem, p_val, d_created, t_used = row
                    
                    # Detect encryption scheme
                    enc_type = "Unknown"
                    if p_val:
                        if isinstance(p_val, bytes):
                            if p_val.startswith(b"v10"):
                                enc_type = "v10 (AES-256-GCM / DPAPI Key)"
                            elif p_val.startswith(b"v20"):
                                enc_type = "v20 (AES-256-GCM / App-Bound DPAPI)"
                            elif len(p_val) > 20 and p_val[0] == 0x01:
                                enc_type = "Legacy DPAPI (CryptProtectData)"
                            else:
                                enc_type = f"Encrypted ({len(p_val)} bytes)"
                        else:
                            enc_type = "Plaintext"

                    dt_created = webkit_timestamp_to_datetime(d_created)

                    records.append({
                        "origin_url": origin or "",
                        "action_url": action or "",
                        "username": u_val or "",
                        "encryption": enc_type,
                        "password_blob_len": len(p_val) if p_val else 0,
                        "date_created": format_datetime(dt_created),
                        "times_used": t_used or 0
                    })
            conn.close()
        except Exception:
            pass
        finally:
            if os.path.exists(tmp_name):
                try: os.remove(tmp_name)
                except Exception: pass

        return records

    def _parse_local_state(self, ls_bytes: bytes) -> Dict[str, Any]:
        try:
            data = json.loads(ls_bytes.decode("utf-8", errors="replace"))
            os_crypt = data.get("os_crypt", {})
            enc_key_b64 = os_crypt.get("encrypted_key", "")
            if enc_key_b64:
                raw_key = base64.b64decode(enc_key_b64)
                has_dpapi_header = raw_key.startswith(b"DPAPI")
                return {
                    "has_encrypted_key": True,
                    "dpapi_header": has_dpapi_header,
                    "key_blob_len": len(raw_key),
                    "encrypted_key_b64": enc_key_b64[:32] + "..."
                }
        except Exception:
            pass
        return {"has_encrypted_key": False}

    def _find_local_state_item(self, prof_dir: str) -> Optional[AD1Item]:
        # 'Local State' is usually in the parent 'User Data' directory of Chromium
        # e.g. prof_dir = .../User Data/Default -> Local State is in .../User Data/Local State
        parent_dir = os.path.dirname(prof_dir).replace("\\", "/").lower()
        for item in self.parser.items:
            if item.is_dir or item.decompressed_size == 0:
                continue
            p_norm = item.full_path.replace("\\", "/").lower()
            if item.item_name.lower() == "local state":
                if parent_dir in p_norm or prof_dir.lower() in p_norm:
                    return item
        return None

    def _find_user_protect_items(self, user: str) -> List[AD1Item]:
        items = []
        u_lower = user.lower()
        for item in self.parser.items:
            if item.is_dir or item.decompressed_size == 0:
                continue
            p_norm = item.full_path.replace("\\", "/").lower()
            if f"users/{u_lower}/" in p_norm or f"documents and settings/{u_lower}/" in p_norm:
                if "/protect/" in p_norm:
                    items.append(item)
        return items

    def _find_system_hives(self) -> Dict[str, AD1Item]:
        hives = {}
        for item in self.parser.items:
            if item.is_dir or item.decompressed_size == 0:
                continue
            p_norm = item.full_path.replace("\\", "/").lower()
            name_lower = item.item_name.lower()
            if "system32/config" in p_norm:
                if name_lower == "sam" and "sam" not in hives:
                    hives["sam"] = item
                elif name_lower == "system" and "system" not in hives:
                    hives["system"] = item
        return hives

    def _find_ntuser_item(self, user: str) -> Optional[AD1Item]:
        u_lower = user.lower()
        for item in self.parser.items:
            if item.is_dir or item.decompressed_size == 0:
                continue
            p_norm = item.full_path.replace("\\", "/").lower()
            if f"users/{u_lower}/" in p_norm and item.item_name.lower() == "ntuser.dat":
                return item
        return None


def print_dpapi_triage_panel(triage_info: Dict[str, Any]):
    """
    Renders a dedicated, high-impact DPAPI Credential Decryption Box in terminal.
    """
    if not triage_info.get("triggered"):
        return

    console.print("\n")
    console.print("[bold red]╔════════════════════════════════════════════════════════════════════════════════╗[/bold red]")
    console.print("[bold red]║   AUTOMATED CREDENTIAL TRIAGE & DPAPI DECRYPTION BUNDLE EXTRACTED           ║[/bold red]")
    console.print("[bold red]╚════════════════════════════════════════════════════════════════════════════════╝[/bold red]")

    for prof in triage_info.get("profiles", []):
        user = prof["user"]
        browser = prof["browser"]
        target_dir = prof["target_dir"]
        stored_creds = prof.get("stored_credentials", [])
        extracted_files = prof.get("extracted_files", [])

        title = f" User: [bold cyan]{user}[/bold cyan] | Browser: [bold yellow]{browser}[/bold yellow] | Target: [bold green]{target_dir}[/bold green]"

        table = Table(
            title=f" Stored Credentials Found in 'Login Data' ({len(stored_creds)} Accounts)",
            show_header=True,
            header_style="bold magenta",
            border_style="red",
            expand=True
        )
        table.add_column("#", style="dim", width=4, justify="right")
        table.add_column("Username / Account", style="bold yellow", width=24)
        table.add_column("Origin / Login URL", style="cyan", min_width=35, overflow="fold")
        table.add_column("Encryption Scheme", style="bold green", width=28)
        table.add_column("Times Used", style="white", width=12, justify="right")

        for idx, cred in enumerate(stored_creds[:20], start=1):
            table.add_row(
                str(idx),
                cred.get("username") or "[dim]<empty>[/dim]",
                cred.get("origin_url") or "",
                cred.get("encryption") or "Encrypted",
                str(cred.get("times_used", 0))
            )

        console.print(table)

        # Artifacts Summary Table
        art_table = Table(
            title=f" Extracted DPAPI MasterKey & Registry Decryption Bundle",
            show_header=True,
            header_style="bold cyan",
            border_style="dim green",
            expand=True
        )
        art_table.add_column("Artifact Type", style="bold yellow", width=28)
        art_table.add_column("Extracted Destination File", style="white", min_width=45)
        art_table.add_column("Size", style="green", width=10, justify="right")

        for art in extracted_files:
            art_table.add_row(
                art.get("type", "File"),
                art.get("path", ""),
                human_size(art.get("size", 0))
            )

        console.print(art_table)
        console.print(f"[bold green] Ready for DPAPI Decryption:[/bold green] Use Mimikatz / DPAPIck / pypykatz on [cyan]{target_dir}[/cyan]\n")
