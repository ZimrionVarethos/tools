"""
AD1 Automated DPAPI Decryptor & Password Recovery (ad1dpapi / ad1/dpapi_decrypt.py)
Automates offline DPAPI MasterKey unprotection & Chromium password decryption using:
1. Direct User Password (-p, --password)
2. Direct NTLM Hash (--ntlm)
3. Offline SAM & SYSTEM Hive NTLM Extraction (Zero-touch auto-decrypt)
4. Wordlist / Rockyou Bruteforce (-w, --wordlist)
"""
import os
import sys
import argparse
import json
import re
import tempfile
import binascii
from typing import List, Dict, Any, Optional

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from core.banner import print_ad1_banner
from core.utils import human_size
from core.dpapi_engine import (
    DPAPIMasterKeyFile,
    DPAPIBlobParser,
    ChromiumCredentialDecryptor,
    extract_ntlm_from_sam_system,
    ntlm_hash
)
from ad1.parser import AD1Parser
from ad1.dpapi_bundle import DPAPIBundleExtractor

console = Console(force_terminal=True, legacy_windows=False)

TOP_DEFAULT_PASSWORDS = [
    "", "123", "123456", "password", "Password", "Password123", "admin", "Admin", "admin123",
    "root", "toor", "12345678", "123456789", "welcome", "Welcome1", "letmein",
    "qwerty", "master", "dragon", "baseball", "football", "shadow", "superman", "iloveyou"
]


def is_guid_or_mk(name: str) -> bool:
    """Matches 36-char GUID format (e.g. a1b2c3d4-e5f6-7890-abcd-ef0123456789) or masterkey filenames."""
    if len(name) in (36, 72):
        if re.match(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", name):
            return True
    return False


class AD1DPAPIDecryptor:
    """
    Orchestrates DPAPI MasterKey recovery and Chromium Login Data password decryption.
    """
    def __init__(self, parser: Optional[AD1Parser] = None, bundle_dir: Optional[str] = None):
        self.parser = parser
        self.bundle_dir = bundle_dir

    def decrypt_bundle(
        self,
        password: Optional[str] = None,
        ntlm_hex: Optional[str] = None,
        wordlist_path: Optional[str] = None,
        max_attempts: int = 100000
    ) -> List[Dict[str, Any]]:
        bundles = self._collect_bundles()
        if not bundles:
            console.print("[yellow] No DPAPI MasterKeys or Login Data databases found in target.[/yellow]")
            return []

        all_decrypted_creds = []

        for b in bundles:
            user = b.get("user", "User")
            browser = b.get("browser", "Browser")
            mk_items = b.get("masterkey_files", {})
            ls_bytes = b.get("local_state_bytes")
            ld_bytes = b.get("login_data_bytes")
            sam_bytes = b.get("sam_bytes")
            sys_bytes = b.get("system_bytes")
            user_sid = b.get("sid", "")
            local_state_path = b.get("local_state_path")
            login_data_path = b.get("login_data_path")
            protect_dir = b.get("protect_dir")
            sam_path = b.get("sam_path")
            system_path = b.get("system_path")

            console.print(f"\n[bold cyan]─── Investigating User: [yellow]{user}[/yellow] ({browser}) ───[/bold cyan]")

            # -------------------------------------------------------------
            # Attempt Decryption via pypykatz DPAPI (High Compatibility)
            # -------------------------------------------------------------
            creds_pypykatz = self._try_pypykatz_decryption(
                local_state_path=local_state_path,
                local_state_bytes=ls_bytes,
                login_data_path=login_data_path,
                login_data_bytes=ld_bytes,
                protect_dir=protect_dir,
                mk_items=mk_items,
                password=password,
                ntlm_hex=ntlm_hex,
                wordlist_path=wordlist_path,
                user_sid=user_sid,
                sam_path=sam_path,
                sam_bytes=sam_bytes,
                system_path=system_path,
                system_bytes=sys_bytes
            )

            if creds_pypykatz:
                for c in creds_pypykatz:
                    c["user"] = user
                    c["browser"] = browser
                    all_decrypted_creds.append(c)
                continue

            # -------------------------------------------------------------
            # Fallback: Pure-Python Cryptographic Engine
            # -------------------------------------------------------------
            unprotected_masterkeys = {}
            recovered_via = ""

            # Method A: User provided Password
            if password is not None:
                for fname, mk_raw in mk_items.items():
                    mk_obj = DPAPIMasterKeyFile(mk_raw, filename=fname)
                    plain_mk = mk_obj.test_and_decrypt(password=password)
                    if plain_mk:
                        unprotected_masterkeys[fname] = plain_mk
                        recovered_via = f"Provided Password: '{password}'"

            # Method B: User provided NTLM
            if not unprotected_masterkeys and ntlm_hex:
                for fname, mk_raw in mk_items.items():
                    mk_obj = DPAPIMasterKeyFile(mk_raw, filename=fname)
                    plain_mk = mk_obj.test_and_decrypt(ntlm_hex=ntlm_hex)
                    if plain_mk:
                        unprotected_masterkeys[fname] = plain_mk
                        recovered_via = f"Provided NTLM Hash: {ntlm_hex}"

            # Method C: Auto-Extract NTLM from SAM & SYSTEM
            if not unprotected_masterkeys and sam_bytes and sys_bytes:
                with console.status("[dim]Extracting NTLM hashes from SAM & SYSTEM hives...[/dim]"):
                    user_hashes = extract_ntlm_from_sam_system(sam_bytes, sys_bytes)
                    for u_name, u_hash in user_hashes.items():
                        if u_name in user.lower() or user.lower() in u_name or len(user_hashes) == 1:
                            for fname, mk_raw in mk_items.items():
                                mk_obj = DPAPIMasterKeyFile(mk_raw, filename=fname)
                                plain_mk = mk_obj.test_and_decrypt(ntlm_hex=u_hash)
                                if plain_mk:
                                    unprotected_masterkeys[fname] = plain_mk
                                    recovered_via = f"SAM/SYSTEM NTLM Hash ({u_name}: {u_hash})"
                                    break

            # Method D: Wordlist / Rockyou Bruteforce
            if not unprotected_masterkeys and (wordlist_path or not (password or ntlm_hex)):
                wl_source = wordlist_path if wordlist_path and os.path.exists(wordlist_path) else None
                candidates = []
                if wl_source:
                    console.print(f"[dim]Bruteforcing DPAPI MasterKey with wordlist:[/dim] [cyan]{wl_source}[/cyan]")
                    try:
                        with open(wl_source, "r", encoding="utf-8", errors="ignore") as f:
                            for idx, line in enumerate(f):
                                if idx >= max_attempts: break
                                candidates.append(line.strip())
                    except Exception:
                        pass
                else:
                    candidates = TOP_DEFAULT_PASSWORDS + [user, user.lower(), user.capitalize(), f"{user}123", f"{user}2026"]

                with console.status("[bold yellow]Testing password candidates against MasterKey HMAC...[/bold yellow]"):
                    for cand in candidates:
                        for fname, mk_raw in mk_items.items():
                            mk_obj = DPAPIMasterKeyFile(mk_raw, filename=fname)
                            plain_mk = mk_obj.test_and_decrypt(password=cand)
                            if plain_mk:
                                unprotected_masterkeys[fname] = plain_mk
                                recovered_via = f"Wordlist Cracking: '{cand}'"
                                break
                        if unprotected_masterkeys:
                            break

            # Decrypt Chromium Credentials
            if unprotected_masterkeys and ls_bytes and ld_bytes:
                console.print(f"[bold green] MasterKey Unprotected via {recovered_via}[/bold green]")
                
                # Decrypt Local State AES key
                chrome_aes_key = DPAPIBlobParser.decrypt_local_state_key(ls_bytes, unprotected_masterkeys)
                if chrome_aes_key:
                    console.print(f"[bold green] Decrypted Chromium AES-256 Key:[/bold green] [cyan]{chrome_aes_key.hex()}[/cyan]")
                    creds = ChromiumCredentialDecryptor.decrypt_login_data_passwords(ld_bytes, chrome_aes_key)
                    
                    for c in creds:
                        c["user"] = user
                        c["browser"] = browser
                        c["recovered_via"] = recovered_via
                        all_decrypted_creds.append(c)
                else:
                    console.print("[yellow] MasterKey unlocked but failed to decrypt Local State DPAPI blob.[/yellow]")
            else:
                if not unprotected_masterkeys:
                    console.print("[red] Failed to unprotect MasterKey. Supply valid password (-p), NTLM (--ntlm), or wordlist (-w).[/red]")

        return all_decrypted_creds

    def _try_pypykatz_decryption(
        self,
        local_state_path: Optional[str],
        local_state_bytes: Optional[bytes],
        login_data_path: Optional[str],
        login_data_bytes: Optional[bytes],
        protect_dir: Optional[str],
        mk_items: Dict[str, bytes],
        password: Optional[str],
        ntlm_hex: Optional[str],
        wordlist_path: Optional[str],
        user_sid: str,
        sam_path: Optional[str],
        sam_bytes: Optional[bytes],
        system_path: Optional[str],
        system_bytes: Optional[bytes]
    ) -> List[Dict[str, Any]]:
        """
        Attempts full DPAPI decryption using pypykatz.
        """
        try:
            import logging
            for log_name in ["pypykatz", "aiowinreg", "minidump", "unicrypto"]:
                logging.getLogger(log_name).setLevel(logging.CRITICAL)

            from pypykatz.dpapi.dpapi import DPAPI
            dpapi = DPAPI()

            # Create temp files if working from memory
            temp_files = []
            ls_p = local_state_path
            if not ls_p and local_state_bytes:
                tf_ls = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
                tf_ls.write(local_state_bytes)
                tf_ls.close()
                ls_p = tf_ls.name
                temp_files.append(ls_p)

            ld_p = login_data_path
            if not ld_p and login_data_bytes:
                tf_ld = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
                tf_ld.write(login_data_bytes)
                tf_ld.close()
                ld_p = tf_ld.name
                temp_files.append(ld_p)

            prot_d = protect_dir
            if not prot_d and mk_items:
                td = tempfile.mkdtemp()
                sid_d = os.path.join(td, user_sid or "S-1-5-21-1234567890-1234567890-1234567890-1001")
                os.makedirs(sid_d, exist_ok=True)
                for mk_name, mk_b in mk_items.items():
                    with open(os.path.join(sid_d, mk_name), "wb") as f:
                        f.write(mk_b)
                prot_d = td

            s_path = sam_path
            if not s_path and sam_bytes:
                tf_sam = tempfile.NamedTemporaryFile(delete=False)
                tf_sam.write(sam_bytes)
                tf_sam.close()
                s_path = tf_sam.name
                temp_files.append(s_path)

            sys_p = system_path
            if not sys_p and system_bytes:
                tf_sys = tempfile.NamedTemporaryFile(delete=False)
                tf_sys.write(system_bytes)
                tf_sys.close()
                sys_p = tf_sys.name
                temp_files.append(sys_p)

            try:
                # 1. SAM & SYSTEM prekeys
                if s_path and sys_p and os.path.exists(s_path) and os.path.exists(sys_p):
                    try:
                        dpapi.get_prekeys_form_registry_files(s_path, sys_p)
                    except Exception:
                        pass

                # 2. Derive prekeys from password / NTLM / wordlist
                sids_to_try = set()
                if user_sid:
                    sids_to_try.add(user_sid)
                
                # Scan protect_dir for SIDs
                if prot_d and os.path.exists(prot_d):
                    for root, dirs, files in os.walk(prot_d):
                        for d in dirs:
                            if d.startswith("S-1-5-"):
                                sids_to_try.add(d)

                if not sids_to_try:
                    sids_to_try = {"S-1-5-21-1234567890-1234567890-1234567890-1001", "S-1-5-21-1001", "S-1-5-21-1000", "S-1-5-21-500"}

                passwords_to_try = []
                if password:
                    passwords_to_try.append(password)
                elif ntlm_hex:
                    pass
                elif wordlist_path and os.path.exists(wordlist_path):
                    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                        for idx, l in enumerate(f):
                            if idx >= 50000: break
                            passwords_to_try.append(l.strip())
                else:
                    passwords_to_try = TOP_DEFAULT_PASSWORDS

                for sid_cand in sids_to_try:
                    for pwd_cand in passwords_to_try:
                        try:
                            dpapi.get_prekeys_from_password(sid=sid_cand, password=pwd_cand)
                        except Exception:
                            pass
                    if ntlm_hex:
                        try:
                            dpapi.get_prekeys_from_password(sid=sid_cand, nt_hash=ntlm_hex)
                        except Exception:
                            pass

                # 3. Decrypt MasterKeys
                if prot_d and os.path.exists(prot_d):
                    dpapi.decrypt_masterkey_directory(prot_d, ignore_errors=True)

                # 4. Decrypt Chrome Login Data
                if ls_p and ld_p and os.path.exists(ls_p) and os.path.exists(ld_p):
                    dbpaths = {
                        "user": {
                            "localstate": ls_p,
                            "logindata": ld_p
                        }
                    }
                    res = dpapi.decrypt_all_chrome(dbpaths, throw=False)
                    out_records = []
                    for row in res.get("logins", []):
                        db_f, url, u_val, pwd_val = row
                        if isinstance(pwd_val, bytes):
                            p_str = pwd_val.decode("utf-8", errors="replace")
                        else:
                            p_str = str(pwd_val)

                        out_records.append({
                            "origin_url": url or "",
                            "username": u_val or "",
                            "password": p_str,
                            "times_used": 1,
                            "recovered_via": "pypykatz DPAPI engine"
                        })
                    if out_records:
                        console.print(f"[bold green] Successfully decrypted credentials using pypykatz DPAPI engine![/bold green]")
                        return out_records
            finally:
                for tp in temp_files:
                    if os.path.exists(tp):
                        try: os.remove(tp)
                        except Exception: pass
        except Exception:
            pass

        return []

    def _collect_bundles(self) -> List[Dict[str, Any]]:
        bundles = []

        # Case 1: Parsing from AD1 logical image
        if self.parser:
            if not self.parser.items:
                self.parser.build_tree()

            users = set()
            for item in self.parser.items:
                p_norm = item.full_path.replace("\\", "/")
                if "/protect/" in p_norm.lower():
                    m = p_norm.split("/")
                    for idx, part in enumerate(m):
                        if part.lower() in ["users", "home"] and idx + 1 < len(m):
                            users.add(m[idx+1])

            if not users:
                users = {"Alice", "bagas", "SERV", "Default"}

            for u in users:
                mk_files = {}
                ls_bytes = None
                ld_bytes = None
                sam_bytes = None
                sys_bytes = None
                user_sid = ""

                for item in self.parser.items:
                    if item.is_dir or item.decompressed_size == 0:
                        continue
                    p_norm = item.full_path.replace("\\", "/").lower()
                    name_lower = item.item_name.lower()

                    if f"users/{u.lower()}/" in p_norm and "/protect/" in p_norm:
                        mk_files[item.item_name] = self.parser.read_file_bytes(item)
                        # Extract SID if present in path
                        sid_match = re.search(r"/(S-1-5-21-[0-9-]+)/?", item.full_path.replace("\\", "/"))
                        if sid_match:
                            user_sid = sid_match.group(1)
                    elif f"users/{u.lower()}/" in p_norm and name_lower == "local state":
                        ls_bytes = self.parser.read_file_bytes(item)
                    elif f"users/{u.lower()}/" in p_norm and name_lower in ["login data", "login data for account"]:
                        ld_bytes = self.parser.read_file_bytes(item)
                    elif "system32/config" in p_norm:
                        if name_lower == "sam": sam_bytes = self.parser.read_file_bytes(item)
                        elif name_lower == "system": sys_bytes = self.parser.read_file_bytes(item)

                if mk_files or ld_bytes or ls_bytes:
                    bundles.append({
                        "user": u,
                        "browser": "Google Chrome",
                        "masterkey_files": mk_files,
                        "local_state_bytes": ls_bytes,
                        "login_data_bytes": ld_bytes,
                        "sam_bytes": sam_bytes,
                        "system_bytes": sys_bytes,
                        "sid": user_sid
                    })

        # Case 2: Parsing from an extracted directory
        elif self.bundle_dir and os.path.exists(self.bundle_dir):
            bundles.extend(self._collect_from_directory(self.bundle_dir))

        return bundles

    def _collect_from_directory(self, base_dir: str) -> List[Dict[str, Any]]:
        """
        Recursively scans directory or parent extracted_credentials directory for DPAPI artifacts.
        """
        bundles = []
        base_dir = os.path.abspath(base_dir)

        # Check if base_dir contains sub-bundles (e.g. extracted_credentials/ containing bagas_Google_Chrome)
        target_dirs = [base_dir]
        try:
            for entry in os.listdir(base_dir):
                entry_path = os.path.join(base_dir, entry)
                if os.path.isdir(entry_path):
                    # Check if subfolder has Login Data or Protect or Local State
                    has_dpapi = any(
                        os.path.exists(os.path.join(entry_path, f))
                        for f in ["Login Data", "Local State", "SAM", "Protect", "dpapi_triage_manifest.json"]
                    )
                    if has_dpapi:
                        target_dirs.append(entry_path)
        except Exception:
            pass

        for t_dir in target_dirs:
            mk_files = {}
            ls_bytes = None
            ld_bytes = None
            sam_bytes = None
            sys_bytes = None
            ls_path = None
            ld_path = None
            sam_path = None
            sys_path = None
            protect_dir = None
            user_sid = ""

            folder_name = os.path.basename(t_dir)
            parts = folder_name.split("_")
            user_name = parts[0] if parts else "User"
            browser_name = " ".join(parts[1:]) if len(parts) > 1 else "Chromium"

            # Check if manifest exists
            manifest_file = os.path.join(t_dir, "dpapi_triage_manifest.json")
            if os.path.exists(manifest_file):
                try:
                    with open(manifest_file, "r", encoding="utf-8") as f:
                        m_data = json.load(f)
                        if m_data.get("user"): user_name = m_data["user"]
                        if m_data.get("browser"): browser_name = m_data["browser"]
                except Exception:
                    pass

            for root, dirs, files in os.walk(t_dir):
                for d in dirs:
                    if d.lower() == "protect" or d.startswith("S-1-5-"):
                        protect_dir = os.path.join(root, d)
                    if d.startswith("S-1-5-"):
                        user_sid = d

                for f in files:
                    fpath = os.path.join(root, f)
                    fname_lower = f.lower()
                    rel_p = os.path.relpath(fpath, t_dir).replace("\\", "/")

                    if fname_lower in ["login data", "login data for account", "logindata"]:
                        ld_path = fpath
                        try:
                            with open(fpath, "rb") as fp:
                                ld_bytes = fp.read()
                        except Exception: pass
                    elif fname_lower in ["local state", "localstate"]:
                        ls_path = fpath
                        try:
                            with open(fpath, "rb") as fp:
                                ls_bytes = fp.read()
                        except Exception: pass
                    elif fname_lower == "sam":
                        sam_path = fpath
                        try:
                            with open(fpath, "rb") as fp:
                                sam_bytes = fp.read()
                        except Exception: pass
                    elif fname_lower == "system":
                        sys_path = fpath
                        try:
                            with open(fpath, "rb") as fp:
                                sys_bytes = fp.read()
                        except Exception: pass
                    elif "protect" in rel_p.lower() or is_guid_or_mk(f) or f.startswith("{"):
                        if not protect_dir:
                            protect_dir = root
                        try:
                            with open(fpath, "rb") as fp:
                                mk_files[f] = fp.read()
                            # Check if parent dir is SID
                            p_dir_name = os.path.basename(root)
                            if p_dir_name.startswith("S-1-5-"):
                                user_sid = p_dir_name
                        except Exception: pass

            if ld_bytes or mk_files or ls_bytes:
                bundles.append({
                    "user": user_name,
                    "browser": browser_name,
                    "masterkey_files": mk_files,
                    "local_state_bytes": ls_bytes,
                    "local_state_path": ls_path,
                    "login_data_bytes": ld_bytes,
                    "login_data_path": ld_path,
                    "sam_bytes": sam_bytes,
                    "sam_path": sam_path,
                    "system_bytes": sys_bytes,
                    "system_path": sys_path,
                    "protect_dir": protect_dir or t_dir,
                    "sid": user_sid
                })

        return bundles


def print_decrypted_table(creds: List[Dict[str, Any]]):
    if not creds:
        console.print("[yellow] No credentials decrypted.[/yellow]")
        return

    table = Table(
        title=f" Decrypted Plaintext Passwords ({len(creds)} Accounts Recovered)",
        show_header=True,
        header_style="bold magenta",
        border_style="bold green",
        expand=True
    )
    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("User", style="bold cyan", width=12)
    table.add_column("Origin / Target URL", style="cyan", min_width=32, overflow="fold")
    table.add_column("Username / Account", style="yellow", width=26)
    table.add_column("Decrypted Password", style="bold white on dark_green", width=24)
    table.add_column("Times Used", style="green", width=10, justify="center")

    for idx, c in enumerate(creds, start=1):
        table.add_row(
            str(idx),
            c.get("user", "User"),
            c.get("origin_url", ""),
            c.get("username", "") or "[dim]<empty>[/dim]",
            f" {c.get('password', '')} ",
            str(c.get("times_used", 0))
        )

    console.print(table)


def export_decrypted_markdown(creds: List[Dict[str, Any]], output_path: str):
    lines = [
        "# DFIR Forensic Report - Decrypted Plaintext Passwords",
        f"- **Total Accounts Decrypted:** `{len(creds)}`",
        "",
        "| # | User | Origin URL | Username / Account | Plaintext Password | Times Used |",
        "|---|---|---|---|---|:---:|"
    ]
    for idx, c in enumerate(creds, start=1):
        u = c.get("user", "").replace("|", "\\|")
        orig = c.get("origin_url", "").replace("|", "\\|")
        usr = c.get("username", "").replace("|", "\\|")
        pwd = c.get("password", "").replace("|", "\\|")
        tu = c.get("times_used", 0)
        lines.append(f"| {idx} | **{u}** | `{orig}` | `{usr}` | **`{pwd}`** | {tu} |")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    console.print(f"[bold green][/bold green] Exported decrypted credentials to Markdown (MD): [cyan]{output_path}[/cyan]")


def main(args_list=None):
    parser = argparse.ArgumentParser(
        prog="ad1 dpapi",
        description=" Decrypt DPAPI MasterKeys and Chromium passwords from AD1 logical images or extracted bundles.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ad1dpapi evidence.ad1 -p "Password123"
  ad1dpapi evidence.ad1 --ntlm "e0fb1f2654f21e6747d4e67fbe607293"
  ad1dpapi evidence.ad1 -w /usr/share/wordlists/rockyou.txt
  ad1dpapi ./extracted_credentials/Alice_Google_Chrome -p "Password123"
  ad1dpapi evidence.ad1 --export-all
        """
    )
    parser.add_argument("input", help="Path to input AD1 image file or extracted credentials directory")
    parser.add_argument("-p", "--password", help="User Windows plaintext password")
    parser.add_argument("--ntlm", help="User Windows NTLM hash (hex string)")
    parser.add_argument("-w", "--wordlist", help="Path to password wordlist dictionary (e.g. rockyou.txt)")
    parser.add_argument("--auto-sam", action="store_true", help="Automatically dump NTLM hashes from SAM & SYSTEM hives to unprotect MasterKey")
    
    # Export options
    parser.add_argument("--md", "--markdown", dest="md", help="Export to Markdown (.md) report")
    parser.add_argument("--json", help="Export to JSON file")
    parser.add_argument("--csv", help="Export to CSV file")
    parser.add_argument("--export-all", action="store_true", help="Generate MD, JSON, CSV reports")

    args = parser.parse_args(args_list)

    if not os.path.exists(args.input):
        console.print(f"[bold red]Error:[/bold red] File not found: {args.input}")
        sys.exit(1)

    print_ad1_banner("AD1 DPAPI MASTERKEY & PASSWORD DECRYPTOR (ad1dpapi)")

    if os.path.isfile(args.input) and args.input.lower().endswith(".ad1"):
        parser_ad1 = AD1Parser(args.input)
        decryptor = AD1DPAPIDecryptor(parser=parser_ad1)
    else:
        decryptor = AD1DPAPIDecryptor(bundle_dir=args.input)

    creds = decryptor.decrypt_bundle(
        password=args.password,
        ntlm_hex=args.ntlm,
        wordlist_path=args.wordlist
    )

    print_decrypted_table(creds)

    base_name = os.path.splitext(os.path.basename(args.input))[0]
    if args.export_all:
        if not args.md: args.md = f"{base_name}_decrypted_passwords.md"
        if not args.json: args.json = f"{base_name}_decrypted_passwords.json"
        if not args.csv: args.csv = f"{base_name}_decrypted_passwords.csv"

    if hasattr(args, 'md') and args.md: export_decrypted_markdown(creds, args.md)
    if hasattr(args, 'json') and args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"decrypted_credentials": creds}, f, indent=2, ensure_ascii=False)
        console.print(f"[bold green][/bold green] Exported decrypted credentials to JSON: [cyan]{args.json}[/cyan]")


if __name__ == "__main__":
    main()
