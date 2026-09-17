"""
AD1 Multi-Browser History Extraction & Forensics Parser
"""
import os
import re
import sqlite3
import tempfile
import urllib.parse
from typing import List, Dict, Any, Optional, Tuple
from .parser import AD1Parser
from .models import AD1Item
from core.utils import (
    webkit_timestamp_to_datetime,
    prtime_to_datetime,
    mac_absolute_time_to_datetime,
    format_datetime,
    extract_search_terms,
    extract_domain
)


class BrowserHistoryExtractor:
    """
    Scans AD1 images for browser history databases (Chrome, Edge, Firefox, Brave, Safari, Opera),
    extracts visited URLs, titles, timestamps, visit counts, user profiles, and search keywords.
    """
    def __init__(self, ad1_parser: AD1Parser):
        self.parser = ad1_parser
        self.extracted_records: List[Dict[str, Any]] = []

    def scan_and_extract(self, browser_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Scan all items in AD1 image for browser history databases and extract history entries.
        """
        if not self.parser.items:
            self.parser.build_tree()

        all_records = []

        for item in self.parser.items:
            if item.is_dir or item.decompressed_size < 512:
                continue

            full_path = item.full_path.replace("\\", "/")
            name_lower = item.item_name.lower()
            path_lower = full_path.lower()

            browser_type = self._detect_browser_type(full_path, name_lower)
            if not browser_type:
                continue

            if browser_filter and browser_filter.upper() != "ALL":
                if browser_filter.lower() not in browser_type.lower():
                    continue

            # Read file bytes from AD1
            file_bytes = self.parser.read_file_bytes(item)
            if not file_bytes or not file_bytes.startswith(b"SQLite format 3\x00"):
                continue

            # Extract user profile context from path
            user_name, profile_name = self._extract_user_context(full_path)

            # Parse SQLite database
            records = self._parse_sqlite_history(
                file_bytes=file_bytes,
                browser_type=browser_type,
                user_name=user_name,
                profile_name=profile_name,
                source_path=full_path
            )
            all_records.extend(records)

        # Sort all records descending by visit_time (newest first)
        def sort_key(rec):
            dt = rec.get("visit_time_obj")
            return dt.timestamp() if dt else 0

        all_records.sort(key=sort_key, reverse=True)
        self.extracted_records = all_records
        return all_records

    def _detect_browser_type(self, full_path: str, name_lower: str) -> Optional[str]:
        """
        Identify browser type from path and filename signatures.
        """
        path_lower = full_path.lower()

        # Google Chrome
        if ("google/chrome" in path_lower or "google\\chrome" in path_lower) and name_lower == "history":
            return "Google Chrome"
        # Microsoft Edge
        if ("microsoft/edge" in path_lower or "microsoft\\edge" in path_lower) and name_lower == "history":
            return "Microsoft Edge"
        # Brave
        if ("bravesoftware/brave-browser" in path_lower or "brave-browser" in path_lower) and name_lower == "history":
            return "Brave Browser"
        # Opera / Opera GX
        if ("opera software" in path_lower or "opera gx" in path_lower) and name_lower == "history":
            return "Opera Browser"
        # Vivaldi
        if "vivaldi" in path_lower and name_lower == "history":
            return "Vivaldi"
        # Firefox
        if ("mozilla/firefox" in path_lower or "firefox" in path_lower or "waterfox" in path_lower or "floorp" in path_lower or "tor browser" in path_lower) and name_lower in ["places.sqlite", "places.sqlite-wal"]:
            return "Mozilla Firefox"
        # Safari
        if "safari" in path_lower and name_lower in ["history.db", "history.plist"]:
            return "Apple Safari"
        # Generic History filename matches
        if name_lower == "history":
            return "Chromium Browser"
        if name_lower == "places.sqlite":
            return "Mozilla Firefox"
        if name_lower == "history.db":
            return "Apple Safari"

        return None

    def _extract_user_context(self, full_path: str) -> Tuple[str, str]:
        """
        Extract Windows/macOS/Linux username and browser profile name from forensic path.
        """
        user_name = "Default"
        profile_name = "Default"

        # Windows Users path: Users/<Username>/... or /Users/<Username>/... or C:/Users/<Username>/...
        user_match = re.search(r"(?:^|/|[a-zA-Z]:/)(?:Users|Documents and Settings|home)/([^/]+)/", full_path, re.IGNORECASE)
        if user_match:
            user_name = user_match.group(1)

        # Profile match: Default, Profile 1, Profile 2, or xxxxx.default-release
        prof_match = re.search(r"/(Default|Profile\s*\d+|[a-zA-Z0-9_-]+\.default(?:-release)?)/?", full_path, re.IGNORECASE)
        if prof_match:
            profile_name = prof_match.group(1)

        return user_name, profile_name

    def _parse_sqlite_history(
        self,
        file_bytes: bytes,
        browser_type: str,
        user_name: str,
        profile_name: str,
        source_path: str
    ) -> List[Dict[str, Any]]:
        """
        Parse browser SQLite database in a temporary isolated environment.
        """
        records = []
        temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        temp_path = temp_db.name

        try:
            temp_db.write(file_bytes)
            temp_db.flush()
            temp_db.close()

            # Connect SQLite
            conn = sqlite3.connect(f"file:{temp_path}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Inspect available tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = set(row[0].lower() for row in cursor.fetchall())

            # 1. Chromium Family Schema (urls & visits)
            if "urls" in tables:
                records.extend(self._parse_chromium_schema(cursor, browser_type, user_name, profile_name, source_path, "visits" in tables))

            # 2. Firefox Schema (moz_places & moz_historyvisits)
            elif "moz_places" in tables:
                records.extend(self._parse_firefox_schema(cursor, browser_type, user_name, profile_name, source_path, "moz_historyvisits" in tables))

            # 3. Safari Schema (history_items & history_visits)
            elif "history_items" in tables:
                records.extend(self._parse_safari_schema(cursor, browser_type, user_name, profile_name, source_path, "history_visits" in tables))

            conn.close()
        except Exception:
            pass
        finally:
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            except Exception:
                pass

        return records

    def _parse_chromium_schema(
        self,
        cursor: sqlite3.Cursor,
        browser_type: str,
        user_name: str,
        profile_name: str,
        source_path: str,
        has_visits_table: bool
    ) -> List[Dict[str, Any]]:
        """
        Parse Chrome/Edge/Brave/Opera/Chromium History SQLite tables.
        """
        records = []
        try:
            if has_visits_table:
                query = """
                SELECT 
                    u.url, 
                    u.title, 
                    u.visit_count, 
                    u.typed_count, 
                    u.last_visit_time,
                    v.visit_time,
                    v.visit_duration,
                    v.transition
                FROM urls u
                LEFT JOIN visits v ON u.id = v.url
                ORDER BY coalesce(v.visit_time, u.last_visit_time) DESC
                """
            else:
                query = """
                SELECT 
                    url, 
                    title, 
                    visit_count, 
                    typed_count, 
                    last_visit_time,
                    last_visit_time AS visit_time,
                    0 AS visit_duration,
                    0 AS transition
                FROM urls
                ORDER BY last_visit_time DESC
                """

            cursor.execute(query)
            rows = cursor.fetchall()

            for r in rows:
                url = r["url"] or ""
                if not url or url.startswith("chrome://") or url.startswith("edge://"):
                    continue

                title = r["title"] or ""
                visit_count = r["visit_count"] or 1
                typed_count = r["typed_count"] or 0
                
                # Timestamp parsing (Chrome uses WebKit microseconds)
                ts_raw = r["visit_time"] or r["last_visit_time"] or 0
                visit_dt = webkit_timestamp_to_datetime(ts_raw)
                
                search_terms = extract_search_terms(url)
                domain = extract_domain(url)

                records.append({
                    "browser": browser_type,
                    "user": user_name,
                    "profile": profile_name,
                    "url": url,
                    "title": title,
                    "visit_time_obj": visit_dt,
                    "visit_time_str": format_datetime(visit_dt),
                    "visit_count": visit_count,
                    "typed_count": typed_count,
                    "domain": domain,
                    "search_terms": search_terms,
                    "transition": r["transition"] if "transition" in r.keys() else 0,
                    "source_file": source_path
                })
        except Exception:
            pass

        return records

    def _parse_firefox_schema(
        self,
        cursor: sqlite3.Cursor,
        browser_type: str,
        user_name: str,
        profile_name: str,
        source_path: str,
        has_historyvisits: bool
    ) -> List[Dict[str, Any]]:
        """
        Parse Mozilla Firefox places.sqlite tables.
        """
        records = []
        try:
            if has_historyvisits:
                query = """
                SELECT 
                    p.url, 
                    p.title, 
                    p.visit_count, 
                    p.typed, 
                    p.last_visit_date,
                    h.visit_date,
                    h.visit_type
                FROM moz_places p
                LEFT JOIN moz_historyvisits h ON p.id = h.place_id
                WHERE p.url IS NOT NULL
                ORDER BY coalesce(h.visit_date, p.last_visit_date) DESC
                """
            else:
                query = """
                SELECT 
                    url, 
                    title, 
                    visit_count, 
                    typed, 
                    last_visit_date,
                    last_visit_date AS visit_date,
                    0 AS visit_type
                FROM moz_places
                WHERE url IS NOT NULL
                ORDER BY last_visit_date DESC
                """

            cursor.execute(query)
            rows = cursor.fetchall()

            for r in rows:
                url = r["url"] or ""
                if not url or url.startswith("about:") or url.startswith("moz-extension://"):
                    continue

                title = r["title"] or ""
                visit_count = r["visit_count"] or 1
                typed_count = r["typed"] if "typed" in r.keys() and r["typed"] else 0

                # Timestamp parsing (Firefox uses PRTime microseconds since 1970)
                ts_raw = r["visit_date"] or r["last_visit_date"] or 0
                visit_dt = prtime_to_datetime(ts_raw)

                search_terms = extract_search_terms(url)
                domain = extract_domain(url)

                records.append({
                    "browser": browser_type,
                    "user": user_name,
                    "profile": profile_name,
                    "url": url,
                    "title": title,
                    "visit_time_obj": visit_dt,
                    "visit_time_str": format_datetime(visit_dt),
                    "visit_count": visit_count,
                    "typed_count": typed_count,
                    "domain": domain,
                    "search_terms": search_terms,
                    "transition": r["visit_type"] if "visit_type" in r.keys() else 0,
                    "source_file": source_path
                })
        except Exception:
            pass

        return records

    def _parse_safari_schema(
        self,
        cursor: sqlite3.Cursor,
        browser_type: str,
        user_name: str,
        profile_name: str,
        source_path: str,
        has_visits: bool
    ) -> List[Dict[str, Any]]:
        """
        Parse Safari History.db tables.
        """
        records = []
        try:
            if has_visits:
                query = """
                SELECT 
                    i.url, 
                    v.title, 
                    i.visit_count, 
                    v.visit_time
                FROM history_items i
                LEFT JOIN history_visits v ON i.id = v.history_item
                ORDER BY v.visit_time DESC
                """
            else:
                query = """
                SELECT 
                    url, 
                    '' AS title, 
                    visit_count, 
                    0 AS visit_time
                FROM history_items
                ORDER BY visit_count DESC
                """

            cursor.execute(query)
            rows = cursor.fetchall()

            for r in rows:
                url = r["url"] or ""
                if not url:
                    continue

                title = r["title"] or ""
                visit_count = r["visit_count"] or 1
                
                # Timestamp parsing (Safari uses Mac absolute time seconds since 2001)
                ts_raw = r["visit_time"] or 0
                visit_dt = mac_absolute_time_to_datetime(ts_raw)

                search_terms = extract_search_terms(url)
                domain = extract_domain(url)

                records.append({
                    "browser": browser_type,
                    "user": user_name,
                    "profile": profile_name,
                    "url": url,
                    "title": title,
                    "visit_time_obj": visit_dt,
                    "visit_time_str": format_datetime(visit_dt),
                    "visit_count": visit_count,
                    "typed_count": 0,
                    "domain": domain,
                    "search_terms": search_terms,
                    "transition": 0,
                    "source_file": source_path
                })
        except Exception:
            pass

        return records
