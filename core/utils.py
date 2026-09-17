"""
Core Forensic Utilities & Timestamp Parsers
"""
from datetime import datetime, timezone, timedelta
import urllib.parse
from typing import Optional, Tuple, Dict, Any


def webkit_timestamp_to_datetime(microseconds: int) -> Optional[datetime]:
    """
    Convert WebKit / Chrome timestamp (microseconds since Jan 1, 1601 UTC)
    to a standard timezone-aware datetime object.
    """
    if not microseconds or microseconds <= 0:
        return None
    try:
        # 11644473600 is seconds between 1601-01-01 and 1970-01-01
        epoch_seconds = (microseconds / 1_000_000.0) - 11644473600.0
        if epoch_seconds < 0:
            return None
        return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc)
    except Exception:
        return None


webkit_to_datetime = webkit_timestamp_to_datetime


def prtime_to_datetime(microseconds: int) -> Optional[datetime]:
    """
    Convert Mozilla PRTime (microseconds since Jan 1, 1970 UTC)
    to a standard timezone-aware datetime object.
    """
    if not microseconds or microseconds <= 0:
        return None
    try:
        return datetime.fromtimestamp(microseconds / 1_000_000.0, tz=timezone.utc)
    except Exception:
        return None


def mac_absolute_time_to_datetime(seconds: float) -> Optional[datetime]:
    """
    Convert Mac Absolute Time / Cocoa Core Data timestamp
    (seconds since Jan 1, 2001 UTC) to datetime object.
    """
    if not seconds or seconds <= 0:
        return None
    try:
        # Seconds between 1970-01-01 and 2001-01-01 = 978307200
        epoch_seconds = seconds + 978307200.0
        return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc)
    except Exception:
        return None


def filetime_to_datetime(filetime: int) -> Optional[datetime]:
    """
    Convert Windows FILETIME (100-nanosecond intervals since Jan 1, 1601 UTC)
    to datetime object.
    """
    if not filetime or filetime <= 0:
        return None
    try:
        epoch_seconds = (filetime / 10_000_000.0) - 11644473600.0
        return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc)
    except Exception:
        return None


def format_datetime(dt: Optional[datetime]) -> str:
    """
    Format datetime into standard ISO-8601 UTC string.
    """
    if dt is None:
        return "N/A"
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def extract_search_terms(url: str) -> Optional[str]:
    """
    Extract search keywords from popular search engine URLs (Google, Bing, Yahoo, DuckDuckGo, YouTube, etc.)
    """
    if not url:
        return None
    try:
        parsed = urllib.parse.urlparse(url)
        netloc = parsed.netloc.lower()
        query_params = urllib.parse.parse_qs(parsed.query)

        # Google, Bing, Yahoo, DuckDuckGo, Ecosia, Baidu, YouTube, GitHub, Reddit
        search_keys = ['q', 'query', 'p', 'search_query', 'k', 'searchTerm', 'keyword', 'text']

        if any(engine in netloc for engine in ['google.', 'bing.com', 'duckduckgo.com', 'yahoo.com', 'ecosia.org', 'youtube.com', 'github.com', 'reddit.com', 'yandex.']):
            for key in search_keys:
                if key in query_params and query_params[key]:
                    return query_params[key][0]
    except Exception:
        pass
    return None


def extract_domain(url: str) -> str:
    """
    Extract clean domain from URL.
    """
    if not url:
        return ""
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc or parsed.path.split('/')[0]
    except Exception:
        return ""


def human_size(size_bytes: int) -> str:
    """
    Convert bytes to human-readable format (KB, MB, GB).
    """
    if size_bytes < 0:
        return "0 B"
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}" if unit != 'B' else f"{size_bytes} B"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"


def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon Entropy of a byte buffer (0.0 to 8.0).
    """
    if not data:
        return 0.0
    import math
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    entropy = 0.0
    for count in counts:
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    return entropy


def is_ascii_printable(data: bytes, threshold: float = 0.85) -> bool:
    """
    Check if byte buffer consists primarily of printable ASCII characters.
    """
    if not data:
        return False
    printable = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
    return (printable / len(data)) >= threshold


def extract_flags_from_bytes(data: bytes) -> list:
    """
    Extract common CTF flag formats (FLAG{...}, CTF{...}, SATSIBER{...}, etc.) from raw bytes.
    """
    if not data:
        return []
    import re
    flags = []
    # Standard format regex
    patterns = [
        rb"(?:[A-Za-z0-9_]{2,15}\{[A-Za-z0-9_\-!@#$%^&*+=:;.]{3,120}\})",
        rb"(?:flag\{[^ \r\n\t\}]{3,120}\})",
        rb"(?:satsiber\{[^ \r\n\t\}]{3,120}\})"
    ]
    for p in patterns:
        matches = re.findall(p, data, re.IGNORECASE)
        for m in matches:
            decoded = m.decode(errors="ignore")
            if decoded not in flags:
                flags.append(decoded)
    return flags
