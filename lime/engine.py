import base64
import json
import lzma
import mmap
import re
import struct
from pathlib import Path

BANNER = re.compile(rb'Linux version [0-9]+\.[0-9]+[ -~]{1,2048}(?:\n\x00|\x00)')


def scan(path):
    path = Path(path)
    size = path.stat().st_size
    if not size:
        raise ValueError('Empty memory file')
    ranges = []
    with path.open('rb') as source, mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as data:
        endian = '<' if data[:4] == b'EMiL' else '>' if data[:4] == b'LiME' else None
        if endian:
            offset, previous = 0, -1
            while offset < size:
                if size - offset < 32:
                    raise ValueError(f'Truncated LiME header at {offset:#x}')
                magic, version, start, end, reserved = struct.unpack_from(endian + 'IIQQ8s', data, offset)
                if magic != 0x4C694D45 or version != 1 or end < start or start <= previous:
                    raise ValueError(f'Invalid LiME range at {offset:#x}')
                length = end - start + 1
                if offset + 32 + length > size:
                    raise ValueError(f'Truncated LiME payload at {offset:#x}')
                ranges.append({'offset': offset + 32, 'start': start, 'length': length})
                previous, offset = end, offset + 32 + length
        else:
            ranges = [{'offset': 0, 'start': None, 'length': size}]
        found = {}
        for region in ranges:
            for match in BANNER.finditer(data, region['offset'], region['offset'] + region['length']):
                raw = match.group()[:-1]
                key = raw.decode('ascii')
                if key not in found:
                    found[key] = {'banner': key, 'release': key.split()[2], 'offset': match.start(), 'count': 0}
                found[key]['count'] += 1
    return {'file': str(path.resolve()), 'size': size, 'format': 'LiME' if endian else 'raw/unknown',
            'ranges': ranges, 'banners': list(found.values())}


def read_isf(path):
    opener = lzma.open if str(path).endswith('.xz') else open
    with opener(path, 'rt', encoding='utf-8') as stream:
        obj = json.load(stream)
    if not isinstance(obj, dict) or not all(isinstance(obj.get(k), dict) and obj[k] for k in ('metadata', 'symbols', 'user_types', 'base_types')):
        raise ValueError('ISF lacks metadata, symbols or type information')
    try:
        banner = base64.b64decode(obj['symbols']['linux_banner']['constant_data'], validate=True).rstrip(b'\x00').decode('ascii')
    except (KeyError, ValueError, UnicodeError) as exc:
        raise ValueError('ISF lacks a valid linux_banner constant_data') from exc
    return obj, banner


def validate_isf(path, report):
    obj, banner = read_isf(path)
    if banner not in [item['banner'] for item in report['banners']]:
        raise ValueError('ISF kernel banner does not exactly match any banner in the dump')
    return obj
