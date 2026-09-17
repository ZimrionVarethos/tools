"""Small filename catalog. Refresh metadata only; never download ISF blobs."""
import argparse
from datetime import datetime, timezone
import gzip
import json
from pathlib import Path
import subprocess
import urllib.request

CATALOG = Path(__file__).resolve().parent / 'isf-catalog.json.gz'
API = 'https://api.github.com/repos/Abyss-W4tcher/volatility3-symbols/git/trees/master?recursive=1'


def load_catalog(path=CATALOG):
    try:
        with gzip.open(path, 'rt', encoding='utf-8') as source:
            return json.load(source)
    except (OSError, ValueError, EOFError):
        return {'files': [], 'commit': '', 'updated': ''}


def main():
    parser = argparse.ArgumentParser(description='Refresh ISF filename/link catalog only (no symbol downloads).')
    parser.add_argument('--from-repo', type=Path, help='Read an existing Git tree offline, without checking out blobs')
    args = parser.parse_args()
    if args.from_repo:
        prefix = ['git', '-C', str(args.from_repo)]
        commit = subprocess.check_output(prefix + ['rev-parse', 'HEAD'], text=True).strip()
        paths = subprocess.check_output(prefix + ['ls-tree', '-r', '--name-only', 'HEAD'], text=True).splitlines()
    else:
        with urllib.request.urlopen(API, timeout=60) as response:
            tree = json.load(response)
        if tree.get('truncated'):
            raise ValueError('Remote tree truncated; keeping previous catalog')
        commit = tree['sha']
        paths = [item['path'] for item in tree['tree'] if item['type'] == 'blob']
    obj = {'commit': commit, 'updated': datetime.now(timezone.utc).isoformat(),
           'files': sorted(p for p in paths if p.endswith('.json.xz'))}
    if not obj['files']:
        raise ValueError('Empty catalog; keeping previous catalog')
    temporary = CATALOG.with_suffix('.tmp')
    with gzip.open(temporary, 'wt', encoding='utf-8') as stream:
        json.dump(obj, stream, separators=(',', ':'))
    temporary.replace(CATALOG)
    print(f"Catalog: {len(obj['files'])} ISF filenames, {CATALOG.stat().st_size} bytes; no ISFs downloaded.")


if __name__ == '__main__':
    main()
