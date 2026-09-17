#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lime.engine import scan
from lime.recommend import recommend, SYMBOLS


def main(argv=None):
    parser = argparse.ArgumentParser(description='Scan LiME/raw Linux memory and assess symbol readiness.')
    parser.add_argument('memory')
    parser.add_argument('--isf', help='Validate an existing JSON or JSON.xz symbol file')
    parser.add_argument('--json', action='store_true', help='Machine-readable report')
    parser.add_argument('--verbose', '-v', action='store_true', help='Show every detected banner')
    parser.add_argument('--symbols-dir', type=Path, default=SYMBOLS, help='Local symbol root to check automatically')
    args = parser.parse_args(argv)
    try:
        report = scan(args.memory)
        advice = recommend(report, args.symbols_dir, args.isf)
        report['status'] = advice['status']
        report['recommendation'] = advice
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print(f"Format: {report['format']} | Size: {report['size'] / 1024**3:.2f} GiB | Ranges: {len(report['ranges'])}")
            if 'selected' in advice:
                print('Kernel: ' + advice['selected']['release'])
            print('\nRekomendasi: ' + advice['message'])
            if advice.get('isf'):
                print('ISF: ' + advice['isf'])
            if advice.get('filename'):
                print('Cari/unduh file: ' + advice['filename'])
            if advice.get('url'):
                print('GitHub: ' + advice['url'])
                if advice.get('download_url'):
                    print('Download: ' + advice['download_url'])
                if advice.get('catalog_status') == 'listed':
                    print('Tercatat di katalog GitHub (' + advice['catalog_updated'][:10] + '); banner ISF belum diverifikasi.')
                else:
                    print('Belum ada satu entri pasti di katalog; link kandidat belum terverifikasi.')
                print('Banner acuan: ' + advice['selected']['banner'].rstrip())
            if advice.get('selection_note'):
                print(advice['selection_note'])
            if advice.get('commands'):
                print('\n' + ('Jalankan:' if advice.get('isf') else 'Setelah file ISF diunduh, jalankan:'))
                for cmd in advice['commands']:
                    print('  ' + cmd)
            if len(report['banners']) > 1 and not args.verbose:
                print(f"\n{len(report['banners'])} variasi banner ditemukan; satu dipilih untuk rekomendasi. Detail: --verbose")
            if args.verbose:
                for item in report['banners']:
                    print(f"Banner at {item['offset']:#x} ({item['count']} occurrences): {item['banner'].rstrip()}")
            if report['format'] != 'LiME':
                print('Raw/unknown: Linux banner detection does not establish that this is a full physical memory dump.')
        return 0 if report['banners'] else 2
    except (OSError, ValueError) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
