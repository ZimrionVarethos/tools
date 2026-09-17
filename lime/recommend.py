"""Actionable, offline symbol recommendations; never claim an unverified download matches."""
import lzma
from pathlib import Path
import re
import shlex
from urllib.parse import quote

from lime.engine import read_isf
from lime.catalog import load_catalog

SYMBOLS = Path(__file__).resolve().parent / 'symbols'
REPOSITORY = 'https://github.com/Abyss-W4tcher/volatility3-symbols'


def shell_path(path):
    value = str(path)
    if re.match(r'^[A-Za-z]:[\\/]', value):
        value = '/mnt/' + value[0].lower() + '/' + value[3:].replace('\\', '/')
    return value


def command(*args):
    return shlex.join([shell_path(arg) for arg in args])


def recommend(report, symbols_dir=SYMBOLS, explicit_isf=None):
    banners = {item['banner']: item for item in report['banners']}
    if not banners:
        return {'status': 'no_linux_banner_found', 'message': 'Banner Linux lengkap tidak ditemukan; belum bisa memilih ISF.'}
    paths = [Path(explicit_isf)] if explicit_isf else sorted(
        p for p in Path(symbols_dir).rglob('*') if p.is_file() and str(p).endswith(('.json', '.json.xz')))
    for path in paths:
        try:
            _, banner = read_isf(path)
        except (OSError, ValueError, TypeError, AttributeError, lzma.LZMAError):
            if explicit_isf:
                raise ValueError('ISF yang diberikan tidak valid')
            continue
        if banner in banners:
            commands = [command('limebuild', report['file'], '--isf', path.resolve())]
            return {'status': 'matching_isf', 'selected': banners[banner], 'isf': str(path.resolve()),
                    'message': 'Pakai ISF ini: banner cocok persis. Jalankan limebuild untuk menyiapkan pemakaian di Vol3.', 'commands': commands}
    if explicit_isf:
        raise ValueError('ISF kernel banner does not exactly match any banner in the dump')
    # Prefer intact Ubuntu suffix and a build timestamp over truncated/stale fragments.
    # This ranks search candidates only; exact ISF validation remains mandatory.
    def rank(item):
        banner = item['banner'].rstrip()
        return (bool(re.search(r'\(Ubuntu [^()]+\)$', banner)),
                bool(re.search(r'\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) \w{3} +\d+ \d\d:\d\d:\d\d', banner)),
                item['count'])
    selected = max(report['banners'], key=rank)
    banner = selected['banner']
    package = re.search(r'\(Ubuntu ([0-9][^\s()]+) [^()]+\)\s*$', banner)
    release = re.fullmatch(r'(\d+\.\d+\.\d+)-(\d+)-([A-Za-z0-9-]+)', selected['release'])
    arch = 'amd64' if 'x86_64-linux-gnu' in banner else 'arm64' if 'aarch64-linux-gnu' in banner else None
    result = {'status': 'find_prebuilt_isf', 'selected': selected,
              'message': 'Cari ISF siap pakai terlebih dahulu; belum perlu build kernel.',
              'selection_note': 'Kandidat pencarian; kecocokan persis baru diverifikasi oleh limebuild.'}
    if package and release and arch and package[1].endswith('-' + release[3]):
        revision = package[1][:-len(release[3])-1]
        filename = f'Ubuntu_{selected["release"]}_{revision}_{arch}.json.xz'
        folder = f'Ubuntu/{arch}/{release[1]}/{release[2]}/{release[3]}'
        result.update(filename=filename, url=REPOSITORY + '/tree/master/' + folder,
                      download_url=REPOSITORY.replace('github.com', 'raw.githubusercontent.com') + '/master/' + folder + '/' + quote(filename, safe=''))
        result['commands'] = [command('limebuild', report['file'], '--isf', './' + filename)]
    else:
        result['url'] = REPOSITORY
        result['query'] = selected['release']
        result['message'] = 'Cari ISF dengan banner berikut; distro/revisi/arsitektur belum cukup pasti untuk menebak nama file.'
        result['commands'] = [command('limebuild', report['file'], '--isf', '/path/ISF-yang-diunduh.json.xz')]
    catalog = load_catalog()
    matches = [p for p in catalog['files'] if p.rsplit('/', 1)[-1] == result.get('filename')]
    if not result.get('filename'):
        matches = [p for p in catalog['files'] if selected['release'] + '_' in p.rsplit('/', 1)[-1]]
    if len(matches) == 1:
        path = matches[0]
        result['filename'] = path.rsplit('/', 1)[-1]
        result['url'] = REPOSITORY + '/blob/' + catalog['commit'] + '/' + quote(path, safe='/')
        result['download_url'] = REPOSITORY.replace('github.com', 'raw.githubusercontent.com') + '/' + catalog['commit'] + '/' + quote(path, safe='/')
        result['catalog_status'] = 'listed'
        result['catalog_updated'] = catalog['updated']
        result['commands'] = [command('limebuild', report['file'], '--isf', './' + result['filename'])]
    else:
        result['catalog_status'] = 'not_listed' if not matches else 'ambiguous'
    return result


def unused_output(path):
    original = path
    count = 1
    while path.exists():
        path = original.with_name(f'import-{count}-' + original.name)
        count += 1
    return path
