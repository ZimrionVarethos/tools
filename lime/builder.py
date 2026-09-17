#!/usr/bin/env python3
import argparse
import json
import lzma
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lime.engine import scan, validate_isf
from lime.recommend import SYMBOLS, command as shell_command


def show_usage(output, memory):
    print(f'ISF siap: {output}')
    print('Jalankan di WSL/Linux:')
    print(shell_command('vol', '-q', '-s', output.parent.parent, '-f', Path(memory).resolve(), 'linux.pslist.PsList'))
    print('Banner dan tipe cocok; hasil plugin menentukan kompatibilitas akhir.')


def main(argv=None):
    parser = argparse.ArgumentParser(description='Build and verify Volatility 3 Linux ISF against a memory dump.')
    parser.add_argument('memory')
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--vmlinux', help='Matching uncompressed ELF kernel containing DWARF debug information')
    source.add_argument('--isf', help='Validate and copy an existing ISF instead of building')
    parser.add_argument('--system-map', help='Optional matching System.map')
    parser.add_argument('--dwarf2json', default='dwarf2json', help='Executable path or command name')
    parser.add_argument('-o', '--output', help='New .json or .json.xz file; --isf defaults to the local symbols/linux directory')
    args = parser.parse_args(argv)
    try:
        report = scan(args.memory)
        if not report['banners']:
            raise ValueError('No complete Linux banner found; cannot verify a symbol build')
        if args.system_map and not args.vmlinux:
            raise ValueError('--system-map requires --vmlinux')
        if not args.output and args.isf:
            candidate = Path(args.isf).resolve()
            obj = validate_isf(candidate, report)
            output = candidate if candidate.parent.name == 'linux' else (SYMBOLS / 'linux' / candidate.name).resolve()
            if output.exists():
                if validate_isf(output, report) != obj:
                    raise ValueError('Different ISF already installed; choose a new --output filename')
                show_usage(output, args.memory)
                return 0
        elif not args.output:
            raise ValueError('--vmlinux requires --output')
        else:
            output = Path(args.output).resolve()
        if output.exists():
            raise ValueError('Output already exists; choose a new filename')
        if not str(output).endswith(('.json', '.json.xz')):
            raise ValueError('Output must end with .json or .json.xz')
        with tempfile.TemporaryDirectory(prefix='limebuild-') as temporary:
            candidate = args.isf
            if args.vmlinux:
                with open(args.vmlinux, 'rb') as elf:
                    if elf.read(4) != b'\x7fELF':
                        raise ValueError('vmlinux must be an uncompressed ELF, not a boot image or package')
                executable = shutil.which(args.dwarf2json)
                if not executable:
                    raise ValueError('dwarf2json missing. Build https://github.com/volatilityfoundation/dwarf2json and pass --dwarf2json PATH')
                command = [executable, 'linux', '--elf', str(Path(args.vmlinux).resolve())]
                if args.system_map:
                    if not Path(args.system_map).is_file():
                        raise ValueError('System.map not found')
                    command += ['--system-map', str(Path(args.system_map).resolve())]
                candidate = Path(temporary) / 'symbols.json'
                print('Generating symbols; large kernels may need 8 GB RAM or more.', file=sys.stderr)
                with candidate.open('wb') as stream:
                    subprocess.run(command, stdout=stream, check=True)
            obj = validate_isf(candidate, report)
            output.parent.mkdir(parents=True, exist_ok=True)
            # Exclusive creation avoids overwriting evidence or existing symbols.
            try:
                stream = output.open('xb')
            except FileExistsError:
                raise ValueError('Output already exists')
            try:
                with stream:
                    if str(output).endswith('.xz'):
                        with lzma.LZMAFile(stream, 'w') as compressed:
                            compressed.write(json.dumps(obj).encode('utf-8'))
                    else:
                        stream.write(json.dumps(obj).encode('utf-8'))
            except BaseException:
                output.unlink(missing_ok=True)
                raise
        show_usage(output, args.memory)
        return 0
    except (OSError, ValueError, subprocess.CalledProcessError, lzma.LZMAError) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
