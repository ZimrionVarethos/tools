#!/usr/bin/env python3
"""Build the native scanner once, then replace the launcher with it."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def main(argv=None):
    if sys.platform != 'linux':
        print('limefast runs on Linux/WSL. Use: wsl python3 /mnt/d/tools/lime/fast.py --help', file=sys.stderr)
        return 1
    folder = Path(__file__).resolve().parent
    source = folder / 'native.cpp'
    binary = folder / 'bin' / 'limefast'
    try:
        if not binary.exists() or source.stat().st_mtime_ns > binary.stat().st_mtime_ns:
            compiler = shutil.which('g++') or shutil.which('clang++')
            if not compiler:
                print('C++ compiler missing. Install g++ or clang++ in Linux/WSL.', file=sys.stderr)
                return 1
            binary.parent.mkdir(exist_ok=True)
            print('Compiling limefast (first run or updated source)...', file=sys.stderr)
            with tempfile.TemporaryDirectory(prefix='build-', dir=binary.parent) as temporary:
                candidate = Path(temporary) / 'limefast'
                subprocess.run([compiler, '-O3', '-std=c++17', '-Wall', '-Wextra', str(source), '-o', str(candidate)], check=True)
                candidate.chmod(0o755)
                os.replace(candidate, binary)
        os.execv(str(binary), [str(binary)] + (sys.argv[1:] if argv is None else argv))
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
