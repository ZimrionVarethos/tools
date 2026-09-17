import base64
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from lime.engine import scan, validate_isf
from lime.builder import main as build
from lime.recommend import recommend


class LimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.banner = b'Linux version 6.8.0-test (builder@test) #1 SMP test\n'
        self.payload = b'padding' + self.banner + b'\0' + b'end'
        self.memory = self.root / 'memory.mem'
        self.memory.write_bytes(struct.pack('<IIQQ8s', 0x4c694d45, 1, 4096, 4096 + len(self.payload) - 1, b'\0'*8) + self.payload)
        self.symbols = self.root / 'source.json'
        self.obj = {'metadata': {'format': '6.2.0'}, 'base_types': {'int': {}}, 'user_types': {'task_struct': {}},
                    'symbols': {'linux_banner': {'address': 1, 'constant_data': base64.b64encode(self.banner + b'\0').decode()}}}
        self.symbols.write_text(json.dumps(self.obj))

    def test_scan_and_import(self):
        report = scan(self.memory)
        self.assertEqual(report['format'], 'LiME')
        self.assertEqual(report['banners'][0]['offset'], 39)
        output = self.root / 'symbols/linux/test.json.xz'
        self.assertEqual(build([str(self.memory), '--isf', str(self.symbols), '-o', str(output)]), 0)
        validate_isf(output, report)
        original = output.read_bytes()
        self.assertEqual(build([str(self.memory), '--isf', str(self.symbols), '-o', str(output)]), 1)
        self.assertEqual(output.read_bytes(), original)

    def test_truncated(self):
        self.memory.write_bytes(self.memory.read_bytes()[:-1])
        with self.assertRaisesRegex(ValueError, 'Truncated'):
            scan(self.memory)

    def test_local_match_and_default_install(self):
        repo = self.root / 'repo/Ubuntu'
        repo.mkdir(parents=True)
        import lzma
        source = repo / 'Ubuntu_6.8.0-test.json.xz'
        source.write_bytes(lzma.compress(json.dumps(self.obj).encode()))
        installed = self.root / 'installed'
        advice = recommend(scan(self.memory), symbols_dir=repo)
        self.assertEqual(advice['isf'], str(source.resolve()))
        self.assertEqual(len(advice['commands']), 1)
        self.assertTrue(advice['commands'][0].startswith('limebuild '))
        with patch('lime.builder.SYMBOLS', installed):
            self.assertEqual(build([str(self.memory), '--isf', str(source)]), 0)
            target = installed / 'linux' / source.name
            before = target.stat().st_mtime_ns
            self.assertEqual(build([str(self.memory), '--isf', str(source)]), 0)
            self.assertEqual(target.stat().st_mtime_ns, before)
            self.assertEqual(build([str(self.memory), '--isf', str(source), '--system-map', 'invalid']), 1)

    def test_mismatch_rejected(self):
        self.obj['symbols']['linux_banner']['constant_data'] = base64.b64encode(b'Linux version wrong\n\0').decode()
        self.symbols.write_text(json.dumps(self.obj))
        with self.assertRaisesRegex(ValueError, 'exactly match'):
            validate_isf(self.symbols, scan(self.memory))

    def test_raw_and_empty(self):
        self.memory.write_bytes(self.payload)
        self.assertEqual(scan(self.memory)['format'], 'raw/unknown')
        self.memory.write_bytes(b'')
        with self.assertRaises(ValueError):
            scan(self.memory)

    def test_big_endian_and_multiple_ranges(self):
        header = lambda start: struct.pack('>IIQQ8s', 0x4c694d45, 1, start, start + len(self.payload) - 1, b'\0'*8)
        self.memory.write_bytes(header(0) + self.payload + header(4096) + self.payload)
        self.assertEqual(scan(self.memory)['banners'][0]['count'], 2)
        self.memory.write_bytes(header(0) + self.payload + header(0) + self.payload)
        with self.assertRaises(ValueError):
            scan(self.memory)


if __name__ == '__main__':
    unittest.main()
