"""Integration tests against the real compiled scanner (Linux/WSL)."""
import csv
import io
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest


@unittest.skipUnless(sys.platform == 'linux' and shutil.which('g++'), 'requires Linux and g++')
class NativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.builddir = tempfile.TemporaryDirectory()
        cls.binary = Path(cls.builddir.name) / 'limefast'
        source = Path(__file__).resolve().parents[1] / 'lime/native.cpp'
        subprocess.run(['g++', '-O2', '-std=c++17', '-Wall', '-Wextra', str(source), '-o', str(cls.binary)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.builddir.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.memory = self.root / 'input with spaces.mem'

    def run_scan(self, *args):
        return subprocess.run([str(self.binary), str(self.memory), *args], capture_output=True, text=True)

    def rows(self, result):
        self.assertEqual(result.returncode, 0, result.stderr)
        return list(csv.DictReader(io.StringIO(result.stdout), delimiter='\t'))

    def lime(self, payloads, big=False):
        parts = []
        for i, payload in enumerate(payloads):
            start = 0x1000 + i*0x10000
            parts.append(struct.pack(('>' if big else '<') + 'IIQQ8s', 0x4c694d45, 1, start, start+len(payload)-1, b'\0'*8) + payload)
        self.memory.write_bytes(b''.join(parts))

    def test_offsets_and_context_escaping(self):
        self.lime([b'\0xxhttps://example.test\t\x1b\\end\0'])
        rows = self.rows(self.run_scan('--kind', 'urls'))
        self.assertEqual(rows[0]['file_offset'], '0x23')
        self.assertEqual(rows[0]['physical_address'], '0x1003')
        self.assertIn('\\x1b', rows[0]['text'])
        self.assertIn('\\x09', rows[0]['text'])
        self.assertNotIn('\x1b', rows[0]['text'])

    def test_find_binary_and_no_cross_range_matches(self):
        self.lime([b'\0needle\x01needle', b'tail'], big=True)
        self.assertEqual(len(self.rows(self.run_scan('--find', 'needle', '--limit', '0'))), 2)
        self.assertEqual(self.rows(self.run_scan('--find', 'needletail')), [])

    def test_truncated_and_overlap(self):
        self.lime([b'abc'])
        good = self.memory.read_bytes()
        self.memory.write_bytes(good[:-1])
        self.assertNotEqual(self.run_scan().returncode, 0)
        self.memory.write_bytes(good + good)
        self.assertNotEqual(self.run_scan().returncode, 0)

    def test_limit_output_protection_and_raw(self):
        self.memory.write_bytes(b'https://one\0https://two\0')
        result = self.run_scan('--kind', 'urls', '--limit', '1')
        self.assertEqual(len(self.rows(result)), 1)
        self.assertIn('partial scan', result.stderr)
        self.assertEqual(self.rows(result)[0]['physical_address'], '-')
        before = self.memory.read_bytes()
        self.assertNotEqual(self.run_scan('-o', str(self.memory)).returncode, 0)
        self.assertEqual(self.memory.read_bytes(), before)

    def test_long_string_and_flag_window_boundary(self):
        self.memory.write_bytes(b'a'*8100 + b' CTF{test_flag_value}' + b'z'*9000)
        self.assertTrue(self.rows(self.run_scan('--kind', 'flags')))

    def test_hexdump_bounds(self):
        self.memory.write_bytes(b'0123456789abcdef')
        result = self.run_scan('--read', '0x2', '--length', '4')
        self.assertEqual(result.returncode, 0)
        self.assertIn('32 33 34 35', result.stdout)
        self.assertIn('|2345|', result.stdout)
        self.assertNotEqual(self.run_scan('--read', '15', '--length', '2').returncode, 0)

    def test_empty_and_invalid_options(self):
        self.memory.write_bytes(b'')
        self.assertNotEqual(self.run_scan().returncode, 0)
        self.memory.write_bytes(b'abcd')
        for args in [('--limit', '-1'), ('--find', ''), ('--kind', 'wrong'), ('--context', '5000')]:
            self.assertNotEqual(self.run_scan(*args).returncode, 0)


if __name__ == '__main__':
    unittest.main()
