from pathlib import Path
import unittest
from unittest.mock import patch

from lime.recommend import recommend, command


BANNER = ('Linux version 6.8.0-124-generic (buildd@test) '
          '(x86_64-linux-gnu-gcc-12) #124~22.04.1-Ubuntu SMP '
          'Tue May 26 21:05:19 UTC  (Ubuntu 6.8.0-124.124~22.04.1-generic 6.8.12)\n')


class Recommendations(unittest.TestCase):
    def report(self):
        variants = [BANNER.replace('Tue May 26 21:05:19 UTC', ''), BANNER, BANNER.rstrip() + '2)\n']
        return {'file': '/tmp/evidence with spaces.mem', 'banners': [
            {'banner': text, 'release': '6.8.0-124-generic', 'count': 1, 'offset': i}
            for i, text in enumerate(variants)]}

    @patch('lime.recommend.Path.rglob', return_value=[])
    def test_exact_candidate_and_full_banner(self, _):
        result = recommend(self.report(), Path('/symbols'))
        self.assertEqual(result['selected']['banner'], BANNER)
        self.assertEqual(result['filename'], 'Ubuntu_6.8.0-124-generic_6.8.0-124.124~22.04.1_amd64.json.xz')
        self.assertIn('/Ubuntu/amd64/6.8.0/124/generic', result['url'])
        self.assertIn("'/tmp/evidence with spaces.mem'", result['commands'][0])
        self.assertEqual(result['status'], 'find_prebuilt_isf')
        self.assertEqual(result['catalog_status'], 'listed')
        self.assertIn('raw.githubusercontent.com', result['download_url'])
        self.assertNotIn('/master/', result['download_url'])

    @patch('lime.recommend.read_isf', return_value=({}, BANNER))
    def test_local_match_overrides_build_recommendation(self, _):
        result = recommend(self.report(), explicit_isf='/symbols/linux/test.json.xz')
        self.assertEqual(result['status'], 'matching_isf')
        self.assertEqual(len(result['commands']), 1)
        self.assertTrue(result['commands'][0].startswith('limebuild '))

    @patch('lime.recommend.read_isf', return_value=({}, 'wrong banner'))
    def test_mismatch_rejected(self, _):
        with self.assertRaises(ValueError):
            recommend(self.report(), explicit_isf='/symbols/linux/test.json.xz')

    @patch('lime.recommend.Path.rglob', return_value=[])
    def test_unknown_distro_no_invented_filename(self, _):
        report = self.report()
        report['banners'] = [{'banner': 'Linux version 6.8.0-custom\n', 'release': '6.8.0-custom', 'count': 1}]
        self.assertNotIn('filename', recommend(report))
        self.assertEqual(recommend({'banners': []})['status'], 'no_linux_banner_found')

    def test_shell_quoting(self):
        self.assertEqual(command('limebuild', '$(touch bad).mem'), "limebuild '$(touch bad).mem'")
        self.assertIn('/mnt/d/', command('vol', '-s', 'D:\\tools\\lime\\symbols'))


if __name__ == '__main__':
    unittest.main()
