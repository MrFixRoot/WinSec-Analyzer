import json
import fnmatch
import posixpath
import re
import shutil
import subprocess
import unittest
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]


def is_private_path(path):
    path = path.replace('\\', '/').lower()
    # The directory marker ships no licensed local rule pack.
    if path == 'config/benchmarks/local/.gitkeep':
        return False
    name = path.rsplit('/', 1)[-1]
    return (
        name in {'agents.md', 'contributing.md', 'claude.md', 'gemini.md',
                 'copilot-instructions.md', '.env'}
        or fnmatch.fnmatchcase(name, '*.agent.md')
        or fnmatch.fnmatchcase(name, '*.instructions.md')
        or fnmatch.fnmatchcase(name, '.env.*')
        or path.startswith(('docs/', '.github/agents/', '.github/instructions/',
                            '.claude/', '.codex/', '.cursor/', 'device/', 'devices/',
                            'scans/', 'snapshots/', 'evidence/', 'reports/', 'logs/',
                            'output/', 'tmp/', 'temp/', 'artifacts/', 'config/private/',
                            'config/local/', 'config/benchmarks/local/'))
    )


class RepoStructureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = json.loads((ROOT / 'catalog/collectors.json').read_text(encoding='utf8'))

    def test_32_collectors_6_domains(self):
        agents = self.catalog['collectors']
        self.assertEqual(len(agents), 32)
        self.assertEqual(len({a['id'] for a in agents}), len(agents))
        self.assertEqual({a['domain'] for a in agents}, {
            'SystemSecurity', 'NetworkSecurity', 'IdentityAccess',
            'ServicesHardening', 'LoggingAuditing', 'PatchManagement',
        })

    def test_registered_agent_implementations(self):
        for a in self.catalog['collectors']:
            with self.subTest(collector=a['id']):
                p = ROOT / 'src/collectors' / a['domain'] / f"{a['id']}.ps1"
                self.assertTrue(p.is_file())
                source = p.read_text(encoding='utf8')
                self.assertIn(f"function {a['function']} ", source)
                self.assertIn('New-WinSecPayload', source)
                self.assertIn('[switch]$Deep', source)
                self.assertFalse(re.search(r'\b(?:Set|Enable|Disable|Remove)-(?:NetFirewall|MpPreference|BitLocker|Service|LocalUser|Smb|ItemProperty)', source))

    def test_inventory_matches_catalog(self):
        inv = json.loads((ROOT / 'catalog/evidence-inventory.json').read_text(encoding='utf8'))
        self.assertEqual(inv['itemCount'], len(inv['items']))
        agents = {a['id'] for a in self.catalog['collectors']}
        self.assertTrue(all(i['collector'] in agents for i in inv['items']))
        self.assertTrue(all(i['cisRuleStatus'] == 'AWAITING_VERIFIED_BENCHMARK' for i in inv['items']))

    def test_rules_and_mappings_only_nist_cis(self):
        nist = json.loads((ROOT / 'config/mappings/nist-csf-2.0.json').read_text(encoding='utf8'))
        corr = json.loads((ROOT / 'config/correlation-rules/cross-domain.json').read_text(encoding='utf8'))
        example = json.loads((ROOT / 'config/benchmarks/CIS/example-NOT-ACTIVE.json').read_text(encoding='utf8'))
        self.assertEqual(nist['framework'], 'NIST CSF 2.0')
        self.assertEqual(len(corr['correlations']), 4)
        self.assertFalse(example['verified'])
        self.assertFalse(example['rules'])
        ids={a['id'] for a in self.catalog['collectors']}
        for rule in corr['correlations']:
            self.assertTrue(set(rule['required']).issubset(ids))
            self.assertTrue(all(f['collector'] in ids for f in rule['facts']))
        self.assertTrue(all(set(c['collectors']).issubset(ids) for c in nist['mappings']))

    def test_privacy_gitignore(self):
        gi=(ROOT/'.gitignore').read_text(encoding='utf8')
        for word in ['AGENTS.md','/CONTRIBUTING.md','/docs/','.github/agents/',
                     '/device/','/devices/','/scans/','/snapshots/','/evidence/',
                     '/reports/','/logs/','/output/','/tmp/','/temp/','/artifacts/',
                     'config/private/','config/local/']:
            self.assertIn(word,gi)

    def test_tracked_files_exclude_private_content(self):
        if not (ROOT / '.git').exists() or not shutil.which('git'):
            self.skipTest('Git index is unavailable in a source archive')
        result = subprocess.run(['git', 'ls-files', '-z'], cwd=ROOT,
                                capture_output=True, check=True)
        files = result.stdout.decode('utf8').split('\0')
        private = [path for path in files if path and is_private_path(path)]
        self.assertEqual(private, [], 'Private paths are still tracked by Git')
        marker = ROOT / 'config/benchmarks/local/.gitkeep'
        if marker.exists():
            self.assertIn(marker.read_text(encoding='utf8').strip(),
                          ('', '# Local licensed benchmark packs are intentionally ignored.'),
                          'The local-pack marker must contain no rule pack or private data')

    def test_public_readme_links(self):
        text = (ROOT / 'README.md').read_text(encoding='utf8')
        for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)', text):
            parts = urlsplit(target.strip('<>'))
            if parts.scheme or parts.netloc or not parts.path:
                continue
            path = posixpath.normpath(unquote(parts.path))
            with self.subTest(link=target):
                self.assertFalse(is_private_path(path), 'README links to private documentation')
                self.assertTrue((ROOT / path).is_file(), 'README link target is missing')

    def test_windows_11_and_no_app_version_in_banner(self):
        common=(ROOT/'src/core/Common.ps1').read_text(encoding='utf8')
        banner=(ROOT/'src/ui/Console.ps1').read_text(encoding='utf8')
        self.assertIn('ProductType',common)
        self.assertIn('22000',common)
        self.assertIn('mrRoot',banner)
        self.assertNotIn('$Version',banner)


if __name__ == '__main__':
    unittest.main()

