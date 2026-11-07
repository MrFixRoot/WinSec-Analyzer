import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


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
        for word in ['/device/','/scans/','/snapshots/','/evidence/','/reports/','/logs/','config/private/','config/local/']:
            self.assertIn(word,gi)
        self.assertTrue((ROOT/'AGENTS.md').exists())
        for domain in {a['domain'] for a in self.catalog['collectors']}:
            self.assertTrue((ROOT/'src/collectors'/domain/'AGENTS.md').is_file())

    def test_windows_11_and_no_app_version_in_banner(self):
        common=(ROOT/'src/core/Common.ps1').read_text(encoding='utf8')
        banner=(ROOT/'src/ui/Console.ps1').read_text(encoding='utf8')
        self.assertIn('ProductType',common)
        self.assertIn('22000',common)
        self.assertIn('mrRoot',banner)
        self.assertNotIn('$Version',banner)


if __name__ == '__main__':
    unittest.main()
