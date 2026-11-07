import os
import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
POWERSHELL = shutil.which("powershell.exe") if os.name == "nt" else None


class UiSessionTests(unittest.TestCase):
    @unittest.skipUnless(POWERSHELL, "Windows PowerShell 5.1 is required")
    def test_synthetic_ui_and_session_regressions(self):
        # A Python child of pwsh otherwise inherits PowerShell 7 module paths.
        environment = {key: value for key, value in os.environ.items()
                       if key.upper() != "PSMODULEPATH"}
        result = subprocess.run(
            [POWERSHELL, "-NoProfile", "-NonInteractive", "-File",
             str(ROOT / "tests/UiSession.Tests.ps1")],
            cwd=ROOT, env=environment, capture_output=True, timeout=90,
        )
        output = (result.stdout + result.stderr).decode(errors="replace")
        self.assertEqual(result.returncode, 0, output)
        self.assertIn("PASS:", output)

    def test_context_help_covers_each_registered_control(self):
        import json
        catalog = json.loads((ROOT / "catalog/collectors.json").read_text(encoding="utf8"))
        for agent in catalog["collectors"]:
            with self.subTest(control=agent["id"]):
                help_text = (ROOT / "help" / (agent["domain"] + ".md")).read_text(encoding="utf8")
                self.assertIn(agent["id"], help_text)
                self.assertIn("Esc", help_text)
                self.assertIn("-c", help_text)
                self.assertIn("-n", help_text)
