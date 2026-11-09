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
        self._check_powershell_script("UiSession.Tests.ps1")

    @unittest.skipUnless(POWERSHELL, "Windows PowerShell 5.1 is required")
    def test_synthetic_device_inventory_regressions(self):
        self._check_powershell_script("Devices.Tests.ps1")

    @unittest.skipUnless(POWERSHELL, "Windows PowerShell 5.1 is required")
    def test_interactive_completion(self):
        self._check_powershell_script("Completion.Tests.ps1")

    @unittest.skipUnless(POWERSHELL, "Windows PowerShell 5.1 is required")
    def test_analysis_recovery(self):
        self._check_powershell_script("AnalysisRecovery.Tests.ps1")

    @unittest.skipUnless(POWERSHELL, "Windows PowerShell 5.1 is required")
    def test_os_context_and_warning_status(self):
        self._check_powershell_script("OSContext.Tests.ps1")

    def _check_powershell_script(self, name):
        # A Python child of pwsh otherwise inherits PowerShell 7 module paths.
        environment = {key: value for key, value in os.environ.items()
                       if key.upper() != "PSMODULEPATH"}
        result = subprocess.run(
            [POWERSHELL, "-NoProfile", "-NonInteractive", "-File",
             str(ROOT / "tests" / name)],
            cwd=ROOT, env=environment, capture_output=True, timeout=90,
        )
        output = (result.stdout + result.stderr).decode(errors="replace")
        self.assertEqual(result.returncode, 0, output)
        self.assertIn("PASS:", output)

    @unittest.skipUnless(POWERSHELL, "Windows PowerShell 5.1 is required")
    def test_context_help_covers_each_registered_control(self):
        self._check_powershell_script("Help.Tests.ps1")
