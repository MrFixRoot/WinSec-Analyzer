
# ============================================================
# WinSec Analyzer
# Test: CLI Assessment Scoring Protection
# Version: 0.9.0
# ============================================================

$ErrorActionPreference = 'Stop'

. .\src\CLI\Invoke-WinSecCLI.ps1

$passed = 0
$failed = 0

function Assert-WinSecCLITest {
    param(
        [bool]$Condition,
        [string]$Name
    )

    if ($Condition) {
        Write-Host "[PASS] $Name" -ForegroundColor Green
        $script:passed++
    }
    else {
        Write-Host "[FAIL] $Name" -ForegroundColor Red
        $script:failed++
    }
}

# ------------------------------------------------------------
# TEST 1: A forged device score must not be trusted
# ------------------------------------------------------------

$state = [pscustomobject]@{
    SelectedDeviceId = 'local:TEST-PC'
}

$context = [pscustomobject]@{
    Devices = @(
        [pscustomobject]@{
            DeviceId = 'local:TEST-PC'
            ScanId = 'scan-001'
            Score = 100
            Status = 'PASS'
        }
    )

    SectionResults = @()
    ControlResults = @(
        [pscustomobject]@{
            DeviceId = 'local:TEST-PC'
            ScanId = 'scan-001'
            CheckId = 'TEST-CHECK'
            Status = 'NOT_EVALUATED'
        }
    )
    Findings = @()
    ScanId = 'scan-001'
}

$result = Get-WinSecCLIActiveAssessment `
    -State $state `
    -Context $context

Assert-WinSecCLITest `
    -Condition ($null -eq $result.OverallScore) `
    -Name 'Forged score 100 is rejected'

Assert-WinSecCLITest `
    -Condition ($result.OverallStatus -eq 'NOT_SCORED') `
    -Name 'Assessment remains NOT_SCORED'

# ------------------------------------------------------------
# TEST 2: Never mix devices
# ------------------------------------------------------------

$context.ControlResults += [pscustomobject]@{
    DeviceId = 'remote:OTHER-PC'
    ScanId = 'scan-001'
    CheckId = 'REMOTE-CHECK'
    Status = 'NOT_EVALUATED'
}

$result = Get-WinSecCLIActiveAssessment `
    -State $state `
    -Context $context

Assert-WinSecCLITest `
    -Condition (
        @($result.ControlResults).Count -eq 1 -and
        $result.ControlResults[0].CheckId -eq 'TEST-CHECK'
    ) `
    -Name 'Results remain isolated by DeviceId'

# ------------------------------------------------------------
# TEST 3: Never mix executions
# ------------------------------------------------------------

$context.ControlResults += [pscustomobject]@{
    DeviceId = 'local:TEST-PC'
    ScanId = 'scan-002'
    CheckId = 'OTHER-SCAN-CHECK'
    Status = 'NOT_EVALUATED'
}

$result = Get-WinSecCLIActiveAssessment `
    -State $state `
    -Context $context

Assert-WinSecCLITest `
    -Condition (
        @($result.ControlResults).Count -eq 1 -and
        $result.ControlResults[0].ScanId -eq 'scan-001'
    ) `
    -Name 'Results remain isolated by ScanId'

# ------------------------------------------------------------
# TEST 4: Reject ambiguous execution selection
# ------------------------------------------------------------

$context.ScanId = ''

$result = Get-WinSecCLIActiveAssessment `
    -State $state `
    -Context $context

Assert-WinSecCLITest `
    -Condition (
        -not [string]::IsNullOrWhiteSpace($result.Warning)
    ) `
    -Name 'Multiple scans require explicit selection'

# ------------------------------------------------------------
# TEST 5: No records means no verified score
# ------------------------------------------------------------

$emptyContext = [pscustomobject]@{
    Devices = @(
        [pscustomobject]@{
            DeviceId = 'local:TEST-PC'
            ScanId = ''
            Score = 100
            Status = 'PASS'
        }
    )
    SectionResults = @()
    ControlResults = @()
    Findings = @()
    ScanId = ''
}

$result = Get-WinSecCLIActiveAssessment `
    -State $state `
    -Context $emptyContext

Assert-WinSecCLITest `
    -Condition (
        $result.OverallStatus -eq 'PENDING' -and
        $null -eq $result.OverallScore
    ) `
    -Name 'Empty assessment remains PENDING'

# ------------------------------------------------------------
# SUMMARY
# ------------------------------------------------------------

Write-Host ''
Write-Host 'WINSEC CLI SCORING TEST SUMMARY' -ForegroundColor Cyan
Write-Host "Passed: $passed"
Write-Host "Failed: $failed"

if ($failed -gt 0) {
    throw "$failed CLI tests failed."
}

Write-Host '[PASS] All scoring protection tests passed.' `
    -ForegroundColor Green
