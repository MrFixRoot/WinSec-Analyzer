# ============================================================
# WinSec Analyzer - Public Result Identity Integration Tests
# PowerShell 5.1 / 7.x; no Pester required.
# Synthetic in-memory data only: no scans, writes or scoring.
# ============================================================

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$projectRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '../..')
)

foreach ($relativePath in @(
    'src/Core/EvaluationEngine.ps1'
    'src/Core/FindingsEngine.ps1'
    'src/Core/ResultModel.ps1'
    'src/CLI/Invoke-WinSecCLI.ps1'
)) {
    . (Join-Path $projectRoot $relativePath)
}

$script:passed = 0
$script:failed = 0

function Assert-WinSecIdentityIntegration {
    param([bool]$Condition, [string]$Message)

    if (-not $Condition) { throw $Message }
}

function Test-WinSecIdentityIntegrationCase {
    param([string]$Name, [scriptblock]$Action)

    try {
        $null = & $Action
        $script:passed++
        Write-Host "[PASS] $Name" -ForegroundColor Green
    }
    catch {
        $script:failed++
        Write-Host "[FAIL] $Name" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor DarkGray
    }
}

function New-WinSecIdentityIntegrationFixture {
    $deviceId = 'local:IDENTITY-FIXTURE'
    $scanId = 'IDENTITY-SCAN-001'
    $control = [pscustomobject]@{
        DeviceId = $deviceId
        ScanId = $scanId
        CheckId = 'WSA-SYS-001'
        SectionKey = 'SystemSecurity'
        Status = 'INFORMATIONAL'
        ObservedStatus = 'INFORMATIONAL'
        Evidence = [pscustomobject]@{
            DeviceId = $deviceId
            ScanId = $scanId
            CheckId = 'WSA-SYS-001'
            CollectionSuccessful = $true
            SyntheticValue = 'IDENTITY-FIXTURE-ONLY'
        }
    }

    # No criteria are supplied, so no PASS/FAIL can be asserted.
    $evaluation = Invoke-WinSecControlEvaluation -ControlResult $control
    $findings = ConvertTo-WinSecFindings `
        -EvaluationResult $evaluation -ControlResult $control
    $session = New-WinSecResultSession `
        -DeviceId $deviceId -ScanId $scanId `
        -ControlResults @($control) `
        -EvaluationResults @($evaluation) `
        -Findings @($findings.Findings)
    $public = ConvertTo-WinSecPublicScanResult -Session $session
    $key = '{0}:{1}{2}:{3}' -f `
        $deviceId.Length, $deviceId, $scanId.Length, $scanId

    return [pscustomobject]@{
        Session = $session
        Public = $public
        State = [pscustomobject]@{ SelectedDeviceId = $deviceId }
        Context = [pscustomobject]@{
            ActiveScanByDevice = @{ $deviceId = $scanId }
            PublicScans = @{ $key = $public }
        }
    }
}

Test-WinSecIdentityIntegrationCase 'Core projections reach the matching CLI assessment' {
    $fixture = New-WinSecIdentityIntegrationFixture
    $assessment = Get-WinSecCLIActiveAssessment `
        -State $fixture.State -Context $fixture.Context

    Assert-WinSecIdentityIntegration (
        $assessment.ControlResults.Count -eq 1 -and
        $assessment.Findings.Count -eq 1 -and
        $assessment.Findings[0].Kind -ceq 'EVALUATION_PENDING' -and
        $assessment.OverallStatus -ceq 'NOT_SCORED' -and
        $null -eq $assessment.OverallScore -and
        $null -eq $assessment.ControlResults[0].PSObject.Properties['Evidence']
    ) 'The safe, unscored Core projection was not preserved.'
}

foreach ($collectionName in @('ControlResults', 'Findings')) {
    foreach ($field in @('DeviceId', 'ScanId')) {
        Test-WinSecIdentityIntegrationCase "$collectionName rejects a substituted $field" {
            $fixture = New-WinSecIdentityIntegrationFixture
            $fixture.Public.$collectionName[0].$field = 'OTHER-IDENTITY'
            $contextBefore = ConvertTo-Json `
                -InputObject $fixture.Context -Depth 12 -Compress
            $rejected = $false
            $assessment = $null

            try {
                $assessment = Get-WinSecCLIActiveAssessment `
                    -State $fixture.State -Context $fixture.Context
            }
            catch {
                $rejected = $true
            }

            Assert-WinSecIdentityIntegration (
                $rejected -and $null -eq $assessment
            ) 'A substituted identity reached the CLI assessment.'
            Assert-WinSecIdentityIntegration (
                (ConvertTo-Json -InputObject $fixture.Context -Depth 12 -Compress) -ceq $contextBefore
            ) 'Identity rejection changed the stored session.'
        }
    }
}

Test-WinSecIdentityIntegrationCase 'A foreign record prevents partial publication' {
    $fixture = New-WinSecIdentityIntegrationFixture
    $foreign = $fixture.Public.ControlResults[0].PSObject.Copy()
    $foreign.ScanId = 'OTHER-SCAN'
    $fixture.Public.ControlResults = @(
        $fixture.Public.ControlResults[0]
        $foreign
    )
    $published = @()
    $rejected = $false

    try {
        Get-WinSecCLIActiveAssessment `
            -State $fixture.State -Context $fixture.Context |
            ForEach-Object { $published += $_ }
    }
    catch {
        $rejected = $true
    }

    Assert-WinSecIdentityIntegration (
        $rejected -and $published.Count -eq 0
    ) 'A valid prefix was published before the foreign record was rejected.'
}

Test-WinSecIdentityIntegrationCase 'CLI readers cannot rewrite the public cache or internal session' {
    $fixture = New-WinSecIdentityIntegrationFixture
    $publicBefore = ConvertTo-Json -InputObject $fixture.Public -Depth 15 -Compress
    $sessionBefore = ConvertTo-Json -InputObject $fixture.Session -Depth 15 -Compress
    $first = Get-WinSecCLIActiveAssessment -State $fixture.State -Context $fixture.Context
    $first.ControlResults[0].Status = 'FAIL'
    $first.Findings[0].ScanId = 'changed'
    $second = Get-WinSecCLIActiveAssessment -State $fixture.State -Context $fixture.Context
    Assert-WinSecIdentityIntegration (
        $second.ControlResults[0].Status -ceq 'INFORMATIONAL' -and
        $second.Findings[0].ScanId -ceq $fixture.Session.ScanId -and
        $publicBefore -ceq (ConvertTo-Json -InputObject $fixture.Public -Depth 15 -Compress) -and
        $sessionBefore -ceq (ConvertTo-Json -InputObject $fixture.Session -Depth 15 -Compress)
    ) 'A CLI read exposed stored mutable references.'
}

Test-WinSecIdentityIntegrationCase 'Rendering receives owned records and cannot change subsequent reads' {
    $fixture = New-WinSecIdentityIntegrationFixture
    $fixture.State | Add-Member -NotePropertyName Screen -NotePropertyValue 'Results'
    $fixture.Context | Add-Member -NotePropertyName Version -NotePropertyValue '0.9.0'
    $before = ConvertTo-Json -InputObject $fixture -Depth 15 -Compress
    $script:renderCalls = 0
    # A deliberately mutating renderer exercises the real CLI dispatch boundary.
    # The function exists only in this test invocation's scope.
    function Show-WinSecResults {
        param($NavigationState, $SectionResults, $ControlResults, $Version)
        $script:renderCalls++
        $ControlResults[0].ScanId = 'renderer-change'
        $ControlResults[0].Status = 'FAIL'
    }
    Show-WinSecCLICurrentScreen -State $fixture.State -Context $fixture.Context
    Assert-WinSecIdentityIntegration (
        $script:renderCalls -eq 1 -and
        $before -ceq (ConvertTo-Json -InputObject $fixture -Depth 15 -Compress)
    ) 'Rendering changed a cached or internal result.'
}

Test-WinSecIdentityIntegrationCase 'A nested private field blocks screen dispatch without disclosure' {
    $fixture = New-WinSecIdentityIntegrationFixture
    $fixture.State | Add-Member -NotePropertyName Screen -NotePropertyValue 'Results'
    $fixture.Context | Add-Member -NotePropertyName Version -NotePropertyValue '0.9.0'
    $fixture.Public.ControlResults[0] | Add-Member -NotePropertyName Metadata `
        -NotePropertyValue @{Items=@(@{OriginalResult='SYNTHETIC-PRIVATE-SCREEN'})}
    $script:renderCalls = 0
    function Show-WinSecResults {
        param($NavigationState, $SectionResults, $ControlResults, $Version)
        $script:renderCalls++
    }
    $caught = $null
    try { Show-WinSecCLICurrentScreen -State $fixture.State -Context $fixture.Context }
    catch { $caught = $_ }
    Assert-WinSecIdentityIntegration (
        $null -ne $caught -and $script:renderCalls -eq 0 -and
        $caught.Exception.Message -notlike '*SYNTHETIC-PRIVATE-SCREEN*'
    ) 'Private data reached the renderer or error message.'
}

Write-Host "Passed: $script:passed"
Write-Host "Failed: $script:failed"

if ($script:failed -gt 0) {
    throw "$script:failed public identity integration test(s) failed."
}
