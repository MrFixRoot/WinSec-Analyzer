# ============================================================
# WinSec Analyzer - Legacy CLI / UI Privacy Integration Tests
# PowerShell 5.1 / 7.x; no Pester required.
# Synthetic in-memory models; no scans, writes or terminal input.
# ============================================================

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$projectRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '../..')
)

foreach ($relativePath in @(
    'src/CLI/Invoke-WinSecCLI.ps1'
    'src/UI/Components/Table.ps1'
    'src/UI/Screens/MainMenu.ps1'
    'src/UI/Screens/Results.ps1'
    'src/UI/Screens/Findings.ps1'
)) {
    . (Join-Path $projectRoot $relativePath)
}

$script:passed = 0
$script:failed = 0
$script:privateMarker = 'SYNTHETIC-UI-PRIVATE-VALUE'

function Assert-WinSecLegacyIntegration {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Test-WinSecLegacyIntegrationCase {
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

function New-WinSecLegacyIntegrationFixture {
    return [pscustomobject]@{
        State = [pscustomobject]@{
            SelectedDeviceId = 'local:LEGACY-UI'
            SectionIndex = 0
            ControlIndex = 0
            FindingsScope = 'Section'
        }
        Context = [pscustomobject]@{
            ScanId = 'LEGACY-UI-001'
            Devices = @(
                [pscustomobject]@{
                    DeviceId = 'local:LEGACY-UI'
                    ScanId = 'LEGACY-UI-001'
                    Score = 100
                    Status = 'PASS'
                }
            )
            SectionResults = @(
                [pscustomobject]@{
                    DeviceId = 'local:LEGACY-UI'
                    ScanId = 'LEGACY-UI-001'
                    Key = 'SystemSecurity'
                    Status = 'NOT_SCORED'
                    Score = $null
                }
            )
            ControlResults = @(
                [pscustomobject]@{
                    DeviceId = 'local:LEGACY-UI'
                    ScanId = 'LEGACY-UI-001'
                    CheckId = 'WSA-SYS-001'
                    Key = 'Defender'
                    SectionKey = 'SystemSecurity'
                    Status = 'NOT_EVALUATED'
                    Score = $null
                }
            )
            Findings = @(
                [pscustomobject]@{
                    DeviceId = 'local:LEGACY-UI'
                    ScanId = 'LEGACY-UI-001'
                    CheckId = 'WSA-SYS-001'
                    SectionKey = 'SystemSecurity'
                    FindingId = 'LEGACY-UI-DIAGNOSTIC'
                    Kind = 'EVALUATION_PENDING'
                    EvaluationStatus = 'NOT_EVALUATED'
                    Title = 'Evaluation is pending'
                    Severity = 'UNASSIGNED'
                    Priority = 'UNASSIGNED'
                    Recommendation = 'Review the approved criteria manually.'
                }
            )
        }
    }
}

Test-WinSecLegacyIntegrationCase 'Safe legacy records reach UI models without evidence or scores' {
    $fixture = New-WinSecLegacyIntegrationFixture
    $assessment = Get-WinSecCLIActiveAssessment `
        -State $fixture.State -Context $fixture.Context
    $sections = @(Get-WinSecMainMenuSections -SectionResults $assessment.SectionResults)
    $controls = @(Get-WinSecSectionControls `
        -SectionKey 'SystemSecurity' -ControlResults $assessment.ControlResults)
    $view = Get-WinSecSelectedFindings `
        -NavigationState $fixture.State `
        -SectionResults $assessment.SectionResults `
        -ControlResults $assessment.ControlResults `
        -Findings $assessment.Findings -ScanId $assessment.ScanId

    Assert-WinSecLegacyIntegration (
        $assessment.OverallStatus -ceq 'NOT_SCORED' -and
        $null -eq $assessment.OverallScore -and
        $sections[0].Status -ceq 'NOT_SCORED' -and
        $sections[0].Score -ceq 'NOT_SCORED' -and
        $controls[0].Status -ceq 'NOT_EVALUATED' -and
        $controls[0].Score -ceq '--/100' -and
        $view.Findings.Count -eq 1 -and
        [string]::IsNullOrWhiteSpace($view.Findings[0].Evidence)
    ) 'The safe legacy assessment was not preserved by UI normalization.'
}

$unsafeInputs = @(
    @{ Collection = 'Findings'; Field = 'Evidence'; Value = $script:privateMarker }
    @{ Collection = 'Findings'; Field = 'RawEvidence'; Value = $script:privateMarker }
    @{ Collection = 'SectionResults'; Field = 'Score'; Value = 90 }
    @{ Collection = 'ControlResults'; Field = 'Score'; Value = 100 }
    @{ Collection = 'Findings'; Field = 'Description'; Value = @{
        Details = @([pscustomobject]@{ ObservedValue = $script:privateMarker })
    } }
    @{ Collection = 'Findings'; Field = 'Metadata'; Value = @{
        Keys = @('Visible')
        Visible = 'REVIEW_ONLY'
        RawEvidence = $script:privateMarker
    } }
)

foreach ($unsafeInput in $unsafeInputs) {
    Test-WinSecLegacyIntegrationCase "$($unsafeInput.Collection).$($unsafeInput.Field) cannot reach the UI" {
        $fixture = New-WinSecLegacyIntegrationFixture
        $collection = $unsafeInput.Collection
        $fixture.Context.$collection[0] | Add-Member `
            -NotePropertyName $unsafeInput.Field `
            -NotePropertyValue $unsafeInput.Value -Force
        $before = ConvertTo-Json -InputObject $fixture -Depth 16 -Compress
        $viewCalls = 0
        $published = @()
        $caught = $null
        try {
            Get-WinSecCLIActiveAssessment `
                -State $fixture.State -Context $fixture.Context |
                ForEach-Object {
                    $viewCalls++
                    $published += Get-WinSecSelectedFindings `
                        -NavigationState $fixture.State `
                        -SectionResults $_.SectionResults `
                        -ControlResults $_.ControlResults `
                        -Findings $_.Findings -ScanId $_.ScanId
                }
        }
        catch {
            $caught = $_
        }

        Assert-WinSecLegacyIntegration (
            $null -ne $caught -and $viewCalls -eq 0 -and $published.Count -eq 0
        ) 'Unsafe legacy input reached the UI normalization step.'
        Assert-WinSecLegacyIntegration (
            $caught.Exception.Message -notmatch [regex]::Escape($script:privateMarker) -and
            (ConvertTo-Json -InputObject $fixture -Depth 16 -Compress) -ceq $before
        ) 'Rejection exposed the private marker or changed the session.'
    }
}

Write-Host "Passed: $script:passed"
Write-Host "Failed: $script:failed"
if ($script:failed -gt 0) {
    throw "$script:failed legacy privacy integration test(s) failed."
}
