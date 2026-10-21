# ============================================================
# WinSec Analyzer - Legacy CLI Privacy Unit Tests
# PowerShell 5.1 / 7.x; synthetic in-memory data only.
# No scans, file writes, scoring activation or Pester.
# ============================================================

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$projectRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '../..')
)
. (Join-Path $projectRoot 'src/CLI/Invoke-WinSecCLI.ps1')

$script:passed = 0
$script:failed = 0
$script:privateMarker = 'SYNTHETIC-LEGACY-PRIVATE-VALUE'

function Assert-WinSecLegacyPrivacy {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Test-WinSecLegacyPrivacyCase {
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

function New-WinSecLegacyPrivacyFixture {
    return [pscustomobject]@{
        State = [pscustomobject]@{ SelectedDeviceId = 'local:LEGACY-TEST' }
        Context = [pscustomobject]@{
            ScanId = 'legacy-001'
            Devices = @(
                [pscustomobject]@{
                    DeviceId = 'local:LEGACY-TEST'
                    ScanId = 'legacy-001'
                    Score = 100
                    Status = 'PASS'
                }
            )
            SectionResults = @(
                [pscustomobject]@{
                    DeviceId = 'local:LEGACY-TEST'
                    ScanId = 'legacy-001'
                    Key = 'SystemSecurity'
                    Name = 'System Security'
                    Status = 'NOT_SCORED'
                    Score = $null
                }
            )
            ControlResults = @(
                [pscustomobject]@{
                    DeviceId = 'local:LEGACY-TEST'
                    ScanId = 'legacy-001'
                    CheckId = 'WSA-SYS-001'
                    SectionKey = 'SystemSecurity'
                    Status = 'NOT_EVALUATED'
                    Score = $null
                }
            )
            Findings = @(
                [pscustomobject]@{
                    DeviceId = 'local:LEGACY-TEST'
                    ScanId = 'legacy-001'
                    CheckId = 'WSA-SYS-001'
                    FindingId = 'LEGACY-DIAGNOSTIC-001'
                    SectionKey = 'SystemSecurity'
                    Kind = 'EVALUATION_PENDING'
                    EvaluationStatus = 'NOT_EVALUATED'
                    Title = 'Evaluation is pending'
                    Severity = 'UNASSIGNED'
                    Priority = 'UNASSIGNED'
                }
            )
        }
    }
}

function Assert-WinSecLegacyPrivacyRejected {
    param([psobject]$Fixture)

    $published = @()
    $caught = $null
    try {
        Get-WinSecCLIActiveAssessment `
            -State $Fixture.State -Context $Fixture.Context |
            ForEach-Object { $published += $_ }
    }
    catch {
        $caught = $_
    }

    Assert-WinSecLegacyPrivacy (
        $null -ne $caught -and $published.Count -eq 0
    ) 'Unsafe legacy data was not rejected before publication.'
    Assert-WinSecLegacyPrivacy (
        $caught.Exception.Message -notmatch [regex]::Escape($script:privateMarker)
    ) 'The rejection exposed a private input value.'
}

Test-WinSecLegacyPrivacyCase 'Safe legacy records remain isolated and NOT_SCORED' {
    $fixture = New-WinSecLegacyPrivacyFixture
    $result = Get-WinSecCLIActiveAssessment `
        -State $fixture.State -Context $fixture.Context

    Assert-WinSecLegacyPrivacy (
        $result.SectionResults.Count -eq 1 -and
        $result.ControlResults.Count -eq 1 -and
        $result.Findings.Count -eq 1 -and
        $result.ScanId -ceq 'legacy-001' -and
        $result.OverallStatus -ceq 'NOT_SCORED' -and
        $null -eq $result.OverallScore
    ) 'Safe legacy records or the unscored state were lost.'
}

foreach ($collection in @('SectionResults', 'ControlResults', 'Findings')) {
    foreach ($field in @('Evidence', 'RawEvidence', 'OriginalResult', 'ObservedValue', 'ExpectedValue')) {
        Test-WinSecLegacyPrivacyCase "$collection rejects $field" {
            $fixture = New-WinSecLegacyPrivacyFixture
            $fixture.Context.$collection[0] | Add-Member `
                -NotePropertyName $field -NotePropertyValue $script:privateMarker
            Assert-WinSecLegacyPrivacyRejected $fixture
        }
    }

    foreach ($score in @(0, 100, '99/100', '', $false)) {
        Test-WinSecLegacyPrivacyCase "$collection rejects a non-null Score of type $($score.GetType().Name)" {
            $fixture = New-WinSecLegacyPrivacyFixture
            $fixture.Context.$collection[0] | Add-Member `
                -NotePropertyName Score -NotePropertyValue $score -Force
            Assert-WinSecLegacyPrivacyRejected $fixture
        }
    }

    foreach ($field in @('OverallScore', 'ScoreValue', 'ScoreResult', 'ScoringPolicy')) {
        Test-WinSecLegacyPrivacyCase "$collection rejects internal scoring field $field" {
            $fixture = New-WinSecLegacyPrivacyFixture
            $fixture.Context.$collection[0] | Add-Member `
                -NotePropertyName $field -NotePropertyValue 100
            Assert-WinSecLegacyPrivacyRejected $fixture
        }
    }

    foreach ($field in @('ScoringEnabled', 'ScoringEligible')) {
        Test-WinSecLegacyPrivacyCase "$collection rejects unauthorized $field" {
            $fixture = New-WinSecLegacyPrivacyFixture
            $fixture.Context.$collection[0] | Add-Member `
                -NotePropertyName $field -NotePropertyValue $true
            Assert-WinSecLegacyPrivacyRejected $fixture
        }
    }

    Test-WinSecLegacyPrivacyCase "$collection rejects nested raw evidence" {
        $fixture = New-WinSecLegacyPrivacyFixture
        $fixture.Context.$collection[0] | Add-Member `
            -NotePropertyName Description -NotePropertyValue @{
                Details = @([pscustomobject]@{ RawEvidence = $script:privateMarker })
            }
        Assert-WinSecLegacyPrivacyRejected $fixture
    }

    Test-WinSecLegacyPrivacyCase "$collection rejects nested scoring" {
        $fixture = New-WinSecLegacyPrivacyFixture
        $fixture.Context.$collection[0] | Add-Member `
            -NotePropertyName Metadata -NotePropertyValue @{
                Details = @([pscustomobject]@{ Score = 100 })
            }
        Assert-WinSecLegacyPrivacyRejected $fixture
    }

    Test-WinSecLegacyPrivacyCase "$collection rejects case-insensitive dictionary evidence keys" {
        $fixture = New-WinSecLegacyPrivacyFixture
        $fixture.Context.$collection = @(@{
            DeviceId = 'local:LEGACY-TEST'
            ScanId = 'legacy-001'
            rAwEvIdEnCe = $script:privateMarker
        })
        Assert-WinSecLegacyPrivacyRejected $fixture
    }

    Test-WinSecLegacyPrivacyCase "$collection rejects dictionary Score zero" {
        $fixture = New-WinSecLegacyPrivacyFixture
        $fixture.Context.$collection = @(@{
            DeviceId = 'local:LEGACY-TEST'
            ScanId = 'legacy-001'
            sCoRe = 0
        })
        Assert-WinSecLegacyPrivacyRejected $fixture
    }
}

Test-WinSecLegacyPrivacyCase 'An empty evidence property is still not a public field' {
    $fixture = New-WinSecLegacyPrivacyFixture
    $fixture.Context.Findings[0] | Add-Member `
        -NotePropertyName Evidence -NotePropertyValue $null
    Assert-WinSecLegacyPrivacyRejected $fixture
}

Test-WinSecLegacyPrivacyCase 'Unsafe records of other devices and scans remain excluded' {
    $fixture = New-WinSecLegacyPrivacyFixture
    $fixture.Context.Findings += @(
        [pscustomobject]@{
            DeviceId = 'remote:OTHER-DEVICE'
            ScanId = 'legacy-001'
            Evidence = $script:privateMarker
        }
        [pscustomobject]@{
            DeviceId = 'local:LEGACY-TEST'
            ScanId = 'legacy-OTHER'
            Evidence = $script:privateMarker
        }
    )
    $result = Get-WinSecCLIActiveAssessment `
        -State $fixture.State -Context $fixture.Context

    Assert-WinSecLegacyPrivacy (
        $result.Findings.Count -eq 1 -and
        (ConvertTo-Json -InputObject $result -Depth 12 -Compress) -notmatch
            [regex]::Escape($script:privateMarker)
    ) 'An unselected record reached the active assessment.'
}

Test-WinSecLegacyPrivacyCase 'Ambiguous histories return an empty warning without exposing raw data' {
    $fixture = New-WinSecLegacyPrivacyFixture
    $fixture.Context.ScanId = ''
    $fixture.Context.Findings += [pscustomobject]@{
        DeviceId = 'local:LEGACY-TEST'
        ScanId = 'legacy-OTHER'
        Evidence = $script:privateMarker
    }
    $result = Get-WinSecCLIActiveAssessment `
        -State $fixture.State -Context $fixture.Context

    Assert-WinSecLegacyPrivacy (
        $result.Warning -and $result.Findings.Count -eq 0 -and
        $result.ControlResults.Count -eq 0
    ) 'Ambiguous history did not remain an empty assessment.'
}

Test-WinSecLegacyPrivacyCase 'Rejection preserves the context and navigation' {
    $fixture = New-WinSecLegacyPrivacyFixture
    $fixture.Context.Findings[0] | Add-Member `
        -NotePropertyName Evidence -NotePropertyValue $script:privateMarker
    $before = ConvertTo-Json -InputObject $fixture -Depth 12 -Compress
    Assert-WinSecLegacyPrivacyRejected $fixture
    Assert-WinSecLegacyPrivacy (
        (ConvertTo-Json -InputObject $fixture -Depth 12 -Compress) -ceq $before
    ) 'Rejection changed the legacy input or navigation.'
}

Test-WinSecLegacyPrivacyCase 'Cyclic structured data is rejected without hanging' {
    $fixture = New-WinSecLegacyPrivacyFixture
    $cycle = @{}
    $cycle['Self'] = $cycle
    $fixture.Context.Findings[0] | Add-Member `
        -NotePropertyName Metadata -NotePropertyValue $cycle
    Assert-WinSecLegacyPrivacyRejected $fixture
}

Test-WinSecLegacyPrivacyCase 'Oversized nested collections fail closed' {
    $fixture = New-WinSecLegacyPrivacyFixture
    $fixture.Context.Findings[0] | Add-Member `
        -NotePropertyName Metadata -NotePropertyValue (@('VALUE') * 10001)
    Assert-WinSecLegacyPrivacyRejected $fixture
}

Test-WinSecLegacyPrivacyCase 'Display getters are rejected without execution' {
    $fixture = New-WinSecLegacyPrivacyFixture
    $script:legacyGetterInvoked = $false
    $fixture.Context.Findings[0] | Add-Member `
        -MemberType ScriptProperty -Name Description -Value {
            $script:legacyGetterInvoked = $true
            throw 'SYNTHETIC-LEGACY-PRIVATE-VALUE'
        }
    Assert-WinSecLegacyPrivacyRejected $fixture
    Assert-WinSecLegacyPrivacy (
        $script:legacyGetterInvoked -eq $false
    ) 'A display getter was executed during validation.'
}

Test-WinSecLegacyPrivacyCase 'Safe nested metadata and disabled scoring flags remain readable' {
    $fixture = New-WinSecLegacyPrivacyFixture
    $fixture.Context.Findings[0] | Add-Member `
        -NotePropertyName Metadata -NotePropertyValue @{
            Labels = @('REVIEW_ONLY', $null)
            ScoringEnabled = $false
            ScoringEligible = $false
            Score = $null
        }
    $result = Get-WinSecCLIActiveAssessment `
        -State $fixture.State -Context $fixture.Context
    Assert-WinSecLegacyPrivacy (
        $result.Findings.Count -eq 1 -and
        $result.Findings[0].Metadata.Labels[0] -ceq 'REVIEW_ONLY' -and
        $result.OverallStatus -ceq 'NOT_SCORED'
    ) 'Safe metadata was not preserved.'
}

Test-WinSecLegacyPrivacyCase 'A dictionary Keys entry cannot hide raw evidence' {
    $fixture = New-WinSecLegacyPrivacyFixture
    $fixture.Context.Findings = @(@{
        DeviceId = 'local:LEGACY-TEST'
        ScanId = 'legacy-001'
        Keys = @('DeviceId', 'ScanId', 'Keys')
        RawEvidence = $script:privateMarker
    })
    Assert-WinSecLegacyPrivacyRejected $fixture
}

Write-Host "Passed: $script:passed"
Write-Host "Failed: $script:failed"
if ($script:failed -gt 0) {
    throw "$script:failed legacy privacy unit test(s) failed."
}
