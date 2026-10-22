# Public metadata regressions. Synthetic in-memory models only.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../../src/Core/ResultModel.ps1')
$script:passed=0; $script:failed=0
function Assert-WinSecPublicContract { param([bool]$Value) if(-not $Value){throw 'Public contract assertion failed.'} }
function Test-WinSecPublicContract {
    param([string]$Name,[scriptblock]$Action)
    try{$null=& $Action;$script:passed++;Write-Host "[PASS] $Name"}
    catch{$script:failed++;Write-Host "[FAIL] $Name : $($_.Exception.Message)"}
}
function New-WinSecPublicContractFixture {
    New-WinSecResultSession -DeviceId 'local:PUBLIC-FIXTURE' -ScanId 'public-1'
}
function Assert-WinSecPublicContractRejected {
    param([object]$Session)
    Assert-WinSecPublicContract (-not (Test-WinSecResultSession $Session))
    $caught=$false
    try{$null=ConvertTo-WinSecPublicScanResult $Session}catch{
        $caught=$true
        Assert-WinSecPublicContract ($_.Exception.Message -notmatch 'PUBLIC_PRIVATE_MARKER')
    }
    Assert-WinSecPublicContract $caught
}
foreach($field in @('CollectionMode','OverallCoverage','AssessmentStatus','OverallStatus','AuditId',
    'StartedAtUTC','CompletedAtUTC','ScoringEligible','ScoringEnabled')) {
    Test-WinSecPublicContract ('Structured private metadata cannot enter public field '+$field) {
        $session=New-WinSecPublicContractFixture
        $session.$field=[pscustomobject]@{Evidence='PUBLIC_PRIVATE_MARKER'}
        Assert-WinSecPublicContractRejected $session
    }
}
foreach($mutation in @(
    @{Field='CollectionMode';Value='UNREVIEWED'},
    @{Field='CollectionMode';Value=@('LOCAL')},
    @{Field='AuditId';Value=@('public-1')},
    @{Field='ScoringEligible';Value='false'},
    @{Field='ScoringEnabled';Value='false'},
    @{Field='ScoringEnabled';Value=$true},
    @{Field='OverallCoverage';Value='100'},
    @{Field='OverallCoverage';Value=100},
    @{Field='OverallCoverage';Value=[double]::NaN},
    @{Field='OverallCoverage';Value=[double]::PositiveInfinity},
    @{Field='OverallCoverage';Value=-1},
    @{Field='OverallCoverage';Value=101},
    @{Field='AssessmentStatus';Value='COMPLETE'}
)) {
    Test-WinSecPublicContract ('Unsupported or unverified public metadata rejects: '+$mutation.Field) {
        $session=New-WinSecPublicContractFixture
        $session.($mutation.Field)=$mutation.Value
        Assert-WinSecPublicContractRejected $session
    }
}
Test-WinSecPublicContract 'An unverified section cannot publish private coverage or invented scores' {
    $session=New-WinSecPublicContractFixture
    $session.SectionResults=@([pscustomobject]@{DeviceId=$session.DeviceId;ScanId=$session.ScanId;Key='SystemSecurity';
        Score=100;Coverage=[pscustomobject]@{Evidence='PUBLIC_PRIVATE_MARKER'};Status='COMPLETE'})
    Assert-WinSecPublicContractRejected $session
}
Test-WinSecPublicContract 'Completion timestamps cannot be reversed after construction' {
    $session=New-WinSecResultSession -DeviceId 'local:PUBLIC-FIXTURE' -ScanId 'public-1' `
        -StartedAtUTC '2026-10-20T00:00:00Z' -CompletedAtUTC '2026-10-20T00:01:00Z' -ExecutionStatus COMPLETED
    $session.CompletedAtUTC='2026-10-19T00:00:00Z'
    Assert-WinSecPublicContractRejected $session
}
Test-WinSecPublicContract 'Valid empty unscored session remains publicly safe' {
    $session=New-WinSecPublicContractFixture
    $public=ConvertTo-WinSecPublicScanResult $session
    Assert-WinSecPublicContract ($public.CollectionMode -ceq 'LOCAL' -and $null -eq $public.OverallCoverage -and
        $null -eq $public.OverallScore -and $public.OverallStatus -ceq 'NOT_SCORED' -and
        $public.AssessmentStatus -ceq 'PENDING' -and $public.SectionResults.Count -eq 0)
}
Write-Host "Passed: $script:passed; Failed: $script:failed"
if($script:failed -gt 0){throw 'Public result contract tests failed.'}
