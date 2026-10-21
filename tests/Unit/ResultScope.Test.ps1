# Scope contracts only: synthetic data in memory; no audits or file writes.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../../src/Core/ResultModel.ps1')
$script:passed=0; $script:failed=0
function Assert-WinSecScope { param([bool]$Value) if (-not $Value) { throw 'Scope assertion failed.' } }
function Assert-WinSecScopeThrows {
    param([scriptblock]$Action)
    $caught=$false
    try { $null=& $Action } catch { $caught=$true }
    Assert-WinSecScope $caught
}
function Test-WinSecScope {
    param([string]$Name,[scriptblock]$Action)
    try { $null=& $Action; $script:passed++; Write-Host "[PASS] $Name" }
    catch { $script:failed++; Write-Host "[FAIL] $Name : $($_.Exception.Message)" }
}
function New-WinSecScopeFixture {
    param([string]$Type='SECTION',[string]$Key='SystemSecurity')
    $control=[pscustomobject]@{DeviceId='local:SCOPE-FIXTURE';ScanId='scope-1';CheckId='WSA-SYS-001';
        SectionKey='SystemSecurity';Status='INFORMATIONAL';Evidence=@{Secret='SCOPE_PRIVATE_VALUE'}}
    New-WinSecResultSession -DeviceId $control.DeviceId -ScanId $control.ScanId -ScopeType $Type -ScopeKey $Key `
        -ExpectedCheckIds @($control.CheckId) -ControlResults @($control) -ExecutionStatus COMPLETED `
        -StartedAtUTC '2026-10-20T00:00:00Z' -CompletedAtUTC '2026-10-20T00:01:00Z'
}
Test-WinSecScope 'Legacy sessions remain valid with unknown scope' {
    $session=New-WinSecResultSession -DeviceId 'local:SCOPE-FIXTURE' -ScanId 'legacy'
    $public=ConvertTo-WinSecPublicScanResult $session
    Assert-WinSecScope ((Test-WinSecResultSession $session) -and $null -eq $public.ScopeType -and $null -eq $public.ScopeKey)
}
foreach($spec in @(@{T='DEVICE';K='ALL'},@{T='SECTION';K='SystemSecurity'},@{T='CONTROL';K='WSA-SYS-001'})) {
    Test-WinSecScope ('Canonical scope survives validation and public projection: '+$spec.T) {
        $session=New-WinSecScopeFixture $spec.T $spec.K
        $public=ConvertTo-WinSecPublicScanResult $session
        Assert-WinSecScope ((Test-WinSecResultSession $session) -and $public.ScopeType -ceq $spec.T -and
            $public.ScopeKey -ceq $spec.K -and $public.PublicProjection -ceq $true -and
            $public.ContainsRawEvidence -ceq $false -and $null -eq $public.OverallScore -and
            $public.OverallStatus -ceq 'NOT_SCORED' -and (ConvertTo-Json $public -Depth 15) -notmatch 'SCOPE_PRIVATE_VALUE|"Evidence"')
    }
}
foreach($spec in @(
    @{ScopeType='DEVICE'},@{ScopeKey='ALL'},@{ScopeType='';ScopeKey=''},
    @{ScopeType='device';ScopeKey='ALL'},@{ScopeType='DEVICE';ScopeKey='all'},
    @{ScopeType='SECTION';ScopeKey='systemsecurity'},@{ScopeType='SECTION';ScopeKey='UnknownSection'},
    @{ScopeType='CONTROL';ScopeKey='../other'},@{ScopeType=@('DEVICE');ScopeKey='ALL'},
    @{ScopeType='CONTROL';ScopeKey=123},@{ScopeType='EXPLICIT_CHECKS';ScopeKey='ALL'}
)) {
    Test-WinSecScope 'Malformed or ambiguous scopes reject without coercion' {
        Assert-WinSecScopeThrows { New-WinSecResultSession -DeviceId 'local:SCOPE-FIXTURE' -ScanId 'invalid' @spec }
    }
}
Test-WinSecScope 'Foreign section cannot be relabeled as the selected section' {
    Assert-WinSecScopeThrows { New-WinSecScopeFixture SECTION NetworkSecurity }
}
Test-WinSecScope 'Foreign control cannot be relabeled as the selected control' {
    Assert-WinSecScopeThrows { New-WinSecScopeFixture CONTROL WSA-SYS-002 }
}
Test-WinSecScope 'Tampering stored scope metadata invalidates the session and export' {
    $session=New-WinSecScopeFixture
    $session.ScopeKey='NetworkSecurity'
    Assert-WinSecScope (-not (Test-WinSecResultSession $session))
    Assert-WinSecScopeThrows { ConvertTo-WinSecPublicScanResult $session }
}
Test-WinSecScope 'An extra executed control cannot hide outside the scope selection' {
    $session=New-WinSecScopeFixture
    $extra=[pscustomobject]@{DeviceId=$session.DeviceId;ScanId=$session.ScanId;CheckId='WSA-NET-001';
        SectionKey='NetworkSecurity';Status='INFORMATIONAL'}
    $session.ControlResults+= $extra
    Assert-WinSecScope (-not (Test-WinSecResultSession $session))
}
Test-WinSecScope 'Unselected controls from other sections remain explicitly unselected' {
    $session=New-WinSecScopeFixture
    $extra=[pscustomobject]@{DeviceId=$session.DeviceId;ScanId=$session.ScanId;CheckId='WSA-NET-001';
        SectionKey='NetworkSecurity';Status='NOT_SELECTED'}
    $session.ControlResults+= $extra
    Assert-WinSecScope (Test-WinSecResultSession $session)
    $public=ConvertTo-WinSecPublicScanResult $session
    Assert-WinSecScope ($public.ControlResults[1].Status -ceq 'NOT_SELECTED')
}
Test-WinSecScope 'Completed scope cannot omit its selected collector record' {
    $session=New-WinSecScopeFixture
    $session.ControlResults=@()
    Assert-WinSecScope (-not (Test-WinSecResultSession $session))
}
Test-WinSecScope 'Completed scope cannot mark a selected control NOT_SELECTED' {
    $session=New-WinSecScopeFixture
    $session.ControlResults[0].Status='NOT_SELECTED'
    Assert-WinSecScope (-not (Test-WinSecResultSession $session))
}
Test-WinSecScope 'A pending scope can declare controls before collection' {
    $session=New-WinSecResultSession -DeviceId 'local:SCOPE-FIXTURE' -ScanId 'pending' `
        -ScopeType CONTROL -ScopeKey WSA-SYS-001 -ExpectedCheckIds @('WSA-SYS-001')
    Assert-WinSecScope (Test-WinSecResultSession $session)
}
Test-WinSecScope 'Unknown legacy scope is never silently inferred from its controls' {
    $session=New-WinSecScopeFixture
    $session.PSObject.Properties.Remove('ScopeType'); $session.PSObject.Properties.Remove('ScopeKey')
    Assert-WinSecScope (Test-WinSecResultSession $session)
    $public=ConvertTo-WinSecPublicScanResult $session
    Assert-WinSecScope ($null -eq $public.ScopeType -and $null -eq $public.ScopeKey)
}
Test-WinSecScope 'Nonselected controls cannot acquire findings under a partial scope' {
    $session=New-WinSecScopeFixture
    $extra=[pscustomobject]@{DeviceId=$session.DeviceId;ScanId=$session.ScanId;CheckId='WSA-NET-001';
        SectionKey='NetworkSecurity';Status='NOT_SELECTED'}
    $session.ControlResults+= $extra
    $session.Findings=@([pscustomobject]@{DeviceId=$session.DeviceId;ScanId=$session.ScanId;CheckId=$extra.CheckId;FindingId='foreign-scope'})
    Assert-WinSecScope (-not (Test-WinSecResultSession $session))
}
Write-Host "Passed: $script:passed; Failed: $script:failed"
if($script:failed -gt 0){ throw 'Result scope unit tests failed.' }
