# Profile preparation and confirmation only. Synthetic policies/identity/terminal.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
. (Join-Path $root 'src/UI/Screens/ScanConfirmation.ps1')
$script:registry=Get-WinSecCheckRegistry -ProjectRoot $root
$script:draft=Get-WinSecAssessmentCatalog $root WSA-SYS-001
$script:passed=0;$script:failed=0
function Assert-WinSecProfile {param([bool]$Value);if(-not $Value){throw 'Assessment profile assertion failed.'}}
function Assert-WinSecProfileRejected {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-WinSecProfile $caught}
function Get-CimInstance {[CmdletBinding()]param($Namespace,$ClassName,$Property,$OperationTimeoutSec);[pscustomobject]@{UUID='12345678-1234-4567-89ab-123456789abc'}}
function Get-WinSecCheckRegistry {
    param($ProjectRoot)
    $copy=Copy-WinSecResultData $script:registry
    $check=$copy.Checks|Where-Object CheckId -CEQ WSA-SYS-001
    $check.ExecutionEnabled=$true;$check.ExecutionReady=$true;$check.ImplementationStatus='VALIDATED';$check.RegistryStatus='READY'
    $copy
}
function Get-WinSecAssessmentCatalog {param($ProjectRoot,$CheckId);if($CheckId -ceq 'WSA-SYS-001'){Copy-WinSecResultData $script:policy}}
function Get-WinSecTerminalSize {$script:terminal}
function Clear-WinSecScreen {$script:lines=@()}
function Write-WinSecText {param($Text,$Color);$script:lines+=$Text}
function New-WinSecResizeState {[pscustomobject]@{}}
function Invoke-WinSecResizeHandler {
    param($ResizeState,$RenderAction)
    if($script:rerender){$script:rerender=$false;$null=& $RenderAction $null;return $true};return $false
}
function Read-WinSecResizeAwareKey {
    param($ResizeState,$RenderAction)
    if($script:keys.Count -eq 0){throw 'Synthetic key queue exhausted.'}
    $key=$script:keys.Dequeue()
    if($null -ne $key.Terminal){$script:terminal=$key.Terminal;$script:rerender=$true}
    $key
}
function New-WinSecProfileKey {
    param([int]$Code,[string]$Character='',[object]$Terminal=$null)
    [pscustomobject]@{VirtualKeyCode=$Code;Character=$Character;ControlKeyState=0;KeyDown=$true;Terminal=$Terminal}
}
function Get-WinSecProfileFixturePlan {
    Get-WinSecScanConfirmationPlan -Coordinator $script:coordinator -ScopeType CONTROL -ScopeKey WSA-SYS-001 -AssessmentProfile TEST
}
function Test-WinSecProfile {
    param([string]$Name,[scriptblock]$Action)
    $catalog=Copy-WinSecResultData $script:draft.Catalog
    $catalog.Status='APPROVED';$catalog.CatalogId='SYNTHETIC-PROFILE';$catalog.CatalogVersion='test-1';$catalog.ScoringEnabled=$false
    $catalog|Add-Member -NotePropertyName EvaluationEnabled -NotePropertyValue $true
    $rule=Copy-WinSecResultData $catalog.Criteria[2];$rule.Approved=$true
    $rule.Source=[pscustomobject]@{Framework='LOCAL_POLICY';Version='test-1';ControlId='SYNTHETIC-RT';Title='SYNTHETIC';Url='https://example.invalid/profile'}
    $rule.Verification=[pscustomobject]@{Status='VERIFIED';ReviewedBy='SYNTHETIC';ReviewedAtUTC='2026-10-16T00:00:00Z'}
    $rule.Applicability=[pscustomobject]@{OSFamily='Windows';OSRelease='Windows 11 TEST';Edition='TEST';Profile='TEST'}
    $catalog.Criteria=@($rule);$catalog.ReviewOnly=@()
    $script:policy=[pscustomobject]@{Catalog=$catalog;Sha256=('D'*64)}
    $script:coordinator=New-WinSecScanCoordinator;$script:coordinator.AssessmentEnabled=$true
    $script:terminal=[pscustomobject]@{Width=120;ContentWidth=119;Height=45}
    $script:keys=New-Object 'System.Collections.Generic.Queue[object]';$script:rerender=$false;$script:lines=@()
    try{$null=& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}
    catch{$script:failed++;Write-Host ('[FAIL] '+$Name+' : '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}
}
Test-WinSecProfile 'Profile preparation exposes approved catalog version and hash without security evidence' {
    $p=Get-WinSecProfileFixturePlan;$request=ConvertFrom-Json $p.RequestJson
    Assert-WinSecProfile ($request.EvaluationProfile.Profile -ceq 'TEST' -and
        $request.EvaluationProfile.Policies[0].CatalogSha256 -ceq ('D'*64) -and
        $request.EvaluationProfile.Policies[0].CatalogVersion -ceq 'test-1' -and
        $p.AssessmentCatalogs['WSA-SYS-001'].Catalog.Criteria.Count -eq 1 -and $script:coordinator.Sessions.Count -eq 0)
    Assert-WinSecProfile ($p.RequestJson -notmatch 'Evidence|ExpectedValue|ReviewedBy|Recommendation')
}
Test-WinSecProfile 'A plan without explicit profile retains the previous confirmation contract' {
    $p=Get-WinSecScanConfirmationPlan -Coordinator $script:coordinator -ScopeType CONTROL -ScopeKey WSA-SYS-001
    Assert-WinSecProfile ($p.RequestJson -notmatch 'EvaluationProfile' -and $null -eq $p.AssessmentCatalogs)
}
Test-WinSecProfile 'The production draft cannot authorize a requested profile' {
    $script:policy=Copy-WinSecResultData $script:draft
    Assert-WinSecProfileRejected {Get-WinSecProfileFixturePlan}
}
foreach($mutation in @(
    {$script:policy.Catalog.Criteria[0].Approved=$false},
    {$script:policy.Catalog.Criteria[0].Verification.Status='PENDING'},
    {$script:policy.Catalog.EvaluationEnabled=$false},
    {$script:policy.Catalog.Status='DRAFT_UNAPPROVED'},
    {$script:coordinator.AssessmentEnabled=$false}
)){
    Test-WinSecProfile 'A profile name cannot override approval or pipeline gates' {
        $null=& $mutation;Assert-WinSecProfileRejected {Get-WinSecProfileFixturePlan}
    }
}
foreach($profile in @($null,'','UNRESOLVED','PENDING_SELECTION','../TEST',@('TEST'),$true,'OTHER')){
    Test-WinSecProfile 'Invalid, unresolved or unknown requested profiles are rejected' {
        Assert-WinSecProfileRejected {Get-WinSecAssessmentProfilePlan $root @('WSA-SYS-001') $profile}
    }
}
Test-WinSecProfile 'A catalog cannot release only a subset of rules for a requested profile or OS scope' {
    foreach($field in @('Profile','OSRelease','Edition')){
        $extra=Copy-WinSecResultData $script:policy.Catalog.Criteria[0];$extra.CriterionId='SYNTHETIC-EXTRA';$extra.Applicability.$field='OTHER'
        $script:policy.Catalog.Criteria=@($script:policy.Catalog.Criteria[0],$extra)
        Assert-WinSecProfileRejected {Get-WinSecProfileFixturePlan}
    }
}
Test-WinSecProfile 'Catalog version and content hash are part of the confirmation fingerprint' {
    $first=Get-WinSecProfileFixturePlan
    $script:policy.Catalog.CatalogVersion='test-2';$second=Get-WinSecProfileFixturePlan
    $script:policy.Sha256=('E'*64);$third=Get-WinSecProfileFixturePlan
    Assert-WinSecProfile ($first.Fingerprint -cne $second.Fingerprint -and $second.Fingerprint -cne $third.Fingerprint)
}
Test-WinSecProfile 'Prepared catalog snapshots do not retain current policy references' {
    $p=Get-WinSecProfileFixturePlan;$script:policy.Catalog.Criteria[0].Recommendation='CHANGED'
    Assert-WinSecProfile ($p.AssessmentCatalogs['WSA-SYS-001'].Catalog.Criteria[0].Recommendation -cne 'CHANGED')
}
foreach($code in @(89,13)){
    Test-WinSecProfile 'Y and Enter confirm only after showing profile and policy provenance' {
        $request=ConvertFrom-Json (Get-WinSecProfileFixturePlan).RequestJson
        $script:keys.Enqueue((New-WinSecProfileKey $code $(if($code -eq 89){'y'}else{''})))
        Assert-WinSecProfile (Show-WinSecScanConfirmation $request)
        $text=$script:lines -join ' '
        Assert-WinSecProfile ($text.Contains('Evaluation profile: TEST') -and $text.Contains('test-1') -and
            $text.Contains(('D'*64)) -and $text.Contains('Windows 11 TEST') -and $text.Contains('NOT_SCORED'))
    }
}
foreach($code in @(78,27)){
    Test-WinSecProfile 'N and Escape cancel profile-bound scan confirmation' {
        $request=ConvertFrom-Json (Get-WinSecProfileFixturePlan).RequestJson
        $script:keys.Enqueue((New-WinSecProfileKey $code $(if($code -eq 78){'n'}else{''})))
        Assert-WinSecProfile (-not (Show-WinSecScanConfirmation $request))
    }
}
Test-WinSecProfile 'A small terminal cannot approve a truncated profile or its hash' {
    $request=ConvertFrom-Json (Get-WinSecProfileFixturePlan).RequestJson
    $script:terminal=[pscustomobject]@{Width=40;ContentWidth=39;Height=20}
    $script:keys.Enqueue((New-WinSecProfileKey 13));$script:keys.Enqueue((New-WinSecProfileKey 27))
    Assert-WinSecProfile (-not (Show-WinSecScanConfirmation $request))
    Assert-WinSecProfile (($script:lines -join ' ') -match 'Resize')
}
Test-WinSecProfile 'Resizing reveals the complete request but requires a new explicit key' {
    $request=ConvertFrom-Json (Get-WinSecProfileFixturePlan).RequestJson
    $script:terminal=[pscustomobject]@{Width=40;ContentWidth=39;Height=20}
    $script:keys.Enqueue((New-WinSecProfileKey 13))
    $script:keys.Enqueue((New-WinSecProfileKey 0 '' ([pscustomobject]@{Width=120;ContentWidth=119;Height=45})))
    $script:keys.Enqueue((New-WinSecProfileKey 13))
    Assert-WinSecProfile (Show-WinSecScanConfirmation $request)
    Assert-WinSecProfile ($script:keys.Count -eq 0 -and ($script:lines -join ' ').Contains(('D'*64)))
}
foreach($mutation in @(
    {param($p);$p|Add-Member -NotePropertyName Evidence -NotePropertyValue 'PRIVATE'},
    {param($p);$p.Policies[0].CatalogSha256='forged'},
    {param($p);$p.Policies[0].OSRelease='UNRESOLVED'},
    {param($p);$p.Policies[0].CheckId='WSA-SYS-002'},
    {param($p);$p.Policies[0].CatalogId="bad`e[0m"}
)){
    Test-WinSecProfile 'Malformed or foreign policy preview cannot be displayed or approved' {
        $request=ConvertFrom-Json (Get-WinSecProfileFixturePlan).RequestJson
        $null=& $mutation $request.EvaluationProfile
        Assert-WinSecProfileRejected {Show-WinSecScanConfirmation $request}
    }
}
Test-WinSecProfile 'Calculated profile metadata is rejected without executing its getter' {
    $request=ConvertFrom-Json (Get-WinSecProfileFixturePlan).RequestJson
    $request.PSObject.Properties.Remove('EvaluationProfile');$script:getterCalls=0
    $request|Add-Member -MemberType ScriptProperty -Name EvaluationProfile -Value {$script:getterCalls++;throw 'PRIVATE-GETTER'}
    Assert-WinSecProfileRejected {Show-WinSecScanConfirmation $request}
    Assert-WinSecProfile ($script:getterCalls -eq 0)
}
Test-WinSecProfile 'Case-ambiguous dictionary profile fields cannot hide the displayed selection' {
    $request=ConvertFrom-Json (Get-WinSecProfileFixturePlan).RequestJson
    $dictionary=New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
    foreach($p in $request.PSObject.Properties){$dictionary.Add($p.Name,$p.Value)}
    $dictionary.Add('evaluationprofile',$request.EvaluationProfile)
    Assert-WinSecProfileRejected {Show-WinSecScanConfirmation $dictionary}
}
Write-Host ('Assessment profile: {0} passed, {1} failed.' -f $script:passed,$script:failed)
if($script:failed){throw 'Assessment profile unit tests failed.'}
