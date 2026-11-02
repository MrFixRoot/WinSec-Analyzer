[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
. (Join-Path $root 'src/Checks/Accounts/Test-LocalAdmins.ps1')
. (Join-Path $root 'src/Checks/Accounts/Test-GuestAccount.ps1')
. (Join-Path $root 'src/Checks/Policies/Test-PasswordPolicy.ps1')
. (Join-Path $root 'src/Checks/Accounts/IdentityAccessCollector.ps1')
. (Join-Path $root 'tests/Fixtures/IdentityAccessMemory.ps1')
function Get-CimInstance {throw 'Unmocked Windows query forbidden.'}
Set-Alias Invoke-WinSecIdentityAccessQuery Invoke-WinSecIdentityFixtureQuery -Scope Script
$passed=0;$failed=0
function Assert-Identity {param([bool]$Value);if(-not $Value){throw 'Identity assertion failed.'}}
function Reject-Identity {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-Identity $caught}
function Test-Identity {param($Name,[scriptblock]$Action);Initialize-WinSecIdentityFixture;try{$null=& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}catch{$script:failed++;Write-Host ('[FAIL] '+$Name+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}
Test-Identity 'Three IAM adapters are enabled only after individual native validation' {
    $c=Get-Content (Join-Path $root 'config/checks.json') -Raw|ConvertFrom-Json
    Assert-Identity (@($c.checks|Where-Object {$_.checkId -clike 'WSA-IAM-*' -and $_.execution.enabled -and $_.implementationStatus -ceq 'VALIDATED'}).Count -eq 3)
    Assert-Identity (@(Get-WinSecTechnicalControls|Where-Object SectionKey -CEQ IdentityAccess).Count -eq 3)
}
foreach($id in @('WSA-IAM-001','WSA-IAM-002','WSA-IAM-003')){Test-Identity ('Typed Markdown and privacy: '+$id) {
    $s=New-WinSecIdentityFixtureSession @($id);$r=New-WinSecTechnicalReport $s $id SYNTHETIC SYNTHETIC;$md=ConvertTo-WinSecTechnicalMarkdown $r
    Assert-Identity ($s.ExecutionStatus -ceq 'COMPLETED' -and $md -notmatch 'PRIVATE-|S-1-5-21-11|/100|NOT_SCORED' -and $IdentityEvents.Count -gt 0)
    Assert-Identity ($IdentityEvents[-1].CompletedSteps -eq $IdentityEvents[-1].TotalSteps)
}}
foreach($role in @('Platform','Administrators','Guest','Password','Lockout')){Test-Identity ('Closed provider failure: '+$role){
    $script:IdentityFailure=$role;$s=New-WinSecIdentityFixtureSession
    Assert-Identity ($s.ExecutionStatus -ceq 'COMPLETED_WITH_ERRORS')
    foreach($c in $s.ControlResults){$r=New-WinSecTechnicalReport $s $c.CheckId SYNTHETIC SYNTHETIC;Assert-Identity ((ConvertTo-WinSecTechnicalMarkdown $r) -notmatch 'PRIVATE-')}
}}
Test-Identity 'Renamed Guest uses RID, disabled state yields no warning' {
    $script:IdentityGuestDisabled=$true;$s=New-WinSecIdentityFixtureSession @('WSA-IAM-002');$r=New-WinSecTechnicalReport $s WSA-IAM-002 SYNTHETIC SYNTHETIC
    $a=New-WinSecFrameworkAnalysis $root $s.DeviceId SYNTHETIC CONTROL WSA-IAM-002 nist-csf @((New-WinSecIdentityFixtureSource $s WSA-IAM-002)) @($r)
    Assert-Identity ($a.Rows.Count -eq 0)
}
Test-Identity 'Wrong Guest RID and invalid required state reject the provider' {
    $script:IdentityGuestSid='S-1-5-21-11-22-33-500';$s=New-WinSecIdentityFixtureSession @('WSA-IAM-002');Assert-Identity (-not $s.ControlResults[0].Evidence.CollectionComplete)
    $script:IdentityGuestSid='S-1-5-21-11-22-33-501';$script:IdentityMissing='Disabled';$s=New-WinSecIdentityFixtureSession @('WSA-IAM-002');Assert-Identity (-not $s.ControlResults[0].Evidence.CollectionComplete)
}
Test-Identity 'Guest optional null remains visible with limited coverage' {
    $script:IdentityMissing='PasswordRequired';$s=New-WinSecIdentityFixtureSession @('WSA-IAM-002');$r=New-WinSecTechnicalReport $s WSA-IAM-002 SYNTHETIC SYNTHETIC
    Assert-Identity ($s.ControlResults[0].Evidence.CollectionComplete -and -not $s.ControlResults[0].Evidence.CoverageComplete -and (ConvertTo-WinSecTechnicalMarkdown $r).Contains('UNKNOWN'))
}
Test-Identity 'Empty member set remains observed without fabricated members' {
    $script:IdentityMemberCount=0;$s=New-WinSecIdentityFixtureSession @('WSA-IAM-001');$r=New-WinSecTechnicalReport $s WSA-IAM-001 SYNTHETIC SYNTHETIC
    Assert-Identity ($s.ControlResults[0].Evidence.Administrators.MemberCount -eq 0 -and $s.ControlResults[0].Evidence.CollectionComplete)
}
Test-Identity 'Member overflow and duplicate SIDs reject inventory without truncation' {
    $script:IdentityMemberCount=257;$s=New-WinSecIdentityFixtureSession @('WSA-IAM-001');Assert-Identity (-not $s.ControlResults[0].Evidence.CollectionComplete)
    $script:IdentityMemberCount=2;$script:IdentityDuplicate=$true;$s=New-WinSecIdentityFixtureSession @('WSA-IAM-001');Assert-Identity (-not $s.ControlResults[0].Evidence.CollectionComplete)
}
Test-Identity 'Policy DWORDs retain zero and TIMEQ_FOREVER, missing required data remains partial' {
    $s=New-WinSecIdentityFixtureSession @('WSA-IAM-003');$r=New-WinSecTechnicalReport $s WSA-IAM-003 SYNTHETIC SYNTHETIC
    Assert-Identity ($s.ControlResults[0].Evidence.Password.MaximumAgeSeconds -eq 4294967295 -and -not $s.ControlResults[0].Evidence.CoverageComplete)
    Assert-Identity (@($r.Rows|Where-Object State -CEQ NOT_COLLECTED).Count -eq 2)
    $script:IdentityMissing='MinimumLength';$s=New-WinSecIdentityFixtureSession @('WSA-IAM-003');Assert-Identity (-not $s.ControlResults[0].Evidence.CollectionComplete)
}
Test-Identity 'Esc before and during collection produces no completed result' {
    Reject-Identity {Test-WinSecLocalAdmins ('local:hw1-'+('b'*64)) cancelled -CancellationAction {$true}}
    Reject-Identity {Test-WinSecPasswordPolicy ('local:hw1-'+('b'*64)) cancelled -CancellationAction {$IdentityCalls.Count -ge 1}}
}
Test-Identity 'Strict report rejects forged count, coverage, negative values and private fields' {
    $s=New-WinSecIdentityFixtureSession @('WSA-IAM-001');$r=New-WinSecTechnicalReport $s WSA-IAM-001 SYNTHETIC SYNTHETIC
    foreach($field in @('Administrators.MemberCount','UnknownFieldCount','CollectionComplete')){
        $copy=Copy-WinSecResultData $r;$row=@($copy.Rows|Where-Object SettingId -CEQ $field)[0];$row.Value=if($row.Value -is [bool]){-not $row.Value}else{-1};Reject-Identity {ConvertTo-WinSecTechnicalReport $copy}
    }
    $row=@($r.Rows|Where-Object SettingId -CEQ Administrators.Members)[0];$data=ConvertFrom-Json $row.Value;$data.Items[0]|Add-Member Name PRIVATE-NAME;$row.Value=ConvertTo-Json $data -Depth 5 -Compress;Reject-Identity {ConvertTo-WinSecTechnicalReport $r}
}
foreach($framework in @('nist-csf','cis-controls','mitre-attack')){Test-Identity ('F reviews saved readings with references, no new queries: '+$framework){
    $s=New-WinSecIdentityFixtureSession;$reports=@($s.ControlResults|ForEach-Object {New-WinSecTechnicalReport $s $_.CheckId SYNTHETIC SYNTHETIC});$sources=@($s.ControlResults|ForEach-Object {New-WinSecIdentityFixtureSource $s $_.CheckId});$before=$IdentityCalls.Count
    $a=New-WinSecFrameworkAnalysis $root $s.DeviceId SYNTHETIC SECTION IdentityAccess $framework $sources $reports
    Assert-Identity ($a.Rows.Count -eq 4 -and @($a.Rows|Where-Object {$_.References.Count -eq 0}).Count -eq 0 -and $IdentityCalls.Count -eq $before)
}}
Write-Host ('IdentityAccess: '+$passed+' passed; '+$failed+' failed.');if($failed){throw 'IdentityAccess tests failed.'}
