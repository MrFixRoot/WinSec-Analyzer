# Synthetic telemetry only. Writer tests use an isolated temporary installation.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
$script:passed=0;$script:failed=0
$device='local:hw1-'+('b'*64)
function Get-CimInstance {throw 'Unexpected native query.'}
function Get-MpComputerStatus {throw 'Unexpected native query.'}
function Get-MpPreference {throw 'Unexpected native query.'}
function Assert-WinSecTechnical {param([bool]$Value);if(-not $Value){throw 'Technical report assertion failed.'}}
function Assert-WinSecTechnicalReject {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-WinSecTechnical $caught}
function Test-WinSecTechnical {
    param([string]$Name,[scriptblock]$Action)
    try{$null=& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}
    catch{$script:failed++;Write-Host ('[FAIL] '+$Name+' : '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}
}
function New-WinSecTechnicalFixture {
    param([string]$Id='WSA-SYS-002')
    $start=[datetime]::UtcNow.AddMinutes(-1).ToString('o');$end=[datetime]::UtcNow.AddSeconds(-1).ToString('o')
    $e=[pscustomobject]@{DeviceId=$device;ScanId='technical-fixture';CheckId=$Id;CollectedAtUTC=$end;
        CollectionSuccessful=$true;CollectionComplete=$true;Private='SYNTHETIC-SECRET'}
    switch($Id) {
        WSA-SYS-001 {
            $e|Add-Member DefenderStatus ([pscustomobject]@{AntivirusEnabled=$false;AMRunningMode='Normal';AntivirusSignatureLastUpdated=[datetime]'2026-10-01T00:00:00Z'})
            $e|Add-Member DefenderPreferences ([pscustomobject]@{PUAProtection=0;ExclusionPath=@('SYNTHETIC-SECRET')})
            $e|Add-Member ExclusionCounts ([pscustomobject]@{Paths=0})
            $e|Add-Member AttackSurfaceReduction ([pscustomobject]@{Available=$true;Complete=$true;ConfiguredRuleCount=1;
                Rules=@([pscustomobject]@{RuleId='56a863a9-875e-4185-98a7-b882c64b5ce5';Mode='BLOCK';RawAction='1';EffectiveEnforcementConfirmed=$false})})
        }
        WSA-SYS-002 {$e|Add-Member SystemVolume ([pscustomobject]@{DriveLetter='C:';ProtectionStatus='OFF';ConversionStatus='FULLY_DECRYPTED';EncryptionPercentage=0;EncryptionMethod='NONE';LockStatus='UNLOCKED';RecoveryPassword='SYNTHETIC-SECRET'})}
        WSA-SYS-003 {
            $e|Add-Member Platform ([pscustomobject]@{Version='10.0.22631';BuildNumber='22631';OperatingSystemSKU=48;ProductType=1;State='OBSERVED'})
            $e|Add-Member UpdateService ([pscustomobject]@{State='Stopped';StartMode='Manual'})
            $e|Add-Member PolicyRegistry ([pscustomobject]@{AutomaticUpdates=[pscustomobject]@{ReadState='READ';NoAutoUpdate=[pscustomobject]@{State='CONFIGURED';Value=0}}})
            $e|Add-Member AutomationPolicy ([pscustomobject]@{IgnoreWindowsUpdateGroupPolicies=[pscustomobject]@{State='NOT_APPLICABLE';Managed=$null;Value=$null}})
            $e|Add-Member RestartInformation ([pscustomobject]@{State='OBSERVED';Value=$false})
        }
    }
    $c=[pscustomobject]@{DeviceId=$device;ScanId=$e.ScanId;CheckId=$Id;SectionKey='SystemSecurity';Status='INFORMATIONAL';ObservedStatus='INFORMATIONAL';TimestampUTC=$end;Evidence=$e}
    New-WinSecResultSession -DeviceId $device -ScanId $e.ScanId -CatalogVersion '1.0.0' -ExpectedCheckIds @($Id) -ControlResults @($c) `
        -StartedAtUTC $start -CompletedAtUTC $end -ExecutionStatus COMPLETED -ScopeType CONTROL -ScopeKey $Id
}
function Get-WinSecTechnicalFixtureReport {
    param([string]$Id='WSA-SYS-002')
    New-WinSecTechnicalReport -Session (New-WinSecTechnicalFixture $Id) -CheckId $Id -DeviceName SYNTHETIC -Hostname SYNTHETIC
}
function Get-WinSecTechnicalFixtureText {
    param($Report)
    $body=ConvertTo-WinSecTechnicalBody $Report
    $m=[ordered]@{SchemaVersion='1.0.0';DeviceId=$Report.DeviceId;ScanId=$Report.ScanId;CheckId=$Report.CheckId;
        ScopeType=$Report.ScopeType;ScopeKey=$Report.ScopeKey;ContentSha256=(Get-WinSecReportTextHash $body)}
    "WinSec technical scan report`n"+(ConvertTo-Json $m -Compress)+"`n`n"+$body
}
foreach($id in @('WSA-SYS-001','WSA-SYS-002','WSA-SYS-003')) {
    Test-WinSecTechnical ('Every allowed field is recorded and private data is excluded: '+$id) {
        $r=Get-WinSecTechnicalFixtureReport $id;$text=Get-WinSecTechnicalFixtureText $r
        $m=ConvertFrom-WinSecTextArtifact $text $device
        Assert-WinSecTechnical ($m.CheckId -ceq $id -and $r.Rows.Count -ge @(Get-WinSecTechnicalDefinitions $id).Count -and
            $text -notmatch 'SYNTHETIC-SECRET|RecoveryPassword|ExclusionPath|"Evidence"' -and $text.Contains('DATOS ESTRUCTURADOS JSON'))
    }
}
Test-WinSecTechnical 'False and zero remain observed rather than missing or failed' {
    $r=Get-WinSecTechnicalFixtureReport WSA-SYS-001
    $av=@($r.Rows|Where-Object SettingId -CEQ DefenderStatus.AntivirusEnabled)[0]
    $pua=@($r.Rows|Where-Object SettingId -CEQ DefenderPreferences.PUAProtection)[0]
    Assert-WinSecTechnical ($av.State -ceq 'OBSERVED' -and $av.Value -is [bool] -and -not $av.Value -and $pua.Value -eq 0 -and $pua.State -ceq 'OBSERVED')
}
Test-WinSecTechnical 'Unknown fields are explicit and do not trigger additional collection' {
    $r=Get-WinSecTechnicalFixtureReport WSA-SYS-001
    Assert-WinSecTechnical (@($r.Rows|Where-Object State -CEQ NOT_COLLECTED).Count -gt 0)
}
Test-WinSecTechnical 'Malformed allowed values are withheld with a diagnostic instead of exposing provider text' {
    $s=New-WinSecTechnicalFixture WSA-SYS-001;$s.ControlResults[0].Evidence.DefenderStatus.AMRunningMode='SYNTHETIC-SECRET'
    $r=New-WinSecTechnicalReport $s WSA-SYS-001 SYNTHETIC SYNTHETIC
    $row=@($r.Rows|Where-Object SettingId -CEQ DefenderStatus.AMRunningMode)[0]
    Assert-WinSecTechnical ($row.Reason -ceq 'INVALID_VALUE' -and $null -eq $row.Value -and (ConvertTo-WinSecTechnicalBody $r) -notmatch 'SYNTHETIC-SECRET')
}
foreach($fault in @('Device','Scope','ArrayIdentity','UnknownRow','Duplicate','MissingRow','UnknownProperty','InjectedValue','Timeline','RawProperty')) {
    Test-WinSecTechnical ('Technical model rejects '+$fault) {
        $r=Get-WinSecTechnicalFixtureReport
        switch($fault) {
            Device {$r.DeviceId='remote:other'};Scope {$r.ScopeKey='WSA-SYS-001'};ArrayIdentity {$r.ScanId=@($r.ScanId)}
            UnknownRow {$r.Rows[0].SettingId='RecoveryPassword'};Duplicate {$r.Rows+=@($r.Rows[0])}
            MissingRow {$r.Rows=@($r.Rows|Select-Object -Skip 1)};UnknownProperty {$r.Rows[0]|Add-Member Extra 'SYNTHETIC-SECRET'}
            InjectedValue {$r.Rows[0].Value='SYNTHETIC-SECRET'};Timeline {$r.CollectedAtUTC='1990-01-01T00:00:00.0000000Z'}
            RawProperty {$r|Add-Member Evidence 'SYNTHETIC-SECRET'}
        }
        Assert-WinSecTechnicalReject {ConvertTo-WinSecTechnicalReport $r}
    }
}
Test-WinSecTechnical 'A changed body or foreign owner is rejected by the deletion reader' {
    $text=Get-WinSecTechnicalFixtureText (Get-WinSecTechnicalFixtureReport)
    Assert-WinSecTechnicalReject {ConvertFrom-WinSecTextArtifact ($text.Replace('BitLocker','CHANGED')) $device}
    Assert-WinSecTechnicalReject {ConvertFrom-WinSecTextArtifact $text ('local:hw1-'+('c'*64))}
}
Test-WinSecTechnical 'Unsupported adapters and legacy scope cannot authorize technical generation' {
    Assert-WinSecTechnicalReject {Get-WinSecTechnicalReportPolicy $root $device @('WSA-NET-003')}
    $r=Get-WinSecTechnicalFixtureReport;$r.ScopeType=$null;$r.ScopeKey=$null
    Assert-WinSecTechnicalReject {ConvertTo-WinSecTechnicalReport $r}
}
Test-WinSecTechnical 'ASR preserves individual action codes and does not claim effective enforcement' {
    $r=Get-WinSecTechnicalFixtureReport WSA-SYS-001
    $rule=@($r.Rows|Where-Object {$_.SettingId -like 'AttackSurfaceReduction.Rules.*'})
    Assert-WinSecTechnical ($rule.Count -eq 3 -and @($rule|Where-Object {$_.SettingId.EndsWith('.RawAction')})[0].Value -eq 1 -and
        @($rule|Where-Object {$_.SettingId.EndsWith('.EffectiveEnforcementConfirmed')})[0].Value -ceq $false)
}
Test-WinSecTechnical 'Reviewed textual modes and NamedPolicy kinds are retained rather than silently discarded' {
    $s=New-WinSecTechnicalFixture WSA-SYS-001
    $s.ControlResults[0].Evidence.AttackSurfaceReduction.Rules[0].RawAction='AuditMode'
    $s.ControlResults[0].Evidence.AttackSurfaceReduction.Rules[0].Mode='AUDIT'
    $r=New-WinSecTechnicalReport $s WSA-SYS-001 SYNTHETIC SYNTHETIC
    Assert-WinSecTechnical (@($r.Rows|Where-Object {$_.SettingId.EndsWith('.RawAction')})[0].Value -ceq 'AuditMode')
    foreach($kind in @('Invalid','Binary','Boolean','Int32','Int64','String')) {
        Assert-WinSecTechnical ((ConvertTo-WinSecTechnicalValue $kind mode) -ceq $kind)
    }
}
Test-WinSecTechnical 'Only verified legacy Windows platforms permit the named-policy exclusion' {
    $r=Get-WinSecTechnicalFixtureReport WSA-SYS-003
    @($r.Rows|Where-Object SettingId -CEQ Platform.BuildNumber)[0].Value=26100
    Assert-WinSecTechnicalReject {ConvertTo-WinSecTechnicalReport $r}
}
Test-WinSecTechnical 'Foreign evidence cannot enter a technical report and absent failed evidence is explicit' {
    $s=New-WinSecTechnicalFixture WSA-SYS-002
    $s.ControlResults[0].Evidence.DeviceId='local:hw1-'+('c'*64)
    Assert-WinSecTechnicalReject {New-WinSecTechnicalReport $s WSA-SYS-002 SYNTHETIC SYNTHETIC}
    $s.ControlResults[0].Evidence=$null;$s.ControlResults[0].Status='ERROR';$s.ControlResults[0].ObservedStatus='ERROR'
    $s.ExecutionStatus='COMPLETED_WITH_ERRORS'
    $r=New-WinSecTechnicalReport $s WSA-SYS-002 SYNTHETIC SYNTHETIC
    Assert-WinSecTechnical ($r.CollectorStatus -ceq 'ERROR' -and @($r.Rows|Where-Object State -CNE NOT_COLLECTED).Count -eq 0)
}
Test-WinSecTechnical 'Fallback provenance is retained and unknown service states stay unknown' {
    $s=New-WinSecTechnicalFixture WSA-SYS-001
    $s.ControlResults[0].Evidence|Add-Member StatusSource 'CIM:MSFT_MpComputerStatus'
    $r=New-WinSecTechnicalReport $s WSA-SYS-001 SYNTHETIC SYNTHETIC
    Assert-WinSecTechnical ((ConvertTo-WinSecTechnicalBody $r).Contains('Fuente: CIM:MSFT_MpComputerStatus'))
    $s=New-WinSecTechnicalFixture WSA-SYS-003;$s.ControlResults[0].Evidence.UpdateService.State='UNKNOWN'
    $r=New-WinSecTechnicalReport $s WSA-SYS-003 SYNTHETIC SYNTHETIC
    Assert-WinSecTechnical (@($r.Rows|Where-Object SettingId -CEQ UpdateService.State)[0].State -ceq 'UNKNOWN')
}
Test-WinSecTechnical 'Managed exports hold the inventory lease and reject a device removed before writing' {
    $script:technicalLeaseHeld=$false;$script:technicalDevicePresent=$true;$script:technicalWrites=0
    function Open-WinSecDeviceInventoryStore {
        param($ProjectRoot)
        $script:technicalLeaseHeld=$true;$lock=[pscustomobject]@{}
        $lock|Add-Member ScriptMethod Dispose {$script:technicalLeaseHeld=$false}
        [pscustomobject]@{Lock=$lock}
    }
    function Import-WinSecDeviceInventory {
        param($ProjectRoot)
        Assert-WinSecTechnical $script:technicalLeaseHeld
        [pscustomobject]@{targets=@(if($script:technicalDevicePresent){[pscustomobject]@{DeviceId=$device;DisplayName='SYNTHETIC'}})}
    }
    function Write-WinSecTechnicalArtifact {
        param($ProjectRoot,$Report)
        Assert-WinSecTechnical $script:technicalLeaseHeld
        $script:technicalWrites++
        [pscustomobject]@{DeviceId=$Report.DeviceId;ScanId=$Report.ScanId;CheckId=$Report.CheckId;Path='synthetic.txt'}
    }
    $c=[pscustomobject]@{ProjectRoot=$root;RequireDeviceInventory=$true}
    $s=New-WinSecTechnicalFixture WSA-SYS-002;$t=[pscustomobject]@{Hostname='SYNTHETIC'}
    $r=Save-WinSecTechnicalReports $c $s $t
    Assert-WinSecTechnical ($r.Status -ceq 'SAVED' -and -not $script:technicalLeaseHeld -and $script:technicalWrites -eq 1)
    $script:technicalDevicePresent=$false
    $r=Save-WinSecTechnicalReports $c $s $t
    Assert-WinSecTechnical ($r.Status -ceq 'FAILED' -and -not $script:technicalLeaseHeld -and $script:technicalWrites -eq 1)
}
$fixtureRoot=Join-Path ([IO.Path]::GetTempPath()) ('WinSec-Tech-'+[guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($fixtureRoot)
try {
    # Only the installation check is substituted. Real path, write and content checks run.
    function Get-WinSecReportInstallation {param($ProjectRoot);if($ProjectRoot -cne $fixtureRoot){throw 'Unexpected fixture installation.'};$fixtureRoot}
    Test-WinSecTechnical 'Writer creates a readable immutable file and collision preserves the previous file' {
        $r=Get-WinSecTechnicalFixtureReport;$a=Write-WinSecTechnicalArtifact $fixtureRoot $r
        $before=Get-Content -LiteralPath $a.Path -Raw -Encoding UTF8
        $meta=ConvertFrom-WinSecMarkdownArtifact $before $device
        Assert-WinSecTechnical ($meta.CheckId -ceq $r.CheckId -and $a.Path.EndsWith('.md') -and $a.Path.Contains('reports') -and $meta.SchemaVersion -ceq '2.0.0')
        Assert-WinSecTechnicalReject {Write-WinSecTechnicalArtifact $fixtureRoot $r}
        Assert-WinSecTechnical ((Get-Content -LiteralPath $a.Path -Raw -Encoding UTF8) -ceq $before)
        Assert-WinSecTechnical (@(Get-ChildItem -LiteralPath ([IO.Path]::GetDirectoryName($a.Path)) -Force|Where-Object Extension -CEQ .tmp).Count -eq 0)
    }
    Test-WinSecTechnical 'Writer rejects a file replacing the device directory without removing it' {
        $r=Get-WinSecTechnicalFixtureReport;$r.DeviceId='local:hw1-'+('c'*64)
        $blocked=Join-Path $fixtureRoot ('reports/exports/'+(Get-WinSecEvidenceHash $r.DeviceId))
        [IO.File]::WriteAllText($blocked,'SYNTHETIC-BLOCKED-DIRECTORY')
        Assert-WinSecTechnicalReject {Write-WinSecTechnicalArtifact $fixtureRoot $r}
        Assert-WinSecTechnical ([IO.File]::ReadAllText($blocked) -ceq 'SYNTHETIC-BLOCKED-DIRECTORY')
    }
} finally {
    $absolute=[IO.Path]::GetFullPath($fixtureRoot);$parent=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\','/')
    if(-not [string]::Equals([IO.Path]::GetDirectoryName($absolute),$parent,[StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($absolute) -cnotmatch '\AWinSec-Tech-[a-f0-9]{32}\z'){throw 'Unsafe technical fixture cleanup.'}
    Remove-Item -LiteralPath $absolute -Recurse -Force
}
[Console]::WriteLine(('Technical reports: {0} passed, {1} failed.' -f $script:passed,$script:failed))
if($script:failed){throw 'Technical report tests failed.'}
