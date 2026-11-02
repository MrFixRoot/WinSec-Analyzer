[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Checks/Defender/DefenderTechnicalSnapshot.ps1')
. (Join-Path $root 'tests/Fixtures/DefenderTechnicalMemory.ps1')
function Get-MpComputerStatus {throw 'Native audit forbidden.'}
function Get-MpPreference {throw 'Native audit forbidden.'}
function Get-CimInstance {throw 'Native audit forbidden.'}
$passed=0;$failed=0
function Assert-DefenderCandidate {param([bool]$Value);if(-not $Value){throw 'Defender candidate assertion failed.'}}
function Reject-DefenderCandidate {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-DefenderCandidate $caught}
function Test-DefenderCandidate {param($Name,[scriptblock]$Action);$f=New-WinSecDefenderTechnicalFixture;try{& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}catch{$script:failed++;Write-Host ('[FAIL] '+$Name+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}
Test-DefenderCandidate 'Reviewed catalog is Defender-only, versioned and valid without production activation' {
    $c=Get-WinSecDefenderTechnicalCatalog;Assert-WinSecSnapshotCatalog $c
    Assert-DefenderCandidate ($c.CheckId -ceq 'WSA-SYS-001' -and $c.CatalogId -ceq 'WinSec.Defender.Candidate' -and $c.Fields.Count -ge 100 -and $c.Inventories.Count -eq 5)
}
Test-DefenderCandidate 'All reviewed fields normalize with honest complete catalog coverage' {
    $p=New-WinSecDefenderFixturePackage $f
    Assert-DefenderCandidate ($p.Snapshot.Collection.Status -ceq 'COMPLETE' -and $p.Snapshot.Collection.Coverage -ceq 'COMPLETE' -and $p.Snapshot.Collection.RetainedRecords -eq 5)
    Assert-WinSecDefenderTechnicalSnapshot $p.Snapshot $f.Identity
}
Test-DefenderCandidate 'False, zero and the native maximum-age sentinel are preserved without interpretation' {
    $s=(New-WinSecDefenderFixturePackage $f).Snapshot
    Assert-DefenderCandidate ((Get-WinSecDefenderFixtureReading $s Status.AntivirusEnabled).Value -ceq $false -and
        (Get-WinSecDefenderFixtureReading $s Preferences.MAPSReporting).Value -eq 0 -and
        (Get-WinSecDefenderFixtureReading $s Status.AntivirusSignatureAgeDays).Value -eq [uint32]::MaxValue)
}
Test-DefenderCandidate 'Existing PUA, IPS, RDP parsing and signature interval readings remain in the candidate' {
    $f.Sources[2].Data.PUAProtection=[uint32]2;$f.Sources[2].Data.DisableIntrusionPreventionSystem=$true
    $f.Sources[2].Data.DisableRdpParsing=$true;$f.Sources[2].Data.SignatureUpdateInterval=[uint32]8
    $s=(New-WinSecDefenderFixturePackage $f).Snapshot
    Assert-DefenderCandidate ((Get-WinSecDefenderFixtureReading $s Preferences.PUAProtection).Value -eq 2 -and
        (Get-WinSecDefenderFixtureReading $s Preferences.DisableIntrusionPreventionSystem).Value -ceq $true -and
        (Get-WinSecDefenderFixtureReading $s Preferences.DisableRdpParsing).Value -ceq $true -and
        (Get-WinSecDefenderFixtureReading $s Preferences.SignatureUpdateIntervalHours).Value -eq 8)
}
Test-DefenderCandidate 'Absent optional telemetry limits coverage without inventing a failure' {
    $f.Sources[1].Data.PSObject.Properties.Remove('AntispywareSignatureAge');$s=(New-WinSecDefenderFixturePackage $f).Snapshot
    Assert-DefenderCandidate ($s.Collection.Status -ceq 'COMPLETE' -and $s.Collection.Coverage -ceq 'LIMITED' -and (Get-WinSecDefenderFixtureReading $s Status.AntispywareSignatureAgeDays).State -ceq 'UNKNOWN')
}
Test-DefenderCandidate 'A numeric Boolean cannot satisfy a required status reading' {
    $f.Sources[1].Data.AntivirusEnabled=0;$s=(New-WinSecDefenderFixturePackage $f).Snapshot
    Assert-DefenderCandidate ($s.Collection.Status -ceq 'PARTIAL' -and (Get-WinSecDefenderFixtureReading $s Status.AntivirusEnabled).Reason -ceq 'INVALID_VALUE')
}
foreach($outcome in @('ERROR','NOT_COLLECTED')){Test-DefenderCandidate ('Source absence remains explicit: '+$outcome) {
    $f.Sources[2].State=$outcome;$f.Sources[2].Data=$null;$s=(New-WinSecDefenderFixturePackage $f).Snapshot
    Assert-DefenderCandidate ($s.Collection.Status -ceq 'PARTIAL' -and (Get-WinSecDefenderFixtureReading $s Preferences.MAPSReporting).State -ceq $outcome)
}}
foreach($damage in @('owner','scan','duplicate','source','timeline','platform','version','scope')){Test-DefenderCandidate ('Foreign or contradictory captured input is rejected: '+$damage) {
    switch($damage){
        owner {$f.Sources[1].DeviceId='local:hw1-'+('c'*64)};scan {$f.Sources[1].ScanId='other'};duplicate {$f.Sources[1].SourceId='Platform'}
        source {$f.Sources[1].State='UNKNOWN'};timeline {$f.Sources[1].CollectedAtUTC='2026-10-29T01:02:04.0000000Z'}
        platform {$f.Sources[0].Data.BuildNumber='19045';$f.Sources[0].Data.Version='10.0.19045'}
        version {$f.Sources[0].Data.Version='10.0.22631'};scope {$f.Identity.ScopeType='SECTION';$f.Identity.ScopeKey='NetworkSecurity'}
    }
    Reject-DefenderCandidate {New-WinSecDefenderFixturePackage $f}
}}
Test-DefenderCandidate 'Selected profile does not fabricate observed edition release or UBR' {
    $f.Sources[0].Data.OperatingSystemSKU=[uint32]121;$s=(New-WinSecDefenderFixturePackage $f).Snapshot
    Assert-DefenderCandidate ($s.Platform.OperatingSystemSKU -eq 121 -and $null -eq $s.Platform.Edition -and $null -eq $s.Platform.OSRelease -and $null -eq $s.Platform.UBR)
}
Test-DefenderCandidate 'Ambiguous local timestamps are unknown rather than assigned an invented timezone' {
    $f.Sources[1].Data.QuickScanEndTime=[datetime]::SpecifyKind([datetime]'2026-10-27T12:00:00',[DateTimeKind]::Unspecified)
    $r=Get-WinSecDefenderFixtureReading (New-WinSecDefenderFixturePackage $f).Snapshot Status.QuickScanEndTime
    Assert-DefenderCandidate ($r.State -ceq 'UNKNOWN' -and $r.Reason -ceq 'INVALID_VALUE' -and $null -eq $r.Value)
}
Test-DefenderCandidate 'No raw exclusions, secrets or unreviewed getters enter the snapshot' {
    $script:getterCalls=0;$f.Sources[1].Data|Add-Member -MemberType ScriptProperty -Name PrivateSecret -Value {$script:getterCalls++;'PRIVATE-SECRET'}
    $f.Sources[1].Data|Add-Member -MemberType ScriptProperty -Name AntivirusEnabled -Value {$script:getterCalls++;'PRIVATE-SECRET'} -Force
    $s=(New-WinSecDefenderFixturePackage $f).Snapshot;$json=ConvertTo-Json -InputObject $s -Depth 16 -Compress
    Assert-DefenderCandidate ($getterCalls -eq 0 -and $json -notmatch 'PRIVATE-|PrivateSecret|ExclusionPath"' -and $s.Collection.Status -ceq 'PARTIAL')
}
Test-DefenderCandidate 'An unknown exclusion list is not converted to an empty configuration' {
    $f.Sources[2].Data.ExclusionPath=$null;$s=(New-WinSecDefenderFixturePackage $f).Snapshot
    Assert-DefenderCandidate ((Get-WinSecDefenderFixtureReading $s ExclusionCounts.ExclusionPathCount).State -ceq 'UNKNOWN')
}
Test-DefenderCandidate 'Malformed exclusion members are not counted as verified configuration entries' {
    $f.Sources[2].Data.ExclusionPath=@([pscustomobject]@{Secret='PRIVATE-SECRET'})
    $s=(New-WinSecDefenderFixturePackage $f).Snapshot;$r=Get-WinSecDefenderFixtureReading $s ExclusionCounts.ExclusionPathCount
    Assert-DefenderCandidate ($r.State -ceq 'UNKNOWN' -and $r.Reason -ceq 'INVALID_VALUE' -and (ConvertTo-Json $s -Depth 16 -Compress) -notmatch 'PRIVATE-SECRET')
}
Test-DefenderCandidate 'Explicit empty ASR arrays are preserved without assuming effective protection' {
    $f=New-WinSecDefenderTechnicalFixture 0;$s=(New-WinSecDefenderFixturePackage $f).Snapshot;$a=@($s.Inventories|Where-Object Id -CEQ ASR)[0]
    Assert-DefenderCandidate ($a.Complete -and $a.ReportedRecords -eq 0 -and $a.RetainedRecords -eq 0 -and $s.Collection.Status -ceq 'COMPLETE')
}
Test-DefenderCandidate 'Null ASR arrays are unavailable, not a proven empty inventory' {
    $f.Sources[2].Data.AttackSurfaceReductionRules_Ids=$null;$f.Sources[2].Data.AttackSurfaceReductionRules_Actions=$null
    $s=(New-WinSecDefenderFixturePackage $f).Snapshot;$a=@($s.Inventories|Where-Object Id -CEQ ASR)[0]
    Assert-DefenderCandidate (-not $a.Complete -and $a.State -ceq 'UNKNOWN' -and $null -eq $a.ReportedRecords -and $s.Collection.Status -ceq 'PARTIAL')
}
foreach($missing in @('AttackSurfaceReductionRules_Ids','AttackSurfaceReductionRules_Actions')){Test-DefenderCandidate ('One null ASR array cannot be completed by an empty companion: '+$missing) {
    $f=New-WinSecDefenderTechnicalFixture 0;$f.Sources[2].Data.$missing=$null
    $s=(New-WinSecDefenderFixturePackage $f).Snapshot;$a=@($s.Inventories|Where-Object Id -CEQ ASR)[0]
    Assert-DefenderCandidate (-not $a.Complete -and $a.State -ceq 'UNKNOWN' -and $null -eq $a.ReportedRecords -and $s.Collection.Status -ceq 'PARTIAL')
}}
foreach($damage in @('length','duplicate','invalid','future')){Test-DefenderCandidate ('ASR rows preserve provenance and inconsistencies: '+$damage) {
    $f=New-WinSecDefenderTechnicalFixture 2
    switch($damage){length {$f.Sources[2].Data.AttackSurfaceReductionRules_Actions=@([uint32]1)}
        duplicate {$f.Sources[2].Data.AttackSurfaceReductionRules_Ids[1]=$f.Sources[2].Data.AttackSurfaceReductionRules_Ids[0]}
        invalid {$f.Sources[2].Data.AttackSurfaceReductionRules_Ids[0]='PRIVATE-SECRET'}
        future {$f.Sources[2].Data.AttackSurfaceReductionRules_Actions[0]=[uint32]999}}
    $s=(New-WinSecDefenderFixturePackage $f).Snapshot;$a=@($s.Inventories|Where-Object Id -CEQ ASR)[0]
    Assert-DefenderCandidate ($a.RetainedRecords -eq 2 -and (ConvertTo-Json $s -Depth 16 -Compress) -notmatch 'PRIVATE-SECRET')
    Assert-DefenderCandidate ($a.Complete -eq ($damage -ceq 'future'))
}}
Test-DefenderCandidate 'ASR has no arbitrary 128 or 512 row cutoff' {
    $f=New-WinSecDefenderTechnicalFixture 513;$s=(New-WinSecDefenderFixturePackage $f).Snapshot;$a=@($s.Inventories|Where-Object Id -CEQ ASR)[0]
    Assert-DefenderCandidate ($a.Complete -and $a.RetainedRecords -eq 513 -and @($s.Batches|Where-Object InventoryId -CEQ ASR).Count -eq 5)
}
Test-DefenderCandidate 'Resource exhaustion remains partial with an explicit pending inventory count' {
    function Get-WinSecDefenderTechnicalPayloadBudget {return 0}
    $s=(New-WinSecDefenderFixturePackage $f).Snapshot;$a=@($s.Inventories|Where-Object Id -CEQ ASR)[0]
    Assert-DefenderCandidate (-not $a.Complete -and $a.Reason -ceq 'RESOURCE_LIMIT' -and $a.ReportedRecords -eq 1 -and $a.RetainedRecords -eq 0 -and $s.Collection.Status -ceq 'PARTIAL')
}
Test-DefenderCandidate 'Cancellation aborts normalization without modifying captured data' {
    $before=ConvertTo-Json -InputObject $f -Depth 10 -Compress;$cancelled=$false
    try{$null=New-WinSecDefenderFixturePackage $f -CancellationAction {$true}}catch [OperationCanceledException]{$cancelled=$true}
    Assert-DefenderCandidate ($cancelled -and (ConvertTo-Json -InputObject $f -Depth 10 -Compress) -ceq $before)
}
Test-DefenderCandidate 'Progress reports retained rows and cancellation interrupts an ASR batch' {
    $f=New-WinSecDefenderTechnicalFixture 513;$script:rows=0;$cancelled=$false
    try{$null=New-WinSecDefenderFixturePackage $f -ProgressCallback {param($event);if($event.InventoryId -ceq 'ASR'){$script:rows=$event.RetainedRecords}} -CancellationAction {$script:rows -ge 7}}
    catch [OperationCanceledException]{$cancelled=$true}
    Assert-DefenderCandidate ($cancelled -and $script:rows -eq 7)
}
Test-DefenderCandidate 'The normalized snapshot is detached from source and identity mutation' {
    $s=(New-WinSecDefenderFixturePackage $f).Snapshot;$f.Identity.ScanId='other';$f.Sources[1].Data.AntivirusEnabled=$true
    Assert-DefenderCandidate ($s.Identity.ScanId -ceq 'candidate-defender' -and (Get-WinSecDefenderFixtureReading $s Status.AntivirusEnabled).Value -ceq $false)
}
Test-DefenderCandidate 'A forged observed string is rejected even if generic string syntax permits it' {
    $s=(New-WinSecDefenderFixturePackage $f).Snapshot;(Get-WinSecDefenderFixtureReading $s Status.AMProductVersion).Value='PRIVATE-SECRET'
    Reject-DefenderCandidate {Assert-WinSecDefenderTechnicalSnapshot $s $f.Identity}
}
Write-Host ("Defender technical candidate: $passed passed; $failed failed.");if($failed){exit 1}
