# Prepared data only; no local Windows audit or application-data writes.
[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Checks/System/WindowsUpdateTechnicalSnapshot.ps1')
. (Join-Path $root 'tests/Fixtures/WindowsUpdateTechnicalMemory.ps1')
function Get-CimInstance {throw 'Native audit forbidden.'}
function Invoke-CimMethod {throw 'Native audit forbidden.'}
function Get-HotFix {throw 'Native audit forbidden.'}
function Get-Service {throw 'Native audit forbidden.'}
$passed=0;$failed=0
function Assert-UpdateCandidate {param([bool]$Value);if(-not $Value){throw 'Windows Update candidate assertion failed.'}}
function Reject-UpdateCandidate {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-UpdateCandidate $caught}
function Test-UpdateCandidate {param($Name,[scriptblock]$Action);$f=New-WinSecWindowsUpdateTechnicalFixture;try{& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}catch{$script:failed++;Write-Host ('[FAIL] '+$Name+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}
Test-UpdateCandidate 'The versioned catalog declares eight inventories and fifty-two reviewed fields' {
    $c=Get-WinSecWindowsUpdateTechnicalCatalog;Assert-WinSecSnapshotCatalog $c
    Assert-UpdateCandidate ($c.CheckId -ceq 'WSA-SYS-003' -and $c.Fields.Count -eq 52 -and $c.Inventories.Count -eq 8)
}
Test-UpdateCandidate 'A complete catalog capture preserves limited provider scope without claiming patch currency' {
    $s=(New-WinSecWindowsUpdateFixturePackage $f).Snapshot
    Assert-UpdateCandidate ($s.Collection.Status -ceq 'COMPLETE' -and $s.Collection.Coverage -ceq 'COMPLETE' -and $s.Collection.NotConfigured -eq 20 -and
        (Get-WinSecWindowsUpdateFixtureReadings $s Capture.InstalledInventoryScope)[0].Value -ceq 'CBS_QFE_ONLY' -and -not $s.PSObject.Properties['Score'] -and
        -not $s.PSObject.Properties['PatchCurrency'])
}
Test-UpdateCandidate 'False zero absent and unknown policy observations remain distinct' {
    $f.Sources[3].Data.NoAutoUpdate=[pscustomobject]@{State='OBSERVED';Kind='DWord';Value=[uint32]0}
    $f.Sources[3].Data.PSObject.Properties.Remove('AUOptions');$s=(New-WinSecWindowsUpdateFixturePackage $f).Snapshot
    Assert-UpdateCandidate ((Get-WinSecWindowsUpdateFixtureReadings $s Reboot.RebootRequired)[0].Value -ceq $false -and
        (Get-WinSecWindowsUpdateFixtureReadings $s GPOAU.NoAutoUpdate)[0].Value -eq 0 -and
        (Get-WinSecWindowsUpdateFixtureReadings $s GPOAU.UseWUServer)[0].State -ceq 'NOT_CONFIGURED' -and
        (Get-WinSecWindowsUpdateFixtureReadings $s GPOAU.AUOptions)[0].State -ceq 'UNKNOWN' -and $s.Collection.Status -ceq 'PARTIAL')
}
foreach($damage in @('kind','bool','numeric-text')){Test-UpdateCandidate ('A malformed DWORD is not a verified policy: '+$damage) {
    $f.Sources[3].Data.AUOptions=[pscustomobject]@{State='OBSERVED';Kind='DWord';Value=[uint32]4}
    switch($damage){kind {$f.Sources[3].Data.AUOptions.Kind='String'};bool {$f.Sources[3].Data.AUOptions.Value=$false};numeric-text {$f.Sources[3].Data.AUOptions.Value='4'}}
    $s=(New-WinSecWindowsUpdateFixturePackage $f).Snapshot
    Assert-UpdateCandidate ((Get-WinSecWindowsUpdateFixtureReadings $s GPOAU.AUOptions)[0].State -ceq 'UNKNOWN')
}}
Test-UpdateCandidate 'A tagged signed policy DWORD preserves its unsigned bits without interpreting them' {
    $f.Sources[3].Data.AUOptions=[pscustomobject]@{State='OBSERVED';Kind='DWord';Value=[int]-1}
    $s=(New-WinSecWindowsUpdateFixturePackage $f).Snapshot
    Assert-UpdateCandidate ((Get-WinSecWindowsUpdateFixtureReadings $s GPOAU.AUOptions)[0].Value -eq [uint32]::MaxValue)
}
Test-UpdateCandidate 'Claimed absence cannot carry a value or conceal an unexpected registry schema' {
    $f.Sources[3].Data.AUOptions.Value=[uint32]0;Reject-UpdateCandidate {New-WinSecWindowsUpdateFixturePackage $f}
    $f=New-WinSecWindowsUpdateTechnicalFixture;$f.Sources[3].Data.AUOptions|Add-Member NoteProperty RawError 'PRIVATE-SECRET'
    Reject-UpdateCandidate {New-WinSecWindowsUpdateFixturePackage $f}
}
Test-UpdateCandidate 'Build and UBR are cross-checked without inventing release or edition from a selected profile' {
    $f.Sources[1].Data.PSObject.Properties.Remove('UBR');$s=(New-WinSecWindowsUpdateFixturePackage $f).Snapshot
    Assert-UpdateCandidate ($s.Collection.Status -ceq 'PARTIAL' -and $null -eq $s.Platform.UBR -and $null -eq $s.Platform.Edition -and $null -eq $s.Platform.OSRelease)
    $f.Sources[1].Data.CurrentBuildNumber.Value='22631';Reject-UpdateCandidate {New-WinSecWindowsUpdateFixturePackage $f}
}
Test-UpdateCandidate 'Stopped and Manual are observed service configuration rather than a fabricated security failure' {
    $s=(New-WinSecWindowsUpdateFixturePackage $f).Snapshot
    Assert-UpdateCandidate ($s.Collection.Status -ceq 'COMPLETE' -and @(Get-WinSecWindowsUpdateFixtureReadings $s Services.State|Where-Object Value -CEQ Stopped).Count -eq 6 -and
        (ConvertTo-Json $s -Depth 16 -Compress) -notmatch 'MISCONFIGURED|"FAIL"')
}
Test-UpdateCandidate 'A missing reviewed service preserves all returned services and remains partial' {
    $f.Sources[2].Data=@($f.Sources[2].Data|Select-Object -First 5);$s=(New-WinSecWindowsUpdateFixturePackage $f).Snapshot
    $i=@($s.Inventories|Where-Object Id -CEQ Services)[0]
    Assert-UpdateCandidate (-not $i.Complete -and $i.ReportedRecords -eq 5 -and $i.RetainedRecords -eq 5 -and $s.Collection.Status -ceq 'PARTIAL')
}
foreach($damage in @('foreign','duplicate','null')){Test-UpdateCandidate ('Unreviewed service identity rejects the inventory: '+$damage) {
    switch($damage){foreign {$f.Sources[2].Data[0].Name='Spooler'};duplicate {$f.Sources[2].Data[1].Name='WUAUSERV'};null {$f.Sources[2].Data[0].Name=$null}}
    Reject-UpdateCandidate {New-WinSecWindowsUpdateFixturePackage $f}
}}
Test-UpdateCandidate 'Duplicate QFE identifiers remain separate returned entries rather than being silently deduplicated' {
    $f.Sources[6].Data[1].HotFixID=$f.Sources[6].Data[0].HotFixID;$s=(New-WinSecWindowsUpdateFixturePackage $f).Snapshot
    Assert-UpdateCandidate (@(Get-WinSecWindowsUpdateFixtureReadings $s InstalledCBSUpdates.HotFixID).Count -eq 2 -and $s.Collection.Status -ceq 'COMPLETE')
}
Test-UpdateCandidate 'Local and FILETIME date strings are retained without a culture or timezone assumption' {
    $f.Sources[6].Data[0].InstalledOn='28-10-2026';$f.Sources[6].Data[1].InstalledOn='01DB0123456789AB'
    $f.Sources[6].Data[0].InstallDate=[datetime]::SpecifyKind([datetime]'2026-10-28T12:00:00',[DateTimeKind]::Unspecified)
    $s=(New-WinSecWindowsUpdateFixturePackage $f).Snapshot
    Assert-UpdateCandidate ((Get-WinSecWindowsUpdateFixtureReadings $s InstalledCBSUpdates.InstalledOn)[0].Value -ceq '28-10-2026' -and
        (Get-WinSecWindowsUpdateFixtureReadings $s InstalledCBSUpdates.InstalledOn)[1].Value -ceq '01DB0123456789AB' -and
        (Get-WinSecWindowsUpdateFixtureReadings $s InstalledCBSUpdates.InstallDate)[0].State -ceq 'UNKNOWN' -and $s.Collection.Coverage -ceq 'LIMITED')
}
Test-UpdateCandidate 'An explicit empty QFE array preserves source time and never claims a full installed-update inventory' {
    $f=New-WinSecWindowsUpdateTechnicalFixture 0;$f.Sources[6].CollectedAtUTC='2026-10-28T01:02:05.0000000Z'
    $s=(New-WinSecWindowsUpdateFixturePackage $f).Snapshot;$i=@($s.Inventories|Where-Object Id -CEQ InstalledCBSUpdates)[0]
    Assert-UpdateCandidate ($i.Complete -and $i.RetainedRecords -eq 0 -and $s.CollectedAtUTC -ceq $f.Sources[6].CollectedAtUTC -and
        (Get-WinSecWindowsUpdateFixtureReadings $s Capture.InstalledInventoryScope)[0].Value -ceq 'CBS_QFE_ONLY')
    $f.Sources[6].Data=$null;Reject-UpdateCandidate {New-WinSecWindowsUpdateFixturePackage $f}
}
Test-UpdateCandidate 'QFE inventory has no arbitrary 128 or 512 total cutoff' {
    $f=New-WinSecWindowsUpdateTechnicalFixture 513;$s=(New-WinSecWindowsUpdateFixturePackage $f).Snapshot
    $i=@($s.Inventories|Where-Object Id -CEQ InstalledCBSUpdates)[0]
    Assert-UpdateCandidate ($i.Complete -and $i.RetainedRecords -eq 513 -and @($s.Batches|Where-Object InventoryId -CEQ InstalledCBSUpdates).Count -eq 5)
}
Test-UpdateCandidate 'Document-budget exhaustion records explicit retained and pending QFE counts' {
    function Get-WinSecWindowsUpdateTechnicalPayloadBudget {return 0}
    $s=(New-WinSecWindowsUpdateFixturePackage $f).Snapshot;$i=@($s.Inventories|Where-Object Id -CEQ InstalledCBSUpdates)[0]
    Assert-UpdateCandidate (-not $i.Complete -and $i.Reason -ceq 'RESOURCE_LIMIT' -and $i.ReportedRecords -eq 2 -and $i.RetainedRecords -eq 0 -and $s.Collection.Status -ceq 'PARTIAL')
}
foreach($state in @('ERROR','NOT_COLLECTED')){Test-UpdateCandidate ('Unavailable sources preserve explicit failure metadata: '+$state) {
    $f.Sources[5].State=$state;$f.Sources[5].Data=$null;$f.Sources[6].State=$state;$f.Sources[6].Data=$null
    $s=(New-WinSecWindowsUpdateFixturePackage $f).Snapshot
    Assert-UpdateCandidate ($s.Collection.Status -ceq 'PARTIAL' -and (Get-WinSecWindowsUpdateFixtureReadings $s Reboot.RebootRequired)[0].State -ceq $state -and
        (Get-WinSecWindowsUpdateFixtureReadings $s Capture.InstalledCBSUpdatesState)[0].Value -ceq $state)
}}
foreach($damage in @('owner','scan','duplicate','scope','control','time','platform','version','raw-error')){Test-UpdateCandidate ('Foreign or contradictory source is rejected: '+$damage) {
    switch($damage){owner {$f.Sources[0].DeviceId='local:hw1-'+('c'*64)};scan {$f.Sources[0].ScanId='other'};duplicate {$f.Sources[1].SourceId='Platform'}
        scope {$f.Identity.ScopeKey='WSA-SYS-001'};control {$f.Identity.CheckId='WSA-SYS-001';$f.Identity.ScopeKey='WSA-SYS-001'}
        time {$f.Sources[6].CollectedAtUTC='2026-10-29T01:02:04.0000000Z'};platform {$f.Sources[0].Data.ProductType=[uint32]3}
        version {$f.Sources[0].Data.Version='10.0.22631'};raw-error {$f.Sources[6].State='ERROR'}
    };Reject-UpdateCandidate {New-WinSecWindowsUpdateFixturePackage $f}
}}
Test-UpdateCandidate 'Home and different branches retain physical policy data without claiming effective applicability' {
    foreach($build in @('22000','22621','22631','26100','26200','28000')){
        $f.Sources[0].Data.Version='10.0.'+$build;$f.Sources[0].Data.BuildNumber=$build;$f.Sources[0].Data.OperatingSystemSKU=[uint32]101
        $f.Sources[1].Data.CurrentBuildNumber.Value=$build;$s=(New-WinSecWindowsUpdateFixturePackage $f).Snapshot
        Assert-UpdateCandidate ($s.Platform.BuildNumber -eq [uint32]$build -and $s.Platform.OperatingSystemSKU -eq 101 -and $s.Collection.NotApplicable -eq 0 -and
            (Get-WinSecWindowsUpdateFixtureReadings $s GPOAU.AUOptions)[0].State -ceq 'NOT_CONFIGURED')
    }
}
Test-UpdateCandidate 'Private URLs installer identities and calculated getters are never read into output' {
    $script:getters=0;$f.Sources[3].Data|Add-Member ScriptProperty WUServer {$script:getters++;'PRIVATE-SECRET'}
    $f.Sources[5].Data|Add-Member ScriptProperty RebootRequired {$script:getters++;'PRIVATE-SECRET'} -Force
    $f.Sources[6].Data[0]|Add-Member NoteProperty InstalledBy 'PRIVATE-SECRET';$f.Sources[6].Data[0]|Add-Member NoteProperty FixComments 'PRIVATE-SECRET'
    $s=(New-WinSecWindowsUpdateFixturePackage $f).Snapshot
    Assert-UpdateCandidate ($script:getters -eq 0 -and (ConvertTo-Json $s -Depth 16 -Compress) -notmatch 'PRIVATE-SECRET|"WUServer"|InstalledBy|FixComments' -and $s.Collection.Status -ceq 'PARTIAL')
}
Test-UpdateCandidate 'QFE normalization progress supports cancellation without mutating captures' {
    $f=New-WinSecWindowsUpdateTechnicalFixture 20;$script:rows=0;$before=ConvertTo-Json $f -Depth 10 -Compress;$cancelled=$false
    try{$null=New-WinSecWindowsUpdateFixturePackage $f -ProgressCallback {param($e);if($e.InventoryId -ceq 'InstalledCBSUpdates'){$script:rows=$e.RetainedRecords}} -CancellationAction {$script:rows -ge 7}}
    catch [OperationCanceledException]{$cancelled=$true}
    Assert-UpdateCandidate ($cancelled -and $script:rows -eq 7 -and (ConvertTo-Json $f -Depth 10 -Compress) -ceq $before)
}
foreach($damage in @('date','scope','collector','ubr','value','source-state')){Test-UpdateCandidate ('Semantic validation rejects forged stored data: '+$damage) {
    $s=(New-WinSecWindowsUpdateFixturePackage $f).Snapshot
    switch($damage){date {(Get-WinSecWindowsUpdateFixtureReadings $s Capture.RebootAtUTC)[0].Value='2026-10-29T01:02:04.0000000Z'}
        scope {(Get-WinSecWindowsUpdateFixtureReadings $s Capture.InstalledInventoryScope)[0].Value='ALL_UPDATES'}
        collector {$s.CollectorVersion='9.0.0'};ubr {$s.Platform.UBR=[uint32]999}
        value {(Get-WinSecWindowsUpdateFixtureReadings $s Services.StartMode)[0].Value='PRIVATE-SECRET'}
        source-state {(Get-WinSecWindowsUpdateFixtureReadings $s Capture.RebootState)[0].Value='ERROR'}
    };Reject-UpdateCandidate {Assert-WinSecWindowsUpdateTechnicalSnapshot $s $f.Identity}
}}
Write-Host ("Windows Update technical candidate: $passed passed; $failed failed.");if($failed){exit 1}
