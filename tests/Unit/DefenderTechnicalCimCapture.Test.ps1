# Only client-side CIM carriers and synthetic source receipts; no Windows queries.
[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Checks/Defender/DefenderTechnicalSnapshot.ps1')
. (Join-Path $root 'tests/Fixtures/DefenderTechnicalMemory.ps1')
function Get-MpComputerStatus {throw 'Native audit forbidden.'}
function Get-MpPreference {throw 'Native audit forbidden.'}
function Get-CimInstance {throw 'Native audit forbidden.'}
function Get-CimClass {throw 'Native audit forbidden.'}
$passed=0;$failed=0
function Assert-CimCapture {param([bool]$Value);if(-not $Value){throw 'CIM capture assertion failed.'}}
function Reject-CimCapture {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-CimCapture $caught}
function Test-CimCapture {
    param([string]$Name,[scriptblock]$Action)
    $f=ConvertTo-WinSecDefenderCimFixture (New-WinSecDefenderTechnicalFixture)
    try{& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}
    catch{$script:failed++;Write-Host ('[FAIL] '+$Name+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}
    finally{Close-WinSecDefenderCimFixture $f}
}
Test-CimCapture 'Typed CIM carriers preserve the ordinary normalized package exactly' {
    $plain=New-WinSecDefenderTechnicalFixture
    $plain.Sources[2].Data.AttackSurfaceReductionRules_Ids=[string[]]$f.Sources[2].Data.CimInstanceProperties['AttackSurfaceReductionRules_Ids'].Value
    $a=New-WinSecDefenderFixturePackage $plain;$b=New-WinSecDefenderFixturePackage $f
    Assert-CimCapture ((ConvertTo-Json -InputObject $a -Depth 20 -Compress) -ceq (ConvertTo-Json -InputObject $b -Depth 20 -Compress))
    Assert-CimCapture ($b.Snapshot.CollectorVersion -ceq '1.2.0' -and $b.Snapshot.Collection.Status -ceq 'COMPLETE')
}
Test-CimCapture 'Only reviewed values enter normalized JSON, never CIM metadata or private properties' {
    $f.Sources[1].Data.CimInstanceProperties.Add([Microsoft.Management.Infrastructure.CimProperty]::Create('ComputerID','PRIVATE-SECRET',[Microsoft.Management.Infrastructure.CimFlags]::None))
    $json=ConvertTo-Json -InputObject (New-WinSecDefenderFixturePackage $f) -Depth 20 -Compress
    Assert-CimCapture ($json -notmatch 'PRIVATE-|ComputerID|CimInstanceProperties|CimSystemProperties|PSComputerName')
}
Test-CimCapture 'ETS getters cannot replace CIM fields, the collection or system metadata' {
    $script:executed=0
    foreach($name in @('AntivirusEnabled','CimInstanceProperties','CimSystemProperties')){
        $f.Sources[1].Data|Add-Member -MemberType ScriptProperty -Name $name -Value {$script:executed++;throw 'PRIVATE-SECRET'} -Force
    }
    $s=(New-WinSecDefenderFixturePackage $f).Snapshot
    Assert-CimCapture ($script:executed -eq 0 -and (Get-WinSecDefenderFixtureReading $s Status.AntivirusEnabled).Value -ceq $false)
}
foreach($area in @('Platform','Status','Preferences')){
    foreach($damage in @('class','namespace')){Test-CimCapture ('Foreign CIM metadata is rejected: '+$area+'/'+$damage) {
        $source=@($f.Sources|Where-Object SourceId -CEQ $area)[0];$source.Data.Dispose()
        $class=switch($area){Platform {'Win32_OperatingSystem'};Status {'MSFT_MpComputerStatus'};Preferences {'MSFT_MpPreference'}}
        $ns=if($area -ceq 'Platform'){'root/cimv2'}else{'root/Microsoft/Windows/Defender'}
        if($damage -ceq 'class'){$class='Win32_Process'}else{$ns='root/Foreign'}
        $source.Data=[Microsoft.Management.Infrastructure.CimInstance]::new($class,$ns)
        $message=$null;try{$null=New-WinSecDefenderFixturePackage $f}catch{$message=$_.Exception.Message}
        Assert-CimCapture ($message -ceq 'Invalid Defender captured CIM source.')
    }}
}
Test-CimCapture 'CIM namespace case and slash spelling do not fabricate a platform version' {
    $f.Sources[0].Data.Dispose();$f.Sources[0].Data=[Microsoft.Management.Infrastructure.CimInstance]::new('win32_operatingsystem','ROOT\CIMV2')
    $s=(New-WinSecDefenderFixturePackage $f).Snapshot
    Assert-CimCapture ($s.Collection.Status -ceq 'PARTIAL' -and $null -eq $s.Platform.BuildNumber)
}
Test-CimCapture 'Missing required CIM telemetry remains UNKNOWN and partial' {
    Set-WinSecDefenderCimFixtureProperty $f.Sources[1] AntivirusEnabled -Remove
    $s=(New-WinSecDefenderFixturePackage $f).Snapshot
    Assert-CimCapture ((Get-WinSecDefenderFixtureReading $s Status.AntivirusEnabled).State -ceq 'UNKNOWN' -and $s.Collection.Status -ceq 'PARTIAL')
}
Test-CimCapture 'Incorrect native scalar types remain INVALID_VALUE without Boolean coercion' {
    Set-WinSecDefenderCimFixtureProperty $f.Sources[1] AntivirusEnabled ([uint32]0) UInt32
    $r=Get-WinSecDefenderFixtureReading (New-WinSecDefenderFixturePackage $f).Snapshot Status.AntivirusEnabled
    Assert-CimCapture ($r.State -ceq 'UNKNOWN' -and $r.Reason -ceq 'INVALID_VALUE' -and $null -eq $r.Value)
}
Test-CimCapture 'CIM null ASR arrays retain unknown inventory without an invented empty configuration' {
    $f.Sources[2].Data.CimInstanceProperties['AttackSurfaceReductionRules_Ids'].Value=$null
    $f.Sources[2].Data.CimInstanceProperties['AttackSurfaceReductionRules_Actions'].Value=$null
    $s=(New-WinSecDefenderFixturePackage $f).Snapshot;$asr=@($s.Inventories|Where-Object Id -CEQ ASR)[0]
    Assert-CimCapture ($s.Collection.Status -ceq 'PARTIAL' -and $asr.State -ceq 'UNKNOWN' -and $null -eq $asr.ReportedRecords)
}
Test-CimCapture 'Explicit empty CIM ASR arrays retain a verified empty inventory' {
    $f.Sources[2].Data.CimInstanceProperties['AttackSurfaceReductionRules_Ids'].Value=[string[]]@()
    $f.Sources[2].Data.CimInstanceProperties['AttackSurfaceReductionRules_Actions'].Value=[uint32[]]@()
    $s=(New-WinSecDefenderFixturePackage $f).Snapshot;$asr=@($s.Inventories|Where-Object Id -CEQ ASR)[0]
    Assert-CimCapture ($s.Collection.Status -ceq 'COMPLETE' -and $asr.Complete -and $asr.ReportedRecords -eq 0)
}
Test-CimCapture 'All 513 CIM ASR records are retained across bounded batches' {
    Close-WinSecDefenderCimFixture $f;$f=ConvertTo-WinSecDefenderCimFixture (New-WinSecDefenderTechnicalFixture 513)
    $s=(New-WinSecDefenderFixturePackage $f).Snapshot;$batches=@($s.Batches|Where-Object InventoryId -CEQ ASR)
    Assert-CimCapture ($batches.Count -eq 5 -and @($batches|ForEach-Object Records).Count -eq 513 -and $s.Collection.Status -ceq 'COMPLETE')
}
Test-CimCapture 'CIM false, zero and UInt32 maximum sentinel are preserved' {
    $s=(New-WinSecDefenderFixturePackage $f).Snapshot
    Assert-CimCapture ((Get-WinSecDefenderFixtureReading $s Status.AntivirusEnabled).Value -ceq $false -and
        (Get-WinSecDefenderFixtureReading $s Preferences.MAPSReporting).Value -eq 0 -and
        (Get-WinSecDefenderFixtureReading $s Status.AntivirusSignatureAgeDays).Value -eq [uint32]::MaxValue)
}
Test-CimCapture 'A disposed native carrier fails closed with no raw exception details' {
    $f.Sources[1].Data.Dispose();$message=$null
    try{$null=New-WinSecDefenderFixturePackage $f}catch{$message=$_.Exception.Message}
    Assert-CimCapture ($message -ceq 'Invalid Defender captured CIM source.')
}
foreach($damage in @('DeviceId','ScanId','CollectedAtUTC','State')){Test-CimCapture ('CIM carriers do not bypass receipt validation: '+$damage) {
    switch($damage){DeviceId {$f.Sources[1].DeviceId='local:hw1-'+('c'*64)};ScanId {$f.Sources[1].ScanId='foreign'}
        CollectedAtUTC {$f.Sources[1].CollectedAtUTC='2026-10-27T01:02:04.0000000Z'};State {$f.Sources[1].State='ERROR'}}
    Reject-CimCapture {New-WinSecDefenderFixturePackage $f}
}}
Test-CimCapture 'Cooperative cancellation stops before processing captured CIM values' {
    $cancelled=$false;try{$null=New-WinSecDefenderFixturePackage $f -CancellationAction {$true}}catch [OperationCanceledException]{$cancelled=$true}
    Assert-CimCapture $cancelled
}
Test-CimCapture 'Normalization detaches the persisted package from native object disposal and mutation' {
    $p=New-WinSecDefenderFixturePackage $f;$f.Sources[1].Data.CimInstanceProperties['AntivirusEnabled'].Value=$true
    Close-WinSecDefenderCimFixture $f
    Assert-WinSecDefenderTechnicalSnapshot $p.Snapshot $f.Identity
    Assert-CimCapture ((Get-WinSecDefenderFixtureReading $p.Snapshot Status.AntivirusEnabled).Value -ceq $false)
}
Test-CimCapture 'Candidate collector 1.0 remains readable and unknown collector versions are rejected' {
    $p=New-WinSecDefenderFixturePackage $f;$p.Snapshot.CollectorVersion='1.0.0';Assert-WinSecDefenderTechnicalSnapshot $p.Snapshot $f.Identity
    $p.Snapshot.CollectorVersion='9.0.0';Reject-CimCapture {Assert-WinSecDefenderTechnicalSnapshot $p.Snapshot $f.Identity}
}
Test-CimCapture 'Collector version validation rejects executable getters without invoking them' {
    $p=New-WinSecDefenderFixturePackage $f;$script:executed=0
    $p.Snapshot|Add-Member -MemberType ScriptProperty -Name CollectorVersion -Value {$script:executed++;'1.1.0'} -Force
    Reject-CimCapture {Assert-WinSecDefenderTechnicalSnapshot $p.Snapshot $f.Identity}
    Assert-CimCapture ($script:executed -eq 0)
}
Write-Host ("Defender CIM capture: $passed passed; $failed failed.");if($failed){exit 1}
