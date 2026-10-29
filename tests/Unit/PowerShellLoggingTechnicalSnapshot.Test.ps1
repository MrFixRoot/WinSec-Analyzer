[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Checks/System/PowerShellLoggingTechnicalSnapshot.ps1')
. (Join-Path $root 'tests/Fixtures/PowerShellLoggingTechnicalMemory.ps1')
function Get-CimInstance {throw 'Native query forbidden.'}
function Get-ItemProperty {throw 'Native Registry query forbidden.'}
function Get-WinEvent {throw 'Event contents forbidden.'}
function Get-EventLog {throw 'Event contents forbidden.'}
function Get-History {throw 'User commands forbidden.'}
$passed=0;$failed=0
function Assert-LoggingCandidate {param([bool]$Value);if(-not $Value){throw 'PowerShell Logging candidate assertion failed.'}}
function Reject-LoggingCandidate {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-LoggingCandidate $caught}
function Test-LoggingCandidate {param($CaseName,[scriptblock]$Action);$f=New-WinSecPowerShellLoggingCandidateFixture;try{& $Action;$script:passed++;Write-Host ('[PASS] '+$CaseName)}catch{$script:failed++;Write-Host ('[FAIL] '+$CaseName+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}

Test-LoggingCandidate 'Five inventories preserve eighteen native definitions and explicit limited coverage' {
    $p=New-WinSecPowerShellLoggingFixturePackage $f;$d=@(Get-WinSecPowerShellLoggingCandidateFields)
    Assert-LoggingCandidate ($p.Catalog.Fields.Count -eq 42 -and $p.Catalog.Inventories.Count -eq 5 -and @($d|Where-Object Derived -EQ $false).Count -eq 18 -and
        $p.Snapshot.Collection.Status -ceq 'COMPLETE' -and $p.Snapshot.Collection.Coverage -ceq 'LIMITED' -and $p.Snapshot.Collection.Observed -eq 39 -and $p.Snapshot.Collection.NotCollected -eq 3)
}
Test-LoggingCandidate 'Engine families and fallback settings keep separate reviewed registry locations' {
    $defs=@(Get-WinSecPowerShellLoggingCandidateFields);$core=@($defs|Where-Object {$_.Inventory -ceq 'Core' -and $_.Property -match 'Fallback$'})
    Assert-LoggingCandidate ($core.Count -eq 3 -and @($core|Where-Object ValueName -CNE UseWindowsPowerShellPolicySetting).Count -eq 0 -and
        ($defs|Where-Object Id -CEQ WinPS.EnableScriptBlockLogging).Key -ceq 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -and
        ($defs|Where-Object Id -CEQ Core.EnableScriptBlockLogging).Key -ceq 'SOFTWARE\Policies\Microsoft\PowerShellCore\ScriptBlockLogging')
}
Test-LoggingCandidate 'Conflicting family values are retained without synthesizing effective policy' {
    $f.Sources[1].Data.EnableScriptBlockLogging.Value=[uint32]0;$s=(New-WinSecPowerShellLoggingFixturePackage $f).Snapshot
    Assert-LoggingCandidate ((Get-WinSecPowerShellLoggingFixtureReadings $s WinPS.EnableScriptBlockLogging)[0].Value -eq 0 -and
        (Get-WinSecPowerShellLoggingFixtureReadings $s Core.EnableScriptBlockLogging)[0].Value -eq 1 -and $s.Collection.Status -ceq 'COMPLETE' -and
        (Get-WinSecPowerShellLoggingFixtureReadings $s Capture.EffectivePolicy)[0].Value -ceq 'NOT_RESOLVED')
}
foreach($definition in @(Get-WinSecPowerShellLoggingCandidateFields|Where-Object Kind -CEQ RegistryFlag)){Test-LoggingCandidate ('Explicit absence is not Disabled and retains its physical policy scope: '+$definition.Id) {
    $source=@($f.Sources|Where-Object SourceId -CEQ $definition.Inventory)[0]
    $source.Data.($definition.Property)=[pscustomobject]@{State='NOT_CONFIGURED';Kind=$null;Value=$null}
    $s=(New-WinSecPowerShellLoggingFixturePackage $f).Snapshot;$r=(Get-WinSecPowerShellLoggingFixtureReadings $s $definition.Id)[0]
    Assert-LoggingCandidate ($r.State -ceq 'NOT_CONFIGURED' -and $r.Reason -ceq 'ABSENT' -and $null -eq $r.Value -and $s.Collection.Status -ceq 'COMPLETE' -and $s.Collection.NotConfigured -eq 1)
}}
foreach($damage in @('missing','null','bool','string','float','negative','qword')){Test-LoggingCandidate ('Missing or invalid flag remains unknown without coercion or default: '+$damage) {
    switch($damage){missing {$f.Sources[1].Data.PSObject.Properties.Remove('EnableModuleLogging')};null {$f.Sources[1].Data.EnableModuleLogging.Value=$null}
        bool {$f.Sources[1].Data.EnableModuleLogging.Value=$false};string {$f.Sources[1].Data.EnableModuleLogging.Value='1'};float {$f.Sources[1].Data.EnableModuleLogging.Value=1.5}
        negative {$f.Sources[1].Data.EnableModuleLogging.Value=-1};qword {$f.Sources[1].Data.EnableModuleLogging.Kind='QWord'}}
    $s=(New-WinSecPowerShellLoggingFixturePackage $f).Snapshot
    Assert-LoggingCandidate ($s.Collection.Status -ceq 'PARTIAL' -and (Get-WinSecPowerShellLoggingFixtureReadings $s WinPS.EnableModuleLogging)[0].State -ceq 'UNKNOWN')
}}
foreach($code in @(2,[uint32]4294967295)){Test-LoggingCandidate 'Unrecognized DWORD flag retains its code with partial status rather than becoming enabled' {
    $f.Sources[2].Data.ModulePolicyFallback.Value=$code;$s=(New-WinSecPowerShellLoggingFixturePackage $f).Snapshot
    Assert-LoggingCandidate ((Get-WinSecPowerShellLoggingFixtureReadings $s Core.ModulePolicyFallback)[0].Value -eq $code -and $s.Collection.Status -ceq 'PARTIAL' -and
        ($s.Inventories|Where-Object Id -CEQ Core).Reason -ceq 'INVALID_VALUE')
}}
foreach($idx in @(0,1,2,3)){foreach($state in @('ERROR','NOT_COLLECTED')){Test-LoggingCandidate ('Failed sources keep unknown counts without inferred absent engines: '+$idx+'/'+$state) {
    $f.Sources[$idx].State=$state;$f.Sources[$idx].Data=$null;$s=(New-WinSecPowerShellLoggingFixturePackage $f).Snapshot;$id=$f.Sources[$idx].SourceId
    Assert-LoggingCandidate ($s.Collection.Status -ceq 'PARTIAL' -and $null -eq ($s.Inventories|Where-Object Id -CEQ $id).ReportedRecords -and
        (Get-WinSecPowerShellLoggingFixtureReadings $s ('Capture.'+$id+'SourceState'))[0].Value -ceq $state)
}}}
foreach($state in @('UNKNOWN','ERROR','NOT_COLLECTED')){Test-LoggingCandidate ('Per-value unavailable state differs from explicit policy absence: '+$state) {
    $f.Sources[1].Data.EnableTranscripting=[pscustomobject]@{State=$state;Kind=$null;Value=$null};$s=(New-WinSecPowerShellLoggingFixturePackage $f).Snapshot
    Assert-LoggingCandidate ($s.Collection.Status -ceq 'PARTIAL' -and (Get-WinSecPowerShellLoggingFixtureReadings $s WinPS.EnableTranscripting)[0].State -ceq $state)
}}
Test-LoggingCandidate 'Private or unreviewed provider extras and getters never reach the snapshot' {
    $d=$f.Sources[2].Data;$d.PSObject.Properties.Remove('EnableTranscripting');$d|Add-Member ScriptProperty EnableTranscripting {throw 'GETTER EXECUTED'}
    foreach($key in @('OutputDirectory','ModuleNames','EncryptionCertificate','EventContents','CommandLine','UserName','Password','Token')){$d|Add-Member NoteProperty $key 'PRIVATE-SECRET'}
    $s=(New-WinSecPowerShellLoggingFixturePackage $f).Snapshot
    Assert-LoggingCandidate ((Get-WinSecPowerShellLoggingFixtureReadings $s Core.EnableTranscripting)[0].State -ceq 'UNKNOWN' -and
        (ConvertTo-Json $s -Depth 16 -Compress) -notmatch 'PRIVATE-SECRET|GETTER EXECUTED|CommandLine|UserName')
}
Test-LoggingCandidate 'Uncollected targets destinations and certificates stay explicit without validating actual logging' {
    $s=(New-WinSecPowerShellLoggingFixturePackage $f).Snapshot
    foreach($key in @('ModuleTargets','TranscriptDestination','EncryptionCertificate')){Assert-LoggingCandidate ((Get-WinSecPowerShellLoggingFixtureReadings $s ('Capture.'+$key))[0].State -ceq 'NOT_COLLECTED')}
    Assert-LoggingCandidate ((Get-WinSecPowerShellLoggingFixtureReadings $s Capture.ContentAccess)[0].Value -ceq 'NOT_PERFORMED' -and
        (Get-WinSecPowerShellLoggingFixtureReadings $s Capture.RuntimeInstallations)[0].Value -ceq 'NOT_SURVEYED')
}
Test-LoggingCandidate 'Cancellation on inventory progress returns no snapshot or caller mutations' {
    $before=ConvertTo-Json $f -Depth 12 -Compress;$script:cancelLogging=$false;$caught=$false
    try{$null=New-WinSecPowerShellLoggingFixturePackage $f -CancellationAction {$script:cancelLogging} -ProgressCallback {param($e);if($e.InventoryId -ceq 'Core'){$script:cancelLogging=$true}}}catch [OperationCanceledException]{$caught=$true}
    Assert-LoggingCandidate ($caught -and (ConvertTo-Json $f -Depth 12 -Compress) -ceq $before)
}
foreach($damage in @('device','scan','scope','control','source','location','time','duplicate','remote','array','state','absence-value','absence-kind','entry-getter','entry-extra')){Test-LoggingCandidate ('Foreign unsafe or unverified logging receipt rejected: '+$damage) {
    switch($damage){device {$f.Sources[1].DeviceId='local:hw1-'+('c'*64)};scan {$f.Sources[1].ScanId='other'};scope {$f.Identity.ScopeKey='WSA-LOG-002'}
        control {$f.Identity.CheckId='WSA-LOG-002';$f.Identity.ScopeKey='WSA-LOG-002'};source {$f.Sources[1].SourceId='OTHER'};location {$f.Sources[1].Location='HKCU_REGISTRY64_WINPS'}
        time {$f.Sources[1].CollectedAtUTC='2026-10-29T00:00:00.0000000Z'};duplicate {$f.Sources[1]=$f.Sources[0]};remote {$f.Sources[1]|Add-Member NoteProperty ComputerName 'REMOTE'}
        array {$f.Sources[1].Data=@($f.Sources[1].Data)};state {$f.Sources[1].Data.EnableModuleLogging.State='NOT_APPLICABLE'}
        absence-value {$f.Sources[1].Data.EnableModuleLogging.State='NOT_CONFIGURED';$f.Sources[1].Data.EnableModuleLogging.Kind=$null}
        absence-kind {$f.Sources[1].Data.EnableModuleLogging.State='NOT_CONFIGURED';$f.Sources[1].Data.EnableModuleLogging.Value=$null}
        entry-getter {$e=$f.Sources[1].Data.EnableModuleLogging;$e.PSObject.Properties.Remove('Value');$e|Add-Member ScriptProperty Value {throw 'GETTER EXECUTED'}}
        entry-extra {$f.Sources[1].Data.EnableModuleLogging|Add-Member NoteProperty CommandLine 'PRIVATE-SECRET'}}
    Reject-LoggingCandidate {New-WinSecPowerShellLoggingFixturePackage $f}
}}
foreach($damage in @('platform','source','scope','authority','effective','runtime','collector','location','date','value','absence','details')){Test-LoggingCandidate ('Stored logging semantic forgery rejected: '+$damage) {
    $s=(New-WinSecPowerShellLoggingFixturePackage $f).Snapshot
    switch($damage){platform {$s.Platform.BuildNumber=[uint32]22631};source {(Get-WinSecPowerShellLoggingFixtureReadings $s Capture.WinPSSourceState)[0].Value='ERROR'}
        scope {(Get-WinSecPowerShellLoggingFixtureReadings $s Capture.Scope)[0].Value='CURRENT_USER'};authority {(Get-WinSecPowerShellLoggingFixtureReadings $s Capture.PolicyAuthority)[0].Value='DOMAIN'}
        effective {(Get-WinSecPowerShellLoggingFixtureReadings $s Capture.EffectivePolicy)[0].Value='NOT_OBSERVED'};runtime {(Get-WinSecPowerShellLoggingFixtureReadings $s Capture.RuntimeInstallations)[0].Value='NOT_PERFORMED'}
        collector {$s.CollectorVersion='9.0.0'};location {(Get-WinSecPowerShellLoggingFixtureReadings $s Capture.WinPSLocation)[0].Value='HKLM_REGISTRY64_CORE'}
        date {(Get-WinSecPowerShellLoggingFixtureReadings $s Capture.CoreTime)[0].Value='2026-10-28T01:02:04.0000000Z'};value {(Get-WinSecPowerShellLoggingFixtureReadings $s Core.EnableModuleLogging)[0].Value=$true}
        absence {$r=(Get-WinSecPowerShellLoggingFixtureReadings $s Platform.Version)[0];$r.State='NOT_CONFIGURED';$r.Reason='ABSENT';$r.Value=$null;$s.Collection.Observed--;$s.Collection.NotConfigured++}
        details {$r=(Get-WinSecPowerShellLoggingFixtureReadings $s Capture.TranscriptDestination)[0];$r.State='OBSERVED';$r.Reason='NONE';$r.Value='PRIVATE-SECRET';$s.Collection.NotCollected--;$s.Collection.Observed++}}
    Reject-LoggingCandidate {Assert-WinSecPowerShellLoggingCandidateSnapshot $s $f.Identity}
}}
Write-Host ("PowerShell Logging technical candidate: $passed passed; $failed failed.");if($failed){exit 1}
