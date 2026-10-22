# Synthetic coordinator history only. No audits, storage or Pester.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
$script:passed=0; $script:failed=0
function Assert-WinSecHistory {param([bool]$Value) if(-not $Value){throw 'History assertion failed.'}}
function Assert-WinSecHistoryRejected {
    param([scriptblock]$Action)
    $received=New-Object 'System.Collections.Generic.List[object]'
    $caught=$false
    try{& $Action | ForEach-Object {$received.Add($_)}}catch{
        $caught=$true
        Assert-WinSecHistory ($_.Exception.Message -notmatch 'RAW_HISTORY_CANARY')
    }
    Assert-WinSecHistory ($caught -and $received.Count -eq 0)
}
function Test-WinSecHistory {
    param([string]$Name,[scriptblock]$Action)
    $script:coordinator=[pscustomobject]@{Component='ScanCoordinator';SchemaVersion='1.0.0';ProjectRoot=$root;
        Registry=[pscustomobject]@{schemaVersion='1.0.0';targets=@()};Sessions=@{};
        ParallelExecution=$false;RemoteExecution=$false;AutomaticEvidencePersistence=$false;ScoringEnabled=$false}
    foreach($device in @('local:HISTORY-A','local:HISTORY-B')) {
        $controls=@(foreach($number in @(1,2)){
            [pscustomobject]@{DeviceId=$device;ScanId='scan-1';CheckId=('WSA-SYS-00'+$number);SectionKey='SystemSecurity';
                Status='INFORMATIONAL';Evidence=@{Value='RAW_HISTORY_CANARY'}}
        })
        $session=New-WinSecResultSession -DeviceId $device -ScanId 'scan-1' -ControlResults $controls `
            -ExpectedCheckIds @('WSA-SYS-001','WSA-SYS-002') -ScopeType SECTION -ScopeKey SystemSecurity `
            -ExecutionStatus COMPLETED -StartedAtUTC '2026-10-20T00:00:00Z' -CompletedAtUTC '2026-10-20T00:01:00Z'
        $script:coordinator.Sessions[(Get-WinSecScanSessionKey $device 'scan-1')]=[pscustomobject]@{
            DeviceId=$device;ScanId='scan-1';Session=$session;RegisteredAtUTC='2026-10-20T00:01:00Z';
            EvidenceStorage=[pscustomobject]@{DeviceId=$device;ScanId='scan-1';Status='NOT_REQUESTED';
                StoredCount=0;FailedCount=0;SkippedCount=0;Failures=@()}}
    }
    $script:entry=$script:coordinator.Sessions['local:HISTORY-A|scan-1']
    try{$null=& $Action;$script:passed++;Write-Host "[PASS] $Name"}
    catch{$script:failed++;Write-Host "[FAIL] $Name : $($_.Exception.Message)"}
}
function Get-WinSecHistoryFixture {Get-WinSecCoordinatorHistory -Coordinator $script:coordinator -DeviceId 'local:HISTORY-A'}
Test-WinSecHistory 'Safe history preserves identity scope and NOT_SCORED without raw data' {
    $rows=@(Get-WinSecHistoryFixture)
    Assert-WinSecHistory ($rows.Count -eq 1 -and $rows[0].DeviceId -ceq 'local:HISTORY-A' -and
        $rows[0].ScopeType -ceq 'SECTION' -and $rows[0].ScopeKey -ceq 'SystemSecurity' -and
        $rows[0].OverallStatus -ceq 'NOT_SCORED' -and $null -eq $rows[0].OverallScore -and
        (ConvertTo-Json -InputObject $rows -Depth 15) -notmatch 'RAW_HISTORY_CANARY|"Evidence"|"Failures"')
}
Test-WinSecHistory 'Empty and unmatched histories remain empty' {
    Assert-WinSecHistory (@(Get-WinSecCoordinatorHistory $script:coordinator 'local:OTHER').Count -eq 0)
    $script:coordinator.Sessions.Clear()
    Assert-WinSecHistory (@(Get-WinSecCoordinatorHistory $script:coordinator).Count -eq 0)
}
Test-WinSecHistory 'Device filtering uses the key and does not read another device payload' {
    $script:getterCalls=0
    $other=$script:coordinator.Sessions['local:HISTORY-B|scan-1'].EvidenceStorage
    $other.PSObject.Properties.Remove('Status')
    $other | Add-Member -MemberType ScriptProperty -Name Status -Value {$script:getterCalls++;'RAW_HISTORY_CANARY'}
    $rows=@(Get-WinSecCoordinatorHistory $script:coordinator 'LOCAL:history-a')
    Assert-WinSecHistory ($rows.Count -eq 1 -and $rows[0].DeviceId -ceq 'local:HISTORY-A' -and $script:getterCalls -eq 0)
}
foreach($spec in @(
    @{Status='NOT_REQUESTED';Stored=0;Failed=0;Skipped=0},
    @{Status='NO_EVIDENCE';Stored=0;Failed=0;Skipped=2},
    @{Status='STORED';Stored=1;Failed=0;Skipped=1},
    @{Status='PARTIAL';Stored=1;Failed=1;Skipped=0},
    @{Status='FAILED';Stored=0;Failed=1;Skipped=1}
)) {
    Test-WinSecHistory ('Consistent synthetic evidence metadata is preserved: '+$spec.Status) {
        $storage=$script:entry.EvidenceStorage
        $storage.Status=$spec.Status;$storage.StoredCount=[long]$spec.Stored
        $storage.FailedCount=[long]$spec.Failed;$storage.SkippedCount=[long]$spec.Skipped
        $row=@(Get-WinSecHistoryFixture)[0]
        Assert-WinSecHistory ($row.EvidenceStorageStatus -ceq $spec.Status -and $row.StoredEvidenceCount -eq $spec.Stored -and
            $row.FailedEvidenceCount -eq $spec.Failed -and $row.StoredEvidenceCount -is [int])
    }
}
foreach($kind in @('ENTRY_DEVICE','ENTRY_SCAN','MODEL_DEVICE','MODEL_SCAN','STORAGE_DEVICE','STORAGE_SCAN','NULL_ENTRY','NULL_STORAGE')) {
    Test-WinSecHistory ('Inconsistent history ownership rejects before emitting rows: '+$kind) {
        switch($kind){
            'ENTRY_DEVICE'{$script:entry.DeviceId='local:HISTORY-B'}
            'ENTRY_SCAN'{$script:entry.ScanId='different-scan'}
            'MODEL_DEVICE'{$script:entry.Session=$script:coordinator.Sessions['local:HISTORY-B|scan-1'].Session}
            'MODEL_SCAN'{$script:entry.Session=New-WinSecResultSession -DeviceId 'local:HISTORY-A' -ScanId 'different-scan'}
            'STORAGE_DEVICE'{$script:entry.EvidenceStorage.DeviceId='local:HISTORY-B'}
            'STORAGE_SCAN'{$script:entry.EvidenceStorage.ScanId='different-scan'}
            'NULL_ENTRY'{$script:coordinator.Sessions['local:HISTORY-A|scan-1']=$null}
            'NULL_STORAGE'{$script:entry.EvidenceStorage=$null}
        }
        Assert-WinSecHistoryRejected {Get-WinSecHistoryFixture}
    }
}
foreach($change in @(
    @{Field='Status';Value=[pscustomobject]@{Evidence='RAW_HISTORY_CANARY'}},
    @{Field='Status';Value='stored'},@{Field='Status';Value='UNKNOWN'},@{Field='Status';Value=@('NOT_REQUESTED')},
    @{Field='StoredCount';Value=[pscustomobject]@{Evidence='RAW_HISTORY_CANARY'}},
    @{Field='StoredCount';Value='0'},@{Field='FailedCount';Value=$true},@{Field='SkippedCount';Value=1.0},
    @{Field='StoredCount';Value=-1},@{Field='FailedCount';Value=[double]::NaN},
    @{Field='StoredCount';Value=[uint64]::MaxValue}
)) {
    Test-WinSecHistory ('Unsafe evidence metadata rejects without coercion: '+$change.Field) {
        $script:entry.EvidenceStorage.($change.Field)=$change.Value
        Assert-WinSecHistoryRejected {Get-WinSecHistoryFixture}
    }
}
foreach($spec in @(
    @{Status='NOT_REQUESTED';Stored=1;Failed=0;Skipped=0},
    @{Status='NOT_REQUESTED';Stored=0;Failed=0;Skipped=1},
    @{Status='STORED';Stored=0;Failed=0;Skipped=2},
    @{Status='STORED';Stored=1;Failed=1;Skipped=0},
    @{Status='PARTIAL';Stored=1;Failed=0;Skipped=1},
    @{Status='FAILED';Stored=1;Failed=1;Skipped=0},
    @{Status='NO_EVIDENCE';Stored=1;Failed=0;Skipped=1},
    @{Status='NO_EVIDENCE';Stored=0;Failed=1;Skipped=1},
    @{Status='STORED';Stored=3;Failed=0;Skipped=0},
    @{Status='FAILED';Stored=0;Failed=1;Skipped=0}
)) {
    Test-WinSecHistory ('Contradictory storage state and counters reject: '+$spec.Status) {
        $storage=$script:entry.EvidenceStorage
        $storage.Status=$spec.Status;$storage.StoredCount=$spec.Stored
        $storage.FailedCount=$spec.Failed;$storage.SkippedCount=$spec.Skipped
        Assert-WinSecHistoryRejected {Get-WinSecHistoryFixture}
    }
}
foreach($key in @('Values',17,'local:HISTORY-A|scan-1|extra','../outside|scan-1')) {
    Test-WinSecHistory 'Invalid index keys cannot hide records or redirect ownership' {
        $script:coordinator.Sessions[$key]=@()
        Assert-WinSecHistoryRejected {Get-WinSecCoordinatorHistory $script:coordinator}
    }
}
Test-WinSecHistory 'A bad later entry cannot expose any partial history' {
    $script:coordinator.Sessions['local:HISTORY-B|scan-1'].EvidenceStorage.Status=[pscustomobject]@{Evidence='RAW_HISTORY_CANARY'}
    Assert-WinSecHistoryRejected {Get-WinSecCoordinatorHistory $script:coordinator}
}
Test-WinSecHistory 'Calculated storage fields reject without running getters' {
    $script:getterCalls=0
    $storage=$script:entry.EvidenceStorage
    $storage.PSObject.Properties.Remove('Status')
    $storage | Add-Member -MemberType ScriptProperty -Name Status -Value {$script:getterCalls++;'RAW_HISTORY_CANARY'}
    Assert-WinSecHistoryRejected {Get-WinSecHistoryFixture}
    Assert-WinSecHistory ($script:getterCalls -eq 0)
}
Test-WinSecHistory 'Whitespace is an invalid filter while explicit empty means all devices' {
    Assert-WinSecHistoryRejected {Get-WinSecCoordinatorHistory $script:coordinator ' '}
    Assert-WinSecHistory (@(Get-WinSecCoordinatorHistory $script:coordinator '').Count -eq 2)
}
Test-WinSecHistory 'Returned rows cannot mutate entries and private storage diagnostics stay internal' {
    $script:entry.EvidenceStorage.Failures=@([pscustomobject]@{Reason='RAW_HISTORY_CANARY'})
    $before=ConvertTo-Json -InputObject $script:coordinator.Sessions -Depth 30 -Compress
    $rows=@(Get-WinSecHistoryFixture)
    Assert-WinSecHistory ((ConvertTo-Json -InputObject $rows -Depth 15) -notmatch 'RAW_HISTORY_CANARY|"Failures"|"Reason"')
    $rows[0].DeviceId='local:CHANGED';$rows[0].StoredEvidenceCount=99
    Assert-WinSecHistory ($before -ceq (ConvertTo-Json -InputObject $script:coordinator.Sessions -Depth 30 -Compress))
}
Test-WinSecHistory 'Legacy sessions keep unknown scope without inventing scope fields' {
    $script:entry.Session.PSObject.Properties.Remove('ScopeType');$script:entry.Session.PSObject.Properties.Remove('ScopeKey')
    $row=@(Get-WinSecHistoryFixture)[0]
    Assert-WinSecHistory ($null -eq $row.PSObject.Properties['ScopeType'] -and $null -eq $row.PSObject.Properties['ScopeKey'])
}
Test-WinSecHistory 'Arrays cannot masquerade as a single entry or storage object' {
    $original=$script:entry.EvidenceStorage
    $script:entry.EvidenceStorage=@($original)
    Assert-WinSecHistoryRejected {Get-WinSecHistoryFixture}
    $script:entry.EvidenceStorage=$original
    $script:coordinator.Sessions['local:HISTORY-A|scan-1']=@($script:entry)
    Assert-WinSecHistoryRejected {Get-WinSecHistoryFixture}
}
Test-WinSecHistory 'Scan case mismatches in index keys reject without changing the store' {
    $script:coordinator.Sessions.Remove('local:HISTORY-A|scan-1')
    $script:coordinator.Sessions['local:HISTORY-A|SCAN-1']=$script:entry
    $before=ConvertTo-Json -InputObject $script:coordinator.Sessions -Depth 30 -Compress
    Assert-WinSecHistoryRejected {Get-WinSecHistoryFixture}
    Assert-WinSecHistory ($before -ceq (ConvertTo-Json -InputObject $script:coordinator.Sessions -Depth 30 -Compress))
}
Test-WinSecHistory 'Equal timestamps and scan identifiers use device identity as a stable tie breaker' {
    $rows=@(Get-WinSecCoordinatorHistory $script:coordinator)
    Assert-WinSecHistory ($rows.Count -eq 2 -and $rows[0].DeviceId -ceq 'local:HISTORY-A' -and $rows[1].DeviceId -ceq 'local:HISTORY-B')
}
Write-Host "Passed: $script:passed; Failed: $script:failed"
if($script:failed -gt 0){throw 'Coordinator history tests failed.'}
