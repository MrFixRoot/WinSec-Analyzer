# In-memory coordinator reads only; synthetic sessions, no audits or storage.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
$script:passed=0; $script:failed=0
function Assert-WinSecSessionRead {param([bool]$Value) if(-not $Value){throw 'Session read assertion failed.'}}
function Assert-WinSecSessionReadRejected {
    param([scriptblock]$Action)
    $caught=$false
    try{$null=& $Action}catch{$caught=$true;Assert-WinSecSessionRead ($_.Exception.Message -notmatch 'READ_PRIVATE_MARKER')}
    Assert-WinSecSessionRead $caught
}
function Test-WinSecSessionRead {
    param([string]$Name,[scriptblock]$Action)
    $script:coordinator=[pscustomobject]@{Component='ScanCoordinator';SchemaVersion='1.0.0';ProjectRoot=$root;
        Registry=[pscustomobject]@{schemaVersion='1.0.0';targets=@()};Sessions=@{};
        ParallelExecution=$false;RemoteExecution=$false;AutomaticEvidencePersistence=$false;ScoringEnabled=$false}
    foreach($pair in @(@('local:READ-A','scan-1'),@('local:READ-A','scan-2'),@('local:READ-B','scan-1'))) {
        $control=[pscustomobject]@{DeviceId=$pair[0];ScanId=$pair[1];CheckId='WSA-SYS-001';
            SectionKey='SystemSecurity';Status='INFORMATIONAL';Evidence=@{Nested=@{Value='READ_PRIVATE_MARKER'};Bytes=[byte[]]@(1,2)}}
        $session=New-WinSecResultSession -DeviceId $pair[0] -ScanId $pair[1] -ControlResults @($control) `
            -ExpectedCheckIds @('WSA-SYS-001') -ScopeType SECTION -ScopeKey SystemSecurity -ExecutionStatus COMPLETED `
            -StartedAtUTC '2026-10-20T00:00:00Z' -CompletedAtUTC '2026-10-20T00:01:00Z'
        $script:coordinator.Sessions[(Get-WinSecScanSessionKey $pair[0] $pair[1])]=[pscustomobject]@{
            DeviceId=$pair[0];ScanId=$pair[1];Session=$session;EvidenceStorage=[pscustomobject]@{
                DeviceId=$pair[0];ScanId=$pair[1];Status='NOT_REQUESTED';StoredCount=0;FailedCount=0;SkippedCount=0;Failures=@()}}
    }
    try{$null=& $Action;$script:passed++;Write-Host "[PASS] $Name"}
    catch{$script:failed++;Write-Host "[FAIL] $Name : $($_.Exception.Message)"}
}
function Get-WinSecSessionReadFixture {
    Get-WinSecCoordinatorSession -Coordinator $script:coordinator -DeviceId 'local:READ-A' -ScanId 'scan-1'
}
Test-WinSecSessionRead 'Every internal read returns a fresh independent snapshot' {
    $first=Get-WinSecSessionReadFixture;$second=Get-WinSecSessionReadFixture
    $stored=$script:coordinator.Sessions['local:READ-A|scan-1'].Session
    Assert-WinSecSessionRead (-not [object]::ReferenceEquals($first,$stored) -and -not [object]::ReferenceEquals($first,$second) -and
        -not [object]::ReferenceEquals($first.ControlResults[0].Evidence,$stored.ControlResults[0].Evidence))
    Assert-WinSecSessionRead ((Test-WinSecResultSession $first) -and $first.ScopeType -ceq 'SECTION' -and $first.ScopeKey -ceq 'SystemSecurity')
}
Test-WinSecSessionRead 'Changing returned identities scope arrays and evidence leaves all stored sessions intact' {
    $before=ConvertTo-Json -InputObject $script:coordinator.Sessions -Depth 30 -Compress
    $copy=Get-WinSecSessionReadFixture
    $copy.DeviceId='local:OTHER';$copy.ScanId='changed';$copy.ScopeKey='NetworkSecurity'
    $copy.ExpectedCheckIds[0]='WSA-NET-001';$copy.ControlResults[0].Evidence.Nested.Value='changed';$copy.ControlResults[0].Evidence.Bytes[0]=99
    $copy.ControlResults=@();$copy.Findings=@()
    Assert-WinSecSessionRead ($before -ceq (ConvertTo-Json -InputObject $script:coordinator.Sessions -Depth 30 -Compress))
}
Test-WinSecSessionRead 'Internal read mutation cannot change subsequent public projection or history' {
    $public=Get-WinSecCoordinatorPublicResult $script:coordinator 'local:READ-A' 'scan-1'
    $before=ConvertTo-Json -InputObject $public -Depth 15 -Compress
    $historyBefore=ConvertTo-Json -InputObject @(Get-WinSecCoordinatorHistory $script:coordinator) -Depth 15 -Compress
    $copy=Get-WinSecSessionReadFixture
    $copy.ExecutionStatus='FAILED';$copy.ControlResults[0].Status='ERROR'
    Assert-WinSecSessionRead ($before -ceq (ConvertTo-Json -InputObject (Get-WinSecCoordinatorPublicResult $script:coordinator 'local:READ-A' 'scan-1') -Depth 15 -Compress))
    Assert-WinSecSessionRead ($historyBefore -ceq (ConvertTo-Json -InputObject @(Get-WinSecCoordinatorHistory $script:coordinator) -Depth 15 -Compress))
}
Test-WinSecSessionRead 'Public and history response rows cannot change stored metadata' {
    $before=ConvertTo-Json -InputObject $script:coordinator.Sessions -Depth 30 -Compress
    $public=Get-WinSecCoordinatorPublicResult $script:coordinator 'local:READ-A' 'scan-1'
    $history=@(Get-WinSecCoordinatorHistory $script:coordinator)
    $public.ControlResults[0].Status='UNKNOWN';$public.ScopeKey='NetworkSecurity';$history[0].ExecutionStatus='FAILED'
    Assert-WinSecSessionRead ($before -ceq (ConvertTo-Json -InputObject $script:coordinator.Sessions -Depth 30 -Compress))
    Assert-WinSecSessionRead ((ConvertTo-Json -InputObject $public -Depth 15) -notmatch 'READ_PRIVATE_MARKER|"Evidence"')
}
Test-WinSecSessionRead 'Missing sessions still return null without changing the store' {
    Assert-WinSecSessionRead ($null -eq (Get-WinSecCoordinatorSession $script:coordinator 'local:READ-A' 'missing'))
    Assert-WinSecSessionRead ($null -eq (Get-WinSecCoordinatorPublicResult $script:coordinator 'local:READ-A' 'missing'))
    Assert-WinSecSessionRead ($script:coordinator.Sessions.Count -eq 3)
}
Test-WinSecSessionRead 'Case-insensitive device lookup preserves canonical recorded identity' {
    $copy=Get-WinSecCoordinatorSession $script:coordinator 'LOCAL:read-a' 'scan-1'
    Assert-WinSecSessionRead ($copy.DeviceId -ceq 'local:READ-A')
}
Test-WinSecSessionRead 'Scan identity is exact even if the hashtable finds a case variant' {
    Assert-WinSecSessionReadRejected {Get-WinSecCoordinatorSession $script:coordinator 'local:READ-A' 'SCAN-1'}
}
foreach($mutation in @('FOREIGN_DEVICE','FOREIGN_SCAN','ENTRY_DEVICE','ENTRY_SCAN','INVALID_MODEL')) {
    Test-WinSecSessionRead ('A valid lookup key cannot publish inconsistent session ownership: '+$mutation) {
        $entry=$script:coordinator.Sessions['local:READ-A|scan-1']
        switch($mutation){
            'FOREIGN_DEVICE'{$entry.Session=$script:coordinator.Sessions['local:READ-B|scan-1'].Session}
            'FOREIGN_SCAN'{$entry.Session=$script:coordinator.Sessions['local:READ-A|scan-2'].Session}
            'ENTRY_DEVICE'{$entry.DeviceId='local:READ-B'}
            'ENTRY_SCAN'{$entry.ScanId='scan-2'}
            'INVALID_MODEL'{$entry.Session.ScanId='different-scan'}
        }
        Assert-WinSecSessionReadRejected {Get-WinSecSessionReadFixture}
        Assert-WinSecSessionReadRejected {Get-WinSecCoordinatorPublicResult $script:coordinator 'local:READ-A' 'scan-1'}
        Assert-WinSecSessionRead ($script:coordinator.Sessions.Count -eq 3)
    }
}
foreach($kind in @('CYCLIC','UNSUPPORTED','OVERSIZED','GETTER')) {
    Test-WinSecSessionRead ('Unsafe stored data rejects without returning a live reference: '+$kind) {
        $stored=$script:coordinator.Sessions['local:READ-A|scan-1'].Session
        $script:getterCalls=0
        switch($kind){
            'CYCLIC'{$value=@{};$value['Next']=$value}
            'UNSUPPORTED'{$value=New-Object System.Text.StringBuilder 'READ_PRIVATE_MARKER'}
            'OVERSIZED'{$value=New-Object 'object[]' 10001}
            'GETTER'{$value=[pscustomobject]@{Safe='data'};$value | Add-Member -MemberType ScriptProperty -Name Calculated -Value {$script:getterCalls++;'READ_PRIVATE_MARKER'}}
        }
        $stored.ControlResults[0].Evidence=$value
        Assert-WinSecSessionReadRejected {Get-WinSecSessionReadFixture}
        Assert-WinSecSessionRead ($script:getterCalls -eq 0 -and [object]::ReferenceEquals($stored,$script:coordinator.Sessions['local:READ-A|scan-1'].Session))
    }
}
Write-Host "Passed: $script:passed; Failed: $script:failed"
if($script:failed -gt 0){throw 'Coordinator session snapshot tests failed.'}
