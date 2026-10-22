# In-memory scope/history context only. No collectors, identity queries or writes.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
$script:passed=0;$script:failed=0
function Get-CimInstance {throw 'Unexpected Windows query.'}
function Invoke-WinSecAudit {throw 'Unexpected audit.'}
function Assert-WinSecAction {param([bool]$Condition);if(-not $Condition){throw 'Scan action assertion failed.'}}
function Test-WinSecAction {
    param([string]$Name,[scriptblock]$Action)
    $script:coordinator=[pscustomobject]@{Component='ScanCoordinator';SchemaVersion='1.0.0';ProjectRoot=$root;
        Registry=[pscustomobject]@{schemaVersion='1.0.0';targets=@()};Sessions=@{};
        ParallelExecution=$false;RemoteExecution=$false;AutomaticEvidencePersistence=$false;ScoringEnabled=$false}
    try{$null=& $Action;$script:passed++;Write-Host "[PASS] $Name"}
    catch{$script:failed++;Write-Host "[FAIL] $Name : $($_.Exception.Message)"}
}
function Add-WinSecActionFixture {
    param([string]$Device='local:ACTION',[string]$Type='DEVICE',[string]$Key='ALL',
        [string]$Status='COMPLETED',[string]$Id='previous',[switch]$Legacy)
    $scope=@{}
    if(-not $Legacy){$scope=@{ScopeType=$Type;ScopeKey=$Key}}
    $section='SystemSecurity';$check='WSA-SYS-001'
    if($Type -ceq 'SECTION'){$section=$Key}
    if($Type -ceq 'CONTROL'){$check=$Key}
    $controls=@();$expected=@();$end='2026-10-20T00:01:00Z'
    if($Status -cin @('COMPLETED','COMPLETED_WITH_ERRORS')){
        $controls=@([pscustomobject]@{DeviceId=$Device;ScanId=$Id;CheckId=$check;SectionKey=$section;
            Status='INFORMATIONAL';Evidence=@{Secret='ACTION-PRIVATE-CANARY'}})
        $expected=@($check)
    }
    if($Status -ceq 'PENDING'){$end=''}
    $session=New-WinSecResultSession -DeviceId $Device -ScanId $Id @scope -ExpectedCheckIds $expected `
        -ControlResults $controls -ExecutionStatus $Status -StartedAtUTC '2026-10-20T00:00:00Z' -CompletedAtUTC $end
    $script:coordinator.Sessions[(Get-WinSecScanSessionKey $Device $Id)]=[pscustomobject]@{
        DeviceId=$Device;ScanId=$Id;Session=$session;EvidenceStorage=[pscustomobject]@{
            DeviceId=$Device;ScanId=$Id;Status='NOT_REQUESTED';StoredCount=0;FailedCount=0;SkippedCount=0;Failures=@()}}
}
foreach($spec in @(@{T='DEVICE';K='ALL'},@{T='SECTION';K='SystemSecurity'},@{T='CONTROL';K='WSA-SYS-001'})){
    Test-WinSecAction ('Empty history means Scan: '+$spec.T) {
        Assert-WinSecAction ((Get-WinSecScanAction $script:coordinator 'local:ACTION' $spec.T $spec.K) -ceq 'Scan')
    }
    foreach($status in @('COMPLETED','COMPLETED_WITH_ERRORS')){
        Test-WinSecAction ('Matching finalized history means Rescan: '+$spec.T+'/'+$status) {
            Add-WinSecActionFixture -Type $spec.T -Key $spec.K -Status $status
            Assert-WinSecAction ((Get-WinSecScanAction $script:coordinator 'local:ACTION' $spec.T $spec.K) -ceq 'Rescan')
        }
    }
    foreach($status in @('PENDING','NO_EXECUTABLE_CHECKS','FAILED','CANCELLED')){
        Test-WinSecAction ('Nonfinal or unsuccessful history cannot cause Rescan: '+$spec.T+'/'+$status) {
            Add-WinSecActionFixture -Type $spec.T -Key $spec.K -Status $status
            Assert-WinSecAction ((Get-WinSecScanAction $script:coordinator 'local:ACTION' $spec.T $spec.K) -ceq 'Scan')
        }
    }
}
Test-WinSecAction 'Another device or another scope cannot cause Rescan' {
    Add-WinSecActionFixture -Device 'local:OTHER'
    Add-WinSecActionFixture -Type SECTION -Key SystemSecurity
    Assert-WinSecAction ((Get-WinSecScanAction $script:coordinator 'local:ACTION' DEVICE ALL) -ceq 'Scan')
    Assert-WinSecAction ((Get-WinSecScanAction $script:coordinator 'local:ACTION' SECTION NetworkSecurity) -ceq 'Scan')
    Assert-WinSecAction ((Get-WinSecScanAction $script:coordinator 'local:ACTION' CONTROL WSA-SYS-001) -ceq 'Scan')
}
Test-WinSecAction 'Another control or a whole-device scan does not complete a control scope' {
    Add-WinSecActionFixture -Type CONTROL -Key WSA-SYS-002
    Add-WinSecActionFixture -Id full
    Assert-WinSecAction ((Get-WinSecScanAction $script:coordinator 'local:ACTION' CONTROL WSA-SYS-001) -ceq 'Scan')
}
Test-WinSecAction 'Legacy unknown scope never authorizes a Rescan label' {
    Add-WinSecActionFixture -Legacy
    Assert-WinSecAction ((Get-WinSecScanAction $script:coordinator 'local:ACTION' DEVICE ALL) -ceq 'Scan')
}
Test-WinSecAction 'Exact scope history remains detached and preserves all source sessions' {
    Add-WinSecActionFixture
    Add-WinSecActionFixture -Type SECTION -Key SystemSecurity -Id partial
    $before=ConvertTo-Json -InputObject $script:coordinator.Sessions -Depth 20 -Compress
    $rows=@(Get-WinSecCoordinatorHistory $script:coordinator 'LOCAL:action' -ScopeType DEVICE -ScopeKey ALL)
    Assert-WinSecAction ($rows.Count -eq 1 -and $rows[0].ScanId -ceq 'previous' -and
        (ConvertTo-Json -InputObject $rows -Depth 5) -notmatch 'ACTION-PRIVATE-CANARY|"Evidence"')
    $rows[0].ScopeKey='changed'
    Assert-WinSecAction ($before -ceq (ConvertTo-Json -InputObject $script:coordinator.Sessions -Depth 20 -Compress))
}
foreach($arguments in @(@{ScopeType='DEVICE'},@{ScopeKey='ALL'},@{ScopeType='device';ScopeKey='ALL'},
    @{ScopeType='DEVICE';ScopeKey=@('ALL')},@{ScopeType='SECTION';ScopeKey='unknown'},@{ScopeType=$null;ScopeKey=$null},
    @{ScopeType='CONTROL';ScopeKey="WSA-SYS-001`n"})){
    Test-WinSecAction 'Malformed scope query fails closed without publishing history' {
        $caught=$null;$rows=New-Object 'System.Collections.Generic.List[object]'
        try{Get-WinSecCoordinatorHistory $script:coordinator 'local:ACTION' @arguments|ForEach-Object{$rows.Add($_)}}catch{$caught=$_}
        Assert-WinSecAction ($null -ne $caught -and $rows.Count -eq 0)
    }
}
Test-WinSecAction 'Scope filtering requires an explicit device' {
    $caught=$false
    try{$null=Get-WinSecCoordinatorHistory $script:coordinator -ScopeType DEVICE -ScopeKey ALL}catch{$caught=$true}
    Assert-WinSecAction $caught
}
Test-WinSecAction 'Corrupt matching history cannot fall back to a Scan label' {
    Add-WinSecActionFixture
    $script:coordinator.Sessions['local:ACTION|previous'].Session.ScopeKey='CHANGED'
    $caught=$false;$received=@()
    try{$received=@(Get-WinSecScanAction $script:coordinator 'local:ACTION' DEVICE ALL)}catch{$caught=$true}
    Assert-WinSecAction ($caught -and $received.Count -eq 0)
}
Write-Host "Passed: $script:passed"
Write-Host "Failed: $script:failed"
if($script:failed -gt 0){throw "$script:failed scan action test(s) failed."}
