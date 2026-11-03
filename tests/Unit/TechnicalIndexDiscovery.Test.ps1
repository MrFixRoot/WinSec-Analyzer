[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Services/TechnicalSourceRestoration.ps1')
$passed=0;$failed=0;$id='local:hw1-'+('a'*64);$script:calls=@()
function Assert-CDU {param([bool]$Value);if(-not $Value){throw 'Combined discovery unit assertion failed.'}}
function Test-CDU {param([string]$Name,[scriptblock]$Action);try{& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}catch{$script:failed++;Write-Host ('[FAIL] '+$Name+': '+$_.Exception.Message)}}
function Read-WinSecTechnicalSourceSessions {param($ProjectRoot,$DeviceId,$CancellationAction)
    $script:calls+='HISTORICAL';[pscustomobject]@{ArtifactType='WinSec.TechnicalSourceDiscovery';SchemaVersion='1.0.0';DeviceId=$DeviceId;Sessions=@()}
}
function Read-WinSecTechnicalIndexDiscovery {param($ProjectRoot,$DeviceId,$CancellationAction)
    $script:calls+='COMBINED';if($script:unsupported){throw [NotSupportedException]::new('MULTI_CONTROL_SESSION_NOT_SUPPORTED')}
    [pscustomobject]@{ArtifactType='WinSec.TechnicalSourceDiscovery';SchemaVersion='1.1.0';DeviceId=$DeviceId;Sessions=@();StoredSessions=@()}
}
function Restore-WinSecTechnicalSourceIndex {param($ProjectRoot,$Discovery,$ExpectedDeviceId,$CancellationAction)
    Copy-WinSecTechnicalIndexMetadata $ProjectRoot $Discovery $ExpectedDeviceId DISCOVERY $CancellationAction
}
Test-CDU 'Existing preparation defaults to discovery and index 1.0 without combined I/O' {
    $script:calls=@();$r=Read-WinSecTechnicalRestoreIndexes $root @([pscustomobject]@{DeviceId=$id})
    Assert-CDU ($r[$id].SchemaVersion -ceq '1.0.0' -and ($script:calls -join ',') -ceq 'HISTORICAL')
}
Test-CDU 'Explicit preparation dispatches discovery 1.1 and returns detached RECORDS indexes only' {
    $script:calls=@();$r=Read-WinSecTechnicalRestoreIndexes $root @([pscustomobject]@{DeviceId=$id}) -IncludeStoredSessions
    Assert-CDU ($r[$id].SchemaVersion -ceq '1.1.0' -and $r[$id].Origin -ceq 'RECORDS' -and $r[$id].StoredSessions.Count -eq 0 -and ($script:calls -join ',') -ceq 'COMBINED')
}
Test-CDU 'Unsupported combined session aborts preparation without silently selecting the historical branch' {
    $script:calls=@();$script:unsupported=$true;$caught=$false
    try{$null=Read-WinSecTechnicalRestoreIndexes $root @([pscustomobject]@{DeviceId=$id}) -IncludeStoredSessions}catch [NotSupportedException]{$caught=$true}finally{$script:unsupported=$false}
    Assert-CDU ($caught -and ($script:calls -join ',') -ceq 'COMBINED')
}
Test-CDU 'Cancellation is preserved before either discovery branch is invoked' {
    $script:calls=@();$caught=$false
    try{$null=Read-WinSecTechnicalRestoreIndexes $root @([pscustomobject]@{DeviceId=$id}) -IncludeStoredSessions -CancellationAction {$true}}catch [OperationCanceledException]{$caught=$true}
    Assert-CDU ($caught -and $script:calls.Count -eq 0)
}
Test-CDU 'Duplicate managed identities reject rather than overwrite another prepared index' {
    $script:calls=@();$caught=$false
    try{$null=Read-WinSecTechnicalRestoreIndexes $root @([pscustomobject]@{DeviceId=$id},[pscustomobject]@{DeviceId=$id}) -IncludeStoredSessions}catch{$caught=$true}
    Assert-CDU $caught
}
Write-Host ("Technical index discovery unit: $passed passed; $failed failed.");if($failed){exit 1}
