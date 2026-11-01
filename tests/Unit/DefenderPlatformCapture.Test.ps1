[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Checks/Defender/DefenderPlatformCapture.ps1')
. (Join-Path $root 'tests/Fixtures/DefenderTechnicalMemory.ps1')
. (Join-Path $root 'tests/Fixtures/DefenderPlatformMemory.ps1')
function Get-MpComputerStatus {throw 'Forbidden native query.'}
function Get-MpPreference {throw 'Forbidden native query.'}
function Get-CimClass {throw 'Forbidden native query.'}
function Get-CimInstance {
    [CmdletBinding()]param($Namespace,$ClassName,$Property,$OperationTimeoutSec)
    Get-WinSecDefenderPlatformFixtureCim -Namespace $Namespace -ClassName $ClassName -Property $Property -OperationTimeoutSec $OperationTimeoutSec
}
$script:jobCalls=0
function Start-Job {[CmdletBinding()]param($ScriptBlock,$ArgumentList);$script:jobCalls++;throw 'Unexpected job in a pure unit test.'}
$passed=0;$failed=0
function Assert-PlatformCapture {param([bool]$Value);if(-not $Value){throw 'Platform capture assertion failed.'}}
function Reject-PlatformCapture {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-PlatformCapture $caught}
function New-PlatformFrame {
    $script:DefenderPlatformFixtureQueries=0
    & (Get-WinSecDefenderPlatformQueryWorker) (Join-Path $root 'src/Checks/Defender/DefenderTechnicalSnapshot.ps1') $f.Identity.DeviceId $f.Identity.ScanId
}
function Read-PlatformFrame {
    param([object]$Frame)
    ConvertFrom-WinSecDefenderPlatformQueryFrame $Frame $f.Identity '2020-01-01T00:00:00.0000000Z' '2099-01-01T00:00:00.0000000Z'
}
function Test-PlatformCapture {
    param([string]$Name,[scriptblock]$Action)
    $f=New-WinSecDefenderTechnicalFixture;$script:DefenderPlatformFixtureMode='Success'
    try{& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}catch{$script:failed++;Write-Host ('[FAIL] '+$Name+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}
}
Test-PlatformCapture 'One local query requests exactly four reviewed fields and returns a normalized source' {
    $frame=New-PlatformFrame;$result=Read-PlatformFrame $frame
    Assert-PlatformCapture ($script:DefenderPlatformFixtureQueries -eq 1 -and $result.Source.State -ceq 'OBSERVED' -and
        $result.Source.Data.BuildNumber -eq 26100 -and $result.Source.Data.OperatingSystemSKU -eq 48 -and
        $result.Provenance.Provider -ceq 'CIM' -and $result.Provenance.RemoteRequested -ceq $false)
    Assert-WinSecSnapshotFields $result.Source @('SourceId','DeviceId','ScanId','CollectedAtUTC','State','Data')
}
Test-PlatformCapture 'No private native metadata or fields enter the transport or capture' {
    $json=ConvertTo-Json -InputObject (Read-PlatformFrame (New-PlatformFrame)) -Depth 10 -Compress
    Assert-PlatformCapture ($json -notmatch 'PRIVATE-|RegisteredUser|SerialNumber|CimInstanceProperties|PSComputerName')
}
Test-PlatformCapture 'Capture retains its full original scope and detaches data from later caller mutation' {
    $frame=New-PlatformFrame;$capture=Read-PlatformFrame $frame
    $f.Identity.ScopeType='DEVICE';$f.Identity.ScopeKey='ALL';$frame.Data.BuildNumber=[uint32]0
    Assert-PlatformCapture ($capture.Identity.ScopeType -ceq 'CONTROL' -and $capture.Identity.ScopeKey -ceq 'WSA-SYS-001' -and
        $capture.Source.Data.BuildNumber -eq 26100)
}
foreach($mode in @('ProviderError','Empty','Duplicate','WrongClass','WrongNamespace','PlainCarrier','InvalidValue','MissingValue','NullValue')){
    Test-PlatformCapture ('Unavailable or invalid source produces an honest failure: '+$mode) {
        $script:DefenderPlatformFixtureMode=$mode;$frame=New-PlatformFrame;$result=Read-PlatformFrame $frame
        $reason=switch($mode){ProviderError {'PROVIDER_UNAVAILABLE'};{$_ -in @('Empty','Duplicate')} {'UNEXPECTED_CARDINALITY'}
            {$_ -in @('WrongClass','WrongNamespace','PlainCarrier')} {'INVALID_SOURCE'};default {'INVALID_VALUE'}}
        Assert-PlatformCapture ($result.Source.State -ceq 'ERROR' -and $null -eq $result.Source.Data -and $result.Diagnostic -ceq $reason -and
            (ConvertTo-Json -InputObject $result -Depth 10 -Compress) -notmatch 'PRIVATE-')
    }
}
Test-PlatformCapture 'Non-output provider streams are suppressed before transport' {
    $script:DefenderPlatformFixtureMode='Noisy';$all=@(New-PlatformFrame *>&1)
    Assert-PlatformCapture ($all.Count -eq 1 -and $all[0].State -ceq 'OBSERVED')
}
Test-PlatformCapture 'Observed older Windows is preserved, not labelled applicable or secure' {
    $script:DefenderPlatformFixtureMode='OlderWindows';$capture=Read-PlatformFrame (New-PlatformFrame)
    Assert-PlatformCapture ($capture.Source.State -ceq 'OBSERVED' -and $capture.Source.Data.BuildNumber -eq 19045)
    $f.Sources[0]=$capture.Source;$f.StartedAtUTC='2020-01-01T00:00:00.0000000Z';$f.CompletedAtUTC='2099-01-01T00:00:00.0000000Z';$f.GeneratedAtUTC=$f.CompletedAtUTC
    Reject-PlatformCapture {New-WinSecDefenderFixturePackage $f}
}
foreach($damage in @('DeviceId','ScanId','SourceId','Schema','State','Reason','Timeline','Extra','DataExtra','DataNull','DataType')){
    Test-PlatformCapture ('Transport validation rejects contradictory or foreign content: '+$damage) {
        $frame=New-PlatformFrame
        switch($damage){DeviceId {$frame.DeviceId='local:hw1-'+('c'*64)};ScanId {$frame.ScanId='other'};SourceId {$frame.SourceId='Status'}
            Schema {$frame.SchemaVersion='other'};State {$frame.State='NOT_APPLICABLE'};Reason {$frame.Reason='INVALID_VALUE'}
            Timeline {$frame.CollectedAtUTC='2100-01-01T00:00:00.0000000Z'};Extra {$frame|Add-Member Extra 'PRIVATE-SECRET'}
            DataExtra {$frame.Data|Add-Member Extra 'PRIVATE-SECRET'};DataNull {$frame.Data=$null};DataType {$frame.Data.ProductType=$true}}
        Reject-PlatformCapture {Read-PlatformFrame $frame}
    }
}
Test-PlatformCapture 'Executable transport getters are rejected without invoking them' {
    $frame=New-PlatformFrame;$script:executed=0
    $frame|Add-Member -MemberType ScriptProperty -Name Reason -Value {$script:executed++;'NONE'} -Force
    Reject-PlatformCapture {Read-PlatformFrame $frame};Assert-PlatformCapture ($script:executed -eq 0)
}
foreach($headerFieldName in @('SchemaVersion','SourceId','DeviceId','ScanId','CollectedAtUTC')){
    Test-PlatformCapture ('Array transport headers cannot masquerade as scalar strings: '+$headerFieldName) {
        $frame=New-PlatformFrame;$frame.$headerFieldName=@($frame.$headerFieldName)
        Reject-PlatformCapture {Read-PlatformFrame $frame}
    }
}
Test-PlatformCapture 'Normalized build text is rejected instead of silently coerced to a number' {
    $frame=New-PlatformFrame;$frame.Data.BuildNumber='26100';Reject-PlatformCapture {Read-PlatformFrame $frame}
}
Test-PlatformCapture 'Executable value conversion is rejected before accessing its methods' {
    $frame=New-PlatformFrame;$script:executed=0;$value=[pscustomobject]@{}
    $value|Add-Member -MemberType ScriptMethod -Name GetType -Value {$script:executed++;throw 'PRIVATE-SECRET'} -Force
    $frame.Data.OperatingSystemSKU=$value
    Reject-PlatformCapture {Read-PlatformFrame $frame};Assert-PlatformCapture ($script:executed -eq 0)
}
Test-PlatformCapture 'Job transport metadata is stripped from the validated capture' {
    $frame=New-PlatformFrame;$frame|Add-Member PSComputerName 'PRIVATE-SECRET';$frame|Add-Member RunspaceId ([guid]::NewGuid());$frame|Add-Member PSShowComputerName $false
    Assert-PlatformCapture ((ConvertTo-Json -InputObject (Read-PlatformFrame $frame) -Depth 10 -Compress) -notmatch 'PRIVATE-|PSComputerName|RunspaceId')
}
Test-PlatformCapture 'Foreign control identity is rejected before starting a provider job' {
    $f.Identity.CheckId='WSA-SYS-002';$f.Identity.ScopeKey='WSA-SYS-002'
    Reject-PlatformCapture {Invoke-WinSecDefenderPlatformCapture $f.Identity};Assert-PlatformCapture ($script:jobCalls -eq 0)
}
Test-PlatformCapture 'Cancellation before acquisition performs no native work' {
    $cancelled=$false;try{$null=Invoke-WinSecDefenderPlatformCapture $f.Identity -CancellationAction {$true}}catch [OperationCanceledException]{$cancelled=$true}
    Assert-PlatformCapture ($cancelled -and $script:jobCalls -eq 0)
}
foreach($value in @('yes',0,$null)){
    Test-PlatformCapture ('Non-Boolean cancellation fails before acquisition: '+[string]$value) {
        Reject-PlatformCapture {Invoke-WinSecDefenderPlatformCapture $f.Identity -CancellationAction {$value}}
        Assert-PlatformCapture ($script:jobCalls -eq 0)
    }
}
Test-PlatformCapture 'Worker startup errors are closed and do not publish a source' {
    $message=$null;try{$null=Invoke-WinSecDefenderPlatformCapture $f.Identity}catch{$message=$_.Exception.Message}
    Assert-PlatformCapture ($message -ceq 'Defender capture worker could not start.')
}
Write-Host ("Defender platform capture: $passed passed; $failed failed.");if($failed){exit 1}
