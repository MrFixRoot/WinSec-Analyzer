# Owned synthetic workers and isolated pairs only; neither Defender nor preferences are queried.
[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Checks/Defender/DefenderStatusCapture.ps1')
. (Join-Path $root 'src/Checks/Defender/DefenderTechnicalStorage.ps1')
. (Join-Path $root 'tests/Fixtures/DefenderTechnicalMemory.ps1')
. (Join-Path $root 'tests/Fixtures/DefenderStatusMemory.ps1')
function Get-MpComputerStatus {throw 'Unmocked native status forbidden.'}
function Get-MpPreference {throw 'Preference acquisition forbidden.'}
function Get-CimInstance {throw 'Unmocked native CIM forbidden.'}
function Get-CimClass {throw 'Unmocked native schema forbidden.'}
function Start-Job {[CmdletBinding()]param([scriptblock]$ScriptBlock,[object[]]$ArgumentList);Start-WinSecDefenderStatusFixtureJob $ScriptBlock $ArgumentList}
$script:DefenderStatusFixtureJobIds=@();$passed=0;$failed=0
$tempParent=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\');$sandbox=Join-Path $tempParent ('wds-'+[guid]::NewGuid().ToString('N').Substring(0,12))
$null=[IO.Directory]::CreateDirectory($sandbox)
function Assert-StatusIntegration {param([bool]$Value);if(-not $Value){throw 'Status integration assertion failed.'}}
function Reject-StatusIntegration {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-StatusIntegration $caught}
function Test-StatusIntegration {
    param([string]$Name,[scriptblock]$Action)
    $f=New-WinSecDefenderTechnicalFixture;$f.Identity.SnapshotId=[guid]::NewGuid().ToString('N');$script:DefenderStatusFixtureMode='Success'
    try{& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}catch{$script:failed++;Write-Host ('[FAIL] '+$Name+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}
}
function Set-StatusIntegrationSource {
    param([object]$Capture)
    $f.Sources[1]=$Capture.Source;$f.StartedAtUTC='2020-01-01T00:00:00.0000000Z'
    $f.CompletedAtUTC=[datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ');$f.GeneratedAtUTC=$f.CompletedAtUTC
}
try {
    foreach($scope in @('CONTROL','SECTION','DEVICE')){Test-StatusIntegration ('Status worker preserves all reviewed fields and original scope through JSON/Markdown: '+$scope) {
        $f.Identity.ScopeType=$scope;$f.Identity.ScopeKey=switch($scope){CONTROL {'WSA-SYS-001'};SECTION {'SystemSecurity'};DEVICE {'ALL'}}
        $script:events=New-Object 'Collections.Generic.List[object]'
        $capture=Invoke-WinSecDefenderStatusCapture $f.Identity -ProgressCallback {param($event);$script:events.Add($event)}
        Set-StatusIntegrationSource $capture;$p=New-WinSecDefenderFixturePackage $f
        $saved=Write-WinSecDefenderTechnicalPair $sandbox $p $f.Identity;$read=Read-WinSecDefenderTechnicalPair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        $md=Get-Content -LiteralPath $saved.MarkdownPath -Raw -Encoding UTF8
        Assert-StatusIntegration ($capture.Coverage.Observed -eq 42 -and $read.PublicationStatus -ceq 'COMMITTED' -and $read.Snapshot.CollectorVersion -ceq '1.3.0' -and
            $read.Snapshot.Identity.ScopeType -ceq $scope -and $md -ceq (ConvertTo-WinSecSnapshotMarkdown $p.Snapshot $p.Catalog $p.CatalogSha256 $f.Identity) -and
            $md -notmatch 'PRIVATE-|ComputerID|ThreatResources|RunspaceId' -and
            (ConvertTo-Json -InputObject $read.Snapshot -Depth 16 -Compress) -ceq (ConvertTo-Json -InputObject $p.Snapshot -Depth 16 -Compress))
        Assert-StatusIntegration ($script:events[0].CompletedSteps -eq 0 -and @($script:events|Where-Object CompletedSteps -EQ 1).Count -eq 1 -and
            $script:events[$script:events.Count-1].Stage -ceq 'STATUS_CAPTURED')
    }}
    foreach($fixtureMode in @('MissingOptional','InvalidVersion','InvalidBoolean','ProviderError')){Test-StatusIntegration ('Incomplete status states and reasons persist without inventing security results: '+$fixtureMode) {
        $script:DefenderStatusFixtureMode=$fixtureMode;$capture=Invoke-WinSecDefenderStatusCapture $f.Identity
        Set-StatusIntegrationSource $capture;$p=New-WinSecDefenderFixturePackage $f
        $saved=Write-WinSecDefenderTechnicalPair $sandbox $p $f.Identity;$read=Read-WinSecDefenderTechnicalPair $sandbox $f.Identity $p.Snapshot.CollectedAtUTC
        $id=switch($fixtureMode){MissingOptional {'Status.AntispywareSignatureAgeDays'};InvalidVersion {'Status.FullScanSignatureVersion'};default {'Status.AntivirusEnabled'}}
        $r=Get-WinSecDefenderFixtureReading $read.Snapshot $id
        $state=if($fixtureMode -ceq 'ProviderError'){'ERROR'}else{'UNKNOWN'}
        $reason=if($fixtureMode -in @('InvalidVersion','InvalidBoolean')){'INVALID_VALUE'}else{'PROVIDER_UNAVAILABLE'}
        $complete=$fixtureMode -in @('MissingOptional','InvalidVersion')
        Assert-StatusIntegration ($r.State -ceq $state -and $r.Reason -ceq $reason -and $null -eq $r.Value -and
            $read.Snapshot.Collection.Coverage -ceq 'LIMITED' -and $read.Snapshot.Collection.Status -ceq $(if($complete){'COMPLETE'}else{'PARTIAL'}))
        $md=Get-Content -LiteralPath $saved.MarkdownPath -Raw -Encoding UTF8
        Assert-StatusIntegration ($md.Contains($reason) -and $md -notmatch 'PRIVATE-')
    }}
    foreach($fixtureMode in @('NoFrame','ExtraFrame','WrongIdentity')){Test-StatusIntegration ('Invalid worker output never publishes a capture: '+$fixtureMode) {
        $script:DefenderStatusFixtureMode=$fixtureMode;$script:completed=0
        Reject-StatusIntegration {Invoke-WinSecDefenderStatusCapture $f.Identity -ProgressCallback {param($event);if($event.CompletedSteps -eq 1){$script:completed++}}}
        Assert-StatusIntegration ($script:completed -eq 0)
    }}
    Test-StatusIntegration 'The watchdog bounds an owned worker and returns no source after timeout' {
        $script:DefenderStatusFixtureMode='Slow';$timedOut=$false
        try{$null=Invoke-WinSecDefenderStatusCapture $f.Identity -TimeoutMilliseconds 100}catch [TimeoutException]{$timedOut=$true}
        Assert-StatusIntegration $timedOut
    }
    Test-StatusIntegration 'Cancellation removes only the owned status worker and preserves an unrelated job' {
        $foreign=Microsoft.PowerShell.Core\Start-Job -ScriptBlock {Start-Sleep -Seconds 30}
        try{
            $script:DefenderStatusFixtureMode='Slow';$script:polls=0;$cancelled=$false
            try{$null=Invoke-WinSecDefenderStatusCapture $f.Identity -CancellationAction {$script:polls++;return ($script:polls -ge 4)}}catch [OperationCanceledException]{$cancelled=$true}
            Assert-StatusIntegration ($cancelled -and $foreign.State -cin @('NotStarted','Running') -and
                @(Get-Job|Where-Object {$_.InstanceId -cin $script:DefenderStatusFixtureJobIds}).Count -eq 0)
        }finally{Stop-Job -Job $foreign -ErrorAction SilentlyContinue;Remove-Job -Job $foreign -Force -ErrorAction SilentlyContinue}
    }
    Test-StatusIntegration 'Cancellation after final source progress still returns no capture' {
        $script:cancelFinal=$false;$cancelled=$false
        try{$null=Invoke-WinSecDefenderStatusCapture $f.Identity -ProgressCallback {param($event);if($event.Stage -ceq 'STATUS_CAPTURED'){$script:cancelFinal=$true}} -CancellationAction {$script:cancelFinal}}
        catch [OperationCanceledException]{$cancelled=$true}
        Assert-StatusIntegration $cancelled
    }
    Test-StatusIntegration 'No owned status jobs remain after success, rejection, timeout or cancellation' {
        Assert-StatusIntegration (@(Get-Job|Where-Object {$_.InstanceId -cin $script:DefenderStatusFixtureJobIds}).Count -eq 0)
    }
}finally{
    foreach($job in @(Get-Job|Where-Object {$_.InstanceId -cin $script:DefenderStatusFixtureJobIds})){
        Stop-Job -Job $job -ErrorAction SilentlyContinue;Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
    }
    $full=[IO.Path]::GetFullPath($sandbox)
    if([IO.Path]::GetDirectoryName($full) -cne $tempParent -or [IO.Path]::GetFileName($full) -cnotmatch '\Awds-[a-f0-9]{12}\z'){throw 'Unsafe status fixture cleanup.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
Write-Host ("Defender status integration: $passed passed; $failed failed.");if($failed){exit 1}
