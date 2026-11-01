# Actual owned jobs, but only synthetic child providers and isolated temporary storage.
[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Checks/Defender/DefenderPlatformCapture.ps1')
. (Join-Path $root 'src/Checks/Defender/DefenderTechnicalStorage.ps1')
. (Join-Path $root 'tests/Fixtures/DefenderTechnicalMemory.ps1')
. (Join-Path $root 'tests/Fixtures/DefenderPlatformMemory.ps1')
function Get-CimInstance {throw 'Unmocked provider forbidden.'}
function Get-MpComputerStatus {throw 'Unmocked provider forbidden.'}
function Get-MpPreference {throw 'Unmocked provider forbidden.'}
function Start-Job {
    [CmdletBinding()]param([scriptblock]$ScriptBlock,[object[]]$ArgumentList)
    Start-WinSecDefenderPlatformFixtureJob -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
}
$script:DefenderPlatformFixtureJobsStarted=0;$script:DefenderPlatformFixtureJobIds=@();$passed=0;$failed=0
$tempParent=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\');$sandbox=Join-Path $tempParent ('wdp-'+[guid]::NewGuid().ToString('N').Substring(0,12))
$null=[IO.Directory]::CreateDirectory($sandbox)
function Assert-PlatformIntegration {param([bool]$Value);if(-not $Value){throw 'Platform integration assertion failed.'}}
function Reject-PlatformIntegration {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-PlatformIntegration $caught}
function Test-PlatformIntegration {
    param([string]$Name,[scriptblock]$Action)
    $f=New-WinSecDefenderTechnicalFixture;$f.Identity.SnapshotId=[guid]::NewGuid().ToString('N');$script:DefenderPlatformFixtureMode='Success'
    try{& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}catch{$script:failed++;Write-Host ('[FAIL] '+$Name+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}
}
function Set-PlatformIntegrationSource {
    param([object]$Capture)
    $f.Sources[0]=$Capture.Source
    # Keep all prepared receipts within one explicit synthetic operation window.
    $f.StartedAtUTC='2020-01-01T00:00:00.0000000Z';$f.CompletedAtUTC=[datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
    $f.GeneratedAtUTC=$f.CompletedAtUTC
}
try {
    foreach($scope in @('CONTROL','SECTION','DEVICE')){Test-PlatformIntegration ('Synthetic query job to immutable JSON/Markdown with original scope: '+$scope) {
        $f.Identity.ScopeType=$scope;$f.Identity.ScopeKey=switch($scope){CONTROL {'WSA-SYS-001'};SECTION {'SystemSecurity'};DEVICE {'ALL'}}
        $script:events=New-Object 'Collections.Generic.List[object]'
        $capture=Invoke-WinSecDefenderPlatformCapture $f.Identity -ProgressCallback {param($event);$script:events.Add($event)}
        Set-PlatformIntegrationSource $capture
        $package=New-WinSecDefenderFixturePackage $f;$saved=Write-WinSecDefenderTechnicalPair $sandbox $package $f.Identity
        $read=Read-WinSecDefenderTechnicalPair $sandbox $f.Identity $package.Snapshot.CollectedAtUTC
        $md=Get-Content -LiteralPath $saved.MarkdownPath -Raw -Encoding UTF8
        Assert-PlatformIntegration ($capture.Source.State -ceq 'OBSERVED' -and $read.PublicationStatus -ceq 'COMMITTED' -and
            $read.Snapshot.Identity.ScopeType -ceq $scope -and $read.Snapshot.Platform.BuildNumber -eq 26100 -and
            $md -ceq (ConvertTo-WinSecSnapshotMarkdown $package.Snapshot $package.Catalog $package.CatalogSha256 $f.Identity) -and
            $md -notmatch 'PRIVATE-|RegisteredUser|SerialNumber|RunspaceId')
        Assert-PlatformIntegration ($script:events.Count -gt 1 -and $script:events[0].CompletedSteps -eq 0 -and
            $script:events[$script:events.Count-1].Stage -ceq 'PLATFORM_CAPTURED' -and
            @($script:events|Where-Object CompletedSteps -EQ 1).Count -eq 1)
    }}
    Test-PlatformIntegration 'Provider failure remains partial and never implies a supported or safe platform' {
        $script:DefenderPlatformFixtureMode='ProviderError';$capture=Invoke-WinSecDefenderPlatformCapture $f.Identity
        Set-PlatformIntegrationSource $capture;$package=New-WinSecDefenderFixturePackage $f
        Assert-PlatformIntegration ($capture.Diagnostic -ceq 'PROVIDER_UNAVAILABLE' -and $package.Snapshot.Collection.Status -ceq 'PARTIAL' -and
            $package.Snapshot.Collection.Coverage -ceq 'LIMITED' -and $null -eq $package.Snapshot.Platform.BuildNumber)
    }
    foreach($mode in @('NoFrame','ExtraFrame','WrongIdentity')){Test-PlatformIntegration ('Invalid worker output never publishes a source: '+$mode) {
        $script:DefenderPlatformFixtureMode=$mode;$script:completed=0
        Reject-PlatformIntegration {Invoke-WinSecDefenderPlatformCapture $f.Identity -ProgressCallback {param($event);if($event.CompletedSteps -eq 1){$script:completed++}}}
        Assert-PlatformIntegration ($script:completed -eq 0)
    }}
    Test-PlatformIntegration 'A bounded watchdog stops and removes only its own worker without publishing' {
        $script:DefenderPlatformFixtureMode='Slow';$timedOut=$false;$script:completed=0
        try{$null=Invoke-WinSecDefenderPlatformCapture $f.Identity -TimeoutMilliseconds 100 -ProgressCallback {param($event);if($event.CompletedSteps -eq 1){$script:completed++}}}
        catch [TimeoutException]{$timedOut=$true}
        Assert-PlatformIntegration ($timedOut -and $script:completed -eq 0)
    }
    Test-PlatformIntegration 'Cancellation during collection preserves an unrelated job and removes its own worker' {
        $foreign=Microsoft.PowerShell.Core\Start-Job -ScriptBlock {Start-Sleep -Seconds 30}
        try {
            $script:DefenderPlatformFixtureMode='Slow';$script:polls=0;$cancelled=$false
            try{$null=Invoke-WinSecDefenderPlatformCapture $f.Identity -CancellationAction {$script:polls++;return ($script:polls -ge 4)}}
            catch [OperationCanceledException]{$cancelled=$true}
            Assert-PlatformIntegration ($cancelled -and $foreign.State -cin @('NotStarted','Running') -and
                @(Get-Job|Where-Object {$_.InstanceId -cin $script:DefenderPlatformFixtureJobIds}).Count -eq 0)
        }finally{Stop-Job -Job $foreign -ErrorAction SilentlyContinue;Remove-Job -Job $foreign -Force -ErrorAction SilentlyContinue}
    }
    Test-PlatformIntegration 'Cancellation from the final progress callback still returns no source' {
        $script:cancelFinal=$false;$cancelled=$false
        try{$null=Invoke-WinSecDefenderPlatformCapture $f.Identity -ProgressCallback {param($event);if($event.Stage -ceq 'PLATFORM_CAPTURED'){$script:cancelFinal=$true}} -CancellationAction {$script:cancelFinal}}
        catch [OperationCanceledException]{$cancelled=$true}
        Assert-PlatformIntegration $cancelled
    }
    Test-PlatformIntegration 'No candidate query workers remain after success, rejection, cancellation and timeout' {
        Assert-PlatformIntegration (@(Get-Job|Where-Object {$_.InstanceId -cin $script:DefenderPlatformFixtureJobIds}).Count -eq 0)
    }
}finally{
    # Only own fixture jobs/directories. Never touch managed inventory, historical pairs or foreign jobs.
    foreach($job in @(Get-Job|Where-Object {$_.InstanceId -cin $script:DefenderPlatformFixtureJobIds})){
        Stop-Job -Job $job -ErrorAction SilentlyContinue;Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
    }
    $full=[IO.Path]::GetFullPath($sandbox)
    if([IO.Path]::GetDirectoryName($full) -cne $tempParent -or [IO.Path]::GetFileName($full) -cnotmatch '\Awdp-[a-f0-9]{12}\z'){throw 'Unsafe platform fixture cleanup.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
Write-Host ("Defender platform integration: $passed passed; $failed failed.");if($failed){exit 1}
