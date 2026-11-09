# Synthetic OS, registry and hardware data only; snapshots stay outside Git.
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$testRoot=Join-Path ([IO.Path]::GetTempPath()) ('winsec-os-context-test-'+[guid]::NewGuid().ToString('N'))
$previousComputerName=$env:COMPUTERNAME
try {
    $env:COMPUTERNAME='SYNTHETIC_OS_CONTEXT'
    Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'WinSecAnalyzer.psm1') -Force -DisableNameChecking
    & (Get-Module WinSecAnalyzer) {
        param($testRoot)
        $script:assertions=0; $script:productType=1; $script:build='26100'
        $script:revision=42; $script:registryMode='complete'; $script:collectorMode='complete'; $script:failCPU=$false
        $script:queries=New-Object 'System.Collections.Generic.List[string]'
        function Assert-Test {param([bool]$Condition,[string]$Message) if (-not $Condition) {throw ('FAIL: '+$Message)}; $script:assertions++}
        function Assert-Throws {param([scriptblock]$Action,[string]$Message) $failed=$false;try {& $Action} catch {$failed=$true};Assert-Test $failed $Message}
        function Test-WinSecElevated {return $false}
        function Get-CimInstance {
            [CmdletBinding()]param($ClassName)
            $script:queries.Add($ClassName)
            switch ($ClassName) {
                'Win32_OperatingSystem' {[pscustomobject]@{BuildNumber=$script:build;ProductType=$script:productType;Caption='SYNTHETIC';Version='10.0.SYNTHETIC';OSArchitecture='SYNTHETIC'}}
                'Win32_ComputerSystem' {[pscustomobject]@{Manufacturer='SYNTHETIC';Model='SYNTHETIC';TotalPhysicalMemory=8GB;NumberOfLogicalProcessors=4}}
                'Win32_Processor' {if ($script:failCPU) {throw 'SYNTHETIC CPU failure'};[pscustomobject]@{Name='SYNTHETIC'}}
                default {throw 'Unexpected CIM query.'}
            }
        }
        function Get-ItemProperty {
            [CmdletBinding()]param($LiteralPath)
            $script:queries.Add('CurrentVersion')
            if ($LiteralPath -ne 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion') {throw 'Unexpected registry path.'}
            if ($script:registryMode -eq 'denied') {throw 'SYNTHETIC registry denied'}
            $values=@{EditionID='SYNTHETIC';DisplayVersion='SYNTHETIC_RELEASE';UBR=$script:revision;InstallationType='Client';ProductId='FORBIDDEN_SENTINEL'}
            switch ($script:registryMode) {
                'missing' {$values.Remove('DisplayVersion');$values.Remove('InstallationType')}
                'badRevision' {$values.UBR='SYNTHETIC_INVALID'}
                'missingRelease' {$values.Remove('DisplayVersion')}
            }
            return [pscustomobject]$values
        }
        function Get-WinSecWindowsDefenderEvidence {
            [CmdletBinding()]param([switch]$Deep)
            if ($script:collectorMode -eq 'error') {throw 'SYNTHETIC collector error'}
            if ($script:collectorMode -eq 'stream') {Write-Warning 'SYNTHETIC stream warning'}
            $warnings=if ($script:collectorMode -eq 'payload') {@('SYNTHETIC payload warning')} else {@()}
            [pscustomobject]@{status='COMPLETED';data=@{synthetic=$true};sources=@('SYNTHETIC');warnings=$warnings}
        }
        $os=Assert-WinSecWindows11
        Assert-Test (($script:queries -join ',') -eq 'Win32_OperatingSystem,CurrentVersion') 'OS validation must precede optional registry reads.'
        Assert-Test ($os.DisplayVersion -eq 'SYNTHETIC_RELEASE' -and $os.UBR -is [int] -and $os.UBR -eq 42 -and $os.InstallationType -eq 'Client' -and $os.Status -eq 'COMPLETED') 'Complete OS metadata must retain stable names and integer UBR.'
        Assert-Test ((ConvertTo-Json $os -Depth 8) -notmatch 'FORBIDDEN_SENTINEL|ProductId') 'OS metadata must exclude registry fields outside the allowlist.'
        foreach ($case in @(@(3,'26100'),@(1,'19045'),@(1,'SYNTHETIC_INVALID'))) {
            $script:productType=$case[0];$script:build=$case[1];$before=$script:queries.Count
            Assert-Throws {Get-WinSecLocalDevice} 'Unsupported or unverifiable OS data must reject device collection.'
            Assert-Test ($script:queries.Count -eq $before+1) 'Rejected operating systems must prevent registry and hardware reads.'
        }
        $script:productType=1;$script:build='26100';$script:revision=0
        Assert-Test ((Assert-WinSecWindows11).UBR -eq 0 -and (Assert-WinSecWindows11).Status -eq 'COMPLETED') 'UBR zero is valid and must not become missing evidence.'
        $script:revision=42
        foreach ($mode in @('missing','badRevision','denied')) {
            $script:registryMode=$mode
            $partial=Assert-WinSecWindows11
            Assert-Test ($partial.Status -eq 'PARTIAL' -and $partial.Warnings.Count -gt 0) 'Missing or invalid optional OS metadata must produce partial status and warnings.'
            if ($mode -eq 'missing') {Assert-Test ($null -eq $partial.DisplayVersion -and $null -eq $partial.InstallationType -and $partial.UBR -eq 42) 'Missing OS fields must remain null while available fields are preserved.'}
            if ($mode -eq 'badRevision') {Assert-Test ($null -eq $partial.UBR) 'Invalid UBR must not be substituted with zero.'}
            if ($mode -eq 'denied') {Assert-Test ($partial.Edition -eq 'Unknown' -and $null -eq $partial.UBR -and $partial.Warnings[0] -match 'SYNTHETIC registry denied') 'A registry failure must preserve its warning and fallback edition.'}
        }
        $local=Get-WinSecLocalDevice
        Assert-Test ($local.status -eq 'PARTIAL' -and $local.os.status -eq 'PARTIAL' -and $local.warnings.Count -gt 0) 'Device status must include OS warnings.'
        $script:registryMode='complete';$script:failCPU=$true
        $hardwarePartial=Get-WinSecLocalDevice
        Assert-Test ($hardwarePartial.status -eq 'PARTIAL' -and $hardwarePartial.os.status -eq 'COMPLETED') 'Hardware warnings must mark the device partial without degrading complete OS metadata.'
        $script:failCPU=$false
        $local=Get-WinSecLocalDevice
        $inventory=Register-WinSecDevice -OutputRoot $testRoot -LocalDevice $local
        $saved=Get-Content (Join-Path $testRoot 'inventory.json') -Raw | ConvertFrom-Json
        Assert-Test ($saved.devices[0].os.displayVersion -eq 'SYNTHETIC_RELEASE' -and $saved.devices[0].os.ubr -eq 42 -and $saved.devices[0].os.installationType -eq 'Client' -and $saved.devices[0].status -eq 'COMPLETED') 'Inventory must persist the full OS context and device status.'
        $inventory.devices[0].PSObject.Properties.Remove('status')
        Save-WinSecDeviceInventory -OutputRoot $testRoot -Inventory $inventory
        $inventory=Register-WinSecDevice -OutputRoot $testRoot -LocalDevice $hardwarePartial
        Assert-Test ($inventory.devices[0].status -eq 'PARTIAL') 'Refreshing an older inventory entry must add status without requiring migration.'

        foreach ($mode in @('complete','missingRelease')) {
            $script:registryMode=$mode
            $path=Invoke-WinSecCollection -Domain SystemSecurity -Collector WindowsDefender -OutputRoot $testRoot 6>$null
            $context=Get-WinSecSnapshotManifest $path
            Assert-Test ($context.Manifest.os.ubr -eq 42 -and $context.Manifest.os.installationType -eq 'Client') 'Snapshots must persist the same OS fields as devices.'
            if ($mode -eq 'complete') {Assert-Test ($context.Manifest.status -eq 'COMPLETED' -and $context.Manifest.os.displayVersion -eq 'SYNTHETIC_RELEASE') 'Complete OS and collector data must produce a completed snapshot.'}
            else {Assert-Test ($context.Manifest.status -eq 'PARTIAL' -and $null -eq $context.Manifest.os.displayVersion -and $context.Manifest.warnings.Count -gt 0 -and $context.Manifest.collectors[0].status -eq 'COMPLETED') 'OS warnings must mark the snapshot partial while retaining the collector status.'}
        }
        $script:registryMode='complete'
        foreach ($mode in @('payload','stream','error')) {
            $script:collectorMode=$mode
            $path=Invoke-WinSecCollection -Domain SystemSecurity -Collector WindowsDefender -OutputRoot $testRoot 6>$null
            $context=Get-WinSecSnapshotManifest $path
            $evidence=Get-WinSecEvidenceFile -Context $context -CollectorId WindowsDefender
            $expected=if ($mode -eq 'error') {'ERROR'} else {'PARTIAL'}
            Assert-Test ($evidence.status -eq $expected -and $evidence.warnings.Count -gt 0 -and $context.Manifest.collectors[0].status -eq $expected -and $context.Manifest.status -eq 'PARTIAL') 'Payload or stream warnings must persist partial evidence; errors must remain errors.'
        }
        foreach ($terminal in @('ERROR','NOT_APPLICABLE')) {Assert-Test ((New-WinSecPayload -Data @{} -Warnings @('SYNTHETIC') -Status $terminal).status -eq $terminal) 'Warnings must not overwrite terminal collector statuses.'}
        $script:collectorMode='complete'
        $session=New-WinSecSession -OutputRoot $testRoot
        winsec -s windowsDefender -Session $session -NoBanner 6>$null
        $hash=Get-WinSecHash $session.Snapshot
        $script:revision=43
        Assert-Throws {winsec -s windowsDefender -Session $session -NoBanner 6>$null} 'An observed OS revision change must require a new snapshot.'
        Assert-Test ((Get-WinSecHash $session.Snapshot) -eq $hash) 'Rejecting changed OS context must preserve the existing snapshot.'
        $script:revision=42;$script:registryMode='missingRelease'
        winsec -s windowsDefender -Session $session -NoBanner 6>$null
        $script:registryMode='complete'
        winsec -s windowsDefender -Session $session -NoBanner 6>$null
        $context=Get-WinSecSnapshotManifest $session.Snapshot
        Assert-Test ($context.Manifest.status -eq 'PARTIAL' -and $context.Manifest.warnings.Count -gt 0 -and $context.Manifest.os.displayVersion -eq 'SYNTHETIC_RELEASE') 'Later reads must retain context warnings and the original OS metadata.'
        Close-WinSecSession $session
        Write-Output ('PASS: '+$script:assertions+' OS/context assertions')
    } $testRoot
} finally {
    $env:COMPUTERNAME=$previousComputerName
    $resolved=[IO.Path]::GetFullPath($testRoot)
    $temp=[IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if (-not $resolved.StartsWith($temp,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($resolved) -notlike 'winsec-os-context-test-*') {throw 'Unsafe test cleanup path.'}
    if (Test-Path -LiteralPath $resolved) {Remove-Item -LiteralPath $resolved -Recurse -Force}
    Remove-Module WinSecAnalyzer -ErrorAction SilentlyContinue
}
