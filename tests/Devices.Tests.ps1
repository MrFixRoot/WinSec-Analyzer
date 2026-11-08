# Synthetic inventory/deletion regressions. Every path is outside the repository.
$ErrorActionPreference='Stop'
$tempBase=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')+'\'
$testRoot=[IO.Path]::GetFullPath((Join-Path $tempBase ('winsec-devices-test-'+[guid]::NewGuid().ToString('N'))))
$previousComputerName=$env:COMPUTERNAME
$junction=$null
try {
    $env:COMPUTERNAME='SYNTHETIC_LOCAL'
    Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'WinSecAnalyzer.psm1') -Force
    & (Get-Module WinSecAnalyzer) {
        param($testRoot)
        $script:assertions=0
        function Assert-Test {
            param([bool]$Condition,[string]$Message)
            if (-not $Condition) { throw ('FAIL: '+$Message) }
            $script:assertions++
        }
        function Assert-Throws {
            param([scriptblock]$Action,[string]$Message)
            $failed=$false
            try { & $Action } catch { $failed=$true }
            Assert-Test $failed $Message
        }
        $script:queryOrder=New-Object 'System.Collections.Generic.List[string]'
        $script:rejectOS=$false; $script:rejectCPU=$false
        function Assert-WinSecWindows11 {
            $script:queryOrder.Add('guard')
            if ($script:rejectOS) { throw 'Synthetic unsupported OS.' }
            [pscustomobject]@{Edition='SYNTHETIC';Build=22000;Arch='SYNTHETIC';Caption='SYNTHETIC'}
        }
        function Test-WinSecElevated {return $false}
        function Get-CimInstance {
            param($ClassName,$ErrorAction)
            $script:queryOrder.Add($ClassName)
            switch ($ClassName) {
                'Win32_ComputerSystem' {
                    [pscustomobject]@{Manufacturer='SYNTHETIC_VENDOR';Model='SYNTHETIC_MODEL';TotalPhysicalMemory=8GB;NumberOfLogicalProcessors=4;SerialNumber='FORBIDDEN_SENTINEL'}
                }
                'Win32_Processor' {
                    if ($script:rejectCPU) { throw 'Synthetic denied CPU source.' }
                    [pscustomobject]@{Name='SYNTHETIC_CPU';ProcessorId='FORBIDDEN_SENTINEL'}
                }
                default {throw 'Unexpected hardware query.'}
            }
        }
        $local=Get-WinSecLocalDevice
        Assert-Test (($script:queryOrder -join ',') -eq 'guard,Win32_ComputerSystem,Win32_Processor') 'Windows 11 must be validated before querying hardware.'
        Assert-Test ($local.hardware.memoryBytes -eq 8GB -and $local.hardware.processors[0] -eq 'SYNTHETIC_CPU') 'Inventory must retain permitted hardware fields with consistent types.'
        Assert-Test ((ConvertTo-Json $local -Depth 15) -notmatch 'FORBIDDEN_SENTINEL|SerialNumber|ProcessorId') 'Inventory must omit hardware identifiers outside the allowlist.'
        $script:rejectOS=$true; $before=$script:queryOrder.Count
        Assert-Throws {Get-WinSecLocalDevice} 'Unsupported operating systems must be rejected.'
        Assert-Test ($script:queryOrder.Count -eq $before+1) 'A failed OS guard must prevent all hardware queries.'
        $script:rejectOS=$false; $script:rejectCPU=$true
        $partial=Get-WinSecLocalDevice
        Assert-Test (@($partial.warnings).Count -eq 1 -and $partial.hardware.model -eq 'SYNTHETIC_MODEL' -and @($partial.hardware.processors).Count -eq 0) 'A failed hardware source must preserve available data and a warning.'
        $script:rejectCPU=$false

        $root=Join-Path $testRoot 'device'
        $deviceEvents=New-WinSecSession -OutputRoot $root
        $inventory=Register-WinSecDevice -OutputRoot $root -LocalDevice $local -Session $deviceEvents
        Assert-Test (@($deviceEvents.Notifications).Count -eq 1) 'A newly registered device must enqueue a creation notification.'
        Assert-Test (@($inventory.devices).Count -eq 1 -and $inventory.devices[0].name -eq $env:COMPUTERNAME) 'A new device must default to the hostname.'
        Assert-Test (@(Get-ChildItem $root -Filter manifest.json -Recurse).Count -eq 0) 'Hardware detection must not create an empty scan.'
        $inventory=Rename-WinSecDevice -OutputRoot $root -DeviceId $local.id -Name '  Operator workstation  '
        $inventory=Register-WinSecDevice -OutputRoot $root -LocalDevice $local -Session $deviceEvents
        Assert-Test (@($deviceEvents.Notifications).Count -eq 1) 'Refreshing an existing device must not repeat its creation event.'
        Assert-Test (@($inventory.devices).Count -eq 1 -and $inventory.devices[0].name -eq 'Operator workstation') 'Detection must preserve a renamed display label and avoid duplicate devices.'
        Assert-Test ($inventory.devices[0].host -eq $env:COMPUTERNAME -and $env:COMPUTERNAME -eq 'SYNTHETIC_LOCAL') 'Renaming inventory must not rename Windows or the source hostname.'
        Assert-Throws {Rename-WinSecDevice -OutputRoot $root -DeviceId $local.id -Name ([string][char]27)} 'Terminal control characters must be rejected in device labels.'
        Assert-Throws {Get-WinSecOutputRoot $script:WinSecRoot} 'The repository root must not be accepted as an inventory output directory.'
        Assert-Throws {Assert-WinSecDevicePath -Root $root -Path (Join-Path $testRoot 'outside')} 'Device paths must remain below the configured output root.'

        $snapshotPaths=@()
        foreach ($edition in @('Windows11_Pro_22000','Windows11_Home_22631')) {
            $run=Join-Path (Join-Path (Join-Path $root $edition) $local.host) '20261107T000000Z_SYNTHETIC'
            $manifest=Join-Path $run 'manifest.json'
            [void](Save-WinSecJson $manifest @{schemaVersion='1';runId='SYNTHETIC';host=$local.host;status='COMPLETED';collectors=@();os=@{family='Windows11';build=22000;productType=1}})
            [void](Save-WinSecJson (Join-Path $run 'correlations/synthetic+synthetic.json') @{synthetic=$true})
            [void](Save-WinSecJson (Join-Path $run 'export/nistcsf/synthetic.json') @{synthetic=$true})
            $snapshotPaths+=$manifest
        }
        $otherRun=Join-Path $root 'Windows11_Pro_22000/SYNTHETIC_OTHER/20261107T000000Z_SYNTHETIC'
        $otherManifest=Join-Path $otherRun 'manifest.json'
        [void](Save-WinSecJson $otherManifest @{schemaVersion='1';runId='SYNTHETIC_OTHER';host='SYNTHETIC_OTHER';status='COMPLETED';collectors=@();os=@{family='Windows11';build=22000;productType=1}})
        $otherHash=Get-WinSecHash $otherManifest
        $inventory=Get-WinSecDeviceInventory $root
        Assert-Test (@($inventory.devices).Count -eq 2) 'Existing captures must be discovered without querying their hardware.'
        Assert-Test (@(Get-WinSecDeviceSnapshots -OutputRoot $root -DeviceId $local.id).Count -eq 2) 'Inventory must include captures across Windows editions and builds.'
        Assert-Throws {Remove-WinSecDeviceData -OutputRoot $root -DeviceId $local.id -Confirmation 'wrong'} 'Deletion must require the exact selected hostname.'
        Assert-Test (Test-Path $snapshotPaths[0]) 'A failed confirmation must preserve all captures.'
        Assert-Throws {Remove-WinSecDeviceData -OutputRoot $root -DeviceId '../outside' -Confirmation '../outside'} 'Unregistered device IDs must not become deletion paths.'

        $outside=Join-Path $testRoot 'outside'
        [void](Save-WinSecJson (Join-Path $outside 'sentinel.json') @{synthetic='preserve'})
        $link=Join-Path (Split-Path -Parent $snapshotPaths[1]) 'junction'
        [void](New-Item -ItemType Junction -Path $link -Target $outside)
        try {
            Assert-Throws {Remove-WinSecDeviceData -OutputRoot $root -DeviceId $local.id -Confirmation $local.host} 'Deletion must reject junctions before deleting any capture.'
            Assert-Test ((Test-Path $snapshotPaths[0]) -and (Test-Path $snapshotPaths[1]) -and (Test-Path (Join-Path $outside 'sentinel.json'))) 'A rejected deletion must preserve both source trees and the junction target.'
        } finally { [IO.Directory]::Delete($link) }
        $plan=@(Get-WinSecDeviceRemovalPlan -OutputRoot $root -DeviceId $local.id)
        Assert-Test ($plan.Count -eq 2) 'Removal must cover all host folders and no other devices.'
        $inventory=Remove-WinSecDeviceData -OutputRoot $root -DeviceId $local.id -Confirmation $local.host
        Assert-Test (@($inventory.devices | Where-Object {$_.id -eq $local.id}).Count -eq 0) 'Deletion must remove the selected inventory record.'
        Assert-Test (@(Get-WinSecDeviceDirectories -OutputRoot $root -DeviceId $local.id).Count -eq 0) 'Deletion must remove the complete device trees, including exports and correlations.'
        Assert-Test ((Get-WinSecHash $otherManifest) -eq $otherHash -and (Test-Path (Join-Path $outside 'sentinel.json'))) 'Deletion must preserve other devices and all data outside their roots.'

        # Exercise the real input reader and inventory UI with queued keys.
        $script:keys=New-Object System.Collections.Queue
        function Read-WinSecKey {
            if ($script:keys.Count -eq 0) { throw 'Unexpected extra input read.' }
            return $script:keys.Dequeue()
        }
        function Get-WinSecCursor {return $null}
        function Clear-Host {}
        function Show-WinSecBanner {}
        function Push-Key {param([int]$Code) $script:keys.Enqueue([pscustomobject]@{VirtualKeyCode=$Code;Character=[char]0})}
        function Push-Text {
            param([string]$Text,[switch]$Enter)
            foreach ($ch in $Text.ToCharArray()) {$script:keys.Enqueue([pscustomobject]@{VirtualKeyCode=0;Character=$ch})}
            if ($Enter) {Push-Key 13}
        }
        $inventory=Register-WinSecDevice -OutputRoot $root -LocalDevice $local
        $run=Split-Path -Parent $snapshotPaths[0]
        [void](Save-WinSecJson (Join-Path $run 'manifest.json') @{schemaVersion='1';runId='SYNTHETIC';host=$local.host;status='COMPLETED';collectors=@();os=@{family='Windows11';build=22000;productType=1}})
        Push-Key 113
        Push-Text 'UI workstation' -Enter
        Push-Key 46
        Push-Key 27
        Push-Key 13
        Push-Key 27
        Push-Text 'q'
        Invoke-WinSecMenu -OutputRoot $root 6>$null
        $inventory=Get-WinSecDeviceInventory $root
        Assert-Test (($inventory.devices | Where-Object {$_.id -eq $local.id}).name -eq 'UI workstation') 'F2 must persist the selected device label.'
        Assert-Test ((Test-Path $snapshotPaths[0]) -and $script:keys.Count -eq 0) 'Esc must cancel Supr without deleting data or requesting another Enter.'
        Push-Key 46
        Push-Text 'wrong' -Enter
        Push-Key 46
        Push-Text $local.host -Enter
        Push-Key 27
        Push-Text 'q'
        $deleted=@(Invoke-WinSecMenu -OutputRoot $root 6>&1)
        $deletedText=($deleted | ForEach-Object {$_.ToString()}) -join [Environment]::NewLine
        Assert-Test ([regex]::Matches($deletedText,'Device and snapshots deleted:').Count -eq 1) 'A confirmed device deletion must notify once, then disappear on the next navigation.'
        Assert-Test (-not (Test-Path $snapshotPaths[0]) -and (Get-WinSecHash $otherManifest) -eq $otherHash) 'Supr must delete only the confirmed host after rejecting an incorrect confirmation.'
        $remaining=Get-WinSecDeviceInventory $root
        Assert-Test (@($remaining.devices | Where-Object {$_.id -eq $local.id}).Count -eq 0) 'Supr must remove the device record as well as its captures.'

        # Reopen saved scans, including a control absent from the latest snapshot.
        $historyRoot=Join-Path $testRoot 'history'
        $hostRoot=Join-Path $historyRoot ('Windows11_SYNTHETIC_22000/'+$local.host)
        $systemRun=Join-Path $hostRoot '20261101T000000Z_SYNTHETIC_SYSTEM'
        $networkRun=Join-Path $hostRoot '20261102T000000Z_SYNTHETIC_NETWORK'
        $systemEntries=@(foreach ($pair in @(@('WindowsDefender','COMPLETED'),@('WindowsFirewall','PARTIAL'))) {
            $relative='SystemSecurity/'+$pair[0]+'.json'
            $path=Join-Path $systemRun $relative
            [void](Save-WinSecJson $path @{schemaVersion='1';runId='SYNTHETIC_SYSTEM';collector=$pair[0];status=$pair[1];data=@{synthetic=$true}})
            @{id=$pair[0];domain='SystemSecurity';status=$pair[1];path=$relative;sha256=(Get-WinSecHash $path)}
        })
        $smbPath=Join-Path $networkRun 'NetworkSecurity/SMB.json'
        [void](Save-WinSecJson $smbPath @{schemaVersion='1';runId='SYNTHETIC_NETWORK';collector='SMB';status='COMPLETED';data=@{synthetic=$true}})
        $systemManifest=Join-Path $systemRun 'manifest.json'
        $networkManifest=Join-Path $networkRun 'manifest.json'
        $os=@{family='Windows11';build=22000;productType=1;edition='SYNTHETIC';arch='SYNTHETIC'}
        [void](Save-WinSecJson $systemManifest @{schemaVersion='1';runId='SYNTHETIC_SYSTEM';host=$local.host;status='PARTIAL';sessionState='CLOSED';collectors=$systemEntries;os=$os})
        [void](Save-WinSecJson $networkManifest @{schemaVersion='1';runId='SYNTHETIC_NETWORK';host=$local.host;status='COMPLETED';sessionState='CLOSED';collectors=@(@{id='SMB';domain='NetworkSecurity';status='COMPLETED';path='NetworkSecurity/SMB.json';sha256=(Get-WinSecHash $smbPath)});os=$os})
        [IO.File]::SetLastWriteTimeUtc($systemManifest,[DateTime]::UtcNow.AddDays(-2))
        [IO.File]::SetLastWriteTimeUtc($networkManifest,[DateTime]::UtcNow.AddDays(-1))
        $systemHash=Get-WinSecHash $systemManifest
        $networkHash=Get-WinSecHash $networkManifest
        function Get-WinSecSMBEvidence {param([switch]$Deep) New-WinSecPayload -Data @{synthetic=$true} -Sources @('SYNTHETIC')}
        Push-Key 13
        Push-Text '1'
        Push-Text 'winsec -a windowsDefender -n' -Enter
        Push-Key 27
        Push-Text 'winsec -a system -n' -Enter
        Push-Key 27
        Push-Text 'winsec -s smb' -Enter
        Push-Key 27
        Push-Text '1'
        Push-Text 'q'
        $screen=@(Invoke-WinSecMenu -OutputRoot $historyRoot 6>&1)
        $text=($screen | ForEach-Object {$_.ToString()}) -join [Environment]::NewLine
        Assert-Test ([regex]::Matches($text,'Snapshot created:').Count -eq 1) 'A new scan must notify exactly once, without repeating its path on later pages.'
        Assert-Test ($text -match 'windowsDefender\s+Scanned \(saved\)' -and $text -match 'windowsFirewall\s+Scanned \(partial\) \(saved\)') 'Previously scanned controls must retain their complete or partial state across sessions.'
        Assert-Test ($text -match 'smb\s+Scanned' -and $text -match 'secureBoot\s+Not yet') 'Only controls without any saved attempt may show Not yet.'
        foreach ($name in @('windowsDefender','systemSecurity')) {
            $export=Get-Content (Join-Path $systemRun ('export/nistcsf/'+$name+'.json')) -Raw | ConvertFrom-Json
            Assert-Test ($export.sourceRunId -eq 'SYNTHETIC_SYSTEM') 'Saved control and section analysis must use one matching source snapshot.'
        }
        Assert-Test (-not (Test-Path (Join-Path $networkRun 'export'))) 'Saved analysis must not be written under an unrelated latest snapshot.'
        Assert-Test ((Get-WinSecHash $systemManifest) -eq $systemHash -and (Get-WinSecHash $networkManifest) -eq $networkHash) 'Reopening, analyzing and scanning must preserve older manifests.'
        $latest=@(Get-WinSecDeviceSnapshots -OutputRoot $historyRoot -DeviceId $local.id)
        $newContext=Get-WinSecSnapshotManifest $latest[0].FullName
        Assert-Test ($latest.Count -eq 3 -and @($newContext.Manifest.collectors).Count -eq 1 -and $newContext.Manifest.collectors[0].id -eq 'SMB') 'A new scan must create its own run without copying older controls into it.'
        Push-Key 13
        Push-Text '1'
        Push-Text 'q'
        $reopened=@(Invoke-WinSecMenu -OutputRoot $historyRoot 6>&1)
        $text=($reopened | ForEach-Object {$_.ToString()}) -join [Environment]::NewLine
        Assert-Test ($text -notmatch 'Snapshot created:|Snapshot saved:|Snapshot:|File created:') 'Opening a saved device must not generate file notifications or a permanent snapshot path.'
        Assert-Test ($text -match 'windowsDefender\s+Scanned \(saved\)' -and $text -notmatch 'windowsDefender\s+Not yet') 'Reopening after a different section scan must still show older saved control states.'
        Assert-Test (@(Get-WinSecDeviceSnapshots -OutputRoot $historyRoot -DeviceId $local.id).Count -eq 3) 'Viewing a saved device must not create another run.'

        Push-Key 40
        Push-Key 38
        Push-Key 38
        Push-Key 13
        Push-Text 'q'
        $arrows=@(Invoke-WinSecMenu -OutputRoot $root 6>&1)
        $text=($arrows | ForEach-Object {$_.ToString()}) -join [Environment]::NewLine
        Assert-Test ($text.Contains('  Device: SYNTHETIC_OTHER') -and $script:keys.Count -eq 0) 'Up and Down must move the highlight, wrap at the list boundary and open the highlighted device with Enter.'
        Push-Text '2' -Enter
        Push-Text 'q'
        $numeric=@(Invoke-WinSecMenu -OutputRoot $root 6>&1)
        $text=($numeric | ForEach-Object {$_.ToString()}) -join [Environment]::NewLine
        Assert-Test ($text.Contains('  Device: SYNTHETIC_OTHER') -and $script:keys.Count -eq 0) 'A device number plus one Enter must open that device directly.'

        $selectionRoot=Join-Path $testRoot 'selection'
        $selection=Register-WinSecDevice -OutputRoot $selectionRoot -LocalDevice $local
        foreach ($index in 1..11) {
            $name='SYNTHETIC_SAVED_{0:00}' -f $index
            $selection.devices+= [pscustomobject]@{
                id=(Get-WinSecDeviceId $name);host=$name;name=$name
                hardware=$null;os=$null;warnings=@();firstSeenAtUtc=$null;lastSeenAtUtc=$null
            }
        }
        Save-WinSecDeviceInventory -OutputRoot $selectionRoot -Inventory $selection
        Push-Text '0' -Enter
        Push-Text '99' -Enter
        Push-Text '12' -Enter
        Push-Text 'q'
        $multiDigit=@(Invoke-WinSecMenu -OutputRoot $selectionRoot 6>&1)
        $text=($multiDigit | ForEach-Object {$_.ToString()}) -join [Environment]::NewLine
        Assert-Test ($text.Contains('  Device: SYNTHETIC_SAVED_11') -and $script:keys.Count -eq 0) 'Multi-digit numbers must be read completely and open the corresponding device on Enter.'
        Assert-Test ($text.Contains('Invalid device number.') -and -not $text.Contains('  Device: '+$local.host)) 'Invalid numbers must keep the inventory open without opening the previous selection.'

        $script:collectionCalls=0
        function Invoke-WinSecCollection { $script:collectionCalls++; throw 'No live collection allowed in this test.' }
        Push-Key 27
        Push-Key 40
        Push-Key 13
        Push-Text 'winsec -s system' -Enter
        Push-Text 'q'
        Invoke-WinSecMenu -OutputRoot $root 6>$null
        Assert-Test ($script:collectionCalls -eq 0 -and $script:keys.Count -eq 0) 'A saved device must be browsable but must never trigger a remote or local scan.'
        Write-Output ('PASS: '+$script:assertions+' device assertions')
    } $testRoot
} finally {
    $env:COMPUTERNAME=$previousComputerName
    $resolved=[IO.Path]::GetFullPath($testRoot)
    if (-not $resolved.StartsWith($tempBase,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($resolved) -notlike 'winsec-devices-test-*') { throw 'Unsafe test cleanup path.' }
    if (Test-Path -LiteralPath $resolved) { Remove-Item -LiteralPath $resolved -Recurse -Force }
    Remove-Module WinSecAnalyzer -ErrorAction SilentlyContinue
}
