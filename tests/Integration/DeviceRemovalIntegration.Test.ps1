# Native deletion against a disposable installation with synthetic identities.
# Protects the working inventory and never invokes a Windows security check.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$sourceRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$temporaryBase=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\','/')
$ownedName='WinSec-Removal-Test-'+[guid]::NewGuid().ToString('N')
$sandbox=[IO.Path]::GetFullPath((Join-Path $temporaryBase $ownedName))
$workingInventory=Join-Path $sourceRoot 'data/devices.json'
$guard=$null; $guardHash=$null; $existed=[IO.File]::Exists($workingInventory)
$savedHostname=$env:COMPUTERNAME
$script:passed=0; $script:failed=0; $script:consent=$true
function Get-CimInstance {
    [CmdletBinding()]
    param($Namespace,$ClassName,$Property,$OperationTimeoutSec)
    if ($ClassName -cne 'Win32_ComputerSystemProduct' -or $Property -cne 'UUID') { throw 'Unexpected Windows query.' }
    return [pscustomobject]@{UUID=$script:uuid}
}
function Assert-WinSecRemovalIntegration {
    param([bool]$Value,[string]$Message='Native removal assertion failed.')
    if (-not $Value) { throw $Message }
}
function New-WinSecRemovalInstallation {
    $script:uuid='12345678-1234-4567-89ab-123456789abc'; $env:COMPUTERNAME='FIRST-FIXTURE'
    $script:first=Register-WinSecLocalDevice -ProjectRoot $sandbox
    $script:uuid='87654321-4321-4567-89ab-cba987654321'; $env:COMPUTERNAME='SECOND-FIXTURE'
    $script:second=Register-WinSecLocalDevice -ProjectRoot $sandbox
    $script:uuid='12345678-1234-4567-89ab-123456789abc'; $env:COMPUTERNAME='FIRST-FIXTURE'
    $script:devices=@(Get-WinSecCLIDevices -ProjectRoot $sandbox -Devices (Import-WinSecDeviceInventory -ProjectRoot $sandbox).targets)
    $script:coordinator=New-WinSecScanCoordinator -ProjectRoot $sandbox
    $script:coordinator.RequireDeviceInventory=$true
    $script:historyPaths=@{}; $script:evidencePaths=@{};$script:technicalPaths=@{}
    foreach ($device in $script:devices) {
        $id=$device.DeviceId; $hash=Get-WinSecEvidenceHash $id
        $scanDir=Join-Path $sandbox ('data/scans/'+$hash)
        $evidenceDir=Join-Path $sandbox ('reports/evidence/'+$hash+'/scan-fixture')
        $null=[IO.Directory]::CreateDirectory($scanDir)
        $null=[IO.Directory]::CreateDirectory($evidenceDir)
        $scanPath=Join-Path $scanDir 'scan-fixture.json'; $evidencePath=Join-Path $evidenceDir 'fixture.wse'
        [IO.File]::WriteAllText($scanPath,(@{SchemaVersion='1.0.0';DeviceId=$id;ScanId='scan-fixture';Synthetic=$true}|ConvertTo-Json),[Text.Encoding]::UTF8)
        [IO.File]::WriteAllText($evidencePath,'SYNTHETIC-STORAGE-TEST',[Text.Encoding]::UTF8)
        $script:historyPaths[$id]=$scanPath; $script:evidencePaths[$id]=$evidencePath
        $script:coordinator.Sessions[(Get-WinSecScanSessionKey $id 'scan-fixture')]=[pscustomobject]@{DeviceId=$id; ScanId='scan-fixture'}
        $exports=Join-Path $sandbox ('reports/exports/'+$hash)
        $null=[IO.Directory]::CreateDirectory($exports)
        $script:technicalPaths[$id]=@()
        foreach($check in @('WSA-SYS-001','WSA-SYS-002','WSA-SYS-003')) {
            $stamp=[datetime]::UtcNow.AddMinutes(-1).ToString('o')
            $report=[pscustomobject]@{SchemaVersion='1.0.0';CatalogVersion='1.0.0';DeviceId=$id;ScanId='scan-fixture';
                CheckId=$check;SectionKey='SystemSecurity';ScopeType='SECTION';ScopeKey='SystemSecurity';
                DeviceName='SYNTHETIC';Hostname='SYNTHETIC';Profile='UNRESOLVED';ObservedOSRelease='UNRESOLVED';ObservedEdition='UNRESOLVED';
                StartedAtUTC=$stamp;CompletedAtUTC=$stamp;CollectedAtUTC=$stamp;GeneratedAtUTC=$stamp;CollectorStatus='ERROR';
                Rows=@(Get-WinSecTechnicalDefinitions $check|ForEach-Object {
                    [pscustomobject]@{SettingId=$_.Id;Value=$null;State='NOT_COLLECTED';Reason='UNAVAILABLE'}
                })}
            $body=ConvertTo-WinSecTechnicalBody $report
            $meta=@{SchemaVersion='1.0.0';DeviceId=$id;ScanId='scan-fixture';CheckId=$check;ScopeType='SECTION';ScopeKey='SystemSecurity';ContentSha256=(Get-WinSecReportTextHash $body)}
            $text="WinSec technical scan report`n"+(ConvertTo-Json $meta -Compress)+"`n`n"+$body
            $technical=Join-Path $exports ($check+'.txt')
            [IO.File]::WriteAllText($technical,$text,[Text.Encoding]::UTF8)
            $script:technicalPaths[$id]+=$technical
            # New Markdown snapshots coexist with legacy TXT without rewriting it.
            $body=ConvertTo-WinSecTechnicalMarkdown $report
            $meta.SchemaVersion='2.0.0';$meta.ContentSha256=Get-WinSecReportTextHash $body
            $technical=Join-Path $exports ($check+'.md')
            [IO.File]::WriteAllText($technical,("<!-- WinSec technical report`n"+(ConvertTo-Json $meta -Compress)+"`n-->`n"+$body),[Text.Encoding]::UTF8)
            $script:technicalPaths[$id]+=$technical
            if($check -ceq 'WSA-SYS-002') {
                $control=[pscustomobject]@{DeviceId=$id;ScanId='scan-fixture';CheckId=$check;SectionKey='SystemSecurity';
                    Status='ERROR';ObservedStatus='ERROR';TimestampUTC=$stamp}
                $session=New-WinSecResultSession -DeviceId $id -ScanId scan-fixture -CatalogVersion '1.0.0' -ExpectedCheckIds @($check) `
                    -ControlResults @($control) -StartedAtUTC $stamp -CompletedAtUTC $stamp -ExecutionStatus COMPLETED_WITH_ERRORS `
                    -ScopeType SECTION -ScopeKey SystemSecurity
                $source=[pscustomobject]@{CheckId=$check;ScanId='scan-fixture';ScopeType='SECTION';ScopeKey='SystemSecurity';CompletedAtUTC=$stamp;
                    Origin='RECORDS';PublicResult=(ConvertTo-WinSecPublicScanResult $session);CatalogVersion=$session.CatalogVersion;ExpectedCheckIds=@($check)}
                $analysis=New-WinSecFrameworkAnalysis -ProjectRoot $sandbox -DeviceId $id -DeviceName SYNTHETIC -ScopeType SECTION `
                    -ScopeKey SystemSecurity -FrameworkId nist-csf -Sources @($source) -Reports @($report)
                $body=New-WinSecFrameworkMarkdown $analysis
                $metadata=@{SchemaVersion='1.0.0';DeviceId=$id;AnalysisId=$analysis.AnalysisId;FrameworkId=$analysis.FrameworkId;ContentSha256=(Get-WinSecReportTextHash $body)}
                [IO.File]::WriteAllText((Join-Path $exports 'framework.md'),("<!-- WinSec framework findings`n"+(ConvertTo-Json $metadata -Compress)+"`n-->`n"+$body),[Text.Encoding]::UTF8)
            }
        }
        # Independently constructed legacy fixtures must remain recognizable.
        $body="# Synthetic public report`n"
        $meta=@{SchemaVersion='1.0.0';DeviceId=$id;ScanId='scan-fixture';ContentSha256=(Get-WinSecReportTextHash $body)}|ConvertTo-Json -Compress
        [IO.File]::WriteAllText((Join-Path $exports 'legacy.txt'),("WinSec public text report`n"+$meta+"`n`n"+$body),[Text.Encoding]::UTF8)
        [IO.File]::WriteAllText((Join-Path $exports 'public.md'),("<!-- WinSec public report`n"+$meta+"`n-->`n"+$body),[Text.Encoding]::UTF8)
    }
    $script:consent=$true
}
function Invoke-WinSecNativeRemoval {
    param([scriptblock]$Confirm={return $script:consent},[string]$DeviceId=$script:first.DeviceId)
    Remove-WinSecManagedDevice -ProjectRoot $sandbox -DeviceId $DeviceId -Coordinator $script:coordinator -Devices $script:devices -ConfirmAction $Confirm
}
function Test-WinSecRemovalIntegrationCase {
    param([string]$Name,[scriptblock]$Action)
    try { $null=& $Action; $script:passed++; Write-Host "[PASS] $Name" }
    catch { $script:failed++; Write-Host "[FAIL] $Name : $($_.Exception.Message)" }
}
try {
    if ($existed) {
        $guard=[IO.File]::Open($workingInventory,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $guardHash=(Get-FileHash -LiteralPath $workingInventory).Hash
    }
    if (Test-Path -LiteralPath $sandbox) { throw 'Fixture installation must not exist.' }
    $null=[IO.Directory]::CreateDirectory($sandbox)
    Copy-Item -LiteralPath (Join-Path $sourceRoot 'src') -Destination $sandbox -Recurse
    Copy-Item -LiteralPath (Join-Path $sourceRoot 'config') -Destination $sandbox -Recurse
    . (Join-Path $sandbox 'src/Core/ScanCoordinator.ps1')
    $script:realReplace=(Get-Command Invoke-WinSecDeviceInventoryReplace).ScriptBlock
    $script:replaceFailures=0; $script:replaceCalls=0; $script:changeBeforeRetry=$false
    function Invoke-WinSecDeviceInventoryReplace {
        [CmdletBinding()]
        param($Source,$Destination)
        $script:replaceCalls++
        if ($script:replaceFailures -gt 0) {
            $script:replaceFailures--
            if ($script:changeBeforeRetry) { [IO.File]::AppendAllText($Destination,' ') }
            throw (New-Object IO.IOException('Synthetic replacement failure.', -2147023721))
        }
        & $script:realReplace @PSBoundParameters
    }
    . (Join-Path $sandbox 'src/Services/DeviceManagementService.ps1')
    $script:realRemovalBackend=(Get-Command Remove-WinSecManagedDevice).ScriptBlock
    function Remove-WinSecManagedDevice {
        [CmdletBinding()]
        param($ProjectRoot,$DeviceId,$Coordinator,$Devices,[scriptblock]$ConfirmAction)
        $script:lastRemovalResult=$null
        $result=& $script:realRemovalBackend @PSBoundParameters
        $script:lastRemovalResult=$result
        return $result
    }
    . (Join-Path $sandbox 'src/CLI/Invoke-WinSecCLI.ps1')
    . (Join-Path $sandbox 'src/UI/Core/NavigationController.ps1')
    . (Join-Path $sandbox 'src/UI/Core/KeyboardController.ps1')
    function Show-WinSecDeviceRemovalConfirmation { param($Request) return $script:consent }
    function Show-WinSecCLICurrentScreen { param($State,$Context) $script:startup=$Context; $State.ExitRequested=$true }
    New-WinSecRemovalInstallation
    $inventoryPath=Join-Path $sandbox 'data/devices.json'
    Test-WinSecRemovalIntegrationCase 'Removal recognizes three technical Markdown, legacy TXT and the framework report' {
        $plan=Get-WinSecDeviceRemovalPlan $sandbox $script:first.DeviceId $script:coordinator $script:devices
        foreach($path in $script:technicalPaths[$script:first.DeviceId]) {
            Assert-WinSecRemovalIntegration (@($plan.Files|Where-Object Path -CEQ $path).Count -eq 1)
        }
        Assert-WinSecRemovalIntegration (@($plan.Files|Where-Object {$_.Path.EndsWith('legacy.txt') -or $_.Path.EndsWith('public.md')}).Count -eq 2)
        Assert-WinSecRemovalIntegration (@($plan.Files|Where-Object {$_.Path.EndsWith('framework.md')}).Count -eq 1)
    }
    Test-WinSecRemovalIntegrationCase 'Corrupt or foreign technical and framework Markdown rejects before consent' {
        foreach($name in @('WSA-SYS-001.md','framework.md')) {
            $path=Join-Path $sandbox ('reports/exports/'+(Get-WinSecEvidenceHash $script:first.DeviceId)+'/'+$name)
            $other=Join-Path $sandbox ('reports/exports/'+(Get-WinSecEvidenceHash $script:second.DeviceId)+'/'+$name)
            $original=[IO.File]::ReadAllBytes($path)
            try {
                foreach($bytes in @([Text.Encoding]::UTF8.GetBytes('corrupt'),[IO.File]::ReadAllBytes($other))) {
                    [IO.File]::WriteAllBytes($path,$bytes);$script:confirmCount=0;$caught=$false
                    try {$null=Invoke-WinSecNativeRemoval -Confirm {$script:confirmCount++;$true}} catch {$caught=$true}
                    Assert-WinSecRemovalIntegration ($caught -and $script:confirmCount -eq 0 -and [IO.File]::Exists($path))
                }
            } finally {[IO.File]::WriteAllBytes($path,$original)}
        }
    }
    Test-WinSecRemovalIntegrationCase 'Corrupt and foreign technical TXT reject removal before confirmation and preserve every file' {
        $path=$script:technicalPaths[$script:first.DeviceId][0];$original=[IO.File]::ReadAllBytes($path)
        $foreign=[IO.File]::ReadAllBytes($script:technicalPaths[$script:second.DeviceId][0])
        try {
            foreach($bytes in @([Text.Encoding]::UTF8.GetBytes('invalid technical file'),$foreign)) {
                [IO.File]::WriteAllBytes($path,$bytes);$script:confirmCount=0;$caught=$false
                try {$null=Invoke-WinSecNativeRemoval -Confirm {$script:confirmCount++;$true}} catch {$caught=$true}
                Assert-WinSecRemovalIntegration ($caught -and $script:confirmCount -eq 0)
                foreach($owner in $script:technicalPaths.Keys){foreach($file in $script:technicalPaths[$owner]){Assert-WinSecRemovalIntegration ([IO.File]::Exists($file))}}
            }
        } finally {[IO.File]::WriteAllBytes($path,$original)}
    }
    Test-WinSecRemovalIntegrationCase 'Atomic replacement retries transient 1175 errors within a bounded unchanged snapshot' {
        $inv=Import-WinSecDeviceInventory $sandbox
        $lease=Open-WinSecDeviceInventoryStore $sandbox
        $script:replaceCalls=0; $script:replaceFailures=2
        try { Save-WinSecDeviceInventory -Store $lease -Json ($inv|ConvertTo-Json -Depth 8) -ExpectedFingerprint (Get-WinSecDeviceInventoryFingerprint $sandbox) }
        finally { $script:replaceFailures=0; $lease.Lock.Dispose() }
        Assert-WinSecRemovalIntegration ($script:replaceCalls -eq 3 -and (Import-WinSecDeviceInventory $sandbox).targets.Count -eq 2)
    }
    Test-WinSecRemovalIntegrationCase 'Atomic retries abort on concurrent changes and stop after five persistent failures' {
        $original=[IO.File]::ReadAllBytes($inventoryPath)
        foreach ($change in @($true,$false)) {
            $lease=Open-WinSecDeviceInventoryStore $sandbox
            $json=[Text.Encoding]::UTF8.GetString($original).TrimStart([char]0xFEFF)
            $script:replaceCalls=0; $script:replaceFailures=99; $script:changeBeforeRetry=$change
            $caught=$false
            try { Save-WinSecDeviceInventory -Store $lease -Json $json -ExpectedFingerprint (Get-WinSecDeviceInventoryFingerprint $sandbox) }
            catch { $caught=$true }
            finally {
                $script:replaceFailures=0; $script:changeBeforeRetry=$false; $lease.Lock.Dispose()
            }
            Assert-WinSecRemovalIntegration ($caught -and (($change -and $script:replaceCalls -eq 1) -or (-not $change -and $script:replaceCalls -eq 5)))
            [IO.File]::WriteAllBytes($inventoryPath,$original)
        }
    }
    $upperEvidencePath=$null
    Test-WinSecRemovalIntegrationCase 'Known case variants include their existing hashed evidence directories' {
        $upper=$script:first.DeviceId.ToUpperInvariant()
        $script:devices[0].DeviceId=$upper
        $upperDirectory=Join-Path $sandbox ('reports/evidence/'+(Get-WinSecEvidenceHash $upper))
        $null=[IO.Directory]::CreateDirectory($upperDirectory)
        $script:upperEvidencePath=Join-Path $upperDirectory 'case-fixture.wse'
        [IO.File]::WriteAllText($script:upperEvidencePath,'SYNTHETIC-STORAGE-TEST')
        $plan=Get-WinSecDeviceRemovalPlan -ProjectRoot $sandbox -DeviceId $script:first.DeviceId -Coordinator $script:coordinator -Devices $script:devices
        Assert-WinSecRemovalIntegration (@($plan.Files | Where-Object Path -CEQ $script:upperEvidencePath).Count -eq 1)
    }
    Test-WinSecRemovalIntegrationCase 'Malformed duplicate and mixed stored identities reject before consent' {
        $file=$script:historyPaths[$script:first.DeviceId]; $original=[IO.File]::ReadAllBytes($file)
        $badDocuments=@(
            (@{SchemaVersion='1.0.0'; DeviceId=$script:second.DeviceId; ScanId='scan-fixture'}|ConvertTo-Json),
            (@{SchemaVersion='1.0.0'; DeviceId=$script:first.DeviceId; ScanId='scan-fixture'; ControlResults=@(@{DeviceId=$script:second.DeviceId;ScanId='scan-fixture'})}|ConvertTo-Json -Depth 8),
            (@{SchemaVersion='1.0.0'; DeviceId=$script:first.DeviceId; ScanId='scan-fixture'; Findings=@(@{DeviceId=$script:first.DeviceId;ScanId='foreign-scan'})}|ConvertTo-Json -Depth 8),
            (@{SchemaVersion='999.0.0'; DeviceId=$script:first.DeviceId; ScanId='scan-fixture'}|ConvertTo-Json),
            ('{"SchemaVersion":"1.0.0","DeviceId":"'+$script:second.DeviceId+'","DeviceId":"'+$script:first.DeviceId+'","ScanId":"scan-fixture"}'),
            '{broken'
        )
        try {
            foreach ($json in $badDocuments) {
                [IO.File]::WriteAllText($file,$json,[Text.Encoding]::UTF8)
                $script:confirmCount=0; $caught=$false
                try { $null=Invoke-WinSecNativeRemoval -Confirm {$script:confirmCount++; $true} } catch { $caught=$true }
                Assert-WinSecRemovalIntegration ($caught -and $script:confirmCount -eq 0 -and [IO.File]::Exists($file) -and $script:coordinator.Sessions.Count -eq 2)
            }
        }
        finally { [IO.File]::WriteAllBytes($file,$original) }
    }
    Test-WinSecRemovalIntegrationCase 'A real junction cannot redirect deletion to another device' {
        $directory=[IO.Path]::GetDirectoryName($script:historyPaths[$script:first.DeviceId])
        $otherDirectory=[IO.Path]::GetDirectoryName($script:historyPaths[$script:second.DeviceId])
        $backup=Join-Path $sandbox 'data/history-fixture-backup'
        Assert-WinSecDeviceRemovalPath $sandbox $directory
        Assert-WinSecDeviceRemovalPath $sandbox $backup
        [IO.Directory]::Move($directory,$backup)
        try {
            $null=New-Item -ItemType Junction -Path $directory -Target $otherDirectory -ErrorAction Stop
            $caught=$false
            try { $null=Invoke-WinSecNativeRemoval } catch { $caught=$true }
            Assert-WinSecRemovalIntegration ($caught -and [IO.File]::Exists($script:historyPaths[$script:second.DeviceId]))
        }
        finally {
            if (Test-Path -LiteralPath $directory) {
                $link=Get-Item -LiteralPath $directory -Force
                if (($link.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 -or
                    -not [IO.Path]::GetFullPath($directory).StartsWith($sandbox+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe junction cleanup.' }
                [IO.Directory]::Delete($directory,$false)
            }
            Assert-WinSecDeviceRemovalPath $sandbox $backup
            Assert-WinSecDeviceRemovalPath $sandbox $directory
            [IO.Directory]::Move($backup,$directory)
        }
    }
    Test-WinSecRemovalIntegrationCase 'Native cancellation preserves file bytes timestamps and both session stores' {
        $before=(Get-FileHash -LiteralPath $inventoryPath).Hash
        $time=(Get-Item -LiteralPath $inventoryPath).LastWriteTimeUtc
        $script:consent=$false
        $result=Invoke-WinSecNativeRemoval
        Assert-WinSecRemovalIntegration ($null -eq $result -and (Get-FileHash -LiteralPath $inventoryPath).Hash -ceq $before -and
            (Get-Item -LiteralPath $inventoryPath).LastWriteTimeUtc -eq $time -and $script:coordinator.Sessions.Count -eq 2 -and
            [IO.File]::Exists($script:historyPaths[$script:first.DeviceId]) -and [IO.File]::Exists($script:evidencePaths[$script:first.DeviceId]))
        $script:consent=$true
    }
    Test-WinSecRemovalIntegrationCase 'An inventory change during consent rejects the stale deletion request' {
        $caught=$false
        try {
            $null=Invoke-WinSecNativeRemoval -Confirm {
                $inv=Import-WinSecDeviceInventory -ProjectRoot $sandbox
                $inv.targets[1].Description='Concurrent metadata'
                $lease=Open-WinSecDeviceInventoryStore -ProjectRoot $sandbox
                try { Save-WinSecDeviceInventory -Store $lease -Json ($inv|ConvertTo-Json -Depth 8) -ExpectedFingerprint (Get-WinSecDeviceInventoryFingerprint $sandbox) }
                finally { $lease.Lock.Dispose() }
                return $true
            }
        } catch { $caught=$true }
        Assert-WinSecRemovalIntegration ($caught -and [IO.File]::Exists($script:historyPaths[$script:first.DeviceId]) -and $script:coordinator.Sessions.Count -eq 2)
    }
    Test-WinSecRemovalIntegrationCase 'A held history file reports incomplete and a newly confirmed retry succeeds' {
        $reader=[IO.File]::Open($script:historyPaths[$script:first.DeviceId],[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        try { $result=Invoke-WinSecNativeRemoval }
        finally { $reader.Dispose() }
        Assert-WinSecRemovalIntegration ($result.Status -ceq 'INCOMPLETE' -and (Import-WinSecDeviceInventory $sandbox).targets.Count -eq 2 -and
            $script:coordinator.Sessions.Count -eq 1 -and [IO.File]::Exists($script:historyPaths[$script:second.DeviceId]))
        $result=Invoke-WinSecNativeRemoval
        Assert-WinSecRemovalIntegration ($result.Status -ceq 'REMOVED' -and (Import-WinSecDeviceInventory $sandbox).targets.Count -eq 1 -and
            -not [IO.File]::Exists($script:historyPaths[$script:first.DeviceId]) -and -not [IO.File]::Exists($script:evidencePaths[$script:first.DeviceId]) -and
            -not [IO.File]::Exists($script:upperEvidencePath))
    }
    Test-WinSecRemovalIntegrationCase 'Deleting one hardware identity preserves all data of the other device' {
        foreach($path in $script:technicalPaths[$script:first.DeviceId]){Assert-WinSecRemovalIntegration (-not [IO.File]::Exists($path))}
        foreach($path in $script:technicalPaths[$script:second.DeviceId]){Assert-WinSecRemovalIntegration ([IO.File]::Exists($path))}
        Assert-WinSecRemovalIntegration ([IO.File]::Exists($script:historyPaths[$script:second.DeviceId]) -and
            [IO.File]::Exists($script:evidencePaths[$script:second.DeviceId]) -and $script:coordinator.Sessions.Count -eq 1)
        $caught=$false
        try { $null=Resolve-WinSecScanTarget -Coordinator $script:coordinator -DeviceId $script:first.DeviceId } catch { $caught=$true }
        Assert-WinSecRemovalIntegration $caught
    }
    Test-WinSecRemovalIntegrationCase 'Real CLI restart registers this computer empty without recovering deleted history' {
        Invoke-WinSecCLI -ProjectRoot $sandbox
        Assert-WinSecRemovalIntegration ($script:startup.Devices.Count -eq 2 -and $script:startup.PublicScans.Count -eq 0 -and
            $script:startup.ScanCoordinator.Sessions.Count -eq 0 -and -not [IO.File]::Exists($script:historyPaths[$script:first.DeviceId]))
        $saved=Import-WinSecDeviceInventory $sandbox
        Assert-WinSecRemovalIntegration (-not (Test-WinSecDeviceInventoryRemoval $saved $script:first.DeviceId))
    }
    Test-WinSecRemovalIntegrationCase 'An inventory replace failure never reports successful removal or resurrects files' {
        $script:devices=@($script:startup.Devices)
        # Recreate only synthetic history that belongs to this fixture.
        $dir=[IO.Path]::GetDirectoryName($script:historyPaths[$script:first.DeviceId])
        $null=[IO.Directory]::CreateDirectory($dir)
        [IO.File]::WriteAllText($script:historyPaths[$script:first.DeviceId],
            (@{SchemaVersion='1.0.0';DeviceId=$script:first.DeviceId;ScanId='scan-fixture';Synthetic=$true}|ConvertTo-Json),[Text.Encoding]::UTF8)
        $reader=[IO.File]::Open($inventoryPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $before=(Get-FileHash -LiteralPath $inventoryPath).Hash
        try { $result=Invoke-WinSecNativeRemoval }
        finally { $reader.Dispose() }
        Assert-WinSecRemovalIntegration ($result.Status -ceq 'INCOMPLETE') 'A locked inventory must report incomplete.'
        Assert-WinSecRemovalIntegration ((Get-FileHash -LiteralPath $inventoryPath).Hash -ceq $before) 'The locked inventory must stay unchanged.'
        Assert-WinSecRemovalIntegration (-not [IO.File]::Exists($script:historyPaths[$script:first.DeviceId])) 'The approved history deletion must precede the failed commit.'
        $retry=Invoke-WinSecNativeRemoval
        Assert-WinSecRemovalIntegration ($retry.Status -ceq 'REMOVED') ('Retry failed: '+$retry.FailureStage+' / '+$retry.FailureCode)
    }
    Test-WinSecRemovalIntegrationCase 'Deleting a configured historical device prevents its catalog row from returning' {
        $configured=[pscustomobject]@{schemaVersion='1.0.0';targets=@([pscustomobject]@{
            DeviceId=$script:second.DeviceId; Hostname='SECOND-FIXTURE'; Mode='LOCAL'; Enabled=$false})}
        [IO.File]::WriteAllText((Join-Path $sandbox 'config/targets.json'),($configured|ConvertTo-Json -Depth 8),[Text.Encoding]::UTF8)
        $configuredRemoval=Invoke-WinSecNativeRemoval -DeviceId $script:second.DeviceId
        Assert-WinSecRemovalIntegration ($configuredRemoval.Status -ceq 'REMOVED') (
            'Configured removal failed: '+$configuredRemoval.FailureStage+' / '+$configuredRemoval.FailureCode)
        $catalogHash=(Get-FileHash -LiteralPath (Join-Path $sandbox 'config/targets.json')).Hash
        Invoke-WinSecCLI -ProjectRoot $sandbox
        Assert-WinSecRemovalIntegration ($script:startup.Devices.Count -eq 1 -and
            $script:startup.Devices[0].DeviceId -ceq $script:first.DeviceId -and
            (Get-FileHash -LiteralPath (Join-Path $sandbox 'config/targets.json')).Hash -ceq $catalogHash)
    }
    Test-WinSecRemovalIntegrationCase 'Real Delete/Supr navigation and CLI branch delete the last row without auto-registration' {
        $context=$script:startup
        $id=$script:first.DeviceId; $key='{0}:{1}{2}:{3}' -f $id.Length,$id,'scan-fixture'.Length,'scan-fixture'
        $context.PublicScans[$key]=[pscustomobject]@{DeviceId=$id;ScanId='scan-fixture'}
        $context.ActiveScanByDevice[$id]='scan-fixture'
        $navigationState=New-WinSecNavigationState
        $key=[pscustomobject]@{KeyDown=$true; Character=[char]0; VirtualKeyCode=46; ControlKeyState=0}
        $action=Get-WinSecKeyboardAction -KeyInfo $key -Screen Devices
        $null=Invoke-WinSecNavigationAction -State $navigationState -Action $action.Action -Devices $context.Devices
        $tokens=$null; $errors=$null
        $ast=[System.Management.Automation.Language.Parser]::ParseFile((Join-Path $sandbox 'src/CLI/Invoke-WinSecCLI.ps1'),[ref]$tokens,[ref]$errors)
        $branches=@($ast.FindAll({param($node)
            $node -is [System.Management.Automation.Language.IfStatementAst] -and
            $node.Extent.Text -match '^if \(\$navigationState\.PendingCommand -eq ''DeleteDevice''\)'
        },$true))
        Assert-WinSecRemovalIntegration ($branches.Count -eq 1 -and @($errors).Count -eq 0)
        $branch=[scriptblock]::Create($branches[0].Extent.Text)
        $registeredDevices=@($context.Devices)
        . $branch
        Assert-WinSecRemovalIntegration ($context.LastDeviceMessage -match 'were deleted') (
            'CLI branch outcome: '+$context.LastDeviceMessage+' / '+$script:lastRemovalResult.FailureStage+' / '+$script:lastRemovalResult.FailureCode)
        Assert-WinSecRemovalIntegration ($context.Devices.Count -eq 0 -and
            $context.PublicScans.Count -eq 0 -and $context.ActiveScanByDevice.Count -eq 0 -and
            (Import-WinSecDeviceInventory $sandbox).targets.Count -eq 0 -and $navigationState.DeviceIndex -eq 0 -and
            $null -eq $navigationState.PendingCommand -and $registeredDevices.Count -eq 0)
    }
    Test-WinSecRemovalIntegrationCase 'Native operations release locks and leave no temporary inventory files' {
        Assert-WinSecRemovalIntegration (@(Get-ChildItem -LiteralPath (Join-Path $sandbox 'data') -Force |
            Where-Object { $_.Name -like '.devices*' }).Count -eq 0)
    }
}
finally {
    $env:COMPUTERNAME=$savedHostname
    $guardFailed=$false
    try {
        if ($existed) { if ((Get-FileHash -LiteralPath $workingInventory).Hash -cne $guardHash) { $guardFailed=$true } }
        elseif ([IO.File]::Exists($workingInventory)) { $guardFailed=$true }
    }
    catch { $guardFailed=$true }
    finally { if ($null -ne $guard) { $guard.Dispose() } }
    $full=[IO.Path]::GetFullPath($sandbox)
    if ([IO.Path]::GetDirectoryName($full) -cne $temporaryBase -or [IO.Path]::GetFileName($full) -cnotmatch '^WinSec-Removal-Test-[a-f0-9]{32}$') { throw 'Unsafe cleanup path.' }
    if (Test-Path -LiteralPath $full) {
        $items=@((Get-Item -LiteralPath $full -Force))+@(Get-ChildItem -LiteralPath $full -Recurse -Force)
        foreach ($item in $items) {
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Unsafe cleanup link.' }
        }
        Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction Stop
    }
    if (Test-Path -LiteralPath $full) { throw 'Cleanup failed.' }
    if ($guardFailed) { throw 'Working inventory changed or could not be protected.' }
    Write-Host '[PASS] Fixture deleted; working inventory unchanged'
}
Write-Host "Passed: $script:passed; Failed: $script:failed"
if ($script:failed -gt 0) { throw 'Native device deletion integration tests failed.' }
