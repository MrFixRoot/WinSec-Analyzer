# Serialización, recuperación y conflictos con almacenamiento exclusivamente en memoria.
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
. (Join-Path $root 'src/CLI/Invoke-WinSecCLI.ps1')
. (Join-Path $root 'src/UI/Screens/MainMenu.ps1')
. (Join-Path $root 'src/UI/Screens/Results.ps1')
. (Join-Path $root 'src/UI/Screens/Devices.ps1')
. (Join-Path $root 'src/UI/Core/NavigationController.ps1')
. (Join-Path $PSScriptRoot '../Fixtures/DeviceInventoryMemoryStore.ps1')
$script:realPublicHistoryReader=(Get-Command Read-WinSecPublicHistoryArtifacts).ScriptBlock
$script:passed=0;$script:failed=0
function Assert-WinSecHistory {param([bool]$Value);if(-not $Value){throw 'Public history assertion failed.'}}
function Assert-WinSecHistoryReject {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-WinSecHistory $caught}
function New-WinSecHistoryFixture {
    param([string]$ScanId='scan-1',[string]$ScopeType='DEVICE',[string]$ScopeKey='ALL',[string]$DeviceId='local:CURRENT-FIXTURE')
    $record=[pscustomobject]@{DeviceId=$DeviceId;ScanId=$ScanId;CheckId='WSA-SYS-001';SectionKey='SystemSecurity';
        Status='INFORMATIONAL';ObservedStatus='INFORMATIONAL';Evidence=@{Secret='PRIVATE-HISTORY-MARKER'}}
    New-WinSecResultSession -DeviceId $DeviceId -ScanId $ScanId -ScopeType $ScopeType -ScopeKey $ScopeKey -ControlResults @($record) `
        -ExpectedCheckIds @('WSA-SYS-001') -ExecutionStatus COMPLETED -StartedAtUTC '2026-10-21T00:00:00Z' -CompletedAtUTC '2026-10-21T00:01:00Z' -CatalogVersion '1.0.0'
}
function Write-WinSecPublicHistoryArtifact {
    param($ProjectRoot,$Record)
    if($script:historyFailWrite){throw 'PRIVATE-HISTORY-MARKER'}
    $key=Get-WinSecScanSessionKey $Record.DeviceId $Record.ScanId
    if($script:historyMemory.ContainsKey($key)){throw 'Duplicate public session.'}
    $script:historyMemory[$key]=Get-WinSecPublicHistoryJson (ConvertFrom-WinSecPublicHistoryRecord $Record).Record
}
function Read-WinSecPublicHistoryArtifacts {
    param($ProjectRoot,$Devices,[ref]$TotalBytes)
    if($null -ne $TotalBytes){$TotalBytes.Value=0;foreach($json in $script:historyMemory.Values){$TotalBytes.Value+=[Text.Encoding]::UTF8.GetByteCount($json)}}
    foreach($json in $script:historyMemory.Values){ConvertFrom-WinSecStoredJson $json}
}
function New-WinSecHistoryContext {
    [pscustomobject]@{ProjectRoot=$root;Devices=@((Import-WinSecDeviceInventory $root).targets);ScanCoordinator=(New-WinSecScanCoordinator);
        PublicScans=@{};ActiveScanByDevice=@{};ActiveScanByScope=@{}}
}
function Test-WinSecHistoryCase {
    param([string]$Name,[scriptblock]$Action)
    Reset-WinSecInventoryMemoryStore;$null=Register-WinSecLocalDevice $root
    $script:historyMemory=@{};$script:historyFailWrite=$false
    try{$null=& $Action;Assert-WinSecHistory (-not $script:inventoryMemory.LeaseHeld -and $script:inventoryMemory.UnexpectedWrites -eq 0);
        $script:passed++;Write-Host "[PASS] $Name"}catch{$script:failed++;Write-Host "[FAIL] $Name : $($_.Exception.Message)";Write-Host $_.ScriptStackTrace}
}
function Invoke-WinSecNativeHistoryReadFixture {
    param([string]$Fault='')
    $record=New-WinSecPublicHistoryRecord (New-WinSecHistoryFixture)
    if($Fault -ceq 'Foreign'){$record=New-WinSecPublicHistoryRecord (New-WinSecHistoryFixture -DeviceId 'local:OLD-FIXTURE')}
    $script:nativeHistoryText=Get-WinSecPublicHistoryJson $record
    $script:nativeHistoryDirectory=Get-WinSecPublicHistoryPath $root 'local:CURRENT-FIXTURE'
    $script:nativeHistoryFile=Get-WinSecPublicHistoryPath $root 'local:CURRENT-FIXTURE' scan-1
    $script:nativeHistoryFault=$Fault;$script:nativeHistoryHashes=0
    $script:nativeTestPath=(Get-Command Test-Path).ScriptBlock;$script:nativeGetItem=(Get-Command Get-Item).ScriptBlock
    $script:nativeGetContent=(Get-Command Get-Content).ScriptBlock
    function Test-Path {
        [CmdletBinding()]param($LiteralPath,$Path,$PathType)
        if($LiteralPath -in @($script:nativeHistoryDirectory,$script:nativeHistoryFile)){return $true}
        & $script:nativeTestPath @PSBoundParameters
    }
    function Get-Item {
        [CmdletBinding()]param($LiteralPath,[switch]$Force)
        if($LiteralPath -in @($script:nativeHistoryDirectory,$script:nativeHistoryFile)){
            return [pscustomobject]@{FullName=$LiteralPath;PSIsContainer=($LiteralPath -ceq $script:nativeHistoryDirectory);
                Attributes=if($script:nativeHistoryFault -ceq 'Link'){[IO.FileAttributes]::ReparsePoint}else{[IO.FileAttributes]::Normal};
                Length=if($script:nativeHistoryFault -ceq 'Oversize'){1048577}else{[Text.Encoding]::UTF8.GetByteCount($script:nativeHistoryText)};
                Extension=if($script:nativeHistoryFault -ceq 'Temporary'){'.tmp'}else{'.json'}}
        }
        & $script:nativeGetItem @PSBoundParameters
    }
    function Get-ChildItem {
        [CmdletBinding()]param($LiteralPath,[switch]$Force)
        if($LiteralPath -ceq $script:nativeHistoryDirectory){return Get-Item $script:nativeHistoryFile}
        throw 'Unexpected fixture enumeration.'
    }
    function Get-Content {
        [CmdletBinding()]param($LiteralPath,[switch]$Raw,$Encoding)
        if($LiteralPath -ceq $script:nativeHistoryFile){return $script:nativeHistoryText}
        & $script:nativeGetContent @PSBoundParameters
    }
    function Get-FileHash {
        [CmdletBinding()]param($LiteralPath,$Algorithm)
        if($LiteralPath -ceq $script:nativeHistoryFile){$script:nativeHistoryHashes++;return [pscustomobject]@{
            Hash=if($script:nativeHistoryFault -ceq 'Changed' -and $script:nativeHistoryHashes -gt 1){'B'*64}else{'A'*64}}}
        Microsoft.PowerShell.Utility\Get-FileHash @PSBoundParameters
    }
    $size=0
    $records=@(& $script:realPublicHistoryReader -ProjectRoot $root -Devices @([pscustomobject]@{DeviceId='local:CURRENT-FIXTURE'}) -TotalBytes ([ref]$size))
    return [pscustomobject]@{Records=$records;Bytes=$size}
}
Test-WinSecHistoryCase 'Roundtrip stores only safe projections and original provenance' {
    $source=New-WinSecHistoryFixture;$record=New-WinSecPublicHistoryRecord $source
    $json=Get-WinSecPublicHistoryJson $record;$loaded=ConvertFrom-WinSecPublicHistoryRecord (ConvertFrom-WinSecStoredJson $json)
    Assert-WinSecHistory ($json -notmatch 'PRIVATE-HISTORY-MARKER|"Evidence"|"ComputerName"|"CriteriaSelections"' -and
        $loaded.Record.CatalogVersion -ceq '1.0.0' -and $loaded.PublicResult.ScopeType -ceq 'DEVICE' -and $loaded.PublicResult.OverallStatus -ceq 'NOT_SCORED')
    $source.ControlResults[0].Status='ERROR'
    Assert-WinSecHistory ($record.PublicResult.ControlResults[0].Status -ceq 'INFORMATIONAL')
}
foreach($field in @('Evidence','RawEvidence','Metadata','Recommendation','Score')){
    Test-WinSecHistoryCase ('Unknown fields reject even with a recomputed digest: '+$field) {
        $record=New-WinSecPublicHistoryRecord (New-WinSecHistoryFixture)
        $record.PublicResult.ControlResults[0] | Add-Member -NotePropertyName $field -NotePropertyValue 'PRIVATE-HISTORY-MARKER'
        $record.ContentSha256=Get-WinSecPublicHistoryDigest $record
        Assert-WinSecHistoryReject {ConvertFrom-WinSecPublicHistoryRecord $record}
    }
}
foreach($mutation in @(
    {$args[0].PublicResult.DeviceId='local:OTHER'},{$args[0].PublicResult.ControlResults[0].ScanId='other-scan'},
    {$args[0].ScopeType='SECTION';$args[0].ScopeKey='NetworkSecurity'},
    {$args[0].PublicResult.OverallScore=100},{$args[0].PublicResult.PublicProjection='true'},
    {$args[0].PublicResult.CheckResults=@()},{$args[0].ExpectedCheckIds=@()},
    {$args[0].SchemaVersion=@('1.0.0')},
    {$args[0].PublicResult.ControlResults[0].SectionKey='NetworkSecurity'})){
    Test-WinSecHistoryCase 'Foreign inconsistent scored and coerced records reject' {
        $record=New-WinSecPublicHistoryRecord (New-WinSecHistoryFixture);& $mutation $record
        $record.ContentSha256=Get-WinSecPublicHistoryDigest $record
        Assert-WinSecHistoryReject {ConvertFrom-WinSecPublicHistoryRecord $record}
    }
}
Test-WinSecHistoryCase 'Integrity mismatch and duplicate JSON keys reject' {
    $record=New-WinSecPublicHistoryRecord (New-WinSecHistoryFixture);$record.CatalogVersion='changed'
    Assert-WinSecHistoryReject {ConvertFrom-WinSecPublicHistoryRecord $record}
    Assert-WinSecHistoryReject {ConvertFrom-WinSecStoredJson '{"SchemaVersion":"1.0.0","SchemaVersion":"1.0.0"}'}
}
Test-WinSecHistoryCase 'Appending sessions never overwrites an earlier scan' {
    Save-WinSecPublicHistory $root (New-WinSecHistoryFixture)
    $before=$script:historyMemory['local:CURRENT-FIXTURE|scan-1']
    Save-WinSecPublicHistory $root (New-WinSecHistoryFixture -ScanId scan-2 -ScopeType CONTROL -ScopeKey WSA-SYS-001)
    Assert-WinSecHistoryReject {Save-WinSecPublicHistory $root (New-WinSecHistoryFixture)}
    Assert-WinSecHistory ($script:historyMemory.Count -eq 2 -and $script:historyMemory['local:CURRENT-FIXTURE|scan-1'] -ceq $before)
}
Test-WinSecHistoryCase 'Write failure never changes previous sessions and releases the inventory lease' {
    Save-WinSecPublicHistory $root (New-WinSecHistoryFixture)
    $script:historyFailWrite=$true
    Assert-WinSecHistoryReject {Save-WinSecPublicHistory $root (New-WinSecHistoryFixture -ScanId scan-2)}
    Assert-WinSecHistory ($script:historyMemory.Count -eq 1)
}
Test-WinSecHistoryCase 'Restart restores full and partial scope caches independently' {
    Save-WinSecPublicHistory $root (New-WinSecHistoryFixture)
    Save-WinSecPublicHistory $root (New-WinSecHistoryFixture -ScanId scan-2 -ScopeType SECTION -ScopeKey SystemSecurity)
    Save-WinSecPublicHistory $root (New-WinSecHistoryFixture -ScanId scan-3 -ScopeType CONTROL -ScopeKey WSA-SYS-001)
    $context=New-WinSecHistoryContext;Restore-WinSecPublicHistory $context
    Assert-WinSecHistory ($context.HistoryReady -and $context.PublicScans.Count -eq 3 -and $context.ScanCoordinator.Sessions.Count -eq 3 -and
        $context.ActiveScanByDevice['local:CURRENT-FIXTURE'] -ceq 'scan-1' -and $context.ActiveScanByScope.Count -eq 3 -and
        (Get-WinSecScanAction $context.ScanCoordinator 'local:CURRENT-FIXTURE' CONTROL WSA-SYS-001) -ceq 'Rescan')
    $state=New-WinSecNavigationState;$state.SelectedDeviceId='local:CURRENT-FIXTURE';$state.Screen='Section'
    # D-043/D-049: the selected control resolves its own session; the section
    # source is queried explicitly and is never replaced by that partial scan.
    Assert-WinSecHistory ((Get-WinSecCLIActiveAssessment $state $context).ScanId -ceq 'scan-3')
    $state.Screen='Findings';$state.FindingsScope='Section'
    Assert-WinSecHistory ((Get-WinSecCLIActiveAssessment $state $context).ScanId -ceq 'scan-2')
    $state.FindingsScope='Control'
    Assert-WinSecHistory ((Get-WinSecCLIActiveAssessment $state $context).ScanId -ceq 'scan-3')
    $context.PublicScans.Values|Select-Object -First 1|ForEach-Object{$_.ControlResults[0].Status='ERROR'}
    Assert-WinSecHistory (($script:historyMemory.Values -join '') -notmatch '"Status":"ERROR"')
}
Test-WinSecHistoryCase 'Partial history does not create a full device assessment' {
    Save-WinSecPublicHistory $root (New-WinSecHistoryFixture -ScopeType CONTROL -ScopeKey WSA-SYS-001)
    $context=New-WinSecHistoryContext;Restore-WinSecPublicHistory $context
    Assert-WinSecHistory ($context.ActiveScanByDevice.Count -eq 0 -and $context.ActiveScanByScope.Count -eq 1 -and
        (Get-WinSecScanAction $context.ScanCoordinator 'local:CURRENT-FIXTURE' DEVICE ALL) -ceq 'Scan')
}
Test-WinSecHistoryCase 'Corruption aborts restoration without partially publishing caches' {
    Save-WinSecPublicHistory $root (New-WinSecHistoryFixture)
    $script:historyMemory['bad']='{"SchemaVersion":"unknown"}'
    $context=New-WinSecHistoryContext
    Assert-WinSecHistoryReject {Restore-WinSecPublicHistory $context}
    Assert-WinSecHistory ($context.PublicScans.Count -eq 0 -and $context.ScanCoordinator.Sessions.Count -eq 0 -and $context.ActiveScanByScope.Count -eq 0)
}
Test-WinSecHistoryCase 'Device rows use verified dates and label partial scope without importing inventory scores' {
    Save-WinSecPublicHistory $root (New-WinSecHistoryFixture -ScopeType CONTROL -ScopeKey WSA-SYS-001)
    $context=New-WinSecHistoryContext;Restore-WinSecPublicHistory $context
    $history=@(Get-WinSecCoordinatorHistory $context.ScanCoordinator)
    $rows=@(Get-WinSecDeviceRows -Devices $context.Devices -History $history -HistoryLoaded)
    Assert-WinSecHistory ($rows[1].LastScan -ceq '2026-10-21 00:01Z CONTROL' -and $rows[1].Status -ceq 'PENDING' -and $rows[1].Score -ceq 'NOT_SCORED')
}
Test-WinSecHistoryCase 'Invalid paths and absent devices cannot reach a history write' {
    Assert-WinSecHistoryReject {Get-WinSecPublicHistoryPath (Join-Path $root 'other') 'local:CURRENT-FIXTURE' scan-1}
    Assert-WinSecHistoryReject {Get-WinSecPublicHistoryPath $root '../bad' scan-1}
    Assert-WinSecHistoryReject {Save-WinSecPublicHistory $root (New-WinSecHistoryFixture -DeviceId 'local:UNKNOWN')}
}
Test-WinSecHistoryCase 'Historical devices retain separate sessions without granting execution rights' {
    $old=New-WinSecPublicHistoryRecord (New-WinSecHistoryFixture -DeviceId 'local:OLD-FIXTURE')
    $script:historyMemory['local:OLD-FIXTURE|scan-1']=Get-WinSecPublicHistoryJson $old
    Save-WinSecPublicHistory $root (New-WinSecHistoryFixture)
    $context=New-WinSecHistoryContext;Restore-WinSecPublicHistory $context
    $state=New-WinSecNavigationState;$state.Screen='MainMenu';$state.SelectedDeviceId='local:OLD-FIXTURE'
    $view=Get-WinSecCLIActiveAssessment $state $context
    Assert-WinSecHistory ($context.PublicScans.Count -eq 2 -and $context.ActiveScanByDevice.Count -eq 2 -and
        $view.ControlResults[0].DeviceId -ceq 'local:OLD-FIXTURE' -and
        -not (Test-WinSecCLIRescanEligibility $state $context.Devices $context.ScanCoordinator))
}
Test-WinSecHistoryCase 'Linked history directory rejects before reading or writing a session' {
    $script:linkedHistoryDirectory=Join-Path $root ('data/scans/'+(Get-WinSecEvidenceHash 'local:CURRENT-FIXTURE'))
    $script:historyOriginalTestPath=(Get-Command Test-Path).ScriptBlock
    $script:historyOriginalGetItem=(Get-Command Get-Item).ScriptBlock
    function Test-Path {
        [CmdletBinding()]param($LiteralPath,$Path,$PathType)
        if($LiteralPath -ceq $script:linkedHistoryDirectory){return $true}
        & $script:historyOriginalTestPath @PSBoundParameters
    }
    function Get-Item {
        [CmdletBinding()]param($LiteralPath,[switch]$Force)
        if($LiteralPath -ceq $script:linkedHistoryDirectory){return [pscustomobject]@{PSIsContainer=$true;Attributes=[IO.FileAttributes]::ReparsePoint}}
        & $script:historyOriginalGetItem @PSBoundParameters
    }
    Assert-WinSecHistoryReject {Get-WinSecPublicHistoryPath $root 'local:CURRENT-FIXTURE' scan-1}
}
Test-WinSecHistoryCase 'Real reader validates ownership integrity and the aggregate byte counter using simulated files' {
    $result=Invoke-WinSecNativeHistoryReadFixture
    Assert-WinSecHistory ($result.Records.Count -eq 1 -and $result.Records[0].DeviceId -ceq 'local:CURRENT-FIXTURE' -and
        $result.Bytes -eq [Text.Encoding]::UTF8.GetByteCount($script:nativeHistoryText))
}
Test-WinSecHistoryCase 'Capacity conflicts stop writes before producing an unreadable history' {
    function Read-WinSecPublicHistoryArtifacts {param($ProjectRoot,$Devices,[ref]$TotalBytes);$TotalBytes.Value=33554432}
    Assert-WinSecHistoryReject {Save-WinSecPublicHistory $root (New-WinSecHistoryFixture)}
    Assert-WinSecHistory ($script:historyMemory.Count -eq 0)
}
foreach($fault in @('Foreign','Link','Oversize','Temporary','Changed')){
    Test-WinSecHistoryCase ('Real reader rejects unsafe storage before publication: '+$fault) {
        Assert-WinSecHistoryReject {Invoke-WinSecNativeHistoryReadFixture $fault}
    }
}
Write-Host "Passed: $script:passed; Failed: $script:failed"
if($script:failed){throw 'Public history tests failed.'}
