# In-memory inventory and synthetic sessions; no physical deletion or audit.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
. (Join-Path $root 'src/Services/DeviceManagementService.ps1')
. (Join-Path $root 'src/Services/ExportService.ps1')
. (Join-Path $root 'src/CLI/Invoke-WinSecCLI.ps1')
. (Join-Path $root 'src/UI/Core/NavigationController.ps1')
. (Join-Path $root 'src/UI/Core/KeyboardController.ps1')
. (Join-Path $root 'src/UI/Screens/DeviceRemovalConfirmation.ps1')
$script:realDialog=(Get-Command Show-WinSecDeviceRemovalConfirmation).ScriptBlock
. (Join-Path $PSScriptRoot '../Fixtures/DeviceInventoryMemoryStore.ps1')
$script:passed=0; $script:failed=0
function Assert-WinSecRemoval { param([bool]$Condition) if (-not $Condition) { throw 'Removal assertion failed.' } }
function Test-WinSecRemovalCase {
    param([string]$Name,[scriptblock]$Action)
    Reset-WinSecInventoryMemoryStore
    $null=Register-WinSecLocalDevice -ProjectRoot $root
    $script:devices=@((Import-WinSecDeviceInventory -ProjectRoot $root).targets)
    $script:coordinator=New-WinSecScanCoordinator -ProjectRoot $root
    foreach ($device in $script:devices) {
        $id=$device.DeviceId; $key=Get-WinSecScanSessionKey $id 'scan-1'
        $script:coordinator.Sessions[$key]=[pscustomobject]@{DeviceId=$id; ScanId='scan-1'}
    }
    $script:dialogAnswer=$true
    $script:dialogAction=$null
    $script:dialogCalls=0
    try {
        $null=& $Action
        Assert-WinSecRemoval (-not $script:inventoryMemory.LeaseHeld -and $script:inventoryMemory.UnexpectedWrites -eq 0 -and
            $script:inventoryMemory.Audits -eq 0 -and -not [IO.Directory]::Exists($script:inventoryMemoryRoot))
        $script:passed++; Write-Host "[PASS] $Name"
    }
    catch { $script:failed++; Write-Host "[FAIL] $Name : $($_.Exception.Message)" }
}
function Invoke-WinSecReportRemovalPlanFixture {
    param([switch]$Corrupt,[switch]$Linked,[switch]$Foreign,[switch]$Text)
    $script:reportRemovalRoot=Join-Path $root ('reports/exports/' + (Get-WinSecEvidenceHash 'local:OLD-FIXTURE'))
    $script:reportRemovalFile=Join-Path $script:reportRemovalRoot 'synthetic.md'
    $script:reportRemovalLinked=[bool]$Linked
    $body="# Public report`n"
    $meta=[ordered]@{SchemaVersion='1.0.0';DeviceId=if($Foreign){'local:OTHER'}else{'local:OLD-FIXTURE'};
        ScanId='scan-1';ContentSha256=(Get-WinSecReportTextHash $body)}
    $script:reportRemovalText="<!-- WinSec public report`n"+(ConvertTo-Json $meta -Compress)+"`n-->`n"+$body
    if($Text) {
        $script:reportRemovalFile=Join-Path $script:reportRemovalRoot 'synthetic.txt'
        # Legacy fixture assembled independently; no TXT writer remains.
        $script:reportRemovalText="WinSec public text report`n"+(ConvertTo-Json $meta -Compress)+"`n`n"+$body
    }
    if($Corrupt){$script:reportRemovalText+='corrupt'}
    $script:reportRemovalTestPath=(Get-Command Test-Path).ScriptBlock
    $script:reportRemovalGetItem=(Get-Command Get-Item).ScriptBlock
    $script:reportRemovalGetContent=(Get-Command Get-Content).ScriptBlock
    function Test-Path {
        [CmdletBinding()]param($LiteralPath,$Path,$PathType)
        if($LiteralPath -in @($script:reportRemovalRoot,$script:reportRemovalFile)){return $true}
        & $script:reportRemovalTestPath @PSBoundParameters
    }
    function Get-Item {
        [CmdletBinding()]param($LiteralPath,[switch]$Force)
        if($LiteralPath -in @($script:reportRemovalRoot,$script:reportRemovalFile)){
            return [pscustomobject]@{FullName=$LiteralPath;PSIsContainer=($LiteralPath -eq $script:reportRemovalRoot);
                Length=[Text.Encoding]::UTF8.GetByteCount($script:reportRemovalText);
                Attributes=if($script:reportRemovalLinked){[IO.FileAttributes]::ReparsePoint}else{[IO.FileAttributes]::Normal}}
        }
        & $script:reportRemovalGetItem @PSBoundParameters
    }
    function Get-ChildItem {
        [CmdletBinding()]param($LiteralPath,[switch]$Force)
        if($LiteralPath -eq $script:reportRemovalRoot){return Get-Item $script:reportRemovalFile}
        throw 'Unexpected fixture enumeration.'
    }
    function Get-Content {
        [CmdletBinding()]param($LiteralPath,[switch]$Raw,$Encoding)
        if($LiteralPath -eq $script:reportRemovalFile){return $script:reportRemovalText}
        & $script:reportRemovalGetContent @PSBoundParameters
    }
    function Get-FileHash {
        [CmdletBinding()]param($LiteralPath,$Algorithm)
        if($LiteralPath -eq $script:reportRemovalFile){return [pscustomobject]@{Hash=(Get-WinSecReportTextHash $script:reportRemovalText)}}
        throw 'Unexpected fixture hash.'
    }
    Get-WinSecDeviceRemovalPlan -ProjectRoot $root -DeviceId 'local:OLD-FIXTURE' -Coordinator $script:coordinator -Devices $script:devices
}
function Assert-WinSecRemovalThrows {
    param([scriptblock]$Action)
    $caught=$false
    try { $null=& $Action } catch { $caught=$true }
    Assert-WinSecRemoval $caught
}
Test-WinSecRemovalCase 'Removal plan includes owned Markdown exports with integrity checked' {
    $plan=Invoke-WinSecReportRemovalPlanFixture
    Assert-WinSecRemoval ($plan.Files.Count -eq 1 -and $plan.Files[0].Path -ceq $script:reportRemovalFile -and
        $plan.Roots -contains $script:reportRemovalRoot -and $script:coordinator.Sessions.Count -eq 2)
}
Test-WinSecRemovalCase 'Corrupt or foreign Markdown prevents removal before confirmation' {
    Assert-WinSecRemovalThrows {Invoke-WinSecReportRemovalPlanFixture -Corrupt}
    Assert-WinSecRemovalThrows {Invoke-WinSecReportRemovalPlanFixture -Foreign}
    Assert-WinSecRemoval ($script:coordinator.Sessions.Count -eq 2)
}
Test-WinSecRemovalCase 'Linked Markdown export storage rejects removal without traversing it' {
    Assert-WinSecRemovalThrows {Invoke-WinSecReportRemovalPlanFixture -Linked}
    Assert-WinSecRemoval ($script:coordinator.Sessions.Count -eq 2)
}
Test-WinSecRemovalCase 'Removal plan accepts legacy TXT ownership without exposing a TXT export API' {
    foreach($name in @('New-WinSecFindingsText','New-WinSecTextArtifactContent','Write-WinSecTextArtifact','Export-WinSecFindingsText')) {
        Assert-WinSecRemoval ($null -eq (Get-Command $name -ErrorAction SilentlyContinue))
    }
    $plan=Invoke-WinSecReportRemovalPlanFixture -Text
    Assert-WinSecRemoval ($plan.Files.Count -eq 1 -and $plan.Files[0].Path.EndsWith('.txt') -and $script:coordinator.Sessions.Count -eq 2)
}
Test-WinSecRemovalCase 'Corrupt foreign or linked TXT rejects removal before confirmation' {
    Assert-WinSecRemovalThrows {Invoke-WinSecReportRemovalPlanFixture -Text -Corrupt}
    Assert-WinSecRemovalThrows {Invoke-WinSecReportRemovalPlanFixture -Text -Foreign}
    Assert-WinSecRemovalThrows {Invoke-WinSecReportRemovalPlanFixture -Text -Linked}
    Assert-WinSecRemoval ($script:coordinator.Sessions.Count -eq 2)
}
function Invoke-WinSecRemovalFixture {
    param([scriptblock]$Confirm={ $true },[string]$DeviceId='local:OLD-FIXTURE')
    Remove-WinSecManagedDevice -ProjectRoot $root -DeviceId $DeviceId -Coordinator $script:coordinator -Devices $script:devices -ConfirmAction $Confirm
}
Test-WinSecRemovalCase 'No confirmation handler rejects before mutation' {
    $before=$script:inventoryMemory.Json
    Assert-WinSecRemovalThrows { Remove-WinSecManagedDevice -ProjectRoot $root -DeviceId 'local:OLD-FIXTURE' -Coordinator $script:coordinator -Devices $script:devices }
    Assert-WinSecRemoval ($script:inventoryMemory.Json -ceq $before -and $script:coordinator.Sessions.Count -eq 2)
}
Test-WinSecRemovalCase 'Cancellation preserves inventory sessions and write count' {
    $before=$script:inventoryMemory.Json; $writes=$script:inventoryMemory.Saves
    $result=Invoke-WinSecRemovalFixture -Confirm { $false }
    Assert-WinSecRemoval ($null -eq $result -and $script:inventoryMemory.Json -ceq $before -and
        $script:inventoryMemory.Saves -eq $writes -and $script:coordinator.Sessions.Count -eq 2)
}
foreach ($handler in @({ }, { 'yes' }, { $true; $true }, { throw 'PRIVATE-REMOVAL-DETAIL' })) {
    Test-WinSecRemovalCase 'Missing ambiguous or failed consent cannot delete' {
        $before=$script:inventoryMemory.Json
        Assert-WinSecRemovalThrows { Invoke-WinSecRemovalFixture -Confirm $handler }
        Assert-WinSecRemoval ($script:inventoryMemory.Json -ceq $before -and $script:coordinator.Sessions.Count -eq 2)
    }
}
Test-WinSecRemovalCase 'Preview includes the exact device history count and re-registration behavior' {
    $null=Invoke-WinSecRemovalFixture -Confirm {
        param($request)
        Assert-WinSecRemoval ($request.Operation -ceq 'DELETE_DEVICE' -and $request.DeviceId -ceq 'local:OLD-FIXTURE' -and
            $request.MemoryScanCount -eq 1 -and $request.StoredFileCount -eq 0 -and -not $request.RegistersAgainOnStartup)
        return $false
    }
}
Test-WinSecRemovalCase 'Confirmed deletion preserves other device metadata and sessions' {
    $before=ConvertTo-Json -InputObject $script:devices[1] -Depth 8 -Compress
    $result=Invoke-WinSecRemovalFixture
    $saved=Import-WinSecDeviceInventory -ProjectRoot $root
    Assert-WinSecRemoval ($result.Status -ceq 'REMOVED' -and $saved.schemaVersion -ceq '1.2.0' -and $saved.targets.Count -eq 1 -and
        (ConvertTo-Json -InputObject $saved.targets[0] -Depth 8 -Compress) -ceq $before -and $script:coordinator.Sessions.Count -eq 1)
    Assert-WinSecRemoval (Test-WinSecDeviceInventoryRemoval $saved 'local:old-fixture')
}
Test-WinSecRemovalCase 'The current device re-registers empty without reviving other removed devices' {
    $null=Invoke-WinSecRemovalFixture
    $script:devices=@((Import-WinSecDeviceInventory -ProjectRoot $root).targets)
    $null=Invoke-WinSecRemovalFixture -DeviceId 'local:CURRENT-FIXTURE'
    $registered=Register-WinSecLocalDevice -ProjectRoot $root
    $saved=Import-WinSecDeviceInventory -ProjectRoot $root
    Assert-WinSecRemoval ($registered.Created -and $saved.targets.Count -eq 1 -and $script:coordinator.Sessions.Count -eq 0 -and
        -not (Test-WinSecDeviceInventoryRemoval $saved 'local:CURRENT-FIXTURE') -and (Test-WinSecDeviceInventoryRemoval $saved 'local:OLD-FIXTURE'))
}
Test-WinSecRemovalCase 'Changed confirmation previews reject without deleting' {
    Assert-WinSecRemovalThrows { Invoke-WinSecRemovalFixture -Confirm { param($r) $r.DeviceId='local:OTHER'; $true } }
    Assert-WinSecRemoval ($script:coordinator.Sessions.Count -eq 2)
}
Test-WinSecRemovalCase 'New sessions during confirmation require a fresh confirmation' {
    Assert-WinSecRemovalThrows { Invoke-WinSecRemovalFixture -Confirm {
        $script:coordinator.Sessions['local:OLD-FIXTURE|scan-2']=[pscustomobject]@{DeviceId='local:OLD-FIXTURE'; ScanId='scan-2'}
        $true
    } }
    Assert-WinSecRemoval ((Import-WinSecDeviceInventory -ProjectRoot $root).targets.Count -eq 2)
}
Test-WinSecRemovalCase 'Inventory mutation during confirmation cannot reuse consent' {
    Assert-WinSecRemovalThrows { Invoke-WinSecRemovalFixture -Confirm {
        $changed=ConvertFrom-WinSecDeviceInventoryJson $script:inventoryMemory.Json
        $changed.targets[0].Hostname='CHANGED-FIXTURE'
        $script:inventoryMemory.Json=ConvertTo-Json -InputObject $changed -Depth 8
        $true
    } }
    Assert-WinSecRemoval ($script:coordinator.Sessions.Count -eq 2)
}
Test-WinSecRemovalCase 'Busy storage cannot delete or drop sessions' {
    $script:inventoryMemory.Busy=$true
    Assert-WinSecRemovalThrows { Invoke-WinSecRemovalFixture }
    Assert-WinSecRemoval ($script:coordinator.Sessions.Count -eq 2)
}
Test-WinSecRemovalCase 'A failed commit reports incomplete and retains a row for a confirmed retry' {
    $script:inventoryMemory.FailSave=$true
    $result=Invoke-WinSecRemovalFixture
    Assert-WinSecRemoval ($result.Status -ceq 'INCOMPLETE' -and $script:coordinator.Sessions.Count -eq 1 -and
        (Import-WinSecDeviceInventory -ProjectRoot $root).targets.Count -eq 2)
    $script:inventoryMemory.FailSave=$false
    Assert-WinSecRemoval ((Invoke-WinSecRemovalFixture).Status -ceq 'REMOVED')
}
Test-WinSecRemovalCase 'Traversal and unknown identifiers cannot delete' {
    Assert-WinSecRemovalThrows { Invoke-WinSecRemovalFixture -DeviceId '../other' }
    Assert-WinSecRemovalThrows { Invoke-WinSecRemovalFixture -DeviceId 'local:NOT-REGISTERED' }
}
Test-WinSecRemovalCase 'Inconsistent session ownership fails closed' {
    $script:coordinator.Sessions['local:OLD-FIXTURE|scan-1'].DeviceId='local:OTHER'
    Assert-WinSecRemovalThrows { Invoke-WinSecRemovalFixture }
}
Test-WinSecRemovalCase 'A foreign session payload cannot be deleted under another device key' {
    $script:coordinator.Sessions['local:OLD-FIXTURE|scan-1'] | Add-Member -NotePropertyName Session -NotePropertyValue (
        [pscustomobject]@{DeviceId='local:OTHER'; ScanId='scan-1'})
    Assert-WinSecRemovalThrows { Invoke-WinSecRemovalFixture }
    Assert-WinSecRemoval ((Import-WinSecDeviceInventory $root).targets.Count -eq 2)
}
Test-WinSecRemovalCase 'An explicit configured device can be removed without editing its catalog' {
    $script:devices+= [pscustomobject]@{DeviceId='remote:CONFIG-FIXTURE'; Hostname='CONFIG-FIXTURE'; Mode='REMOTE'; Enabled=$false}
    $result=Invoke-WinSecRemovalFixture -DeviceId 'remote:CONFIG-FIXTURE'
    Assert-WinSecRemoval ($result.Status -ceq 'REMOVED' -and
        (Test-WinSecDeviceInventoryRemoval (Import-WinSecDeviceInventory -ProjectRoot $root) 'remote:CONFIG-FIXTURE'))
}
Test-WinSecRemovalCase 'Removal metadata rejects duplicate hashes invalid types and active/removed conflicts' {
    $hash=Get-WinSecDeviceInventoryIdentityHash 'local:OLD-FIXTURE'
    foreach ($doc in @(
        [pscustomobject]@{schemaVersion='1.1.0'; targets=@(); removedDeviceHashes=@($hash,$hash)},
        [pscustomobject]@{schemaVersion='1.1.0'; targets=@(); removedDeviceHashes=@('invalid')},
        [pscustomobject]@{schemaVersion='1.1.0'; targets=@(); removedDeviceHashes=$hash},
        [pscustomobject]@{schemaVersion='1.1.0'; targets=@($script:devices[0]); removedDeviceHashes=@($hash)}
    )) { Assert-WinSecRemovalThrows { ConvertFrom-WinSecDeviceInventoryJson (ConvertTo-Json -InputObject $doc -Depth 8) } }
}
Test-WinSecRemovalCase 'Delete/Supr only requests deletion from a nonempty Devices screen' {
    $key=[pscustomobject]@{KeyDown=$true; Character=[char]0; VirtualKeyCode=46; ControlKeyState=0}
    Assert-WinSecRemoval ((Get-WinSecKeyboardAction -KeyInfo $key -Screen Devices).Action -ceq 'DeleteDevice')
    Assert-WinSecRemoval ((Get-WinSecKeyboardAction -KeyInfo $key -Screen MainMenu).Action -ceq 'None')
    foreach ($modifier in @(1,2,4,8)) {
        $key.ControlKeyState=$modifier
        Assert-WinSecRemoval ((Get-WinSecKeyboardAction -KeyInfo $key -Screen Devices).Action -ceq 'None')
    }
    $key.ControlKeyState=0; $key.KeyDown=$false
    Assert-WinSecRemoval ((Get-WinSecKeyboardAction -KeyInfo $key -Screen Devices).Action -ceq 'None')
    $letter=[pscustomobject]@{KeyDown=$true; Character='D'; VirtualKeyCode=68; ControlKeyState=0}
    Assert-WinSecRemoval ((Get-WinSecKeyboardAction -KeyInfo $letter -Screen Devices).Action -ceq 'None')
    $letter.Character='d'
    Assert-WinSecRemoval ((Get-WinSecKeyboardAction -KeyInfo $letter -Screen Devices).Action -ceq 'None')
    $state=New-WinSecNavigationState
    $null=Invoke-WinSecNavigationAction -State $state -Action DeleteDevice -Devices @()
    Assert-WinSecRemoval ($null -eq $state.PendingCommand)
    $null=Invoke-WinSecNavigationAction -State $state -Action DeleteDevice -Devices $script:devices
    Assert-WinSecRemoval ($state.PendingCommand -ceq 'DeleteDevice' -and $script:coordinator.Sessions.Count -eq 2)
}
function Show-WinSecDeviceRemovalConfirmation {
    param($Request)
    $script:dialogCalls++
    if ($null -ne $script:dialogAction) { return (& $script:dialogAction $Request) }
    return $script:dialogAnswer
}
function New-WinSecRemovalCLIContext {
    $context=[pscustomobject]@{ProjectRoot=$root; Devices=$script:devices; ScanCoordinator=$script:coordinator;
        PublicScans=@{}; ActiveScanByDevice=@{}; SectionResults=@(); ControlResults=@(); Findings=@(); ScanId='scan-1'; LastDeviceMessage=''}
    foreach ($device in $script:devices) {
        $id=$device.DeviceId
        $publicKey='{0}:{1}{2}:{3}' -f $id.Length,$id,'scan-1'.Length,'scan-1'
        $context.PublicScans[$publicKey]=[pscustomobject]@{DeviceId=$id; ScanId='scan-1'}
        $context.ActiveScanByDevice[$id]='scan-1'
        $context.Findings+= [pscustomobject]@{DeviceId=$id; ScanId='scan-1'; FindingId='synthetic'}
    }
    return $context
}
Test-WinSecRemovalCase 'CLI cancellation preserves row navigation public scans and findings' {
    $context=New-WinSecRemovalCLIContext; $state=New-WinSecNavigationState
    $before=ConvertTo-Json -InputObject $context -Depth 15 -Compress
    $script:dialogAnswer=$false
    $result=Invoke-WinSecCLIDeviceRemoval -State $state -Context $context
    Assert-WinSecRemoval ($null -eq $result -and $before -ceq (ConvertTo-Json -InputObject $context -Depth 15 -Compress) -and
        $state.DeviceIndex -eq 0 -and $state.History.Count -eq 0)
}
Test-WinSecRemovalCase 'CLI removes only selected rows maps findings and navigation references' {
    $context=New-WinSecRemovalCLIContext; $state=New-WinSecNavigationState
    $null=$state.History.Add([pscustomobject]@{SelectedDeviceId='local:OLD-FIXTURE'})
    $result=Invoke-WinSecCLIDeviceRemoval -State $state -Context $context
    Assert-WinSecRemoval ($result.Status -ceq 'REMOVED' -and $context.Devices.Count -eq 1 -and
        $context.Devices[0].DeviceId -ceq 'local:CURRENT-FIXTURE' -and $context.PublicScans.Count -eq 1 -and
        $context.ActiveScanByDevice.Count -eq 1 -and $context.Findings.Count -eq 1 -and
        $context.Findings[0].DeviceId -ceq 'local:CURRENT-FIXTURE' -and $context.ScanId -ceq 'scan-1' -and $state.History.Count -eq 0)
}
Test-WinSecRemovalCase 'Coordinator session keys cannot authorize a public CLI record or open confirmation' {
    $context=New-WinSecRemovalCLIContext;$state=New-WinSecNavigationState
    $id='local:OLD-FIXTURE';$scan='scan-1';$publicKey='{0}:{1}{2}:{3}' -f $id.Length,$id,$scan.Length,$scan
    $context.PublicScans[(Get-WinSecScanSessionKey $id $scan)]=$context.PublicScans[$publicKey]
    $context.PublicScans.Remove($publicKey)
    Assert-WinSecRemovalThrows {Invoke-WinSecCLIDeviceRemoval $state $context}
    Assert-WinSecRemoval ($script:dialogCalls -eq 0 -and $script:coordinator.Sessions.Count -eq 2 -and
        (Import-WinSecDeviceInventory $root).targets.Count -eq 2)
}
Test-WinSecRemovalCase 'Multiple valid public scans reach confirmation and only the selected device is removed' {
    $context=New-WinSecRemovalCLIContext;$state=New-WinSecNavigationState
    $id='local:OLD-FIXTURE';$scan='scan-2';$publicKey='{0}:{1}{2}:{3}' -f $id.Length,$id,$scan.Length,$scan
    $context.PublicScans[$publicKey]=[pscustomobject]@{DeviceId=$id;ScanId=$scan}
    $script:coordinator.Sessions[(Get-WinSecScanSessionKey $id $scan)]=[pscustomobject]@{DeviceId=$id;ScanId=$scan}
    $r=Invoke-WinSecCLIDeviceRemoval $state $context
    Assert-WinSecRemoval ($r.Status -ceq 'REMOVED' -and $script:dialogCalls -eq 1 -and $context.PublicScans.Count -eq 1 -and
        $script:coordinator.Sessions.Count -eq 1 -and $context.Devices[0].DeviceId -ceq 'local:CURRENT-FIXTURE')
}
Test-WinSecRemovalCase 'Deleting the last row leaves an empty Devices screen without registering implicitly' {
    $context=New-WinSecRemovalCLIContext; $state=New-WinSecNavigationState
    $null=Invoke-WinSecCLIDeviceRemoval -State $state -Context $context
    $null=Invoke-WinSecCLIDeviceRemoval -State $state -Context $context
    Assert-WinSecRemoval ($context.Devices.Count -eq 0 -and $context.PublicScans.Count -eq 0 -and
        $context.ActiveScanByDevice.Count -eq 0 -and $context.ScanId -ceq '' -and $state.DeviceIndex -eq 0 -and
        $null -eq $state.SelectedDeviceId -and (Import-WinSecDeviceInventory -ProjectRoot $root).targets.Count -eq 0)
}
Test-WinSecRemovalCase 'CLI rejects ambiguous legacy data and corrupt public ownership before confirmation' {
    $context=New-WinSecRemovalCLIContext; $state=New-WinSecNavigationState
    $context.Findings=@([pscustomobject]@{FindingId='unowned'})
    Assert-WinSecRemovalThrows { Invoke-WinSecCLIDeviceRemoval -State $state -Context $context }
    $context=New-WinSecRemovalCLIContext
    ($context.PublicScans.Values|Where-Object DeviceId -CEQ 'local:OLD-FIXTURE').DeviceId='local:OTHER'
    Assert-WinSecRemovalThrows { Invoke-WinSecCLIDeviceRemoval -State $state -Context $context }
    Assert-WinSecRemoval ($script:coordinator.Sessions.Count -eq 2)
}
Test-WinSecRemovalCase 'CLI incomplete deletion keeps the row but invalidates the selected cached results' {
    $context=New-WinSecRemovalCLIContext; $state=New-WinSecNavigationState
    $script:inventoryMemory.FailSave=$true
    $result=Invoke-WinSecCLIDeviceRemoval -State $state -Context $context
    Assert-WinSecRemoval ($result.Status -ceq 'INCOMPLETE' -and $context.Devices.Count -eq 2 -and $context.PublicScans.Count -eq 1 -and
        $context.LastDeviceMessage -match 'incomplete' -and $context.ActiveScanByDevice.Count -eq 1)
}
Test-WinSecRemovalCase 'A changing public view invalidates CLI consent before any deletion' {
    $context=New-WinSecRemovalCLIContext; $state=New-WinSecNavigationState
    $script:changingContext=$context
    $script:dialogAction={
        $id='local:OLD-FIXTURE';$scan='scan-2'
        $key='{0}:{1}{2}:{3}' -f $id.Length,$id,$scan.Length,$scan
        $script:changingContext.PublicScans[$key]=[pscustomobject]@{DeviceId=$id; ScanId=$scan}
        return $true
    }
    Assert-WinSecRemovalThrows { Invoke-WinSecCLIDeviceRemoval -State $state -Context $context }
    Assert-WinSecRemoval ($script:coordinator.Sessions.Count -eq 2 -and (Import-WinSecDeviceInventory $root).targets.Count -eq 2)
}
Test-WinSecRemovalCase 'A hash table key named Keys cannot hide inconsistent session ownership' {
    $script:coordinator.Sessions['Keys']=@()
    Assert-WinSecRemovalThrows { Invoke-WinSecRemovalFixture }
    $script:coordinator.Sessions.Remove('Keys')
    $context=New-WinSecRemovalCLIContext; $state=New-WinSecNavigationState
    $context.PublicScans['Keys']=@()
    Assert-WinSecRemovalThrows { Invoke-WinSecCLIDeviceRemoval -State $state -Context $context }
    Assert-WinSecRemoval ((Import-WinSecDeviceInventory $root).targets.Count -eq 2 -and $script:coordinator.Sessions.Count -eq 2)
}
Test-WinSecRemovalCase 'Device removal clears only its scoped selections and preserves other devices' {
    $context=New-WinSecRemovalCLIContext;$state=New-WinSecNavigationState
    $oldKey=Get-WinSecCLIScopeKey 'local:OLD-FIXTURE' SECTION SystemSecurity
    $otherKey=Get-WinSecCLIScopeKey 'local:CURRENT-FIXTURE' CONTROL WSA-SYS-001
    $context|Add-Member -NotePropertyName ActiveScanByScope -NotePropertyValue @{$oldKey='scan-1';$otherKey='scan-1'}
    $oldCache=(Get-WinSecScanSessionKey 'local:OLD-FIXTURE' 'scan-1')+'|WSA-SYS-001'
    $otherCache=(Get-WinSecScanSessionKey 'local:CURRENT-FIXTURE' 'scan-1')+'|WSA-SYS-001'
    $context.ScanCoordinator.TechnicalSnapshots[$oldCache]=[pscustomobject]@{DeviceId='local:OLD-FIXTURE'}
    $context.ScanCoordinator.TechnicalSnapshots[$otherCache]=[pscustomobject]@{DeviceId='local:CURRENT-FIXTURE'}
    $context|Add-Member FrameworkFindings ([pscustomobject]@{DeviceId='local:OLD-FIXTURE'})
    $context|Add-Member FrameworkSourcesStamp 'old-analysis'
    $null=Invoke-WinSecCLIDeviceRemoval -State $state -Context $context
    Assert-WinSecRemoval ($context.ActiveScanByScope.Count -eq 1 -and $context.ActiveScanByScope.ContainsKey($otherKey) -and
        -not $context.ScanCoordinator.TechnicalSnapshots.ContainsKey($oldCache) -and $context.ScanCoordinator.TechnicalSnapshots.ContainsKey($otherCache) -and
        $null -eq $context.FrameworkFindings -and $null -eq $context.FrameworkSourcesStamp)
}
Test-WinSecRemovalCase 'Scope selection changes during deletion confirmation require fresh consent' {
    $context=New-WinSecRemovalCLIContext;$state=New-WinSecNavigationState
    $context|Add-Member -NotePropertyName ActiveScanByScope -NotePropertyValue @{}
    $script:scopeChangeContext=$context
    $script:dialogAction={ $script:scopeChangeContext.ActiveScanByScope['changed']='scan-2';$true }
    Assert-WinSecRemovalThrows {Invoke-WinSecCLIDeviceRemoval -State $state -Context $context}
    Assert-WinSecRemoval ((Import-WinSecDeviceInventory $root).targets.Count -eq 2)
}
# Exercise the actual dialog against the existing in-memory removal backend.
function Get-WinSecTerminalSize {[pscustomobject]@{Width=100;ContentWidth=99;Height=40}}
function Clear-WinSecScreen {}
function Write-WinSecText {param($Text,$Color)}
function New-WinSecResizeState {[pscustomobject]@{}}
function Invoke-WinSecResizeHandler {param($ResizeState,$RenderAction)}
function Read-WinSecResizeAwareKey {param($ResizeState,$RenderAction);$script:dialogKeys.Dequeue()}
foreach($keyCode in @(13,27,78)){
    Test-WinSecRemovalCase ('Real confirmation key reaches only the memory backend: '+$keyCode) {
        $script:dialogKeys=New-Object 'System.Collections.Generic.Queue[object]'
        $script:dialogKeys.Enqueue([pscustomobject]@{VirtualKeyCode=$keyCode;Character=if($keyCode -eq 78){'N'}else{''};
            ControlKeyState=0;KeyDown=$true})
        if($keyCode -eq 78){$script:dialogKeys.Enqueue([pscustomobject]@{VirtualKeyCode=27;Character='';ControlKeyState=0;KeyDown=$true})}
        $before=ConvertTo-Json -InputObject @($script:coordinator.Sessions,$script:inventoryMemory.Json) -Depth 20 -Compress
        $context=New-WinSecRemovalCLIContext;$state=New-WinSecNavigationState
        $script:dialogAction={param($request); & $script:realDialog -Request $request}
        $result=Invoke-WinSecCLIDeviceRemoval $state $context
        if($keyCode -eq 13){
            Assert-WinSecRemoval ($null -ne $result -and (Import-WinSecDeviceInventory $root).targets.Count -eq 1 -and
                $script:coordinator.Sessions.Count -eq 1)
        }
        else {
            Assert-WinSecRemoval ($null -eq $result -and $before -ceq
                (ConvertTo-Json -InputObject @($script:coordinator.Sessions,$script:inventoryMemory.Json) -Depth 20 -Compress))
        }
    }
}
foreach($spec in @(@{Keys=@(39,13);Accept=$false},@{Keys=@(39,37,13);Accept=$true})) {
    Test-WinSecRemovalCase ('Real CLI confirmation selects Accept or Cancel with arrows and Enter: '+$spec.Accept) {
        $script:dialogKeys=New-Object 'System.Collections.Generic.Queue[object]'
        foreach($code in $spec.Keys){$script:dialogKeys.Enqueue([pscustomobject]@{VirtualKeyCode=$code;Character='';ControlKeyState=0;KeyDown=$true})}
        $context=New-WinSecRemovalCLIContext;$state=New-WinSecNavigationState
        $before=ConvertTo-Json $context -Depth 20 -Compress
        $script:dialogAction={param($request); & $script:realDialog -Request $request}
        $result=Invoke-WinSecCLIDeviceRemoval $state $context
        if($spec.Accept){Assert-WinSecRemoval ($result.Status -ceq 'REMOVED' -and $context.Devices.Count -eq 1)}
        else{Assert-WinSecRemoval ($null -eq $result -and $before -ceq (ConvertTo-Json $context -Depth 20 -Compress))}
        Assert-WinSecRemoval ($script:dialogCalls -eq 1 -and $script:dialogKeys.Count -eq 0)
    }
}
Write-Host "Passed: $script:passed; Failed: $script:failed"
if ($script:failed -gt 0) { throw 'Device removal unit tests failed.' }
