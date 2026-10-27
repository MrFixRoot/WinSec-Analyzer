# Real coordinator, AuditEngine selection, ResultModel and confirmation UI.
# Collector boundary and local UUID are synthetic. No Windows collection,
# startup, native persistence or writes to application/system configuration.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
. (Join-Path $root 'src/UI/Core/ResizeHandler.ps1')
. (Join-Path $root 'src/UI/Screens/ScanConfirmation.ps1')
$script:catalog=Get-WinSecCheckRegistry -ProjectRoot $root
$enabled=@($script:catalog.Checks|Where-Object ExecutionEnabled)
if($enabled.Count -ne 5 -or (($enabled.CheckId | Sort-Object) -join '|') -cne 'WSA-NET-001|WSA-NET-002|WSA-SYS-001|WSA-SYS-002|WSA-SYS-003' -or
    @($enabled | Where-Object {-not $_.ExecutionReady -or $_.ImplementationStatus -cne 'VALIDATED'}).Count -ne 0){
    throw 'Only validated System Security, Firewall and SMBv1 controls may be enabled in production.'
}
$script:passed=0;$script:failed=0
function Get-CimInstance {[pscustomobject]@{UUID='12345678-1234-4567-89ab-123456789abc'}}
function Assert-WinSecScopeIntegration {param([bool]$Condition);if(-not $Condition){throw 'Scope integration assertion failed.'}}
function Test-WinSecScopeIntegration {
    param([string]$Name,[scriptblock]$Action)
    $script:keys=New-Object 'System.Collections.Generic.Queue[object]'
    $script:terminal=[pscustomobject]@{Width=100;ContentWidth=99;Height=40}
    $script:lines=New-Object 'System.Collections.Generic.List[string]'
    $script:collected=New-Object 'System.Collections.Generic.List[string]'
    $script:readyIds=@('WSA-SYS-001','WSA-SYS-002','WSA-NET-001')
    $script:errorCheck='';$script:storageCalls=0;$script:confirmCalls=0
    try{$null=& $Action;$script:passed++;Write-Host "[PASS] $Name"}
    catch{$script:failed++;Write-Host "[FAIL] $Name : $($_.Exception.Message)"}
}
function Get-WinSecCheckRegistry {
    param($ProjectRoot)
    $registry=Copy-WinSecResultData -Value $script:catalog
    # Only the in-memory fixture is executable; production remains unchanged.
    foreach($check in $registry.Checks){
        $check.ExecutionEnabled=$false;$check.ExecutionReady=$false
        if($check.CheckId -cin $script:readyIds){
            $check.ExecutionEnabled=$true;$check.ExecutionReady=$true
            $check.ImplementationStatus='VALIDATED';$check.RegistryStatus='READY'
        }
    }
    return $registry
}
function Import-WinSecAuditDependencies {
    param([switch]$SkipScoring)
    Assert-WinSecScopeIntegration ([bool]$SkipScoring)
    # Definitions are already loaded. Preserve the mocked collector boundary.
}
function Invoke-WinSecAuditCheck {
    param($Check,$DeviceId,$ScanId)
    $script:collected.Add($Check.CheckId)
    $observed=if($Check.CheckId -ceq $script:errorCheck){'ERROR'}else{'INFORMATIONAL'}
    New-WinSecAuditRecord -Check $Check -DeviceId $DeviceId -ScanId $ScanId -Status INFORMATIONAL `
        -ObservedStatus $observed -Evidence @{Secret='SYNTHETIC-SCOPE-PRIVATE'}
}
function Assert-WinSecEvidenceProtection {$script:storageCalls++;throw 'Unexpected native storage.'}
function Get-WinSecEvidenceStorageRoot {$script:storageCalls++;throw 'Unexpected native storage.'}
function Save-WinSecCoordinatedEvidence {$script:storageCalls++;throw 'Unexpected native storage.'}
function Get-WinSecTerminalSize {$script:terminal}
function Clear-WinSecScreen {$script:lines.Clear()}
function Write-WinSecText {param($Text,$Color);$script:lines.Add([string]$Text)}
function Read-WinSecResizeAwareKey {
    param($ResizeState,$RenderAction)
    if($script:keys.Count -eq 0){throw 'No synthetic keyboard input remains.'}
    $key=$script:keys.Dequeue()
    if($null -ne $key.PSObject.Properties['Terminal']){$script:terminal=$key.Terminal}
    return $key
}
function Add-WinSecScopeKey {
    param([string]$Character='', [int]$Code=0, $Terminal=$null)
    $key=[pscustomobject]@{Character=$Character;VirtualKeyCode=$Code;ControlKeyState=0;KeyDown=$true}
    if($null -ne $Terminal){$key|Add-Member -NotePropertyName Terminal -NotePropertyValue $Terminal}
    $script:keys.Enqueue($key)
}
$confirm={param($request);$script:confirmCalls++;Show-WinSecScanConfirmation -Request $request}
foreach($spec in @(@{T='DEVICE';K='ALL';Count=3;Label='Local device'},
    @{T='SECTION';K='SystemSecurity';Count=2;Label='Section: SystemSecurity'},
    @{T='CONTROL';K='WSA-SYS-001';Count=1;Label='Control: WSA-SYS-001'})){
    Test-WinSecScopeIntegration ('Confirmed scope reaches real engine, session, projection and history: '+$spec.T) {
        $coordinator=New-WinSecScanCoordinator
        Add-WinSecScopeKey -Code 13
        $result=Invoke-WinSecCoordinatedScan -Coordinator $coordinator -ScopeType $spec.T -ScopeKey $spec.K -ConfirmAction $confirm
        $selected=@($result.ControlResults|Where-Object{$_.Status -cne 'NOT_SELECTED'})
        $session=Get-WinSecCoordinatorSession -Coordinator $coordinator -DeviceId $result.DeviceId -ScanId $result.ScanId
        $history=@(Get-WinSecCoordinatorHistory -Coordinator $coordinator -DeviceId $result.DeviceId)
        Assert-WinSecScopeIntegration ($script:collected.Count -eq $spec.Count -and $selected.Count -eq $spec.Count -and
            $result.ControlResults.Count -eq 14 -and $result.ScopeType -ceq $spec.T -and $result.ScopeKey -ceq $spec.K -and
            $session.ScopeKey -ceq $spec.K -and $history[0].ScopeKey -ceq $spec.K -and
            $result.OverallStatus -ceq 'NOT_SCORED' -and $null -eq $result.OverallScore -and
            ($script:lines -join ' ').Contains($spec.Label) -and $script:confirmCalls -eq 1 -and $script:storageCalls -eq 0 -and
            (ConvertTo-Json -InputObject @($result,$history) -Depth 20) -notmatch 'SYNTHETIC-SCOPE-PRIVATE|"Evidence"')
    }
    Test-WinSecScopeIntegration ('Enter confirms the fully visible '+$spec.T+' request') {
        $coordinator=New-WinSecScanCoordinator
        Add-WinSecScopeKey -Code 13
        $result=Invoke-WinSecCoordinatedScan -Coordinator $coordinator -ScopeType $spec.T -ScopeKey $spec.K -ConfirmAction $confirm
        Assert-WinSecScopeIntegration ($null -ne $result -and $script:collected.Count -eq $spec.Count)
    }
    foreach($code in @(27,78)){
        Test-WinSecScopeIntegration ('Esc cancels and N is ignored before any collector for '+$spec.T+' key '+$code) {
            $coordinator=New-WinSecScanCoordinator
            Add-WinSecScopeKey -Character $(if($code -eq 78){'N'}else{''}) -Code $code
            if($code -eq 78){Add-WinSecScopeKey -Code 27}
            $result=Invoke-WinSecCoordinatedScan -Coordinator $coordinator -ScopeType $spec.T -ScopeKey $spec.K -ConfirmAction $confirm
            Assert-WinSecScopeIntegration ($null -eq $result -and $script:collected.Count -eq 0 -and
                $script:confirmCalls -eq 1 -and $coordinator.Sessions.Count -eq 0 -and $script:storageCalls -eq 0 -and $script:keys.Count -eq 0)
        }
    }
}
Test-WinSecScopeIntegration 'Narrow terminal wraps the complete section request without clipping its scope or controls' {
    $coordinator=New-WinSecScanCoordinator
    $script:terminal=[pscustomobject]@{Width=40;ContentWidth=39;Height=28}
    Add-WinSecScopeKey -Code 13
    $result=Invoke-WinSecCoordinatedScan -Coordinator $coordinator -ScopeType SECTION -ScopeKey SystemSecurity -ConfirmAction $confirm
    Assert-WinSecScopeIntegration ($result.ScopeKey -ceq 'SystemSecurity' -and $script:collected.Count -eq 2 -and
        ($script:lines -join '').Contains('Section: SystemSecurity') -and
        @($script:lines|Where-Object{$_.Length -gt 39}).Count -eq 0 -and $script:lines.Count -lt 28)
}
Test-WinSecScopeIntegration 'Small terminal and shrink reject Enter until a complete request is visible' {
    $coordinator=New-WinSecScanCoordinator
    $small=[pscustomobject]@{Width=40;ContentWidth=39;Height=10}
    Add-WinSecScopeKey -Code 13 -Terminal $small
    Add-WinSecScopeKey -Code 27
    $result=Invoke-WinSecCoordinatedScan -Coordinator $coordinator -ScopeType SECTION -ScopeKey SystemSecurity -ConfirmAction $confirm
    Assert-WinSecScopeIntegration ($null -eq $result -and $script:collected.Count -eq 0 -and
        $coordinator.Sessions.Count -eq 0 -and ($script:lines -join ' ') -match 'Resize to view')
}
Test-WinSecScopeIntegration 'Resize alone never confirms; a fresh Enter approves the complete scoped request' {
    $coordinator=New-WinSecScanCoordinator
    $script:terminal=[pscustomobject]@{Width=40;ContentWidth=39;Height=10}
    $full=[pscustomobject]@{Width=80;ContentWidth=79;Height=30}
    Add-WinSecScopeKey -Code 13
    Add-WinSecScopeKey -Terminal $full
    Add-WinSecScopeKey -Code 13
    $result=Invoke-WinSecCoordinatedScan -Coordinator $coordinator -ScopeType CONTROL -ScopeKey WSA-SYS-001 -ConfirmAction $confirm
    Assert-WinSecScopeIntegration ($result.ScopeKey -ceq 'WSA-SYS-001' -and $script:collected.Count -eq 1 -and
        ($script:lines -join ' ') -match 'Control: WSA-SYS-001' -and
        @($script:lines|Where-Object{$_.Length -gt 79}).Count -eq 0 -and $script:lines.Count -lt 30)
}
Test-WinSecScopeIntegration 'Explicitly disabled catalog fixture cannot create a scoped session even when Enter is pressed' {
    $coordinator=New-WinSecScanCoordinator;$script:readyIds=@()
    Add-WinSecScopeKey -Code 13;Add-WinSecScopeKey -Code 13;Add-WinSecScopeKey -Code 27
    $result=Invoke-WinSecCoordinatedScan -Coordinator $coordinator -ScopeType SECTION -ScopeKey SystemSecurity -ConfirmAction $confirm
    Assert-WinSecScopeIntegration ($null -eq $result -and $script:collected.Count -eq 0 -and
        $coordinator.Sessions.Count -eq 0 -and ($script:lines -join ' ') -match 'NO_EXECUTABLE_CHECKS')
}
Test-WinSecScopeIntegration 'Technical errors stay errors without scoring or manufactured findings under a control scope' {
    $coordinator=New-WinSecScanCoordinator;$script:errorCheck='WSA-SYS-001'
    Add-WinSecScopeKey -Code 13
    $result=Invoke-WinSecCoordinatedScan -Coordinator $coordinator -ScopeType CONTROL -ScopeKey WSA-SYS-001 -ConfirmAction $confirm
    $record=@($result.ControlResults|Where-Object{$_.CheckId -ceq 'WSA-SYS-001'})[0]
    Assert-WinSecScopeIntegration ($result.ExecutionStatus -ceq 'COMPLETED_WITH_ERRORS' -and
        $record.ObservedStatus -ceq 'ERROR' -and $result.OverallStatus -ceq 'NOT_SCORED' -and
        @($result.Findings).Count -eq 0 -and $script:collected.Count -eq 1)
}
Test-WinSecScopeIntegration 'Scan and Rescan labels follow exact scope history and Enter creates separate sessions' {
    $coordinator=New-WinSecScanCoordinator
    Add-WinSecScopeKey -Code 13
    $full=Invoke-WinSecCoordinatedScan -Coordinator $coordinator -ConfirmAction $confirm
    Assert-WinSecScopeIntegration (($script:lines -join ' ') -match 'CONFIRM SCAN' -and
        ($script:lines -join ' ') -notmatch 'CONFIRM RESCAN')
    $key=Get-WinSecScanSessionKey $full.DeviceId $full.ScanId
    $before=ConvertTo-Json -InputObject $coordinator.Sessions[$key] -Depth 25 -Compress
    Add-WinSecScopeKey -Code 13
    $section=Invoke-WinSecCoordinatedScan -Coordinator $coordinator -ScopeType SECTION -ScopeKey SystemSecurity -ConfirmAction $confirm
    Assert-WinSecScopeIntegration (($script:lines -join ' ') -match 'CONFIRM SCAN')
    Add-WinSecScopeKey -Code 13
    $repeat=Invoke-WinSecCoordinatedScan -Coordinator $coordinator -ScopeType SECTION -ScopeKey SystemSecurity -ConfirmAction $confirm
    Assert-WinSecScopeIntegration (($script:lines -join ' ') -match 'CONFIRM RESCAN' -and
        $coordinator.Sessions.Count -eq 3 -and $section.ScanId -cne $repeat.ScanId -and
        (Get-WinSecScanAction $coordinator $full.DeviceId DEVICE ALL) -ceq 'Rescan' -and
        (Get-WinSecScanAction $coordinator $full.DeviceId CONTROL WSA-SYS-001) -ceq 'Scan' -and
        $before -ceq (ConvertTo-Json -InputObject $coordinator.Sessions[$key] -Depth 25 -Compress))
}
Write-Host "Passed: $script:passed"
Write-Host "Failed: $script:failed"
if($script:failed -gt 0){throw "$script:failed coordinator scope integration test(s) failed."}
