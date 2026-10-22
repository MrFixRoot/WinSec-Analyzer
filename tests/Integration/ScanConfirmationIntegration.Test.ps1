# CLI -> ScanCoordinator -> real confirmation UI; only terminal/collector data
# are simulated. No scans, evidence persistence, configuration writes or Pester.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/CLI/Invoke-WinSecCLI.ps1')
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
. (Join-Path $root 'src/UI/Core/ResizeHandler.ps1')
. (Join-Path $root 'src/UI/Screens/ScanConfirmation.ps1')
$script:realRegistry = (Get-Command Get-WinSecCheckRegistry).ScriptBlock
$script:passed = 0
$script:failed = 0

function Assert-WinSecConfirmationIntegration {
    param([bool]$Condition, [string]$Message = 'Confirmation integration assertion failed.')
    if (-not $Condition) { throw $Message }
}
function Test-WinSecConfirmationIntegrationCase {
    param([string]$Name, [scriptblock]$Action)
    $script:auditCalls = 0
    $script:version = 'SYNTHETIC-CONFIRMATION'
    $script:keys = New-Object 'System.Collections.Generic.Queue[object]'
    $script:terminal = [pscustomobject]@{ Width = 100; ContentWidth = 99; Height = 40 }
    try {
        $null = & $Action
        $script:passed++
        Write-Host "[PASS] $Name"
    }
    catch {
        $script:failed++
        Write-Host "[FAIL] $Name : $($_.Exception.Message)"
    }
}
function Get-WinSecCheckRegistry {
    param($ProjectRoot)
    return [pscustomobject]@{
        CatalogVersion = $script:version
        Sections = @([pscustomobject]@{ key = 'SystemSecurity' })
        Checks = @([pscustomobject]@{
            CheckId = 'WSA-SYS-001'; Name = 'Synthetic confirmation control'; SectionKey = 'SystemSecurity'
            ExecutionEnabled = $true; ExecutionReady = $true
            ImplementationStatus = 'VALIDATED'; RegistryStatus = 'READY'
            ScriptPath = Join-Path $ProjectRoot 'src/Checks/Defender/Test-Defender.ps1'
        })
    }
}
function Invoke-WinSecAudit {
    param($DeviceId, $ScanId, $CheckIds, $Registry, [switch]$SkipScoring)
    $script:auditCalls++
    Assert-WinSecConfirmationIntegration ($SkipScoring -and @($CheckIds).Count -eq 1)
    return [pscustomobject]@{
        DeviceId = $DeviceId; ScanId = $ScanId; AuditId = $ScanId; CollectionMode = 'LOCAL'
        ComputerName = 'SYNTHETIC'; CatalogVersion = $Registry.CatalogVersion
        StartedAtUTC = '2026-01-01T00:00:00Z'; CompletedAtUTC = '2026-01-01T00:01:00Z'
        ExecutionStatus = 'COMPLETED'; ScoringEnabled = $false; OverallScore = $null; ScoreResult = $null
        ControlResults = @([pscustomobject]@{
            DeviceId = $DeviceId; ScanId = $ScanId; CheckId = 'WSA-SYS-001'; SectionKey = 'SystemSecurity'
            Status = 'INFORMATIONAL'; ObservedStatus = 'INFORMATIONAL'
            Evidence = [pscustomobject]@{ Synthetic = $true }
        })
    }
}
function Get-WinSecTerminalSize { return $script:terminal }
function Clear-WinSecScreen { $script:lines = @() }
function Write-WinSecText { param($Text, $Color) $script:lines += $Text }
function Read-WinSecResizeAwareKey {
    param($ResizeState, $RenderAction)
    if ($script:keys.Count -eq 0) { throw 'No simulated confirmation input remains.' }
    $key = $script:keys.Dequeue()
    if ($key.PSObject.Properties['Terminal']) { $script:terminal = $key.Terminal }
    if ($key.PSObject.Properties['CatalogChange']) { $script:version = 'CHANGED' }
    return $key
}
function Add-WinSecConfirmationIntegrationKey {
    param([string]$Character = '', [int]$Code = 0, [switch]$CatalogChange, [switch]$Small)
    $key = [pscustomobject]@{
        Character = $Character; VirtualKeyCode = $Code; ControlKeyState = 0; KeyDown = $true
    }
    if ($CatalogChange) { $key | Add-Member -NotePropertyName CatalogChange -NotePropertyValue $true }
    if ($Small) {
        $key | Add-Member -NotePropertyName Terminal -NotePropertyValue ([pscustomobject]@{
            Width = 40; ContentWidth = 39; Height = 10
        })
    }
    $script:keys.Enqueue($key)
}
function New-WinSecConfirmationIntegrationContext {
    $target = New-WinSecLocalTarget
    return [pscustomobject]@{
        State = [pscustomobject]@{ Screen = 'Devices'; DeviceIndex=0; SelectedDeviceId = $target.DeviceId }
        Context = [pscustomobject]@{
            Devices = @($target)
            ScanCoordinator = New-WinSecScanCoordinator
            ActiveScanByDevice = @{}
            PublicScans = @{}
            LastScanMessage = 'PREVIOUS-MESSAGE'
        }
    }
}

Test-WinSecConfirmationIntegrationCase 'Explicit Y connects the real CLI dialog to the coordinator' {
    $fixture = New-WinSecConfirmationIntegrationContext
    Add-WinSecConfirmationIntegrationKey -Character 'Y' -Code 89
    $public = Invoke-WinSecCLILocalRescan -State $fixture.State -Context $fixture.Context
    Assert-WinSecConfirmationIntegration ($script:auditCalls -eq 1 -and $public.PublicProjection -ceq $true)
    Assert-WinSecConfirmationIntegration ($fixture.Context.PublicScans.Count -eq 1 -and
        $fixture.Context.ScanCoordinator.Sessions.Count -eq 1 -and $public.OverallStatus -ceq 'NOT_SCORED')
    Assert-WinSecConfirmationIntegration (($script:lines -join ' ').Contains('Synthetic confirmation control'))
}
Test-WinSecConfirmationIntegrationCase 'Escape preserves the existing public result and coordinator history' {
    $fixture = New-WinSecConfirmationIntegrationContext
    Add-WinSecConfirmationIntegrationKey -Character 'Y' -Code 89
    $first = Invoke-WinSecCLILocalRescan -State $fixture.State -Context $fixture.Context
    # Keep every state field except the two user-facing notices. Avoid a JSON
    # round trip here: it can reinterpret timestamps in the previous session.
    $before = ConvertTo-Json -InputObject @($fixture.State,
        ($fixture.Context | Select-Object * -ExcludeProperty LastScanMessage,LastDeviceMessage)) -Depth 20 -Compress
    Add-WinSecConfirmationIntegrationKey -Code 27
    $cancelled = Invoke-WinSecCLILocalRescan -State $fixture.State -Context $fixture.Context
    Assert-WinSecConfirmationIntegration ($null -eq $cancelled -and $script:auditCalls -eq 1)
    Assert-WinSecConfirmationIntegration (
        (ConvertTo-Json -InputObject @($fixture.State,
            ($fixture.Context | Select-Object * -ExcludeProperty LastScanMessage,LastDeviceMessage)) -Depth 20 -Compress) -ceq $before -and
        $fixture.Context.LastScanMessage -ceq 'Scan cancelled. Previous results were preserved.' -and
        $fixture.Context.LastDeviceMessage -ceq $fixture.Context.LastScanMessage
    ) 'Cancellation changed the selected assessment or its prior state.'
}
Test-WinSecConfirmationIntegrationCase 'A small resized terminal cannot approve with Y' {
    $fixture = New-WinSecConfirmationIntegrationContext
    Add-WinSecConfirmationIntegrationKey -Character 'Y' -Code 89 -Small
    Add-WinSecConfirmationIntegrationKey -Code 27
    $cancelled = Invoke-WinSecCLILocalRescan -State $fixture.State -Context $fixture.Context
    Assert-WinSecConfirmationIntegration ($null -eq $cancelled -and $script:auditCalls -eq 0 -and
        $fixture.Context.PublicScans.Count -eq 0 -and $fixture.Context.LastScanMessage -ceq 'Scan cancelled. Previous results were preserved.')
}
Test-WinSecConfirmationIntegrationCase 'Catalog changes while the dialog is open abort before collection' {
    $fixture = New-WinSecConfirmationIntegrationContext
    Add-WinSecConfirmationIntegrationKey -Character 'Y' -Code 89 -CatalogChange
    $caught = $false
    try { $null = Invoke-WinSecCLILocalRescan -State $fixture.State -Context $fixture.Context }
    catch { $caught = $true }
    Assert-WinSecConfirmationIntegration ($caught -and $script:auditCalls -eq 0 -and
        $fixture.Context.PublicScans.Count -eq 0 -and $fixture.Context.ScanCoordinator.Sessions.Count -eq 0)
}
Test-WinSecConfirmationIntegrationCase 'A second accepted operation gets its own confirmation and session' {
    $fixture = New-WinSecConfirmationIntegrationContext
    Add-WinSecConfirmationIntegrationKey -Character 'Y' -Code 89
    $first = Invoke-WinSecCLILocalRescan -State $fixture.State -Context $fixture.Context
    Add-WinSecConfirmationIntegrationKey -Character 'Y' -Code 89
    $second = Invoke-WinSecCLILocalRescan -State $fixture.State -Context $fixture.Context
    Assert-WinSecConfirmationIntegration ($first.ScanId -cne $second.ScanId -and $script:auditCalls -eq 2 -and
        $fixture.Context.PublicScans.Count -eq 2 -and $fixture.Context.ScanCoordinator.Sessions.Count -eq 2)
}
Test-WinSecConfirmationIntegrationCase 'An explicitly disabled registry reports NO_EXECUTABLE_CHECKS without an audit' {
    $fakeRegistry = (Get-Command Get-WinSecCheckRegistry).ScriptBlock
    try {
        Set-Item -Path Function:\Get-WinSecCheckRegistry -Value {
            param($ProjectRoot)
            $registry=& $script:realRegistry -ProjectRoot $ProjectRoot
            foreach($check in $registry.Checks){$check.ExecutionEnabled=$false;$check.ExecutionReady=$false}
            return $registry
        }
        $fixture = New-WinSecConfirmationIntegrationContext
        Add-WinSecConfirmationIntegrationKey -Character 'Y' -Code 89
        Add-WinSecConfirmationIntegrationKey -Code 27
        $result = Invoke-WinSecCLILocalRescan -State $fixture.State -Context $fixture.Context
        Assert-WinSecConfirmationIntegration ($null -eq $result -and $script:auditCalls -eq 0 -and
            $fixture.Context.PublicScans.Count -eq 0 -and $fixture.Context.ScanCoordinator.Sessions.Count -eq 0)
        Assert-WinSecConfirmationIntegration (($script:lines -join ' ').Contains('NO_EXECUTABLE_CHECKS'))
    }
    finally { Set-Item -Path Function:\Get-WinSecCheckRegistry -Value $fakeRegistry }
}

Test-WinSecConfirmationIntegrationCase 'Selecting Cancel with arrows and Enter cannot collect or publish' {
    $fixture = New-WinSecConfirmationIntegrationContext
    Add-WinSecConfirmationIntegrationKey -Code 39
    Add-WinSecConfirmationIntegrationKey -Code 13
    $result = Invoke-WinSecCLILocalRescan -State $fixture.State -Context $fixture.Context
    Assert-WinSecConfirmationIntegration ($null -eq $result -and $script:auditCalls -eq 0 -and
        $fixture.Context.PublicScans.Count -eq 0 -and $fixture.Context.ScanCoordinator.Sessions.Count -eq 0 -and
        $fixture.Context.LastDeviceMessage -ceq 'Scan cancelled. Previous results were preserved.')
}
Write-Host "Passed: $script:passed"
Write-Host "Failed: $script:failed"
if ($script:failed -gt 0) { throw "$script:failed confirmation integration test(s) failed." }
