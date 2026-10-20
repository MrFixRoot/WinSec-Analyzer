# Per-operation confirmation contracts. All collectors are mocked.
# Catalog/script files are only read; no Windows scans or file writes.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
$script:passed = 0
$script:failed = 0

function Assert-WinSecConfirmationTest {
    param([bool]$Condition, [string]$Message = 'Confirmation assertion failed.')
    if (-not $Condition) { throw $Message }
}
function Test-WinSecConfirmationCase {
    param([string]$Name, [scriptblock]$Action)
    $script:auditCalls = 0
    $script:persistenceCalls = 0
    $script:catalogVersion = 'CONFIRMATION-FIXTURE'
    $script:available = $true
    $script:resultMutation = ''
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
function Assert-WinSecConfirmationRejected {
    param([scriptblock]$Action)
    $caught = $null
    try { $null = & $Action } catch { $caught = $_ }
    Assert-WinSecConfirmationTest ($null -ne $caught)
    Assert-WinSecConfirmationTest ($caught.Exception.Message -notmatch 'PRIVATE-FIXTURE')
    Assert-WinSecConfirmationTest ($script:auditCalls -eq 0)
    Assert-WinSecConfirmationTest ($script:persistenceCalls -eq 0)
}

# A regression must fail safely before touching real evidence storage.
function Assert-WinSecEvidenceProtection { $script:persistenceCalls++; throw 'Unexpected evidence preflight in an in-memory test.' }
function Get-WinSecEvidenceStorageRoot { param($ProjectRoot) $script:persistenceCalls++; throw 'Unexpected storage access.' }
function Save-WinSecCoordinatedEvidence { param($ProjectRoot, $Session) $script:persistenceCalls++; throw 'Unexpected evidence write.' }

# Readiness is synthetic test data, never a production configuration edit.
function Get-WinSecCheckRegistry {
    param([string]$ProjectRoot)
    $checks = @(
        foreach ($number in @(1, 2)) {
            [pscustomobject]@{
                CheckId = 'WSA-SYS-00' + $number
                Name = 'Synthetic control ' + $number
                SectionKey = 'SystemSecurity'
                ExecutionEnabled = $script:available
                ExecutionReady = $script:available
                ImplementationStatus = 'VALIDATED'
                RegistryStatus = 'READY'
                ScriptPath = Join-Path $ProjectRoot 'src/Checks/Defender/Test-Defender.ps1'
            }
        }
    )
    return [pscustomobject]@{
        Checks = $checks
        Sections = @([pscustomobject]@{ key = 'SystemSecurity' })
        CatalogVersion = $script:catalogVersion
    }
}
function Invoke-WinSecAudit {
    param($DeviceId, $ScanId, [string[]]$CheckIds, $Registry, [switch]$SkipScoring)
    $script:auditCalls++
    $script:lastIds = @($CheckIds)
    $script:skipScoring = [bool]$SkipScoring
    $result = [pscustomobject]@{
        DeviceId = $DeviceId; ScanId = $ScanId; AuditId = $ScanId
        ComputerName = 'SYNTHETIC'; CollectionMode = 'LOCAL'
        StartedAtUTC = '2026-01-01T00:00:00Z'; CompletedAtUTC = '2026-01-01T00:01:00Z'
        ExecutionStatus = 'COMPLETED'; OverallScore = $null; ScoreResult = $null
        ScoringEnabled = $false; CatalogVersion = $Registry.CatalogVersion
        ControlResults = @(
            foreach ($check in $Registry.Checks) {
                [pscustomobject]@{
                    CheckId = $check.CheckId; DeviceId = $DeviceId; ScanId = $ScanId
                    SectionKey = $check.SectionKey
                    Status = if ($CheckIds -ccontains $check.CheckId) { 'INFORMATIONAL' } else { 'NOT_SELECTED' }
                    ObservedStatus = 'INFORMATIONAL'
                    Evidence = [pscustomobject]@{ Synthetic = $true }
                }
            }
        )
    }
    switch ($script:resultMutation) {
        'OMIT' { $result.ControlResults[0].Status = 'NOT_SELECTED' }
        'EXTRA' { $result.ControlResults[1].Status = 'INFORMATIONAL' }
        'VERSION' { $result.CatalogVersion = 'FOREIGN-CATALOG' }
    }
    return $result
}

Test-WinSecConfirmationCase 'A direct call without confirmation cannot audit' {
    $coordinator = New-WinSecScanCoordinator
    Assert-WinSecConfirmationRejected { Invoke-WinSecCoordinatedScan -Coordinator $coordinator }
    Assert-WinSecConfirmationTest ($coordinator.Sessions.Count -eq 0)
}
Test-WinSecConfirmationCase 'Cancellation preserves a prior session and performs no audit' {
    $coordinator = New-WinSecScanCoordinator
    $old = [pscustomobject]@{ Marker = 'PREVIOUS-SESSION' }
    $coordinator.Sessions['previous'] = $old
    $result = Invoke-WinSecCoordinatedScan -Coordinator $coordinator -ConfirmAction { param($request) $false }
    Assert-WinSecConfirmationTest ($null -eq $result -and $script:auditCalls -eq 0)
    Assert-WinSecConfirmationTest ($coordinator.Sessions.Count -eq 1 -and
        [object]::ReferenceEquals($coordinator.Sessions['previous'], $old))
}
foreach ($invalidDecision in @('Y', 1, @($true, $true), $null)) {
    Test-WinSecConfirmationCase 'Only exactly one Boolean can approve' {
        $coordinator = New-WinSecScanCoordinator
        Assert-WinSecConfirmationRejected {
            Invoke-WinSecCoordinatedScan -Coordinator $coordinator -ConfirmAction { param($request) $invalidDecision }
        }
    }
}
Test-WinSecConfirmationCase 'Confirmation errors are generic and cannot audit' {
    $coordinator = New-WinSecScanCoordinator
    Assert-WinSecConfirmationRejected {
        Invoke-WinSecCoordinatedScan -Coordinator $coordinator -ConfirmAction { throw 'PRIVATE-FIXTURE' }
    }
}
Test-WinSecConfirmationCase 'Approval displays the local device and actual executable selection' {
    $coordinator = New-WinSecScanCoordinator
    $result = Invoke-WinSecCoordinatedScan -Coordinator $coordinator -ConfirmAction {
        param($request)
        Assert-WinSecConfirmationTest ($request.Operation -ceq 'SCAN' -and $request.ReadOnly -ceq $true)
        Assert-WinSecConfirmationTest ($request.DeviceId -ceq (New-WinSecLocalTarget).DeviceId)
        Assert-WinSecConfirmationTest ($request.Hostname -ceq (New-WinSecLocalTarget).Hostname)
        Assert-WinSecConfirmationTest ($request.Checks.Count -eq 2 -and $request.SelectionMode -ceq 'ALL_EXECUTABLE')
        $true
    }
    Assert-WinSecConfirmationTest ($script:auditCalls -eq 1 -and $script:skipScoring)
    Assert-WinSecConfirmationTest ($result.PublicProjection -ceq $true -and $result.OverallStatus -ceq 'NOT_SCORED')
}
Test-WinSecConfirmationCase 'Explicit selection executes only the confirmed control' {
    $coordinator = New-WinSecScanCoordinator
    $result = Invoke-WinSecCoordinatedScan -Coordinator $coordinator -CheckIds @('WSA-SYS-002') -ConfirmAction {
        param($request)
        Assert-WinSecConfirmationTest ($request.SelectionMode -ceq 'EXPLICIT_CHECKS' -and
            $request.Checks.Count -eq 1 -and $request.Checks[0].CheckId -ceq 'WSA-SYS-002')
        $true
    }
    Assert-WinSecConfirmationTest ($script:lastIds.Count -eq 1 -and $script:lastIds[0] -ceq 'WSA-SYS-002')
    Assert-WinSecConfirmationTest ($result.ControlResults[0].Status -ceq 'NOT_SELECTED')
}
Test-WinSecConfirmationCase 'Every rescan requires another approval' {
    $coordinator = New-WinSecScanCoordinator
    $script:confirmationCalls = 0
    $confirm = { param($request) $script:confirmationCalls++; return ($script:confirmationCalls -eq 1) }
    $first = Invoke-WinSecCoordinatedScan -Coordinator $coordinator -ConfirmAction $confirm
    $second = Invoke-WinSecCoordinatedScan -Coordinator $coordinator -ConfirmAction $confirm
    Assert-WinSecConfirmationTest ($script:confirmationCalls -eq 2 -and $script:auditCalls -eq 1)
    Assert-WinSecConfirmationTest ($null -ne $first -and $null -eq $second -and $coordinator.Sessions.Count -eq 1)
}
Test-WinSecConfirmationCase 'Modified confirmation previews are rejected' {
    $coordinator = New-WinSecScanCoordinator
    Assert-WinSecConfirmationRejected {
        Invoke-WinSecCoordinatedScan -Coordinator $coordinator -ConfirmAction {
            param($request) $request.Checks[0].Name = 'CHANGED'; $true
        }
    }
}
Test-WinSecConfirmationCase 'A catalog change after approval requires fresh confirmation' {
    $coordinator = New-WinSecScanCoordinator
    Assert-WinSecConfirmationRejected {
        Invoke-WinSecCoordinatedScan -Coordinator $coordinator -ConfirmAction {
            param($request) $script:catalogVersion = 'CHANGED'; $true
        }
    }
}
Test-WinSecConfirmationCase 'A target disabled during confirmation cannot run' {
    $coordinator = New-WinSecScanCoordinator
    Assert-WinSecConfirmationRejected {
        Invoke-WinSecCoordinatedScan -Coordinator $coordinator -ConfirmAction {
            param($request)
            $coordinator.Registry.targets = @([pscustomobject]@{
                DeviceId = $request.DeviceId; Hostname = $request.Hostname; Mode = 'LOCAL'; Enabled = $false
            })
            $true
        }
    }
}
Test-WinSecConfirmationCase 'No executable controls cannot create a session even if approval is attempted' {
    $coordinator = New-WinSecScanCoordinator
    $script:available = $false
    Assert-WinSecConfirmationRejected {
        Invoke-WinSecCoordinatedScan -Coordinator $coordinator -ConfirmAction {
            param($request)
            Assert-WinSecConfirmationTest ($request.Checks.Count -eq 0)
            $true
        }
    }
    Assert-WinSecConfirmationTest ($coordinator.Sessions.Count -eq 0)
}
Test-WinSecConfirmationCase 'Raw evidence requires its own confirmation handler' {
    $coordinator = New-WinSecScanCoordinator
    Assert-WinSecConfirmationRejected {
        Invoke-WinSecCoordinatedScan -Coordinator $coordinator -PersistEvidence -ConfirmAction { $true }
    }
}
foreach ($mutation in @('OMIT', 'EXTRA', 'VERSION')) {
    Test-WinSecConfirmationCase "A result outside the approved selection cannot be published: $mutation" {
        $coordinator = New-WinSecScanCoordinator
        $script:resultMutation = $mutation
        $caught = $false
        try {
            $null = Invoke-WinSecCoordinatedScan -Coordinator $coordinator -CheckIds @('WSA-SYS-001') `
                -ConfirmAction { $true }
        }
        catch { $caught = $true }
        Assert-WinSecConfirmationTest ($caught -and $script:auditCalls -eq 1 -and $coordinator.Sessions.Count -eq 0)
    }
}
Test-WinSecConfirmationCase 'A control disabled during confirmation cannot run' {
    $coordinator = New-WinSecScanCoordinator
    Assert-WinSecConfirmationRejected {
        Invoke-WinSecCoordinatedScan -Coordinator $coordinator -ConfirmAction {
            param($request) $script:available = $false; $true
        }
    }
}
Test-WinSecConfirmationCase 'Declining separate evidence consent prevents both audit and persistence' {
    $coordinator = New-WinSecScanCoordinator
    $result = Invoke-WinSecCoordinatedScan -Coordinator $coordinator -PersistEvidence `
        -ConfirmAction { $true } -ConfirmEvidenceAction {
            param($request)
            Assert-WinSecConfirmationTest ($request.Operation -ceq 'STORE_RAW_EVIDENCE')
            $false
        }
    Assert-WinSecConfirmationTest ($null -eq $result -and $script:auditCalls -eq 0 -and $coordinator.Sessions.Count -eq 0)
}
foreach ($invalidEvidenceDecision in @('Y', @($true, $true), $null)) {
    Test-WinSecConfirmationCase 'Separate evidence consent must also be exactly one Boolean' {
        $coordinator = New-WinSecScanCoordinator
        Assert-WinSecConfirmationRejected {
            Invoke-WinSecCoordinatedScan -Coordinator $coordinator -PersistEvidence `
                -ConfirmAction { $true } -ConfirmEvidenceAction { $invalidEvidenceDecision }
        }
        Assert-WinSecConfirmationTest ($coordinator.Sessions.Count -eq 0)
    }
}
Test-WinSecConfirmationCase 'Evidence confirmation errors cannot expose private text or start a scan' {
    $coordinator = New-WinSecScanCoordinator
    Assert-WinSecConfirmationRejected {
        Invoke-WinSecCoordinatedScan -Coordinator $coordinator -PersistEvidence `
            -ConfirmAction { $true } -ConfirmEvidenceAction { throw 'PRIVATE-FIXTURE' }
    }
}
Test-WinSecConfirmationCase 'Modified evidence confirmation requests cannot start a scan' {
    $coordinator = New-WinSecScanCoordinator
    Assert-WinSecConfirmationRejected {
        Invoke-WinSecCoordinatedScan -Coordinator $coordinator -PersistEvidence `
            -ConfirmAction { $true } -ConfirmEvidenceAction { param($request) $request.DeviceId = 'local:OTHER'; $true }
    }
}

# UI dependencies are replaced with in-memory terminal/key fixtures.
. (Join-Path $root 'src/UI/Screens/ScanConfirmation.ps1')
function Get-WinSecTerminalSize { return $script:terminal }
function Clear-WinSecScreen { $script:lines = @() }
function Write-WinSecText { param($Text, $Color) $script:lines += $Text }
function New-WinSecResizeState { return [pscustomobject]@{} }
function Invoke-WinSecResizeHandler {
    param($ResizeState, $RenderAction)
    if ($script:needsRender) { $script:needsRender = $false; $null = & $RenderAction $null; return $true }
    return $false
}
function Read-WinSecResizeAwareKey {
    param($ResizeState, $RenderAction)
    if ($script:keys.Count -eq 0) { throw 'Test key queue exhausted.' }
    $key = $script:keys.Dequeue()
    if ($key.PSObject.Properties['Terminal']) { $script:terminal = $key.Terminal; $script:needsRender = $true }
    return $key
}
function New-WinSecConfirmationUIFixture {
    $script:terminal = [pscustomobject]@{ Width = 100; ContentWidth = 99; Height = 40 }
    $script:keys = New-Object 'System.Collections.Generic.Queue[object]'
    $script:needsRender = $false
    return [pscustomobject]@{
        Operation = 'SCAN'; DeviceId = 'local:UI-FIXTURE'; Hostname = 'UI-FIXTURE'
        SelectionMode = 'ALL_EXECUTABLE'; ReadOnly = $true; CatalogVersion = 'FIXTURE'
        Checks = @([pscustomobject]@{ CheckId = 'WSA-SYS-001'; SectionKey = 'SystemSecurity'; Name = 'Synthetic control' })
    }
}
function New-WinSecConfirmationKey {
    param([string]$Character = '', [int]$Code = 0, [int]$Modifiers = 0)
    return [pscustomobject]@{ Character = $Character; VirtualKeyCode = $Code; ControlKeyState = $Modifiers; KeyDown = $true }
}
Test-WinSecConfirmationCase 'UI explicitly confirms Y after showing identity scope controls and read-only mode' {
    $request = New-WinSecConfirmationUIFixture
    $script:keys.Enqueue((New-WinSecConfirmationKey -Character 'y' -Code 89))
    $result = Show-WinSecScanConfirmation -Request $request
    Assert-WinSecConfirmationTest ($result -ceq $true)
    $text = $script:lines -join ' '
    foreach ($expected in @('local:UI-FIXTURE', 'UI-FIXTURE', 'Scope:', 'WSA-SYS-001', 'READ ONLY')) {
        Assert-WinSecConfirmationTest ($text.Contains($expected))
    }
}
foreach ($code in @(27, 13, 78)) {
    Test-WinSecConfirmationCase 'Escape Enter and N cancel instead of approving' {
        $request = New-WinSecConfirmationUIFixture
        $character = if ($code -eq 78) { 'n' } else { '' }
        $script:keys.Enqueue((New-WinSecConfirmationKey -Character $character -Code $code))
        Assert-WinSecConfirmationTest ((Show-WinSecScanConfirmation -Request $request) -ceq $false)
    }
}
Test-WinSecConfirmationCase 'Small terminals cannot approve a truncated request' {
    $request = New-WinSecConfirmationUIFixture
    $script:terminal = [pscustomobject]@{ Width = 40; ContentWidth = 39; Height = 10 }
    $script:keys.Enqueue((New-WinSecConfirmationKey -Character 'y' -Code 89))
    $script:keys.Enqueue((New-WinSecConfirmationKey -Code 27))
    Assert-WinSecConfirmationTest ((Show-WinSecScanConfirmation -Request $request) -ceq $false)
}
Test-WinSecConfirmationCase 'Resizing only redraws and does not imply consent' {
    $request = New-WinSecConfirmationUIFixture
    $key = New-WinSecConfirmationKey
    $key | Add-Member -NotePropertyName Terminal -NotePropertyValue ([pscustomobject]@{
        Width = 40; ContentWidth = 39; Height = 10
    })
    $script:keys.Enqueue($key)
    $script:keys.Enqueue((New-WinSecConfirmationKey -Character 'y' -Code 89))
    $script:keys.Enqueue((New-WinSecConfirmationKey -Code 27))
    Assert-WinSecConfirmationTest ((Show-WinSecScanConfirmation -Request $request) -ceq $false)
}
Test-WinSecConfirmationCase 'A resized complete request can be explicitly approved' {
    $request = New-WinSecConfirmationUIFixture
    $script:terminal = [pscustomobject]@{ Width = 40; ContentWidth = 39; Height = 10 }
    $key = New-WinSecConfirmationKey -Character 'Y' -Code 89
    $key | Add-Member -NotePropertyName Terminal -NotePropertyValue ([pscustomobject]@{
        Width = 100; ContentWidth = 99; Height = 40
    })
    $script:keys.Enqueue($key)
    Assert-WinSecConfirmationTest ((Show-WinSecScanConfirmation -Request $request) -ceq $true)
}
Test-WinSecConfirmationCase 'No executable checks shows the real limitation and cannot approve' {
    $request = New-WinSecConfirmationUIFixture
    $request.Checks = @()
    $script:keys.Enqueue((New-WinSecConfirmationKey -Character 'Y' -Code 89))
    $script:keys.Enqueue((New-WinSecConfirmationKey -Code 27))
    Assert-WinSecConfirmationTest ((Show-WinSecScanConfirmation -Request $request) -ceq $false)
    Assert-WinSecConfirmationTest (($script:lines -join ' ').Contains('NO_EXECUTABLE_CHECKS'))
}
Test-WinSecConfirmationCase 'Ctrl Y is ignored' {
    $request = New-WinSecConfirmationUIFixture
    $script:keys.Enqueue((New-WinSecConfirmationKey -Character 'Y' -Code 89 -Modifiers 8))
    $script:keys.Enqueue((New-WinSecConfirmationKey -Code 27))
    Assert-WinSecConfirmationTest ((Show-WinSecScanConfirmation -Request $request) -ceq $false)
}
Test-WinSecConfirmationCase 'The scan dialog cannot authorize raw evidence storage' {
    $request = New-WinSecConfirmationUIFixture
    $request.Operation = 'STORE_RAW_EVIDENCE'
    Assert-WinSecConfirmationRejected { Show-WinSecScanConfirmation -Request $request }
}
Write-Host "Passed: $script:passed"
Write-Host "Failed: $script:failed"
if ($script:failed -gt 0) { throw "$script:failed confirmation unit test(s) failed." }
