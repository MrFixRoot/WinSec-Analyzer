# Coordinador, AuditEngine, recolector Defender, identidad y ResultModel reales.
# CIM y cmdlets Defender simulados; sin consultas Windows ni escritura de datos.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
. (Join-Path $root 'src/CLI/Invoke-WinSecCLI.ps1')
. (Join-Path $root 'src/UI/Core/ResizeHandler.ps1')
. (Join-Path $root 'src/UI/Screens/ScanConfirmation.ps1')
. (Join-Path $root 'src/UI/Screens/ScanProgress.ps1')
$script:catalog = Get-WinSecCheckRegistry -ProjectRoot $root
$enabled=@($script:catalog.Checks|Where-Object ExecutionEnabled)
if($enabled.Count -ne 1 -or $enabled[0].CheckId -cne 'WSA-SYS-001' -or -not $enabled[0].ExecutionReady){throw 'Only validated Defender may be enabled in production.'}
$script:passed = 0
$script:failed = 0
$script:statusCalls = 0
$script:preferenceCalls = 0
$script:uuid = '12345678-1234-4567-89ab-123456789abc'

function Assert-WinSecDefenderIntegration {
    param([bool]$Condition, [string]$Message = 'Defender integration assertion failed.')
    if (-not $Condition) { throw $Message }
}

function New-WinSecDefenderIntegrationStatus {
    [pscustomobject]@{
        AMRunningMode = 'Normal'; AntivirusEnabled = $true; AMServiceEnabled = $true
        RealTimeProtectionEnabled = $true; IsTamperProtected = $true
    }
}

function New-WinSecDefenderIntegrationPreference {
    [pscustomobject]@{
        PUAProtection = 1; MAPSReporting = 2; SubmitSamplesConsent = 1
        AttackSurfaceReductionRules_Ids = @(
            'd4f940ab-401b-4efc-aadc-ad5f3c50688a', $null,
            '3b576869-a4ec-4529-8536-b80a7769e899'
        )
        AttackSurfaceReductionRules_Actions = @(1, 2, $null)
        ExclusionPath = @('C:\PRIVATE-DEFENDER-INTEGRATION-SENTINEL')
    }
}

function Get-CimInstance {
    [CmdletBinding()]
    param([string]$Namespace, [string]$ClassName, [string[]]$Property, [int]$OperationTimeoutSec)
    if ($Namespace -ceq 'root/cimv2' -and $ClassName -ceq 'Win32_ComputerSystemProduct') {
        return [pscustomobject]@{ UUID = $script:uuid }
    }
    if ($Namespace -cne 'root/Microsoft/Windows/Defender') { throw 'Unexpected synthetic CIM namespace.' }
    $script:cimCalls++
    if ($script:unavailable) { throw 'Synthetic telemetry unavailable.' }
    switch -CaseSensitive ($ClassName) {
        'MSFT_MpComputerStatus' { return New-WinSecDefenderIntegrationStatus }
        'MSFT_MpPreference' { return New-WinSecDefenderIntegrationPreference }
        default { throw 'Unexpected synthetic CIM class.' }
    }
}

function Get-MpComputerStatus {
    [CmdletBinding()]
    param()
    $script:statusCalls++
    if ($script:cancelOnStatus) {
        $script:progressKeys.Enqueue([pscustomobject]@{VirtualKeyCode=27;KeyDown=$true;ControlKeyState=0})
    }
    if ($script:fallback -or $script:unavailable) { throw 'Synthetic primary status unavailable.' }
    New-WinSecDefenderIntegrationStatus
}

function Get-MpPreference {
    [CmdletBinding()]
    param()
    $script:preferenceCalls++
    if ($script:fallback) { throw 'Synthetic primary preferences unavailable.' }
    New-WinSecDefenderIntegrationPreference
}

function Import-WinSecDeviceInventory {
    param($ProjectRoot)
    [pscustomobject]@{
        schemaVersion = '1.2.0'; targets = @(New-WinSecLocalTarget); removedDeviceHashes = @()
    }
}

function Get-WinSecCheckRegistry {
    param($ProjectRoot)
    $registry = Copy-WinSecResultData $script:catalog
    foreach($item in $registry.Checks){$item.ExecutionEnabled=$false;$item.ExecutionReady=$false}
    if ($script:ready) {
        $check = $registry.Checks | Where-Object CheckId -CEQ 'WSA-SYS-001'
        # Eligibility belongs only to this in-memory fixture.
        $check.ExecutionEnabled = $true
        $check.ExecutionReady = $true
        $check.ImplementationStatus = 'VALIDATED'
        $check.RegistryStatus = 'READY'
    }
    return $registry
}

function Save-WinSecPublicHistory {
    param($ProjectRoot, $Session)
    if (-not $script:allowHistorySave) { throw 'Unexpected native history persistence.' }
    if ($script:failHistorySave) { throw 'PRIVATE-SYNTHETIC-HISTORY-ERROR' }
    $script:savedHistory = New-WinSecPublicHistoryRecord -Session $Session
}
function Save-WinSecCoordinatedEvidence { throw 'Unexpected raw evidence persistence.' }
function Get-WinSecTerminalSize { $script:terminal }
function Clear-WinSecScreen {
    $script:frames.Add(($script:lines -join '|'))
    $script:lines.Clear()
}
function Write-WinSecText { param($Text,$Color); $script:lines.Add([string]$Text) }
function Read-WinSecPendingKey {
    if ($script:progressKeys.Count) { return $script:progressKeys.Dequeue() }
    return $null
}
function Read-WinSecResizeAwareKey {
    param($ResizeState,$RenderAction)
    if (-not $script:confirmationKeys.Count) { throw 'Synthetic confirmation keys exhausted.' }
    $script:confirmationKeys.Dequeue()
}

function Test-WinSecDefenderIntegration {
    param([string]$Name, [scriptblock]$Action)
    $script:statusCalls = 0; $script:preferenceCalls = 0; $script:cimCalls = 0
    $script:confirmCalls = 0; $script:ready = $true
    $script:fallback = $false; $script:unavailable = $false
    $script:cancelOnStatus = $false
    $script:allowHistorySave = $false; $script:failHistorySave = $false; $script:savedHistory = $null
    $script:events = New-Object 'System.Collections.Generic.List[object]'
    $script:lines = New-Object 'System.Collections.Generic.List[string]'
    $script:frames = New-Object 'System.Collections.Generic.List[string]'
    $script:confirmationKeys = New-Object 'System.Collections.Generic.Queue[object]'
    $script:progressKeys = New-Object 'System.Collections.Generic.Queue[object]'
    $script:terminal = [pscustomobject]@{Width=100;ContentWidth=99;Height=40}
    $script:uuid = '12345678-1234-4567-89ab-123456789abc'
    $script:coordinator = New-WinSecScanCoordinator -ProjectRoot $root
    $script:localId = (New-WinSecLocalTarget).DeviceId
    $script:coordinator.Registry = [pscustomobject]@{
        schemaVersion = '1.0.0'; targets = @(New-WinSecLocalTarget)
    }
    try {
        $null = & $Action
        $script:passed++
        Write-Host ('[PASS] ' + $Name)
    }
    catch {
        $script:failed++
        Write-Host ('[FAIL] ' + $Name + ' : ' + $_.Exception.Message)
        Write-Host $_.ScriptStackTrace
    }
}

$confirm = {
    param($request)
    $script:confirmCalls++
    Assert-WinSecDefenderIntegration ($request.DeviceId -ceq $script:localId -and
        $request.ReadOnly -ceq $true -and $request.Checks.Count -eq 1 -and
        $request.Checks[0].CheckId -ceq 'WSA-SYS-001')
    return $true
}

Test-WinSecDefenderIntegration 'Import and initialization never collect Defender telemetry' {
    Assert-WinSecDefenderIntegration ($script:statusCalls -eq 0 -and
        $script:preferenceCalls -eq 0 -and $script:cimCalls -eq 0)
}

foreach ($scope in @(
    @{ Type = 'DEVICE'; Key = 'ALL' },
    @{ Type = 'SECTION'; Key = 'SystemSecurity' },
    @{ Type = 'CONTROL'; Key = 'WSA-SYS-001' }
)) {
    Test-WinSecDefenderIntegration ('Confirmed real Defender collector reaches ResultModel: ' + $scope.Type) {
        $result = Invoke-WinSecCoordinatedScan -Coordinator $script:coordinator `
            -ScopeType $scope.Type -ScopeKey $scope.Key -ConfirmAction $confirm
        $session = Get-WinSecCoordinatorSession $script:coordinator $result.DeviceId $result.ScanId
        $selected = @($session.ControlResults | Where-Object Status -CNE 'NOT_SELECTED')
        Assert-WinSecDefenderIntegration ($script:confirmCalls -eq 1 -and
            $script:statusCalls -eq 1 -and $script:preferenceCalls -eq 1 -and $script:cimCalls -eq 0)
        Assert-WinSecDefenderIntegration ($result.ExecutionStatus -ceq 'COMPLETED' -and
            $result.DeviceId -ceq $script:localId -and $result.ScopeType -ceq $scope.Type -and
            $result.ScopeKey -ceq $scope.Key -and $selected.Count -eq 1 -and
            $selected[0].ObservedStatus -ceq 'INFORMATIONAL')
        $asr = $selected[0].Evidence.AttackSurfaceReduction
        Assert-WinSecDefenderIntegration ($asr.Complete -ceq $false -and
            $asr.Rules[1].Mode -ceq 'UNKNOWN' -and $asr.Modes.AUDIT -eq 0)
        Assert-WinSecDefenderIntegration ($result.OverallScore -eq $null -and
            $result.OverallStatus -ceq 'NOT_SCORED' -and $result.Findings.Count -eq 0)
        # Existing public-history contract accepts safe results, without persisting raw data.
        $record = New-WinSecPublicHistoryRecord -Session $session
        $json = Get-WinSecPublicHistoryJson $record
        $restored = (ConvertFrom-WinSecPublicHistoryRecord (ConvertFrom-WinSecStoredJson $json)).Record
        Assert-WinSecDefenderIntegration ($restored.DeviceId -ceq $script:localId -and
            $restored.ScanId -ceq $result.ScanId -and $restored.ScopeKey -ceq $scope.Key -and
            $json -notmatch 'PRIVATE-DEFENDER-INTEGRATION-SENTINEL|DefenderPreferences|AttackSurfaceReduction' -and
            $restored.PublicResult.ContainsRawEvidence -ceq $false)
    }
}

Test-WinSecDefenderIntegration 'Cancellation never collects or publishes a session' {
    $result = Invoke-WinSecCoordinatedScan -Coordinator $script:coordinator `
        -ScopeType CONTROL -ScopeKey WSA-SYS-001 -ConfirmAction { $false }
    Assert-WinSecDefenderIntegration ($null -eq $result -and $script:statusCalls -eq 0 -and
        $script:preferenceCalls -eq 0 -and $script:coordinator.Sessions.Count -eq 0)
}

Test-WinSecDefenderIntegration 'An explicitly disabled Defender fixture cannot execute' {
    $script:ready = $false
    $rejected = $false
    try {
        $null = Invoke-WinSecCoordinatedScan -Coordinator $script:coordinator `
            -ScopeType CONTROL -ScopeKey WSA-SYS-001 -ConfirmAction $confirm
    }
    catch { $rejected = $true }
    Assert-WinSecDefenderIntegration ($rejected -and $script:statusCalls -eq 0 -and
        $script:preferenceCalls -eq 0 -and $script:coordinator.Sessions.Count -eq 0)
}

Test-WinSecDefenderIntegration 'Foreign hardware cannot execute a local Defender scan' {
    $rejected = $false
    try {
        $null = Invoke-WinSecCoordinatedScan -Coordinator $script:coordinator `
            -DeviceId ('local:hw1-' + ('b' * 64)) -ScopeType CONTROL -ScopeKey WSA-SYS-001 -ConfirmAction $confirm
    }
    catch { $rejected = $true }
    Assert-WinSecDefenderIntegration ($rejected -and $script:statusCalls -eq 0 -and
        $script:preferenceCalls -eq 0 -and $script:confirmCalls -eq 0)
}

Test-WinSecDefenderIntegration 'CIM fallback preserves hardware identity and source' {
    $script:fallback = $true
    $result = Invoke-WinSecCoordinatedScan -Coordinator $script:coordinator `
        -ScopeType CONTROL -ScopeKey WSA-SYS-001 -ConfirmAction $confirm
    $session = Get-WinSecCoordinatorSession $script:coordinator $result.DeviceId $result.ScanId
    $evidence = ($session.ControlResults | Where-Object CheckId -CEQ 'WSA-SYS-001').Evidence
    Assert-WinSecDefenderIntegration ($script:cimCalls -eq 2 -and $evidence.DeviceId -ceq $script:localId -and
        $evidence.StatusSource -ceq 'CIM:MSFT_MpComputerStatus' -and
        $evidence.PreferenceSource -ceq 'CIM:MSFT_MpPreference')
}

Test-WinSecDefenderIntegration 'Unavailable telemetry remains a technical error without invented findings' {
    $script:unavailable = $true
    $result = Invoke-WinSecCoordinatedScan -Coordinator $script:coordinator `
        -ScopeType CONTROL -ScopeKey WSA-SYS-001 -ConfirmAction $confirm
    $control = $result.ControlResults | Where-Object CheckId -CEQ 'WSA-SYS-001'
    Assert-WinSecDefenderIntegration ($result.ExecutionStatus -ceq 'COMPLETED_WITH_ERRORS' -and
        $control.ObservedStatus -ceq 'ERROR' -and $result.Findings.Count -eq 0 -and
        $result.OverallScore -eq $null -and $result.OverallStatus -ceq 'NOT_SCORED')
}

Test-WinSecDefenderIntegration 'Progress contains real counts and completes only after session publication' {
    $result = Invoke-WinSecCoordinatedScan -Coordinator $script:coordinator `
        -ScopeType CONTROL -ScopeKey WSA-SYS-001 -ConfirmAction $confirm -ProgressCallback {
            param($event)
            $script:events.Add([pscustomobject]@{Phase=$event.Phase;Completed=$event.CompletedChecks;Total=$event.TotalChecks;
                Published=$script:coordinator.Sessions.Count})
            'Ignored observer output'
        }
    Assert-WinSecDefenderIntegration (($script:events.Phase -join ',') -ceq 'READING,CHECK_COMPLETED,FINALIZING,COMPLETED')
    Assert-WinSecDefenderIntegration (($script:events.Completed -join ',') -ceq '0,1,1,1')
    Assert-WinSecDefenderIntegration ($script:events[0].Published -eq 0 -and $script:events[-1].Published -eq 1 -and
        $script:statusCalls -eq 1 -and $result.OverallScore -eq $null)
}

Test-WinSecDefenderIntegration 'Cancelling before collection publishes no new session' {
    $result = Invoke-WinSecCoordinatedScan -Coordinator $script:coordinator `
        -ScopeType CONTROL -ScopeKey WSA-SYS-001 -ConfirmAction $confirm `
        -CancellationAction {$true} -ProgressCallback {param($event);$script:events.Add($event)}
    Assert-WinSecDefenderIntegration ($null -eq $result -and $script:statusCalls -eq 0 -and
        $script:events[-1].Phase -ceq 'CANCELLED' -and $script:coordinator.Sessions.Count -eq 0)
}

Test-WinSecDefenderIntegration 'Cancellation after Defender returns discards partial results and preserves history' {
    $previous = Invoke-WinSecCoordinatedScan -Coordinator $script:coordinator `
        -ScopeType CONTROL -ScopeKey WSA-SYS-001 -ConfirmAction $confirm
    $before = ConvertTo-Json $script:coordinator.Sessions -Depth 35 -Compress
    $script:statusCalls = 0
    $result = Invoke-WinSecCoordinatedScan -Coordinator $script:coordinator `
        -ScopeType CONTROL -ScopeKey WSA-SYS-001 -ConfirmAction $confirm `
        -CancellationAction {$script:statusCalls -gt 0} -ProgressCallback {param($event);$script:events.Add($event)}
    Assert-WinSecDefenderIntegration ($null -eq $result -and $script:statusCalls -eq 1 -and
        $script:events[-1].Phase -ceq 'CANCELLED' -and $script:events[-1].CompletedChecks -eq 1 -and
        $before -ceq (ConvertTo-Json $script:coordinator.Sessions -Depth 35 -Compress))
}

Test-WinSecDefenderIntegration 'Failed public persistence never reports completion or publishes a session' {
    $script:coordinator.PublicHistoryEnabled = $true
    $script:allowHistorySave = $true; $script:failHistorySave = $true
    $caught = $false
    try {
        $null = Invoke-WinSecCoordinatedScan -Coordinator $script:coordinator `
            -ScopeType CONTROL -ScopeKey WSA-SYS-001 -ConfirmAction $confirm `
            -ProgressCallback {param($event);$script:events.Add($event)}
    } catch { $caught = $true }
    Assert-WinSecDefenderIntegration ($caught -and $script:coordinator.Sessions.Count -eq 0 -and
        $script:events[-1].Phase -ceq 'FINALIZING' -and $null -eq $script:savedHistory)
}

Test-WinSecDefenderIntegration 'Confirmation cancellation emits no progress and never reads Defender' {
    $result = Invoke-WinSecCoordinatedScan -Coordinator $script:coordinator `
        -ScopeType CONTROL -ScopeKey WSA-SYS-001 -ConfirmAction {$false} `
        -ProgressCallback {param($event);$script:events.Add($event)}
    Assert-WinSecDefenderIntegration ($null -eq $result -and $script:events.Count -eq 0 -and $script:statusCalls -eq 0)
}

Test-WinSecDefenderIntegration 'CLI Scan and Rescan render real progress and publish safe public history in memory' {
    $script:coordinator.PublicHistoryEnabled = $true; $script:allowHistorySave = $true
    $state = [pscustomobject]@{Screen='Devices';DeviceIndex=0;SelectedDeviceId=$script:localId}
    $context = [pscustomobject]@{ScanCoordinator=$script:coordinator;Devices=@(New-WinSecLocalTarget);
        ActiveScanByDevice=@{};ActiveScanByScope=@{};PublicScans=@{};LastScanMessage=''}
    foreach ($expectedAction in @('SCAN','RESCAN')) {
        $script:confirmationKeys.Enqueue([pscustomobject]@{VirtualKeyCode=13;Character='';KeyDown=$true;ControlKeyState=0})
        $script:frames.Clear()
        $result = Invoke-WinSecCLILocalRescan -State $state -Context $context -ShowProgress
        $frames = @($script:frames.ToArray()) + @($script:lines -join '|')
        Assert-WinSecDefenderIntegration (($frames -join '|') -match ('WINSEC - '+$expectedAction+' - READ ONLY') -and
            ($frames -join '|') -match 'Reading control: WSA-SYS-001' -and
            ($frames -join '|') -match '99%' -and ($frames -join '|') -match '100%')
        Assert-WinSecDefenderIntegration ($script:savedHistory.ScanId -ceq $result.ScanId -and
            $context.ActiveScanByDevice[$script:localId] -ceq $result.ScanId -and
            $script:savedHistory.PublicResult.ContainsRawEvidence -ceq $false -and $result.Findings.Count -eq 0)
    }
    Assert-WinSecDefenderIntegration ($script:statusCalls -eq 2 -and $context.PublicScans.Count -eq 2)
}

Test-WinSecDefenderIntegration 'Escape during a real mocked Defender read preserves the last CLI assessment' {
    $script:coordinator.PublicHistoryEnabled = $true; $script:allowHistorySave = $true
    $state = [pscustomobject]@{Screen='Devices';DeviceIndex=0;SelectedDeviceId=$script:localId}
    $context = [pscustomobject]@{ScanCoordinator=$script:coordinator;Devices=@(New-WinSecLocalTarget);
        ActiveScanByDevice=@{};ActiveScanByScope=@{};PublicScans=@{};LastScanMessage=''}
    $script:confirmationKeys.Enqueue([pscustomobject]@{VirtualKeyCode=13;Character='';KeyDown=$true;ControlKeyState=0})
    $previous = Invoke-WinSecCLILocalRescan -State $state -Context $context -ShowProgress
    $before = ConvertTo-Json $context.PublicScans -Depth 25 -Compress
    $script:cancelOnStatus = $true
    $script:confirmationKeys.Enqueue([pscustomobject]@{VirtualKeyCode=13;Character='';KeyDown=$true;ControlKeyState=0})
    $cancelled = Invoke-WinSecCLILocalRescan -State $state -Context $context -ShowProgress
    Assert-WinSecDefenderIntegration ($null -eq $cancelled -and $script:coordinator.Sessions.Count -eq 1 -and
        $script:savedHistory.ScanId -ceq $previous.ScanId -and $context.ActiveScanByDevice[$script:localId] -ceq $previous.ScanId -and
        $context.LastDeviceMessage -match 'cancelled' -and
        $before -ceq (ConvertTo-Json $context.PublicScans -Depth 25 -Compress))
    Assert-WinSecDefenderIntegration (($script:lines -join '|') -match 'Cancelled' -and
        ($script:lines -join '|') -notmatch '100%')
}

Write-Host ('Defender coordinator integration: {0} passed, {1} failed.' -f $script:passed, $script:failed)
if ($script:failed -gt 0) { throw 'Defender coordinator integration failed.' }
