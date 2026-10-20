# Synthetic collector/confirmation boundaries for CLI contract integration tests.
# Dot-source after ScanCoordinator, then restore in a finally block. This fixture
# never executes a check, changes the production catalog or writes evidence.
$script:confirmedScanOriginalFunctions = @{}
foreach ($name in @('Get-WinSecCheckRegistry', 'Invoke-WinSecAudit', 'Show-WinSecScanConfirmation')) {
    $command = Get-Command $name -CommandType Function -ErrorAction SilentlyContinue
    $script:confirmedScanOriginalFunctions[$name] = if ($null -eq $command) { $null } else { $command.ScriptBlock }
}

function Get-WinSecCheckRegistry {
    param($ProjectRoot)
    $registry = & $script:confirmedScanOriginalFunctions['Get-WinSecCheckRegistry'] -ProjectRoot $ProjectRoot
    # Only this newly loaded, in-memory test object is changed.
    $selected = @($registry.Checks | Where-Object { $_.CheckId -ceq 'WSA-SYS-001' })
    if ($selected.Count -ne 1) { throw 'Synthetic integration control is missing.' }
    $selected[0].ExecutionEnabled = $true
    $selected[0].ExecutionReady = $true
    $selected[0].ImplementationStatus = 'VALIDATED'
    $selected[0].RegistryStatus = 'READY'
    return $registry
}

function Show-WinSecScanConfirmation {
    param($Request)
    if ($Request.Operation -cne 'SCAN' -or $Request.ReadOnly -cne $true -or
        @($Request.Checks).Count -ne 1 -or $Request.Checks[0].CheckId -cne 'WSA-SYS-001') {
        throw 'Unexpected synthetic confirmation request.'
    }
    return $true
}

function Invoke-WinSecAudit {
    param($DeviceId, $ScanId, $CheckIds, $Registry, [switch]$SkipScoring)
    if (-not $SkipScoring -or @($CheckIds).Count -ne 1 -or $CheckIds[0] -cne 'WSA-SYS-001') {
        throw 'Unexpected synthetic collector request.'
    }
    $controls = @(
        foreach ($check in $Registry.Checks) {
            $status = if ($check.CheckId -ceq 'WSA-SYS-001') { 'INFORMATIONAL' } else { 'NOT_SELECTED' }
            [pscustomobject]@{
                DeviceId = $DeviceId; ScanId = $ScanId; CheckId = $check.CheckId
                SectionKey = $check.SectionKey; Status = $status; ObservedStatus = $status
                Evidence = if ($status -ceq 'INFORMATIONAL') { [pscustomobject]@{ Synthetic = $true } } else { $null }
            }
        }
    )
    return [pscustomobject]@{
        DeviceId = $DeviceId; ScanId = $ScanId; AuditId = $ScanId; CollectionMode = 'LOCAL'
        ComputerName = 'SYNTHETIC'; CatalogVersion = $Registry.CatalogVersion
        StartedAtUTC = '2026-01-01T00:00:00Z'; CompletedAtUTC = '2026-01-01T00:01:00Z'
        ExecutionStatus = 'COMPLETED'; ScoringEnabled = $false; OverallScore = $null; ScoreResult = $null
        ControlResults = $controls
    }
}

function Restore-WinSecConfirmedScanFixture {
    foreach ($name in $script:confirmedScanOriginalFunctions.Keys) {
        $original = $script:confirmedScanOriginalFunctions[$name]
        if ($null -eq $original) {
            Remove-Item -LiteralPath "Function:script:$name" -ErrorAction SilentlyContinue
        }
        else {
            Set-Item -LiteralPath "Function:script:$name" -Value $original
        }
    }
}
