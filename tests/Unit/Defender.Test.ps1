
# ============================================================
# WinSec Analyzer
# Test Suite : Defender
# Version    : 0.9.0
# Author     : mrRoot
#
# Description:
# Microsoft Defender Antivirus unit tests.
#
# Includes:
# - Defender evidence collection
# - CIM fallback
# - Evidence privacy
# - Error handling
# - Device and scan identity
# - PUA protection assessment
# - ASR rules and operating modes
# - Cloud-delivered protection
# - Network Protection
# - Controlled Folder Access
# - Passive mode behavior
# - No compliance scoring without approved criteria
# - Static read-only verification
#
# PowerShell 5.1 / 7.x
# No Pester required.
#
# IMPORTANT:
# All Defender and CIM responses are mocked.
# This suite does not modify Windows security settings.
# ============================================================

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$script:Passed = 0
$script:Failed = 0

$script:Root = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '..\..')
)

$script:Collector = Join-Path `
    $script:Root `
    'src/Checks/Defender/Test-Defender.ps1'

if (-not (
    Test-Path -LiteralPath $script:Collector -PathType Leaf
)) {
    throw "Collector not found: $script:Collector"
}

. $script:Collector

$script:LocalDeviceId = 'local:hw1-' + ('a' * 64)


# ============================================================
# ASSERTION HELPERS
# ============================================================

function Assert-True {
    param(
        [bool]$Value,
        [string]$Reason = 'Expected true.'
    )

    if (-not $Value) {
        throw $Reason
    }
}

function Assert-Equal {
    param(
        [AllowNull()][object]$Actual,
        [AllowNull()][object]$Expected,
        [string]$Reason = 'Values differ.'
    )

    if ($null -eq $Expected) {
        if ($null -ne $Actual) {
            throw "$Reason Expected null, got [$Actual]."
        }
        return
    }

    if ($null -eq $Actual -or $Actual -ne $Expected) {
        throw "$Reason Expected [$Expected], got [$Actual]."
    }
}

function Assert-Throws {
    param(
        [scriptblock]$Action
    )

    $thrown = $false

    try {
        $null = & $Action
    }
    catch {
        $thrown = $true
    }

    Assert-True $thrown 'Expected an exception.'
}

function Assert-Contains {
    param(
        [AllowNull()][object]$Text,
        [string]$Pattern
    )

    Assert-True (
        ([string]$Text) -match $Pattern
    ) "Expected pattern [$Pattern]."
}


# ============================================================
# MOCK CONFIGURATION
# ============================================================

function Reset-DefenderMock {
    $script:M = @{
        IdentityMode = 'OK'
        IdentityCalls = 0
        StatusMode = 'OK'
        PreferenceMode = 'OK'

        CimStatusMode = 'OK'
        CimPreferenceMode = 'OK'

        StatusCalls = 0
        PreferenceCalls = 0

        CimStatusCalls = 0
        CimPreferenceCalls = 0

        CimRequests = (
            New-Object 'System.Collections.Generic.List[object]'
        )

        RunningMode = 'Normal'
        AntivirusEnabled = $true
        Realtime = $true

        Tamper = $true
        Outdated = $false

        SignaturesAge = 1
        QuickScanAge = 2
        FullScanAge = 8

        PUA = 1

        MAPS = 2
        Samples = 1
        BlockAtFirst = $false

        Network = 1
        Folder = 1

        ASRIds = @(
            'd4f940ab-401b-4efc-aadc-ad5f3c50688a'
            '3b576869-a4ec-4529-8536-b80a7769e899'
        )

        ASRActions = @(1, 2)

        PathExclusions = @(
            'C:\PRIVATE\WINSEC_SENTINEL'
            'D:\SECRET\FILE'
        )

        ProcessExclusions = @(
            'C:\PRIVATE\PROCESS.EXE'
        )

        ExtensionExclusions = @(
            '.secret'
        )
    }
}


# ============================================================
# MOCK DEFENDER STATUS
# ============================================================

function New-MockStatus {
    return [pscustomobject]@{
        AMRunningMode = $script:M.RunningMode

        AMServiceEnabled = $true

        AntivirusEnabled = $script:M.AntivirusEnabled

        RealTimeProtectionEnabled = $script:M.Realtime

        BehaviorMonitorEnabled = $true
        OnAccessProtectionEnabled = $true
        IoavProtectionEnabled = $true
        NISEnabled = $true

        IsTamperProtected = $script:M.Tamper

        DefenderSignaturesOutOfDate = $script:M.Outdated

        AntivirusSignatureAge = $script:M.SignaturesAge

        AntivirusSignatureLastUpdated = (
            [datetime]::UtcNow.AddDays(-1)
        )

        AntivirusSignatureVersion = 'UNIT.1'

        NISSignatureAge = 1
        NISSignatureVersion = 'UNIT.NIS'

        AMEngineVersion = 'UNIT.ENGINE'
        AMProductVersion = 'UNIT.PRODUCT'

        QuickScanAge = $script:M.QuickScanAge
        FullScanAge = $script:M.FullScanAge
    }
}


# ============================================================
# MOCK DEFENDER PREFERENCES
# ============================================================

function New-MockPreference {
    return [pscustomobject]@{
        DisableRealtimeMonitoring = $false
        DisableBehaviorMonitoring = $false
        DisableIOAVProtection = $false

        DisableBlockAtFirstSeen = $script:M.BlockAtFirst

        DisableScriptScanning = $false
        DisableArchiveScanning = $false
        DisableEmailScanning = $false
        DisableRemovableDriveScanning = $false

        DisableScanningNetworkFiles = $false

        DisableScanningMappedNetworkDrivesForFullScan = $false

        PUAProtection = $script:M.PUA

        MAPSReporting = $script:M.MAPS
        SubmitSamplesConsent = $script:M.Samples

        CloudBlockLevel = 2
        CloudExtendedTimeout = 10

        EnableNetworkProtection = $script:M.Network

        EnableControlledFolderAccess = $script:M.Folder

        AttackSurfaceReductionRules_Ids = $script:M.ASRIds

        AttackSurfaceReductionRules_Actions = $script:M.ASRActions

        ExclusionPath = $script:M.PathExclusions

        ExclusionProcess = $script:M.ProcessExclusions

        ExclusionExtension = $script:M.ExtensionExclusions

        AttackSurfaceReductionOnlyExclusions = @(
            'C:\PRIVATE\ASR'
        )

        ControlledFolderAccessAllowedApplications = @(
            'C:\PRIVATE\APP.EXE'
        )

        ControlledFolderAccessProtectedFolders = @(
            'C:\PRIVATE\FOLDER'
        )
    }
}


# ============================================================
# MOCK DEFENDER COMMANDS
# ============================================================

function Get-WinSecLocalHardwareDeviceId {
    [CmdletBinding()]
    param()

    $script:M.IdentityCalls++
    switch ($script:M.IdentityMode) {
        'Throw' { throw 'PRIVATE-HARDWARE-IDENTITY-ERROR' }
        'Empty' { return }
        'Multiple' { return @($script:LocalDeviceId, $script:LocalDeviceId) }
        'Malformed' { return 'local:unverified' }
        'NonText' { return [pscustomobject]@{ DeviceId = $script:LocalDeviceId } }
        'Uppercase' { return $script:LocalDeviceId.ToUpperInvariant() }
        default { return $script:LocalDeviceId }
    }
}

function Get-MpComputerStatus {
    [CmdletBinding()]
    param()

    $script:M.StatusCalls++

    switch ($script:M.StatusMode) {
        'Throw' {
            throw 'Synthetic Defender status failure'
        }

        'Empty' {
            return
        }

        'Partial' {
            return [pscustomobject]@{
                AMRunningMode = 'Normal'
            }
        }

        'Unrecognized' {
            return [pscustomobject]@{
                OtherProperty = 1
            }
        }

        default {
            return New-MockStatus
        }
    }
}

function Get-MpPreference {
    [CmdletBinding()]
    param()

    $script:M.PreferenceCalls++

    switch ($script:M.PreferenceMode) {
        'Throw' {
            throw 'Synthetic Defender preference failure'
        }

        'Empty' {
            return
        }

        'Partial' {
            return [pscustomobject]@{
                PUAProtection = $script:M.PUA

                ExclusionPath = @(
                    'C:\PRIVATE\WINSEC_SENTINEL'
                )
            }
        }

        'NoPUA' {
            $p = New-MockPreference

            $p.PSObject.Properties.Remove(
                'PUAProtection'
            )

            return $p
        }

        'NoASR' {
            $p = New-MockPreference

            $p.PSObject.Properties.Remove(
                'AttackSurfaceReductionRules_Ids'
            )

            return $p
        }

        'NoExclusions' {
            $p = New-MockPreference

            $p.PSObject.Properties.Remove(
                'ExclusionPath'
            )

            return $p
        }

        default {
            return New-MockPreference
        }
    }
}


# ============================================================
# MOCK CIM FALLBACK
# ============================================================

function Get-CimInstance {
    [CmdletBinding()]
    param(
        [string]$Namespace,
        [string]$ClassName
    )

    $script:M.CimRequests.Add(
        [pscustomobject]@{
            Namespace = $Namespace
            ClassName = $ClassName
        }
    )

    if (
        $Namespace -cne 'root/Microsoft/Windows/Defender'
    ) {
        throw 'Unexpected CIM namespace.'
    }

    switch ($ClassName) {

        'MSFT_MpComputerStatus' {
            $script:M.CimStatusCalls++

            if ($script:M.CimStatusMode -eq 'Throw') {
                throw 'Synthetic CIM status failure'
            }

            if ($script:M.CimStatusMode -eq 'Empty') {
                return
            }

            return New-MockStatus
        }

        'MSFT_MpPreference' {
            $script:M.CimPreferenceCalls++

            if ($script:M.CimPreferenceMode -eq 'Throw') {
                throw 'Synthetic CIM preference failure'
            }

            if ($script:M.CimPreferenceMode -eq 'Empty') {
                return
            }

            return New-MockPreference
        }

        default {
            throw 'Unexpected CIM class.'
        }
    }
}


# ============================================================
# TEST EXECUTION HELPERS
# ============================================================

function Invoke-MockedDefender {
    return Test-WinSecDefender `
        -DeviceId $script:LocalDeviceId `
        -ScanId 'DEFENDER-UNIT-001' `
        -CheckId 'WSA-SYS-001'
}

function Test-Case {
    param(
        [string]$Name,
        [scriptblock]$Run
    )

    Reset-DefenderMock

    try {
        $null = & $Run

        $script:Passed++

        Write-Host "[PASS] $Name" -ForegroundColor Green
    }
    catch {
        $script:Failed++

        Write-Host (
            "[FAIL] $Name - $($_.Exception.Message)"
        ) -ForegroundColor Red
    }
}

function Get-Area {
    param(
        [object]$Result,
        [string]$Name
    )

    return $Result.Evidence.Analysis.Areas.PSObject.Properties[
        $Name
    ].Value
}

function Get-Indicator {
    param(
        [object]$Result,
        [string]$Area,
        [string]$Name
    )

    return ,@(
        (Get-Area $Result $Area).Indicators |
            Where-Object {
                $_.Name -eq $Name
            }
    )
}


# ============================================================
# TEST GROUP 1 - RESULT CONTRACT
# ============================================================

Write-Host ''
Write-Host 'WinSec Analyzer - Defender unit tests'
Write-Host ''

Test-Case 'Collector function exists' {
    Assert-True (
        $null -ne (
            Get-Command Test-WinSecDefender -ErrorAction Stop
        )
    )
}

Test-Case 'Required parameters exist' {
    $p = (Get-Command Test-WinSecDefender).Parameters

    foreach ($k in @(
        'DeviceId',
        'ScanId',
        'CheckId'
    )) {
        Assert-True ($p.ContainsKey($k)) "Missing $k"
    }
}

Test-Case 'Single structured result' {
    $r = @(Invoke-MockedDefender)

    Assert-Equal $r.Count 1

    Assert-True ($null -ne $r[0].Evidence)
}

Test-Case 'Collector returns informational' {
    Assert-Equal `
        (Invoke-MockedDefender).Status `
        'INFORMATIONAL'
}

Test-Case 'Check identity' {
    $r = Invoke-MockedDefender

    Assert-Equal $r.CheckId 'WSA-SYS-001'
    Assert-Equal $r.SectionKey 'SystemSecurity'
}

Test-Case 'Device identity' {
    $r = Invoke-MockedDefender

    Assert-Equal `
        $r.DeviceId `
        $script:LocalDeviceId

    Assert-Equal $r.Evidence.DeviceId $r.DeviceId
}

Test-Case 'Scan identity' {
    $r = Invoke-MockedDefender

    Assert-Equal $r.ScanId 'DEFENDER-UNIT-001'
    Assert-Equal $r.Evidence.ScanId $r.ScanId
}

Test-Case 'Collection timestamp is recent UTC' {
    $r = Invoke-MockedDefender

    $t = [datetimeoffset]::Parse(
        $r.Evidence.CollectedAtUTC
    )

    Assert-True (
        $t -gt [datetimeoffset]::UtcNow.AddMinutes(-5) -and
        $t -le [datetimeoffset]::UtcNow
    )
}

Test-Case 'Primary command sources' {
    $r = Invoke-MockedDefender

    Assert-Equal `
        $r.Evidence.StatusSource `
        'Get-MpComputerStatus'

    Assert-Equal `
        $r.Evidence.PreferenceSource `
        'Get-MpPreference'
}

Test-Case 'No CIM when primary succeeds' {
    $null = Invoke-MockedDefender

    Assert-Equal $script:M.CimStatusCalls 0
    Assert-Equal $script:M.CimPreferenceCalls 0
}

Test-Case 'Status telemetry values' {
    $r = Invoke-MockedDefender

    Assert-Equal `
        $r.Evidence.DefenderStatus.AntivirusEnabled `
        $true

    Assert-Equal `
        $r.Evidence.DefenderStatus.RealTimeProtectionEnabled `
        $true
}

Test-Case 'Preference telemetry values' {
    $r = Invoke-MockedDefender

    Assert-Equal `
        $r.Evidence.DefenderPreferences.PUAProtection `
        1

    Assert-Equal `
        $r.Evidence.DefenderPreferences.MAPSReporting `
        2
}

Test-Case 'Partial status stays unknown, not false' {
    $script:M.StatusMode = 'Partial'

    $r = Invoke-MockedDefender

    Assert-Equal $r.Status 'INFORMATIONAL'

    Assert-Equal `
        $r.Evidence.DefenderStatus.AntivirusEnabled `
        $null
}

Test-Case 'Partial preferences stay unknown' {
    $script:M.PreferenceMode = 'Partial'

    $r = Invoke-MockedDefender

    Assert-Equal `
        $r.Evidence.DefenderPreferences.MAPSReporting `
        $null

    Assert-Equal `
        $r.Evidence.ExclusionCounts.Processes `
        $null
}

Test-Case 'Invalid CheckId rejected' {
    Assert-Throws {
        Test-WinSecDefender `
            -DeviceId $env:COMPUTERNAME `
            -ScanId 'ID' `
            -CheckId 'OTHER'
    }
}

Test-Case 'Remote identity rejected' {
    Assert-Throws {
        Test-WinSecDefender `
            -DeviceId 'remote:OTHER' `
            -ScanId 'ID' `
            -CheckId 'WSA-SYS-001'
    }
}

Test-Case 'Current hardware identity accepted' {
    $r = Test-WinSecDefender `
        -DeviceId $script:LocalDeviceId `
        -ScanId 'ID' `
        -CheckId 'WSA-SYS-001'

    Assert-Equal $r.DeviceId $script:LocalDeviceId
    Assert-Equal $r.Evidence.DeviceId $script:LocalDeviceId
    Assert-Equal $script:M.IdentityCalls 1
}

foreach ($rejectedId in @(
    $env:COMPUTERNAME,
    ('local:{0}' -f $env:COMPUTERNAME),
    ('local:hw1-' + ('b' * 64)),
    $script:LocalDeviceId.ToUpperInvariant()
)) {
    Test-Case 'Legacy, foreign or noncanonical identity cannot collect' {
        Assert-Throws {
            Test-WinSecDefender -DeviceId $rejectedId -ScanId 'ID' -CheckId 'WSA-SYS-001'
        }
        Assert-Equal $script:M.StatusCalls 0
        Assert-Equal $script:M.PreferenceCalls 0
        Assert-Equal $script:M.CimRequests.Count 0
    }
}

foreach ($identityMode in @('Throw', 'Empty', 'Multiple', 'Malformed', 'NonText', 'Uppercase')) {
    Test-Case ('Invalid hardware identity provider aborts before collection: ' + $identityMode) {
        $script:M.IdentityMode = $identityMode
        $message = ''
        try { $null = Invoke-MockedDefender }
        catch { $message = $_.Exception.Message }
        Assert-Equal $message 'Unable to validate local hardware identity for Microsoft Defender.'
        Assert-Equal $script:M.StatusCalls 0
        Assert-Equal $script:M.PreferenceCalls 0
        Assert-Equal $script:M.CimRequests.Count 0
    }
}

Test-Case 'Blank scan ID rejected' {
    Assert-Throws {
        Test-WinSecDefender `
            -DeviceId $env:COMPUTERNAME `
            -ScanId '' `
            -CheckId 'WSA-SYS-001'
    }
}


# ============================================================
# TEST GROUP 2 - CIM AND ERROR HANDLING
# ============================================================

Test-Case 'CIM recovers status failure' {
    $script:M.StatusMode = 'Throw'

    $r = Invoke-MockedDefender

    Assert-Equal $r.Status 'INFORMATIONAL'

    Assert-Equal `
        $r.Evidence.StatusSource `
        'CIM:MSFT_MpComputerStatus'
}

Test-Case 'CIM recovers empty status' {
    $script:M.StatusMode = 'Empty'

    $r = Invoke-MockedDefender

    Assert-Equal `
        $r.Evidence.StatusSource `
        'CIM:MSFT_MpComputerStatus'
}

Test-Case 'CIM recovers preference failure' {
    $script:M.PreferenceMode = 'Throw'

    $r = Invoke-MockedDefender

    Assert-Equal `
        $r.Evidence.PreferenceSource `
        'CIM:MSFT_MpPreference'
}

Test-Case 'CIM recovers empty preferences' {
    $script:M.PreferenceMode = 'Empty'

    $r = Invoke-MockedDefender

    Assert-Equal `
        $r.Evidence.PreferenceSource `
        'CIM:MSFT_MpPreference'
}

Test-Case 'Both status sources fail safely' {
    $script:M.StatusMode = 'Throw'
    $script:M.CimStatusMode = 'Throw'

    $r = Invoke-MockedDefender

    Assert-Equal $r.Status 'ERROR'

    Assert-Equal `
        $r.Evidence.CollectionSuccessful `
        $false

    Assert-Equal $script:M.PreferenceCalls 0
}

Test-Case 'Unrecognized status causes ERROR' {
    $script:M.StatusMode = 'Unrecognized'

    Assert-Equal `
        (Invoke-MockedDefender).Status `
        'ERROR'
}

Test-Case 'Preferences failure is informational' {
    $script:M.PreferenceMode = 'Throw'
    $script:M.CimPreferenceMode = 'Throw'

    $r = Invoke-MockedDefender

    Assert-Equal $r.Status 'INFORMATIONAL'

    Assert-Equal `
        $r.Evidence.PreferenceCollectionSuccessful `
        $false

    Assert-True (
        @($r.Evidence.CollectionIssues).Count -ge 2
    )
}

Test-Case 'CIM namespace is local Defender' {
    $script:M.StatusMode = 'Throw'
    $script:M.PreferenceMode = 'Throw'

    $null = Invoke-MockedDefender

    Assert-Equal $script:M.CimRequests.Count 2

    foreach ($request in $script:M.CimRequests) {
        Assert-Equal `
            $request.Namespace `
            'root/Microsoft/Windows/Defender'
    }
}


# ============================================================
# TEST GROUP 3 - EVIDENCE PRIVACY
# ============================================================

Test-Case 'Path exclusion count' {
    Assert-Equal `
        (Invoke-MockedDefender).Evidence.ExclusionCounts.Paths `
        2
}

Test-Case 'Process exclusion count' {
    Assert-Equal `
        (Invoke-MockedDefender).Evidence.ExclusionCounts.Processes `
        1
}

Test-Case 'Extension exclusion count' {
    Assert-Equal `
        (Invoke-MockedDefender).Evidence.ExclusionCounts.Extensions `
        1
}

Test-Case 'ASR exclusion count' {
    Assert-Equal `
        (Invoke-MockedDefender).Evidence.ExclusionCounts.ASR `
        1
}

Test-Case 'Controlled folder allowlist count' {
    Assert-Equal `
        (Invoke-MockedDefender).Evidence.ExclusionCounts.ControlledFolderAllowedApplications `
        1
}

Test-Case 'Protected folder count' {
    Assert-Equal `
        (Invoke-MockedDefender).Evidence.ExclusionCounts.ControlledFolderProtectedFolders `
        1
}

Test-Case 'Exclusion values never leak into evidence' {
    $json = ConvertTo-Json `
        -InputObject (Invoke-MockedDefender).Evidence `
        -Depth 18

    foreach ($secret in @(
        'WINSEC_SENTINEL',
        'PROCESS.EXE',
        'APP.EXE',
        'SECRET\FILE'
    )) {
        Assert-True (
            -not $json.Contains($secret)
        ) "Sensitive exclusion leaked: $secret"
    }
}

Test-Case 'Empty exclusions give zero' {
    $script:M.PathExclusions = @()
    $script:M.ProcessExclusions = @()
    $script:M.ExtensionExclusions = @()

    $r = Invoke-MockedDefender

    Assert-Equal $r.Evidence.ExclusionCounts.Paths 0

    Assert-Equal $r.Evidence.ExclusionCounts.Processes 0
}

Test-Case 'Null exclusions give zero' {
    $script:M.PathExclusions = $null

    Assert-Equal `
        (Invoke-MockedDefender).Evidence.ExclusionCounts.Paths `
        0
}

Test-Case 'Missing exclusions stay unknown' {
    $script:M.PreferenceMode = 'NoExclusions'

    Assert-Equal `
        (Invoke-MockedDefender).Evidence.ExclusionCounts.Paths `
        $null
}


# ============================================================
# TEST GROUP 4 - COMPLIANCE SAFEGUARDS
# ============================================================

Test-Case 'Evidence never has official compliance score' {
    $r = Invoke-MockedDefender

    Assert-Equal $r.Status 'INFORMATIONAL'

    Assert-Equal $r.Evidence.ScoringEligible $false
    Assert-Equal $r.Evidence.CriteriaSource $null

    Assert-Equal `
        $r.Evidence.ComplianceAssessment `
        'NOT_EVALUATED'
}

Test-Case 'All indicators are ungraded' {
    $r = Invoke-MockedDefender

    foreach (
        $area in
        $r.Evidence.Analysis.Areas.PSObject.Properties
    ) {
        foreach ($indicator in $area.Value.Indicators) {
            Assert-Equal $indicator.ScoringEligible $false

            Assert-Equal `
                $indicator.ComplianceStatus `
                'NOT_EVALUATED'

            Assert-Equal `
                $indicator.EffectiveProtectionConfirmed `
                $false
        }
    }
}

Test-Case 'Collector has no dangerous built-in commands' {
    $tokens = $null
    $errors = $null

    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $script:Collector,
        [ref]$tokens,
        [ref]$errors
    )

    Assert-Equal @($errors).Count 0

    $forbidden = (
        '^(Set-Mp|Add-Mp|Remove-Mp|Start-MpScan$|' +
        'Update-MpSignature$|Set-Item|New-Item|' +
        'Remove-Item|Clear-Item|Set-Content|' +
        'Add-Content|Out-File|Export-|Set-Service|' +
        'Start-Service|Stop-Service|Restart-Service|' +
        'New-CimSession|Invoke-CimMethod|' +
        'Set-CimInstance|Remove-CimInstance|' +
        'New-CimInstance|Invoke-Expression$|' +
        'Start-Process$|Invoke-Command$|' +
        'Restart-Computer$)'
    )

    $commands = $ast.FindAll(
        {
            param($a)

            $a -is [System.Management.Automation.Language.CommandAst]
        },
        $true
    )

    foreach ($cmd in $commands) {
        $name = $cmd.GetCommandName()

        Assert-True (
            -not ($name -match $forbidden)
        ) "Forbidden command: $name"
    }
}


# ============================================================
# TEST GROUP 5 - DEFENDER OPERATION
# ============================================================

Test-Case 'Passive mode is not auto-failed' {
    $script:M.RunningMode = 'Passive Mode'

    $r = Invoke-MockedDefender

    Assert-Equal $r.Status 'INFORMATIONAL'

    Assert-Contains `
        ($r.Evidence.Observations -join ' ') `
        'passive mode'
}

Test-Case 'Inactive realtime is observed' {
    $script:M.Realtime = $false

    $r = Invoke-MockedDefender

    Assert-Contains `
        ($r.Evidence.Observations -join ' ') `
        'real-time protection is disabled'
}

Test-Case 'Outdated signatures observed' {
    $script:M.Outdated = $true

    $r = Invoke-MockedDefender

    Assert-Contains `
        ($r.Evidence.Observations -join ' ') `
        'outdated'
}

Test-Case 'Tamper disabled observed' {
    $script:M.Tamper = $false

    $r = Invoke-MockedDefender

    Assert-Contains `
        ($r.Evidence.Observations -join ' ') `
        'Tamper protection'
}

Test-Case 'Missing tamper state stays null' {
    $script:M.Tamper = $null

    Assert-Equal `
        (Invoke-MockedDefender).Evidence.DefenderStatus.IsTamperProtected `
        $null
}

Test-Case 'Nine internal areas exist' {
    $a = (Invoke-MockedDefender).Evidence.Analysis.Areas

    Assert-Equal @($a.PSObject.Properties).Count 9

    foreach ($key in @(
        'CoreProtection',
        'ThreatProtection',
        'CloudProtection',
        'Integrity',
        'NetworkProtection',
        'RansomwareProtection',
        'AttackSurfaceReduction',
        'UpdatesAndScans',
        'ExclusionsAndHardening'
    )) {
        Assert-True (
            $null -ne $a.PSObject.Properties[$key]
        ) "Missing area $key"
    }
}

Test-Case 'PUA belongs to ThreatProtection' {
    $r = Invoke-MockedDefender

    $item = Get-Indicator `
        $r `
        'ThreatProtection' `
        'Potentially unwanted applications (PUA)'

    Assert-Equal $item.Count 1

    Assert-True (
        $null -eq $r.Evidence.Analysis.Areas.PSObject.Properties['PUA']
    )
}


Test-Case 'Internal area counts match indicators' {
    $r = Invoke-MockedDefender

    $sum = 0

    Write-Host ''
    Write-Host 'DEFENDER INDICATOR DIAGNOSTICS' -ForegroundColor Cyan

    foreach (
        $property in
        $r.Evidence.Analysis.Areas.PSObject.Properties
    ) {
        $area = $property.Value

        $actualCount = @($area.Indicators).Count
        $reportedCount = $area.IndicatorCount

        Write-Host (
            '{0}: Reported={1}, Actual={2}' -f
            $property.Name,
            $reportedCount,
            $actualCount
        )

        Assert-Equal `
            $reportedCount `
            $actualCount `
            "Incorrect count in $($property.Name)"

        $sum += $actualCount
    }

    Write-Host ''
    Write-Host "Sum of areas : $sum"
    Write-Host "Global total : $($r.Evidence.Analysis.IndicatorCount)"
    Write-Host ''

    Assert-Equal `
        $sum `
        $r.Evidence.Analysis.IndicatorCount `
        'Global indicator count does not match the areas.'
}


# ============================================================
# TEST GROUP 6 - PUA PROTECTION
# ============================================================

foreach ($row in @(
    @{Value=0; Mode='DISABLED'; Blocking=$false}
    @{Value=1; Mode='BLOCK'; Blocking=$true}
    @{Value=2; Mode='AUDIT'; Blocking=$false}
    @{Value=99; Mode='UNKNOWN'; Blocking=$null}
    @{Value='Disabled'; Mode='DISABLED'; Blocking=$false}
    @{Value='Enabled'; Mode='BLOCK'; Blocking=$true}
    @{Value='AuditMode'; Mode='AUDIT'; Blocking=$false}
)) {
    Test-Case "PUA maps $($row.Value) to $($row.Mode)" {
        $script:M.PUA = $row.Value

        $r = Invoke-MockedDefender

        $a = $r.Evidence.PUAProtectionAssessment

        Assert-Equal $a.Mode $row.Mode

        Assert-Equal `
            $a.BlockingConfigured `
            $row.Blocking

        Assert-Equal `
            $a.EffectiveProtectionConfirmed `
            $false

        Assert-Equal $a.ScoringEligible $false
    }
}

Test-Case 'Null PUA remains unknown' {
    $script:M.PUA = $null

    Assert-Equal `
        (Invoke-MockedDefender).Evidence.PUAProtectionAssessment.Mode `
        'UNKNOWN'
}

Test-Case 'Missing PUA property remains unknown' {
    $script:M.PreferenceMode = 'NoPUA'

    Assert-Equal `
        (Invoke-MockedDefender).Evidence.PUAProtectionAssessment.Mode `
        'UNKNOWN'
}

Test-Case 'PUA does not attest browser download blocking' {
    $r = Invoke-MockedDefender

    Assert-Equal `
        $r.Evidence.PUAProtectionAssessment.DownloadBlocking `
        $null

    Assert-Equal `
        $r.Evidence.PUAProtectionAssessment.DownloadBlockingEvaluated `
        $false
}

Test-Case 'PUA in passive mode is not confirmed effective' {
    $script:M.RunningMode = 'Passive Mode'

    $r = Invoke-MockedDefender

    Assert-Equal `
        $r.Evidence.PUAProtectionAssessment.Mode `
        'BLOCK'

    Assert-Equal `
        $r.Evidence.PUAProtectionAssessment.EffectiveProtectionConfirmed `
        $false
}

Test-Case 'PUA disabled generates observation' {
    $script:M.PUA = 0

    $r = Invoke-MockedDefender

    Assert-Contains `
        ($r.Evidence.Observations -join ' ') `
        'PUA blocking is disabled'
}

Test-Case 'PUA audit generates observation' {
    $script:M.PUA = 2

    $r = Invoke-MockedDefender

    Assert-Contains `
        ($r.Evidence.Observations -join ' ') `
        'audit mode'
}


# ============================================================
# TEST GROUP 7 - CLOUD PROTECTION
# ============================================================

Test-Case 'MAPS configured' {
    $r = Invoke-MockedDefender

    $item = Get-Indicator `
        $r 'CloudProtection' `
        'Cloud-delivered protection (MAPS)'

    Assert-Equal $item[0].State 'CONFIGURED'
}

Test-Case 'MAPS disabled' {
    $script:M.MAPS = 0

    $r = Invoke-MockedDefender

    $item = Get-Indicator `
        $r 'CloudProtection' `
        'Cloud-delivered protection (MAPS)'

    Assert-Equal $item[0].State 'DISABLED'
}

Test-Case 'Missing MAPS is unknown' {
    $script:M.MAPS = $null

    $r = Invoke-MockedDefender

    $item = Get-Indicator `
        $r 'CloudProtection' `
        'Cloud-delivered protection (MAPS)'

    Assert-Equal $item[0].State 'UNKNOWN'
}

Test-Case 'Sample submission is descriptive' {
    $r = Invoke-MockedDefender

    $item = Get-Indicator `
        $r 'CloudProtection' `
        'Sample submission consent'

    Assert-Equal $item[0].State 'AUTOMATIC'
}

Test-Case 'Block at first sight disabled is reviewed' {
    $script:M.BlockAtFirst = $true

    $r = Invoke-MockedDefender

    $item = Get-Indicator `
        $r 'CloudProtection' `
        'Block at first sight preference'

    Assert-Equal $item[0].State 'DISABLED'
}

Test-Case 'Cloud does not attest remote connectivity' {
    $r = Invoke-MockedDefender

    Assert-Contains `
        ($r.Evidence.Observations -join ' ') `
        'were not tested'
}


# ============================================================
# TEST GROUP 8 - NETWORK PROTECTION
# ============================================================

foreach ($row in @(
    @{V=0; S='DISABLED'}
    @{V=1; S='BLOCK'}
    @{V=2; S='AUDIT'}
    @{V=99; S='UNKNOWN'}
)) {
    Test-Case "Network Protection $($row.V) gives $($row.S)" {
        $script:M.Network = $row.V

        $r = Invoke-MockedDefender

        $item = Get-Indicator `
            $r 'NetworkProtection' `
            'Microsoft Defender Network Protection'

        Assert-Equal $item[0].State $row.S
    }
}


# ============================================================
# TEST GROUP 9 - CONTROLLED FOLDER ACCESS
# ============================================================

foreach ($row in @(
    @{V=0; S='DISABLED'}
    @{V=1; S='BLOCK'}
    @{V=2; S='AUDIT'}
    @{V=3; S='BLOCK_DISK_MODIFICATION'}
    @{V=4; S='AUDIT_DISK_MODIFICATION'}
)) {
    Test-Case "Controlled folder mode $($row.V) gives $($row.S)" {
        $script:M.Folder = $row.V

        $r = Invoke-MockedDefender

        $item = Get-Indicator `
            $r 'RansomwareProtection' `
            'Controlled folder access'

        Assert-Equal $item[0].State $row.S
    }
}


# ============================================================
# TEST GROUP 10 - ATTACK SURFACE REDUCTION
# ============================================================

Test-Case 'ASR inventory includes two GUID rules' {
    $r = Invoke-MockedDefender

    $asr = $r.Evidence.AttackSurfaceReduction

    Assert-Equal $asr.ConfiguredRuleCount 2

    Assert-Equal $asr.Rules[0].Mode 'BLOCK'

    Assert-Equal $asr.Rules[1].Mode 'AUDIT'
}

Test-Case 'ASR counts match modes' {
    $m = (Invoke-MockedDefender).Evidence.AttackSurfaceReduction.Modes

    Assert-Equal $m.BLOCK 1
    Assert-Equal $m.AUDIT 1
}

Test-Case 'ASR missing arrays remain unknown' {
    $script:M.PreferenceMode = 'NoASR'

    $a = (Invoke-MockedDefender).Evidence.AttackSurfaceReduction

    Assert-Equal $a.Available $false

    Assert-Equal $a.ConfiguredRuleCount $null
}

Test-Case 'ASR mismatched arrays are incomplete' {
    $script:M.ASRActions = @(1)

    $a = (Invoke-MockedDefender).Evidence.AttackSurfaceReduction

    Assert-Equal $a.Complete $false

    Assert-True (@($a.Issues).Count -gt 0)
}

Test-Case 'ASR nulls at different positions never shift an action to another rule' {
    $script:M.ASRIds = @($script:M.ASRIds[0], $null, $script:M.ASRIds[1])
    $script:M.ASRActions = @(1, 2, $null)
    $a = (Invoke-MockedDefender).Evidence.AttackSurfaceReduction
    Assert-Equal $a.Complete $false
    Assert-Equal $a.ConfiguredRuleCount 2
    Assert-Equal $a.Rules[0].Mode 'BLOCK'
    Assert-Equal $a.Rules[1].Mode 'UNKNOWN'
    Assert-Equal $a.Modes.AUDIT 0
    Assert-Equal $a.Modes.UNKNOWN 1
    Assert-True (@($a.Issues).Count -gt 0)
}

Test-Case 'ASR null action preserves later rule positions' {
    $script:M.ASRIds += '01443614-cd74-433a-b99e-2ecdc07bfc25'
    $script:M.ASRActions = @(1, $null, 0)
    $a = (Invoke-MockedDefender).Evidence.AttackSurfaceReduction
    Assert-Equal $a.Complete $false
    Assert-Equal $a.Rules[1].Mode 'UNKNOWN'
    Assert-Equal $a.Rules[2].Mode 'DISABLED'
}

Test-Case 'ASR entirely null arrays are unavailable as complete evidence' {
    $script:M.ASRIds = $null
    $script:M.ASRActions = $null
    $a = (Invoke-MockedDefender).Evidence.AttackSurfaceReduction
    Assert-Equal $a.Complete $false
    Assert-Equal $a.ConfiguredRuleCount 0
    Assert-True (@($a.Issues).Count -gt 0)
}

Test-Case 'ASR explicit empty arrays describe an empty configured inventory' {
    $script:M.ASRIds = @()
    $script:M.ASRActions = @()
    $a = (Invoke-MockedDefender).Evidence.AttackSurfaceReduction
    Assert-Equal $a.Complete $true
    Assert-Equal $a.ConfiguredRuleCount 0
    Assert-Equal $a.UnlistedRulesAssessed $false
}

Test-Case 'ASR action capacity is checked even when identifier list is short' {
    $script:M.ASRActions = @(1) * 129
    $a = (Invoke-MockedDefender).Evidence.AttackSurfaceReduction
    Assert-Equal $a.Complete $false
    Assert-True (($a.Issues -join '|') -match 'safety limit')
}

Test-Case 'ASR duplicate IDs are not double counted' {
    $script:M.ASRIds = @(
        $script:M.ASRIds[0],
        $script:M.ASRIds[0]
    )

    $a = (Invoke-MockedDefender).Evidence.AttackSurfaceReduction

    Assert-Equal $a.Complete $false

    Assert-Equal $a.ConfiguredRuleCount 1
}

Test-Case 'ASR invalid GUID does not become a rule' {
    $script:M.ASRIds = @('INVALID-GUID')
    $script:M.ASRActions = @(1)

    $a = (Invoke-MockedDefender).Evidence.AttackSurfaceReduction

    Assert-Equal $a.Complete $false

    Assert-Equal $a.ConfiguredRuleCount 0
}

Test-Case 'ASR unknown action is reported' {
    $script:M.ASRActions = @(1, 99)

    $a = (Invoke-MockedDefender).Evidence.AttackSurfaceReduction

    Assert-Equal $a.Modes.UNKNOWN 1

    Assert-Equal $a.Complete $false
}

Test-Case 'ASR WARN mode recognized' {
    $script:M.ASRActions = @(6, 2)

    $a = (Invoke-MockedDefender).Evidence.AttackSurfaceReduction

    Assert-Equal $a.Rules[0].Mode 'WARN'
}

Test-Case 'ASR does not assume unlisted rules' {
    $a = (Invoke-MockedDefender).Evidence.AttackSurfaceReduction

    Assert-Equal $a.UnlistedRulesAssessed $false
}

Test-Case 'ASR remains ungraded' {
    $r = Invoke-MockedDefender

    foreach ($rule in $r.Evidence.AttackSurfaceReduction.Rules) {
        Assert-Equal `
            $rule.EffectiveEnforcementConfirmed `
            $false
    }
}


# ============================================================
# FINAL SUMMARY
# ============================================================

$total = $script:Passed + $script:Failed

Write-Host ''
Write-Host ('=' * 60)
Write-Host 'DEFENDER UNIT TEST SUMMARY'
Write-Host "TOTAL: $total"
Write-Host "PASS:  $script:Passed"
Write-Host "FAIL:  $script:Failed"
Write-Host ('=' * 60)

if ($script:Failed -gt 0) {
    throw "$($script:Failed) Defender unit test(s) failed."
}

Write-Host 'All Defender unit tests passed.' `
    -ForegroundColor Green
