
# ============================================================
# WinSec Analyzer
# Component  : Defender
# Version    : 0.9.0
# Author     : mrRoot
#
# Description:
# Microsoft Defender Antivirus security assessment.
#
# Includes:
# - Antivirus status and operating mode
# - Real-time and behavior protection
# - Threat protection and PUA assessment
# - Cloud-delivered protection
# - Attack Surface Reduction (ASR)
# - Network Protection
# - Controlled Folder Access
# - Ransomware protection
# - Tamper Protection
# - Antivirus signatures and scanning
# - Security configuration and exclusions
# - CIM fallback
# - Evidence privacy and identity
# - Contextual security recommendations
# - Consistent indicator grouping and counting
# - No compliance scoring without approved criteria
#
# PowerShell 5.1 / 7.x
#
# IMPORTANT:
# This component performs read-only security assessments.
# It never modifies Windows Defender or system settings.
# It never executes remediation commands.
# Framework compliance requires verified criteria.
# ============================================================


# ============================================================
# PROPERTY HELPERS
# ============================================================

function Get-WinSecDefenderProperty {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($null -eq $InputObject) {
        return $null
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) {
            return ,$InputObject[$Name]
        }

        return $null
    }

    $property = $InputObject.PSObject.Properties[$Name]

    if ($null -eq $property) {
        return $null
    }

    return ,$property.Value
}


function Test-WinSecDefenderProperty {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($null -eq $InputObject) {
        return $false
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        return $InputObject.Contains($Name)
    }

    return (
        $null -ne $InputObject.PSObject.Properties[$Name]
    )
}


function Get-WinSecDefenderAllowlist {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string[]]$Names
    )

    $safe = [ordered]@{}

    foreach ($name in $Names) {
        $value = Get-WinSecDefenderProperty `
            -InputObject $InputObject `
            -Name $name

        if (
            ($null -ne $value) -and (
                $value -is [array] -or
                $value -is [System.Collections.IDictionary] -or
                (
                    $value -isnot [string] -and
                    $value -isnot [ValueType]
                )
            )
        ) {
            $value = $null
        }

        $safe[$name] = $value
    }

    return [pscustomobject]$safe
}


function Get-WinSecDefenderCount {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if (-not (
        Test-WinSecDefenderProperty `
            -InputObject $InputObject `
            -Name $Name
    )) {
        return $null
    }

    $items = Get-WinSecDefenderProperty `
        -InputObject $InputObject `
        -Name $Name

    if ($null -eq $items) {
        return 0
    }

    return @(
        $items | Where-Object {
            $null -ne $_ -and
            -not [string]::IsNullOrWhiteSpace([string]$_)
        }
    ).Count
}


# ============================================================
# SECURITY MODE NORMALIZATION
# ============================================================

function ConvertTo-WinSecDefenderEnumMode {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value,

        [ValidateSet('PUA', 'Network', 'Folder', 'ASR')]
        [string]$Kind = 'PUA'
    )

    if ($null -eq $Value) {
        return 'UNKNOWN'
    }

    $v = ([string]$Value).Trim().ToUpperInvariant()

    switch ($Kind) {
        'PUA' {
            switch ($v) {
                { $_ -in @('0', 'DISABLED') } {
                    return 'DISABLED'
                }

                { $_ -in @('1', 'ENABLED', 'BLOCK') } {
                    return 'BLOCK'
                }

                { $_ -in @('2', 'AUDIT', 'AUDITMODE') } {
                    return 'AUDIT'
                }

                default {
                    return 'UNKNOWN'
                }
            }
        }

        'Network' {
            switch ($v) {
                { $_ -in @('0', 'DISABLED') } {
                    return 'DISABLED'
                }

                { $_ -in @('1', 'ENABLED', 'BLOCK') } {
                    return 'BLOCK'
                }

                { $_ -in @('2', 'AUDIT', 'AUDITMODE') } {
                    return 'AUDIT'
                }

                default {
                    return 'UNKNOWN'
                }
            }
        }

        'Folder' {
            switch ($v) {
                { $_ -in @('0', 'DISABLED') } {
                    return 'DISABLED'
                }

                { $_ -in @('1', 'ENABLED', 'BLOCK') } {
                    return 'BLOCK'
                }

                { $_ -in @('2', 'AUDIT', 'AUDITMODE') } {
                    return 'AUDIT'
                }

                { $_ -in @('3', 'BLOCKDISKMODIFICATIONONLY') } {
                    return 'BLOCK_DISK_MODIFICATION'
                }

                { $_ -in @('4', 'AUDITDISKMODIFICATIONONLY') } {
                    return 'AUDIT_DISK_MODIFICATION'
                }

                default {
                    return 'UNKNOWN'
                }
            }
        }

        'ASR' {
            switch ($v) {
                { $_ -in @('0', 'DISABLED') } {
                    return 'DISABLED'
                }

                { $_ -in @('1', 'ENABLED', 'BLOCK') } {
                    return 'BLOCK'
                }

                { $_ -in @('2', 'AUDIT', 'AUDITMODE') } {
                    return 'AUDIT'
                }

                { $_ -in @('5', 'NOTCONFIGURED') } {
                    return 'NOT_CONFIGURED'
                }

                { $_ -in @('6', 'WARN') } {
                    return 'WARN'
                }

                default {
                    return 'UNKNOWN'
                }
            }
        }
    }
}


# ============================================================
# PUA PROTECTION ASSESSMENT
# ============================================================

function Get-WinSecDefenderPUAAssessment {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$RawValue,

        [AllowNull()]
        [string]$Source
    )

    $mode = ConvertTo-WinSecDefenderEnumMode `
        -Value $RawValue `
        -Kind PUA

    $number = $null

    switch ($mode) {
        'DISABLED' {
            $number = 0
            $description = 'PUA blocking is disabled in the observed preference.'
        }

        'BLOCK' {
            $number = 1
            $description = 'PUA blocking is configured; effective protection is not independently verified.'
        }

        'AUDIT' {
            $number = 2
            $description = 'PUA audit mode is configured; detections do not imply blocking.'
        }

        default {
            $description = 'PUA state is unavailable or unrecognized.'
        }
    }

    $blocking = $null

    if ($mode -eq 'BLOCK') {
        $blocking = $true
    }

    if ($mode -in @('DISABLED', 'AUDIT')) {
        $blocking = $false
    }

    return [pscustomobject]@{
        Name = 'Potentially Unwanted Applications'

        Source = $Source
        RawValue = $RawValue
        NumericValue = $number
        Mode = $mode

        BlockingConfigured = $blocking

        DownloadBlocking = $null
        DownloadBlockingEvaluated = $false
        EffectiveProtectionConfirmed = $false

        Description = $description

        ComplianceAssessment = 'NOT_EVALUATED'
        ScoringEligible = $false
        CriteriaSource = $null

        Reference = 'https://learn.microsoft.com/en-us/defender-endpoint/detect-block-potentially-unwanted-apps-microsoft-defender-antivirus'
    }
}


# ============================================================
# ATTACK SURFACE REDUCTION ASSESSMENT
# ============================================================

function Get-WinSecDefenderASRSummary {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Preference
    )

    $ids = Get-WinSecDefenderProperty `
        -InputObject $Preference `
        -Name 'AttackSurfaceReductionRules_Ids'

    $actions = Get-WinSecDefenderProperty `
        -InputObject $Preference `
        -Name 'AttackSurfaceReductionRules_Actions'

    $hasIds = Test-WinSecDefenderProperty `
        -InputObject $Preference `
        -Name 'AttackSurfaceReductionRules_Ids'

    $hasActions = Test-WinSecDefenderProperty `
        -InputObject $Preference `
        -Name 'AttackSurfaceReductionRules_Actions'

    $rules = New-Object 'System.Collections.Generic.List[object]'
    $issues = New-Object 'System.Collections.Generic.List[string]'

    $counts = [ordered]@{
        BLOCK = 0
        AUDIT = 0
        WARN = 0
        DISABLED = 0
        NOT_CONFIGURED = 0
        UNKNOWN = 0
    }

    if (-not $hasIds -or -not $hasActions) {
        return [pscustomobject]@{
            Available = $false
            Complete = $false
            ConfiguredRuleCount = $null
            Modes = [pscustomobject]$counts
            Rules = @()
            Issues = @('ASR rule arrays unavailable.')
            UnlistedRulesAssessed = $false
        }
    }

    # Preserve positions: filtering nulls independently can attach an action
    # to another rule and falsely report a complete inventory.
    $idList = @($ids)
    $actionList = @($actions)

    if ($idList.Count -ne $actionList.Count) {
        $issues.Add(
            'ASR identifiers and actions have different counts; alignment cannot be trusted.'
        )
    }

    if ($idList.Count -gt 128 -or $actionList.Count -gt 128) {
        $issues.Add(
            'ASR evidence exceeds the collection safety limit (128 entries).'
        )
    }

    $limit = [Math]::Min(
        [Math]::Min($idList.Count, $actionList.Count),
        128
    )

    $seen = @{}

    for ($i = 0; $i -lt $limit; $i++) {
        if ($idList[$i] -isnot [string]) {
            $issues.Add('An ASR rule identifier was missing or was not text.')
            continue
        }

        $id = $idList[$i]
        $guid = [guid]::Empty

        if (-not [guid]::TryParse($id, [ref]$guid)) {
            $issues.Add(
                'An ASR rule identifier was not a valid GUID.'
            )

            continue
        }

        $id = $guid.ToString('D')

        if ($seen.ContainsKey($id)) {
            $issues.Add(
                'Duplicate ASR rule identifier detected.'
            )

            continue
        }

        $seen[$id] = $true

        $mode = ConvertTo-WinSecDefenderEnumMode `
            -Value $actionList[$i] `
            -Kind ASR

        $counts[$mode]++

        $rules.Add(
            [pscustomobject]@{
                RuleId = $id
                Mode = $mode
                RawAction = [string]$actionList[$i]
                EffectiveEnforcementConfirmed = $false
            }
        )
    }

    if ($counts.UNKNOWN -gt 0) {
        $issues.Add(
            'One or more ASR actions are unrecognized.'
        )
    }

    return [pscustomobject]@{
        Available = $true
        Complete = ($issues.Count -eq 0)
        ConfiguredRuleCount = $rules.Count
        Modes = [pscustomobject]$counts
        Rules = @($rules.ToArray())
        Issues = @($issues.ToArray())
        UnlistedRulesAssessed = $false
    }
}


# ============================================================
# SECURITY INDICATOR MODEL
# ============================================================

function Get-WinSecDefenderConfigurationModes {
    [CmdletBinding()]
    param([object]$Status,[object]$Preferences,[object]$Pua,[object]$Asr)
    $puaMode=Get-WinSecDefenderProperty $Pua 'Mode'
    if($puaMode -isnot [string] -or $puaMode -cnotin @('BLOCK','AUDIT','DISABLED')){$puaMode=$null}
    $cloud=Get-WinSecDefenderProperty $Preferences 'MAPSReporting';$cloudMode=$null
    if($null -ne $cloud -and ($cloud -is [string] -or $cloud.GetType().IsEnum -or
        $cloud.GetType() -in @([byte],[sbyte],[int16],[uint16],[int32],[uint32],[int64],[uint64]))) {
        if([string]$cloud -in @('1','2','Basic','Advanced')){$cloudMode='ENABLED'}
        elseif([string]$cloud -in @('0','Disabled')){$cloudMode='DISABLED'}
    }
    $tamper=Get-WinSecDefenderProperty $Status 'IsTamperProtected';$tamperMode=$null
    if($tamper -is [bool]){$tamperMode=if($tamper){'ENABLED'}else{'DISABLED'}}
    $driverMode=$null
    if((Get-WinSecDefenderProperty $Asr 'Available') -is [bool] -and $Asr.Available -and
        (Get-WinSecDefenderProperty $Asr 'Complete') -is [bool] -and $Asr.Complete -and $Asr.Rules -is [array]) {
        $matches=@($Asr.Rules|Where-Object {$_.RuleId -ceq '56a863a9-875e-4185-98a7-b882c64b5ce5'})
        if($matches.Count -eq 0){$driverMode='NOT_CONFIGURED'}
        elseif($matches.Count -eq 1 -and $matches[0].Mode -is [string] -and
            $matches[0].Mode -cin @('BLOCK','AUDIT','WARN','DISABLED','NOT_CONFIGURED')){$driverMode=$matches[0].Mode}
    }
    # Null is deliberate: an unknown state must never compare as a failed value.
    [pscustomobject]@{Pua=$puaMode;Cloud=$cloudMode;Tamper=$tamperMode;AsrVulnerableDriver=$driverMode}
}

function Add-WinSecDefenderIndicator {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]]$List,

        [Parameter(Mandatory)]
        [string]$Area,

        [Parameter(Mandatory)]
        [string]$Name,

        [AllowNull()]
        [object]$Value,

        [AllowNull()]
        [string]$Mode,

        [Parameter(Mandatory)]
        [string]$Recommendation,

        [Parameter(Mandatory)]
        [string]$Reference,

        [bool]$Review = $false
    )

    $state = if (
        $null -eq $Value -or
        $Mode -eq 'UNKNOWN'
    ) {
        'UNKNOWN'
    }
    else {
        $Mode
    }

    $List.Add(
        [pscustomobject]@{
            Area = $Area
            Name = $Name
            ObservedValue = $Value
            State = $state

            ReviewRecommended = (
                $Review -and $state -ne 'UNKNOWN'
            )

            Recommendation = $Recommendation
            Reference = $Reference

            ComplianceStatus = 'NOT_EVALUATED'
            ScoringEligible = $false
            EffectiveProtectionConfirmed = $false
        }
    )
}


# ============================================================
# MICROSOFT DEFENDER COLLECTOR
# ============================================================

function Test-WinSecDefender {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$DeviceId,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ScanId,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$CheckId
    )

    # ========================================================
    # IDENTITY VALIDATION
    # ========================================================

    if ($CheckId -cne 'WSA-SYS-001') {
        throw 'Invalid CheckId for Microsoft Defender.'
    }

    # TargetRegistry owns hardware identity. Hostnames and local: prefixes
    # alone never authorize a query, including for legacy inventory entries.
    if ($DeviceId -cnotmatch '^local:hw1-[a-f0-9]{64}$') {
        throw 'Defender requires the current local hardware DeviceId.'
    }

    try {
        $localIds = @(Get-WinSecLocalHardwareDeviceId -ErrorAction Stop)
    }
    catch {
        throw 'Unable to validate local hardware identity for Microsoft Defender.'
    }

    if ($localIds.Count -ne 1 -or $localIds[0] -isnot [string] -or
        $localIds[0] -cnotmatch '^local:hw1-[a-f0-9]{64}$') {
        throw 'Unable to validate local hardware identity for Microsoft Defender.'
    }

    if ($DeviceId -cne $localIds[0]) {
        throw 'Defender collector is local-only; DeviceId differs from the current hardware.'
    }

    # ========================================================
    # DOCUMENTATION
    # ========================================================

    $docs = [ordered]@{
        Antivirus = 'https://learn.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus'

        Cloud = 'https://learn.microsoft.com/en-us/defender-endpoint/configure-block-at-first-sight-microsoft-defender-antivirus'

        ASR = 'https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-overview'

        CFA = 'https://learn.microsoft.com/en-us/defender-endpoint/enable-controlled-folders'

        Network = 'https://learn.microsoft.com/en-us/defender-endpoint/enable-network-protection'

        PUA = 'https://learn.microsoft.com/en-us/defender-endpoint/detect-block-potentially-unwanted-apps-microsoft-defender-antivirus'
    }

    $issues = New-Object 'System.Collections.Generic.List[string]'
    $observations = New-Object 'System.Collections.Generic.List[string]'
    $indicators = New-Object 'System.Collections.Generic.List[object]'

    $now = [DateTime]::UtcNow.ToString('o')

    $statusRaw = $null
    $prefRaw = $null

    $statusSource = $null
    $prefSource = $null

    # ========================================================
    # STATUS COLLECTION
    # ========================================================

    try {
        $statusRaw = Get-MpComputerStatus -ErrorAction Stop

        if ($null -ne $statusRaw) {
            $statusSource = 'Get-MpComputerStatus'
        }
    }
    catch {
        $issues.Add(
            'Get-MpComputerStatus was unavailable or failed.'
        )
    }

    if ($null -eq $statusRaw) {
        try {
            $statusRaw = Get-CimInstance `
                -Namespace 'root/Microsoft/Windows/Defender' `
                -ClassName 'MSFT_MpComputerStatus' `
                -ErrorAction Stop

            if ($null -ne $statusRaw) {
                $statusSource = 'CIM:MSFT_MpComputerStatus'
            }
        }
        catch {
            $issues.Add(
                'Local CIM Defender status query was unavailable or failed.'
            )
        }
    }

    # ========================================================
    # RESULT CONTRACT
    # ========================================================

    $base = [ordered]@{
        CheckId = $CheckId
        DeviceId = $DeviceId
        ScanId = $ScanId

        SectionKey = 'SystemSecurity'
        Status = 'INFORMATIONAL'

        Evidence = $null
        NotApplicableReason = $null

        ErrorMessage = ''
        TimestampUTC = $now
    }

    $knownStatusNames = @(
        'AMRunningMode'
        'AntivirusEnabled'
        'AMServiceEnabled'
        'RealTimeProtectionEnabled'
        'BehaviorMonitorEnabled'
        'OnAccessProtectionEnabled'
        'NISEnabled'
        'AMProductVersion'
    )

    $recognized = $false

    foreach ($name in $knownStatusNames) {
        if (
            $null -ne (
                Get-WinSecDefenderProperty `
                    -InputObject $statusRaw `
                    -Name $name
            )
        ) {
            $recognized = $true
            break
        }
    }

    if (-not $recognized) {
        $base.Status = 'ERROR'

        $base.ErrorMessage = if ($null -eq $statusRaw) {
            'Unable to collect Microsoft Defender antivirus status.'
        }
        else {
            'Unable to collect usable status: no recognizable Defender telemetry.'
        }

        $base.Evidence = [pscustomobject]@{
            CheckId = $CheckId
            DeviceId = $DeviceId
            ScanId = $ScanId
            CollectedAtUTC = $now

            CollectionSuccessful = $false
            PreferenceCollectionSuccessful = $false

            StatusSource = $statusSource
            PreferenceSource = $null

            CollectionIssues = @($issues.ToArray())

            Observations = @(
                'Antivirus status could not be assessed.'
            )

            ScoringEligible = $false
            ComplianceAssessment = 'NOT_EVALUATED'
            CriteriaSource = $null
        }

        return [pscustomobject]$base
    }

    # ========================================================
    # PREFERENCE COLLECTION
    # ========================================================

    try {
        $prefRaw = Get-MpPreference -ErrorAction Stop

        if ($null -ne $prefRaw) {
            $prefSource = 'Get-MpPreference'
        }
    }
    catch {
        $issues.Add(
            'Get-MpPreference was unavailable or failed.'
        )
    }

    if ($null -eq $prefRaw) {
        try {
            $prefRaw = Get-CimInstance `
                -Namespace 'root/Microsoft/Windows/Defender' `
                -ClassName 'MSFT_MpPreference' `
                -ErrorAction Stop

            if ($null -ne $prefRaw) {
                $prefSource = 'CIM:MSFT_MpPreference'
            }
        }
        catch {
            $issues.Add(
                'Local CIM Defender preference query was unavailable or failed.'
            )
        }
    }

    if ($null -eq $prefRaw) {
        $observations.Add(
            'Defender preferences could not be collected; related states remain unknown.'
        )
    }

    # ========================================================
    # SAFE EVIDENCE COLLECTION
    # ========================================================

    $statusNames = @(
        'AMRunningMode'
        'AMServiceEnabled'
        'AntivirusEnabled'
        'RealTimeProtectionEnabled'
        'BehaviorMonitorEnabled'
        'OnAccessProtectionEnabled'
        'IoavProtectionEnabled'
        'NISEnabled'
        'IsTamperProtected'
        'DefenderSignaturesOutOfDate'
        'AntivirusSignatureAge'
        'AntivirusSignatureLastUpdated'
        'AntivirusSignatureVersion'
        'NISSignatureAge'
        'NISSignatureLastUpdated'
        'NISSignatureVersion'
        'AMEngineVersion'
        'AMProductVersion'
        'QuickScanAge'
        'FullScanAge'
        'QuickScanEndTime'
        'FullScanEndTime'
        'RebootRequired'
        'ComputerState'
    )

    $preferenceNames = @(
        'DisableRealtimeMonitoring'
        'DisableBehaviorMonitoring'
        'DisableIOAVProtection'
        'DisableBlockAtFirstSeen'
        'DisableScriptScanning'
        'DisableArchiveScanning'
        'DisableEmailScanning'
        'DisableRemovableDriveScanning'
        'DisableScanningNetworkFiles'
        'DisableScanningMappedNetworkDrivesForFullScan'
        'DisableCatchupQuickScan'
        'DisableCatchupFullScan'
        'DisableIntrusionPreventionSystem'
        'DisablePrivacyMode'
        'PUAProtection'
        'MAPSReporting'
        'SubmitSamplesConsent'
        'CloudBlockLevel'
        'CloudExtendedTimeout'
        'CheckForSignaturesBeforeRunningScan'
        'SignatureUpdateInterval'
        'ScanScheduleDay'
        'ScanParameters'
        'ScanAvgCPULoadFactor'
        'EnableNetworkProtection'
        'AllowNetworkProtectionOnWinServer'
        'AllowNetworkProtectionDownLevel'
        'EnableControlledFolderAccess'
        'EnableFileHashComputation'
        'DisableRdpParsing'
        'DisableHttpParsing'
        'DisableDnsOverTcpParsing'
        'DisableSshParsing'
        'DisableTlsParsing'
    )

    $status = Get-WinSecDefenderAllowlist `
        -InputObject $statusRaw `
        -Names $statusNames

    $preferences = Get-WinSecDefenderAllowlist `
        -InputObject $prefRaw `
        -Names $preferenceNames

    # ========================================================
    # PRIVACY-PRESERVING EXCLUSION COUNTS
    # ========================================================

    $exclusions = [pscustomobject]@{
        Paths = (
            Get-WinSecDefenderCount $prefRaw 'ExclusionPath'
        )

        Processes = (
            Get-WinSecDefenderCount $prefRaw 'ExclusionProcess'
        )

        Extensions = (
            Get-WinSecDefenderCount $prefRaw 'ExclusionExtension'
        )

        ASR = (
            Get-WinSecDefenderCount `
                $prefRaw 'AttackSurfaceReductionOnlyExclusions'
        )

        ControlledFolderAllowedApplications = (
            Get-WinSecDefenderCount `
                $prefRaw 'ControlledFolderAccessAllowedApplications'
        )

        ControlledFolderProtectedFolders = (
            Get-WinSecDefenderCount `
                $prefRaw 'ControlledFolderAccessProtectedFolders'
        )
    }

    $pua = Get-WinSecDefenderPUAAssessment `
        -RawValue $preferences.PUAProtection `
        -Source $prefSource

    $asr = Get-WinSecDefenderASRSummary `
        -Preference $prefRaw

    foreach ($message in $asr.Issues) {
        $issues.Add($message)
    }

    # ========================================================
    # CORE ANTIVIRUS PROTECTION
    #
    # Each entry is a structured object.
    # This prevents array flattening and incorrect counts.
    # ========================================================

    $avFields = @(
        [pscustomobject]@{
            Property = 'AMServiceEnabled'
            Name = 'Microsoft Defender Antivirus service'
            Area = 'CoreProtection'
        }

        [pscustomobject]@{
            Property = 'AntivirusEnabled'
            Name = 'Antivirus enabled'
            Area = 'CoreProtection'
        }

        [pscustomobject]@{
            Property = 'RealTimeProtectionEnabled'
            Name = 'Real-time protection'
            Area = 'CoreProtection'
        }

        [pscustomobject]@{
            Property = 'BehaviorMonitorEnabled'
            Name = 'Behavior monitoring'
            Area = 'CoreProtection'
        }

        [pscustomobject]@{
            Property = 'OnAccessProtectionEnabled'
            Name = 'On-access protection'
            Area = 'CoreProtection'
        }

        [pscustomobject]@{
            Property = 'IoavProtectionEnabled'
            Name = 'Internet/download file scanning'
            Area = 'CoreProtection'
        }

        [pscustomobject]@{
            Property = 'NISEnabled'
            Name = 'Network Inspection System'
            Area = 'CoreProtection'
        }

        [pscustomobject]@{
            Property = 'IsTamperProtected'
            Name = 'Tamper protection'
            Area = 'Integrity'
        }
    )

    foreach ($field in $avFields) {
        $value = Get-WinSecDefenderProperty `
            -InputObject $status `
            -Name $field.Property

        $mode = if ($null -eq $value) {
            'UNKNOWN'
        }
        elseif ($value -eq $true) {
            'ENABLED'
        }
        elseif ($value -eq $false) {
            'DISABLED'
        }
        else {
            'UNKNOWN'
        }

        Add-WinSecDefenderIndicator `
            -List $indicators `
            -Area $field.Area `
            -Name $field.Name `
            -Value $value `
            -Mode $mode `
            -Recommendation 'Review Defender operating mode, policy and security requirements before changing this setting.' `
            -Reference $docs.Antivirus `
            -Review ($mode -eq 'DISABLED')
    }

    # ========================================================
    # DEFENDER OPERATING MODE
    # ========================================================

    $runMode = $status.AMRunningMode

    $runModeNormalized = if ($null -eq $runMode) {
        'UNKNOWN'
    }
    else {
        ([string]$runMode).ToUpperInvariant()
    }

    Add-WinSecDefenderIndicator `
        -List $indicators `
        -Area CoreProtection `
        -Name 'Antivirus running mode' `
        -Value $runMode `
        -Mode $runModeNormalized `
        -Recommendation 'Confirm whether Defender is intended to run actively or alongside another security product.' `
        -Reference $docs.Antivirus `
        -Review $false

    if ([string]$runMode -match 'Passive') {
        $observations.Add(
            'Microsoft Defender is in passive mode; configuration alone does not confirm effective active protection.'
        )
    }

    if (
        $status.RealTimeProtectionEnabled -eq $false -and
        $null -ne $status.RealTimeProtectionEnabled
    ) {
        $observations.Add(
            'Microsoft Defender real-time protection is disabled according to status telemetry.'
        )
    }

    if ($status.DefenderSignaturesOutOfDate -eq $true) {
        $observations.Add(
            'Microsoft Defender signatures are reported as outdated.'
        )
    }

    if (
        $status.IsTamperProtected -eq $false -and
        $null -ne $status.IsTamperProtected
    ) {
        $observations.Add(
            'Tamper protection is reported as disabled.'
        )
    }

    if (
        $status.AntivirusEnabled -eq $false -and
        $null -ne $status.AntivirusEnabled
    ) {
        $observations.Add(
            'Microsoft Defender Antivirus is reported as disabled; check passive mode and third-party antivirus context.'
        )
    }

    # ========================================================
    # DEFENDER PROTECTION PREFERENCES
    # ========================================================

    $reversePreferences = @(
        [pscustomobject]@{
            Property = 'DisableRealtimeMonitoring'
            Name = 'Real-time monitoring preference'
            Area = 'CoreProtection'
        }

        [pscustomobject]@{
            Property = 'DisableBehaviorMonitoring'
            Name = 'Behavior monitoring preference'
            Area = 'CoreProtection'
        }

        [pscustomobject]@{
            Property = 'DisableIOAVProtection'
            Name = 'Downloaded file scanning preference'
            Area = 'CoreProtection'
        }

        [pscustomobject]@{
            Property = 'DisableScriptScanning'
            Name = 'Script scanning'
            Area = 'ThreatProtection'
        }

        [pscustomobject]@{
            Property = 'DisableArchiveScanning'
            Name = 'Archive scanning'
            Area = 'ThreatProtection'
        }

        [pscustomobject]@{
            Property = 'DisableEmailScanning'
            Name = 'Email scanning'
            Area = 'ThreatProtection'
        }

        [pscustomobject]@{
            Property = 'DisableRemovableDriveScanning'
            Name = 'Removable drive scanning'
            Area = 'ThreatProtection'
        }

        [pscustomobject]@{
            Property = 'DisableScanningNetworkFiles'
            Name = 'Network file scanning'
            Area = 'ThreatProtection'
        }

        [pscustomobject]@{
            Property = 'DisableScanningMappedNetworkDrivesForFullScan'
            Name = 'Mapped drives during full scan'
            Area = 'ThreatProtection'
        }
    )

    foreach ($entry in $reversePreferences) {
        $value = Get-WinSecDefenderProperty `
            -InputObject $preferences `
            -Name $entry.Property

        $mode = if ($null -eq $value) {
            'UNKNOWN'
        }
        elseif ($value -eq $true) {
            'DISABLED'
        }
        elseif ($value -eq $false) {
            'ENABLED'
        }
        else {
            'UNKNOWN'
        }

        Add-WinSecDefenderIndicator `
            -List $indicators `
            -Area $entry.Area `
            -Name $entry.Name `
            -Value $value `
            -Mode $mode `
            -Recommendation 'Review the applicable Defender antivirus policy and operational requirements.' `
            -Reference $docs.Antivirus `
            -Review ($mode -eq 'DISABLED')
    }

    # ========================================================
    # PUA / PUP PROTECTION
    #
    # Part of ThreatProtection.
    # No standalone PUA section or registered check.
    # ========================================================

    Add-WinSecDefenderIndicator `
        -List $indicators `
        -Area ThreatProtection `
        -Name 'Potentially unwanted applications (PUA)' `
        -Value $pua.RawValue `
        -Mode $pua.Mode `
        -Recommendation 'Consider configuring PUA blocking after assessing organizational policy and antivirus mode.' `
        -Reference $docs.PUA `
        -Review ($pua.Mode -in @('DISABLED', 'AUDIT'))

    switch ($pua.Mode) {
        'DISABLED' {
            $observations.Add(
                'PUA blocking is disabled in Defender preferences.'
            )
        }

        'AUDIT' {
            $observations.Add(
                'PUA is in audit mode; this setting does not actively block PUA.'
            )
        }

        'BLOCK' {
            $observations.Add(
                'PUA blocking is configured; effective blocking and browser downloads were not verified.'
            )
        }

        default {
            $observations.Add(
                'PUA protection state could not be determined.'
            )
        }
    }

    # ========================================================
    # CLOUD-DELIVERED PROTECTION
    # ========================================================

    $maps = $preferences.MAPSReporting

    $mapsMode = if ($null -eq $maps) {
        'UNKNOWN'
    }
    elseif ([string]$maps -in @('0', 'Disabled')) {
        'DISABLED'
    }
    elseif ([string]$maps -in @(
        '1', '2', 'Basic', 'Advanced'
    )) {
        'CONFIGURED'
    }
    else {
        'UNKNOWN'
    }

    Add-WinSecDefenderIndicator `
        -List $indicators `
        -Area CloudProtection `
        -Name 'Cloud-delivered protection (MAPS)' `
        -Value $maps `
        -Mode $mapsMode `
        -Recommendation 'Review cloud protection and data sharing policy; confirm service availability independently.' `
        -Reference $docs.Cloud `
        -Review ($mapsMode -eq 'DISABLED')

    $samples = $preferences.SubmitSamplesConsent

    $sampleMode = if ($null -eq $samples) {
        'UNKNOWN'
    }
    elseif ([string]$samples -in @(
        '1', '3', 'SendSafeSamples', 'SendAllSamples'
    )) {
        'AUTOMATIC'
    }
    elseif ([string]$samples -in @(
        '0', '2', 'AlwaysPrompt', 'NeverSend'
    )) {
        'RESTRICTED'
    }
    else {
        'UNKNOWN'
    }

    Add-WinSecDefenderIndicator `
        -List $indicators `
        -Area CloudProtection `
        -Name 'Sample submission consent' `
        -Value $samples `
        -Mode $sampleMode `
        -Recommendation 'Verify sample-submission settings against privacy and cloud protection requirements.' `
        -Reference $docs.Cloud `
        -Review ($sampleMode -eq 'RESTRICTED')

    $blockFirst = $preferences.DisableBlockAtFirstSeen

    $blockFirstMode = if ($null -eq $blockFirst) {
        'UNKNOWN'
    }
    elseif ($blockFirst -eq $false) {
        'CONFIGURED'
    }
    elseif ($blockFirst -eq $true) {
        'DISABLED'
    }
    else {
        'UNKNOWN'
    }

    Add-WinSecDefenderIndicator `
        -List $indicators `
        -Area CloudProtection `
        -Name 'Block at first sight preference' `
        -Value $blockFirst `
        -Mode $blockFirstMode `
        -Recommendation 'Review cloud protection, sample submission and antivirus updates together.' `
        -Reference $docs.Cloud `
        -Review ($blockFirstMode -eq 'DISABLED')

    $bafsPrerequisites = (
        $mapsMode -eq 'CONFIGURED' -and
        $sampleMode -eq 'AUTOMATIC' -and
        $blockFirstMode -eq 'CONFIGURED' -and
        $status.DefenderSignaturesOutOfDate -eq $false
    )

    if ($bafsPrerequisites) {
        $observations.Add(
            'Block at first sight local prerequisites appear configured; cloud reachability and enforcement were not tested.'
        )
    }

    # ========================================================
    # NETWORK PROTECTION
    # ========================================================

    $networkMode = ConvertTo-WinSecDefenderEnumMode `
        -Value $preferences.EnableNetworkProtection `
        -Kind Network

    Add-WinSecDefenderIndicator `
        -List $indicators `
        -Area NetworkProtection `
        -Name 'Microsoft Defender Network Protection' `
        -Value $preferences.EnableNetworkProtection `
        -Mode $networkMode `
        -Recommendation 'Review network protection mode, antivirus active mode, OS support and Windows Server prerequisites.' `
        -Reference $docs.Network `
        -Review ($networkMode -in @('DISABLED', 'AUDIT'))

    if ($networkMode -eq 'BLOCK') {
        $observations.Add(
            'Network Protection block mode is configured; platform prerequisites and active enforcement were not verified.'
        )
    }

    # ========================================================
    # RANSOMWARE PROTECTION
    # ========================================================

    $folderMode = ConvertTo-WinSecDefenderEnumMode `
        -Value $preferences.EnableControlledFolderAccess `
        -Kind Folder

    Add-WinSecDefenderIndicator `
        -List $indicators `
        -Area RansomwareProtection `
        -Name 'Controlled folder access' `
        -Value $preferences.EnableControlledFolderAccess `
        -Mode $folderMode `
        -Recommendation 'Evaluate controlled folder access and approved applications according to workload compatibility.' `
        -Reference $docs.CFA `
        -Review ($folderMode -in @(
            'DISABLED', 'AUDIT', 'AUDIT_DISK_MODIFICATION'
        ))

    # ========================================================
    # ATTACK SURFACE REDUCTION
    # ========================================================

    $asrSummaryMode = if (
        $asr.Available -and $asr.Complete
    ) {
        'CONFIGURED'
    }
    else {
        'UNKNOWN'
    }

    Add-WinSecDefenderIndicator `
        -List $indicators `
        -Area AttackSurfaceReduction `
        -Name 'Configured ASR rule count' `
        -Value $asr.ConfiguredRuleCount `
        -Mode $asrSummaryMode `
        -Recommendation 'Review individual ASR rule modes and rule applicability before interpreting unconfigured or unsupported rules.' `
        -Reference $docs.ASR `
        -Review $false

    if (-not $asr.Complete) {
        $observations.Add(
            'ASR rule inventory is incomplete or has inconsistent entries; no inference about unlisted rules is made.'
        )
    }

    foreach ($rule in $asr.Rules) {
        Add-WinSecDefenderIndicator `
            -List $indicators `
            -Area AttackSurfaceReduction `
            -Name ('ASR rule {0}' -f $rule.RuleId) `
            -Value $rule.RawAction `
            -Mode $rule.Mode `
            -Recommendation 'Validate rule applicability, dependencies and deployment policy before considering block mode.' `
            -Reference $docs.ASR `
            -Review ($rule.Mode -in @(
                'DISABLED', 'NOT_CONFIGURED', 'AUDIT'
            ))
    }

    # ========================================================
    # SIGNATURE UPDATES AND SCANNING
    # ========================================================

    $scanFields = @(
        [pscustomobject]@{
            Property = 'QuickScanAge'
            Name = 'Quick scan age (days)'
        }

        [pscustomobject]@{
            Property = 'FullScanAge'
            Name = 'Full scan age (days)'
        }

        [pscustomobject]@{
            Property = 'AntivirusSignatureAge'
            Name = 'Antivirus signature age (days)'
        }

        [pscustomobject]@{
            Property = 'NISSignatureAge'
            Name = 'Network signature age (days)'
        }
    )

    foreach ($scanField in $scanFields) {
        $value = Get-WinSecDefenderProperty `
            -InputObject $status `
            -Name $scanField.Property

        $mode = if ($null -eq $value) {
            'UNKNOWN'
        }
        else {
            'OBSERVED'
        }

        Add-WinSecDefenderIndicator `
            -List $indicators `
            -Area UpdatesAndScans `
            -Name $scanField.Name `
            -Value $value `
            -Mode $mode `
            -Recommendation 'Compare collected age against an approved, OS-specific threshold; do not infer compliance from age alone.' `
            -Reference $docs.Antivirus `
            -Review $false
    }

    # ========================================================
    # EXCLUSIONS AND SECURITY HARDENING
    # ========================================================

    $countFields = @(
        [pscustomobject]@{
            Property = 'Paths'
            Name = 'Path exclusions'
        }

        [pscustomobject]@{
            Property = 'Processes'
            Name = 'Process exclusions'
        }

        [pscustomobject]@{
            Property = 'Extensions'
            Name = 'Extension exclusions'
        }

        [pscustomobject]@{
            Property = 'ASR'
            Name = 'ASR-only exclusions'
        }

        [pscustomobject]@{
            Property = 'ControlledFolderAllowedApplications'
            Name = 'Controlled folder allowlist'
        }

        [pscustomobject]@{
            Property = 'ControlledFolderProtectedFolders'
            Name = 'Additional controlled folders'
        }
    )

    foreach ($countField in $countFields) {
        $value = Get-WinSecDefenderProperty `
            -InputObject $exclusions `
            -Name $countField.Property

        $mode = if ($null -eq $value) {
            'UNKNOWN'
        }
        else {
            'COUNT_ONLY'
        }

        Add-WinSecDefenderIndicator `
            -List $indicators `
            -Area ExclusionsAndHardening `
            -Name $countField.Name `
            -Value $value `
            -Mode $mode `
            -Recommendation 'Review exclusions under least-privilege policy; raw paths and application names are intentionally withheld.' `
            -Reference $docs.Antivirus `
            -Review (
                $null -ne $value -and
                $value -gt 0
            )
    }

    # ========================================================
    # INTERNAL SECURITY ANALYSIS AREAS
    # ========================================================

    $areaNames = @(
        'CoreProtection'
        'ThreatProtection'
        'CloudProtection'
        'Integrity'
        'NetworkProtection'
        'RansomwareProtection'
        'AttackSurfaceReduction'
        'UpdatesAndScans'
        'ExclusionsAndHardening'
    )

    $areas = [ordered]@{}

    foreach ($areaName in $areaNames) {
        $entries = @(
            $indicators.ToArray() |
                Where-Object {
                    $_.Area -eq $areaName
                }
        )

        $areas[$areaName] = [pscustomobject]@{
            Name = $areaName
            Indicators = $entries

            IndicatorCount = $entries.Count

            ReviewCount = @(
                $entries | Where-Object {
                    $_.ReviewRecommended
                }
            ).Count

            UnknownCount = @(
                $entries | Where-Object {
                    $_.State -eq 'UNKNOWN'
                }
            ).Count
        }
    }

    # ========================================================
    # EVIDENCE AND ANALYSIS RESULT
    # ========================================================

    $reviewIndicatorCount = @(
        $indicators.ToArray() |
            Where-Object {
                $_.ReviewRecommended
            }
    ).Count

    $unknownIndicatorCount = @(
        $indicators.ToArray() |
            Where-Object {
                $_.State -eq 'UNKNOWN'
            }
    ).Count

    $base.Evidence = [pscustomobject]@{
        CheckId = $CheckId
        DeviceId = $DeviceId
        ScanId = $ScanId
        CollectedAtUTC = $now

        CollectionSuccessful = $true

        PreferenceCollectionSuccessful = (
            $null -ne $prefRaw
        )

        StatusSource = $statusSource
        PreferenceSource = $prefSource

        DefenderStatus = $status
        DefenderPreferences = $preferences

        PUAProtectionAssessment = $pua

        ExclusionCounts = $exclusions
        AttackSurfaceReduction = $asr
        ConfigurationModes = Get-WinSecDefenderConfigurationModes -Status $status -Preferences $preferences -Pua $pua -Asr $asr

        Analysis = [pscustomobject]@{
            Areas = [pscustomobject]$areas

            IndicatorCount = $indicators.Count

            ReviewIndicatorCount = $reviewIndicatorCount

            UnknownIndicatorCount = $unknownIndicatorCount

            ScoringEligible = $false
            ComplianceAssessment = 'NOT_EVALUATED'
        }

        Observations = @($observations.ToArray())
        CollectionIssues = @($issues.ToArray())

        ScoringEligible = $false
        ComplianceAssessment = 'NOT_EVALUATED'
        CriteriaSource = $null

        FrameworkMappingsVerified = $false

        Documentation = [pscustomobject]$docs
    }

    return [pscustomobject]$base
}
