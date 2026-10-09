function Test-PowerShellSecurity {
    [CmdletBinding()]
    param()

    $Results = @()

    # ========================================================
    # HELPER - Standardized assessment result
    # ========================================================

    function New-PSecurityResult {
        param(
            [string]$Control,
            [string]$Status,
            [string]$Severity,
            [int]$Score,
            [int]$MaxScore,
            [string]$Evidence,
            [string]$Recommendation
        )

        [PSCustomObject]@{
            Control        = $Control
            Category       = 'PowerShell Security'
            Status         = $Status
            Severity       = $Severity
            Score          = $Score
            MaxScore       = $MaxScore
            Evidence       = $Evidence
            Recommendation = $Recommendation
        }
    }

    # ========================================================
    # HELPER - Resolve PowerShell 7 policy
    #
    # Precedence:
    # 1. Computer PowerShellCore policy
    # 2. User PowerShellCore policy
    # 3. CurrentUser powershell.config.json
    # 4. AllUsers powershell.config.json
    #
    # Legacy Windows PowerShell policies are not evaluated.
    # ========================================================

    function Get-PSCorePolicyValue {
        param(
            [string]$Section,
            [string]$Setting
        )

        $RegistrySources = @(
            @{
                Root   = 'HKLM:\SOFTWARE\Policies\Microsoft\PowerShellCore'
                Source = 'Computer Policy'
            },
            @{
                Root   = 'HKCU:\SOFTWARE\Policies\Microsoft\PowerShellCore'
                Source = 'User Policy'
            }
        )

        foreach ($RegistrySource in $RegistrySources) {

            $Path = Join-Path $RegistrySource.Root $Section

            try {
                $PathExists = Test-Path `
                    -LiteralPath $Path `
                    -ErrorAction Stop
            }
            catch {
                return [PSCustomObject]@{
                    State           = 'ERROR'
                    Enabled         = $null
                    Source          = $RegistrySource.Source
                    Details         = $_.Exception.Message
                    Modules         = @()
                    OutputDirectory = ''
                }
            }

            if (-not $PathExists) {
                continue
            }

            try {
                $Data = Get-ItemProperty `
                    -LiteralPath $Path `
                    -ErrorAction Stop
            }
            catch {
                return [PSCustomObject]@{
                    State   = 'ERROR'
                    Enabled = $null
                    Source  = $RegistrySource.Source
                    Details = $_.Exception.Message
                    Modules = @()
                    OutputDirectory = ''
                }
            }

            # A PowerShellCore policy may delegate to older
            # Windows PowerShell policy settings. We do not
            # evaluate that legacy configuration.

            $LegacyOption = $Data.PSObject.Properties[
                'UseWindowsPowerShellPolicySetting'
            ]

            if (
                $null -ne $LegacyOption -and
                [string]$LegacyOption.Value -in @('1', 'True')
            ) {
                return [PSCustomObject]@{
                    State   = 'DELEGATED'
                    Enabled = $null
                    Source  = $RegistrySource.Source
                    Details = 'Policy delegates to Windows PowerShell settings, excluded from this PowerShell 7-only assessment.'
                    Modules = @()
                    OutputDirectory = ''
                }
            }

            $Property = $Data.PSObject.Properties[$Setting]

            if ($null -eq $Property) {
                continue
            }

            $RawValue = [string]$Property.Value

            if ($RawValue -notin @('0', '1', 'True', 'False')) {
                return [PSCustomObject]@{
                    State   = 'ERROR'
                    Enabled = $null
                    Source  = $RegistrySource.Source
                    Details = "Invalid value for $Setting."
                    Modules = @()
                    OutputDirectory = ''
                }
            }

            $Enabled = $RawValue -in @('1', 'True')
            $Modules = @()
            $OutputDirectory = ''

            if ($Section -eq 'ModuleLogging') {

                $ModulePath = Join-Path $Path 'ModuleNames'

                if (Test-Path -LiteralPath $ModulePath) {

                    try {
                        $ModuleKey = Get-Item `
                            -LiteralPath $ModulePath `
                            -ErrorAction Stop

                        $Modules = @(
                            foreach ($ValueName in $ModuleKey.GetValueNames()) {

                                $ModuleName = [string]$ModuleKey.GetValue(
                                    $ValueName
                                )

                                if (-not [string]::IsNullOrWhiteSpace($ModuleName)) {
                                    $ModuleName
                                }
                            }
                        )
                    }
                    catch {
                        return [PSCustomObject]@{
                            State   = 'ERROR'
                            Enabled = $null
                            Source  = $RegistrySource.Source
                            Details = "Unable to read module logging configuration: $($_.Exception.Message)"
                            Modules = @()
                            OutputDirectory = ''
                        }
                    }
                }
            }

            if ($Section -eq 'Transcription') {

                $DirectoryProperty = $Data.PSObject.Properties[
                    'OutputDirectory'
                ]

                if ($null -ne $DirectoryProperty) {
                    $OutputDirectory = [string]$DirectoryProperty.Value
                }
            }

            return [PSCustomObject]@{
                State           = 'CONFIGURED'
                Enabled         = $Enabled
                Source          = $RegistrySource.Source
                Details         = "$Setting=$RawValue"
                Modules         = $Modules
                OutputDirectory = $OutputDirectory
            }
        }

        # ====================================================
        # PowerShell 7 JSON configuration
        # ====================================================

        $UserConfigDirectory = Split-Path `
            $PROFILE.CurrentUserCurrentHost `
            -Parent

        $ConfigSources = @(
            @{
                Path   = Join-Path $UserConfigDirectory 'powershell.config.json'
                Source = 'CurrentUser JSON'
            },
            @{
                Path   = Join-Path $PSHOME 'powershell.config.json'
                Source = 'AllUsers JSON'
            }
        )

        foreach ($ConfigSource in $ConfigSources) {

            try {

                $ConfigExists = Test-Path `
                    -LiteralPath $ConfigSource.Path `
                    -ErrorAction Stop
            }
            catch {

                return [PSCustomObject]@{
                    State           = 'ERROR'
                    Enabled         = $null
                    Source          = $ConfigSource.Source
                    Details         = $_.Exception.Message
                    Modules         = @()
                    OutputDirectory = ''
                }
            }

            if (-not $ConfigExists) {
                continue
            }

            try {

                $Config = Get-Content `
                    -LiteralPath $ConfigSource.Path `
                    -Raw `
                    -ErrorAction Stop |
                    ConvertFrom-Json -AsHashtable -ErrorAction Stop

                # Support PowerShellPolicies and root-level policies.

if ($Config -isnot [System.Collections.IDictionary]) {
    continue
}

$SectionData = $null

# Check nested PowerShellPolicies first.
if ($Config.Contains('PowerShellPolicies')) {

    $Policies = $Config['PowerShellPolicies']

    if (
        $Policies -is [System.Collections.IDictionary] -and
        $Policies.Contains($Section)
    ) {

        $Candidate = $Policies[$Section]

        if (
            $Candidate -is [System.Collections.IDictionary] -and
            $Candidate.Contains($Setting)
        ) {
            $SectionData = $Candidate
        }
    }
}

                # Check root-level configuration as fallback.
                if (
                    $null -eq $SectionData -and
                    $Config.Contains($Section)
                ) {
                    $SectionData = $Config[$Section]
                }

                if ($SectionData -isnot [System.Collections.IDictionary]) {
                    continue
                }

                if (-not $SectionData.Contains($Setting)) {
                    continue
                }

                $RawValue = $SectionData[$Setting]

                if ($RawValue -isnot [bool]) {
                    throw "Invalid Boolean value for $Section.$Setting"
                }

                $Modules = @()
                $OutputDirectory = ''

                if (
                    $Section -eq 'ModuleLogging' -and
                    $SectionData.Contains('ModuleNames')
                ) {
                    $Modules = @(
                        $SectionData['ModuleNames'] |
                            Where-Object {
                                -not [string]::IsNullOrWhiteSpace(
                                    [string]$_
                                )
                            }
                    )
                }

                if (
                    $Section -eq 'Transcription' -and
                    $SectionData.Contains('OutputDirectory')
                ) {
                    $OutputDirectory = [string]$SectionData[
                        'OutputDirectory'
                    ]
                }

                return [PSCustomObject]@{
                    State           = 'CONFIGURED'
                    Enabled         = [bool]$RawValue
                    Source          = $ConfigSource.Source
                    Details         = "$Setting=$RawValue"
                    Modules         = $Modules
                    OutputDirectory = $OutputDirectory
                }
            }
            catch {

                return [PSCustomObject]@{
                    State   = 'ERROR'
                    Enabled = $null
                    Source  = $ConfigSource.Source
                    Details = $_.Exception.Message
                    Modules = @()
                    OutputDirectory = ''
                }
            }
        }

        return [PSCustomObject]@{
            State           = 'NOT_CONFIGURED'
            Enabled         = $null
            Source          = 'PowerShellCore'
            Details         = 'No explicit PowerShell 7 policy was detected.'
            Modules         = @()
            OutputDirectory = ''
        }
    }

    # ========================================================
    # HELPER - Add standardized policy assessment
    # ========================================================

    function New-LoggingAssessment {
        param(
            [string]$Control,
            [string]$Severity,
            [int]$MaxScore,
            [object]$Policy,
            [string]$Recommendation
        )

        $Status = 'WARNING'
        $Score = 0
        $EffectiveMaxScore = $MaxScore
        $Evidence = "$($Policy.Details); Source=$($Policy.Source)"

        switch ($Policy.State) {

            'CONFIGURED' {
                if ($Policy.Enabled -eq $true) {
                    $Status = 'PASS'
                    $Score = $MaxScore
                }
                else {
                    $Status = 'WARNING'
                }
            }

            'NOT_CONFIGURED' {
                $Status = 'WARNING'
            }

            'DELEGATED' {
                $Status = 'INFO'
                $EffectiveMaxScore = 0
            }

            'ERROR' {
                $Status = 'ERROR'
                $Severity = 'Unknown'
                $EffectiveMaxScore = 0
            }
        }

        New-PSecurityResult `
            -Control $Control `
            -Status $Status `
            -Severity $Severity `
            -Score $Score `
            -MaxScore $EffectiveMaxScore `
            -Evidence $Evidence `
            -Recommendation $Recommendation
    }

    # ========================================================
    # 1. SCRIPT BLOCK LOGGING
    # 40 points
    # ========================================================

    $ScriptBlock = Get-PSCorePolicyValue `
        -Section 'ScriptBlockLogging' `
        -Setting 'EnableScriptBlockLogging'

    $Results += New-LoggingAssessment `
        -Control 'Script Block Logging' `
        -Severity 'High' `
        -MaxScore 40 `
        -Policy $ScriptBlock `
        -Recommendation 'Enable PowerShell 7 Script Block Logging through the PowerShell Core policy or powershell.config.json.'

    # ========================================================
    # 2. MODULE LOGGING
    # 20 points
    # ========================================================

    $ModuleLogging = Get-PSCorePolicyValue `
        -Section 'ModuleLogging' `
        -Setting 'EnableModuleLogging'

    if (
        $ModuleLogging.State -eq 'CONFIGURED' -and
        $ModuleLogging.Enabled -eq $true
    ) {

        $ModuleNames = @($ModuleLogging.Modules)

        if ($ModuleNames.Count -gt 0) {

            $Names = $ModuleNames -join ', '

            $Results += New-PSecurityResult `
                -Control 'Module Logging' `
                -Status 'PASS' `
                -Severity 'Medium' `
                -Score 20 `
                -MaxScore 20 `
                -Evidence "Enabled; Modules=$Names; Source=$($ModuleLogging.Source)" `
                -Recommendation 'Review the selected modules periodically to ensure security-relevant activity is logged.'
        }
        else {

            $Results += New-PSecurityResult `
                -Control 'Module Logging' `
                -Status 'WARNING' `
                -Severity 'Medium' `
                -Score 0 `
                -MaxScore 20 `
                -Evidence "Module logging is enabled, but no module names were found. Source=$($ModuleLogging.Source)" `
                -Recommendation 'Configure the modules that should generate pipeline execution logs.'
        }
    }
    else {

        $Results += New-LoggingAssessment `
            -Control 'Module Logging' `
            -Severity 'Medium' `
            -MaxScore 20 `
            -Policy $ModuleLogging `
            -Recommendation 'Enable Module Logging and specify the modules to monitor.'
    }

    # ========================================================
    # 3. POWERSHELL TRANSCRIPTION
    # 25 points
    # ========================================================

    $Transcription = Get-PSCorePolicyValue `
        -Section 'Transcription' `
        -Setting 'EnableTranscripting'

    $Results += New-LoggingAssessment `
        -Control 'PowerShell Transcription' `
        -Severity 'High' `
        -MaxScore 25 `
        -Policy $Transcription `
        -Recommendation 'Enable PowerShell transcription and use a protected location for transcript files.'

    # ========================================================
    # TRANSCRIPTION OUTPUT DIRECTORY
    # Informational
    # ========================================================

    if (
        $Transcription.State -eq 'CONFIGURED' -and
        $Transcription.Enabled -eq $true
    ) {

        if (
            [string]::IsNullOrWhiteSpace(
                $Transcription.OutputDirectory
            )
        ) {

            $Results += New-PSecurityResult `
                -Control 'Transcription Output Directory' `
                -Status 'WARNING' `
                -Severity 'Medium' `
                -Score 0 `
                -MaxScore 0 `
                -Evidence 'No explicit transcription output directory is configured.' `
                -Recommendation 'Consider a centralized, access-controlled transcript directory.'
        }
        else {

            $Results += New-PSecurityResult `
                -Control 'Transcription Output Directory' `
                -Status 'INFO' `
                -Severity 'Info' `
                -Score 0 `
                -MaxScore 0 `
                -Evidence "Configured directory: $($Transcription.OutputDirectory)" `
                -Recommendation 'Verify directory permissions, retention and protection against modification. This assessment does not validate ACLs.'
        }
    }

    # ========================================================
    # 4. POWERSHELL CORE EVENT LOG
    # 15 points
    # ========================================================

    try {

        $EventLog = Get-WinEvent `
            -ListLog 'PowerShellCore/Operational' `
            -ErrorAction Stop

        if ($EventLog.IsEnabled -eq $true) {

            $Results += New-PSecurityResult `
                -Control 'PowerShellCore Operational Event Log' `
                -Status 'PASS' `
                -Severity 'High' `
                -Score 15 `
                -MaxScore 15 `
                -Evidence "Event log is enabled; MaximumSizeBytes=$($EventLog.MaximumSizeInBytes)" `
                -Recommendation 'Verify log retention, forwarding and monitoring requirements.'
        }
        else {

            $Results += New-PSecurityResult `
                -Control 'PowerShellCore Operational Event Log' `
                -Status 'WARNING' `
                -Severity 'High' `
                -Score 0 `
                -MaxScore 15 `
                -Evidence 'PowerShellCore/Operational event log is disabled.' `
                -Recommendation 'Enable the PowerShellCore Operational event log.'
        }
    }
    catch {

        $LogError = $_

        if (
            $LogError.FullyQualifiedErrorId -match
            'NoMatchingLogsFound|LogNotFound'
        ) {

            $Results += New-PSecurityResult `
                -Control 'PowerShellCore Operational Event Log' `
                -Status 'WARNING' `
                -Severity 'High' `
                -Score 0 `
                -MaxScore 15 `
                -Evidence 'PowerShellCore/Operational event log was not found.' `
                -Recommendation 'Verify registration of the PowerShell 7 event provider.'
        }
        else {

            $Results += New-PSecurityResult `
                -Control 'PowerShellCore Operational Event Log' `
                -Status 'ERROR' `
                -Severity 'Unknown' `
                -Score 0 `
                -MaxScore 0 `
                -Evidence $LogError.Exception.Message `
                -Recommendation 'Verify event log access and PowerShell 7 event provider registration.'
        }
    }

    # ========================================================
    # 5. EXECUTION POLICY
    # Informational - Not a security boundary
    # ========================================================

    try {

        $ExecutionPolicy = Get-ExecutionPolicy -ErrorAction Stop

        $PolicyList = @(
            Get-ExecutionPolicy -List -ErrorAction Stop |
                ForEach-Object {
                    "$($_.Scope)=$($_.ExecutionPolicy)"
                }
        ) -join '; '

        $Results += New-PSecurityResult `
            -Control 'Execution Policy' `
            -Status 'INFO' `
            -Severity 'Info' `
            -Score 0 `
            -MaxScore 0 `
            -Evidence "Effective=$ExecutionPolicy; Scopes=$PolicyList" `
            -Recommendation 'Review execution policy as a safety setting. Do not rely on it as a security boundary.'
    }
    catch {

        $Results += New-PSecurityResult `
            -Control 'Execution Policy' `
            -Status 'ERROR' `
            -Severity 'Unknown' `
            -Score 0 `
            -MaxScore 0 `
            -Evidence $_.Exception.Message `
            -Recommendation 'Review PowerShell execution policy manually.'
    }

    # ========================================================
    # 6. LANGUAGE MODE
    # Informational
    # ========================================================

    $LanguageMode = [string](
        $ExecutionContext.SessionState.LanguageMode
    )

    $Results += New-PSecurityResult `
        -Control 'PowerShell Language Mode' `
        -Status 'INFO' `
        -Severity 'Info' `
        -Score 0 `
        -MaxScore 0 `
        -Evidence "Current session LanguageMode=$LanguageMode" `
        -Recommendation 'Review application control requirements. FullLanguage alone is not evidence of a vulnerability.'

    # ========================================================
    # 7. PSREADLINE HISTORY
    # Informational - Never read history contents
    # ========================================================

    try {

        if (
            Get-Command Get-PSReadLineOption `
                -ErrorAction SilentlyContinue
        ) {

            $HistoryOptions = Get-PSReadLineOption `
                -ErrorAction Stop

            $Results += New-PSecurityResult `
                -Control 'PSReadLine History Configuration' `
                -Status 'INFO' `
                -Severity 'Info' `
                -Score 0 `
                -MaxScore 0 `
                -Evidence "HistorySaveStyle=$($HistoryOptions.HistorySaveStyle); HistorySavePath=$($HistoryOptions.HistorySavePath)" `
                -Recommendation 'Review local history retention and access permissions. Avoid placing credentials or secrets in interactive commands.'
        }
        else {

            $Results += New-PSecurityResult `
                -Control 'PSReadLine History Configuration' `
                -Status 'INFO' `
                -Severity 'Info' `
                -Score 0 `
                -MaxScore 0 `
                -Evidence 'PSReadLine configuration is not available in this session.' `
                -Recommendation 'Review interactive command history handling when applicable.'
        }
    }
    catch {

        $Results += New-PSecurityResult `
            -Control 'PSReadLine History Configuration' `
            -Status 'INFO' `
            -Severity 'Info' `
            -Score 0 `
            -MaxScore 0 `
            -Evidence "Unable to query PSReadLine options: $($_.Exception.Message)" `
            -Recommendation 'Review PSReadLine configuration manually if required.'
    }

    return $Results
}