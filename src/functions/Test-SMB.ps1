function Test-SMB {
    [CmdletBinding()]
    param()

    $Results = @()

    function New-SMBResult {
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
            Category       = 'SMB Security'
            Status         = $Status
            Severity       = $Severity
            Score          = $Score
            MaxScore       = $MaxScore
            Evidence       = $Evidence
            Recommendation = $Recommendation
        }
    }

    # ========================================================
    # Verify SMB cmdlets
    # ========================================================

    if (-not (Get-Command Get-SmbServerConfiguration -ErrorAction SilentlyContinue)) {

        $Results += New-SMBResult `
            -Control 'SMB Configuration Availability' `
            -Status 'ERROR' `
            -Severity 'Unknown' `
            -Score 0 `
            -MaxScore 0 `
            -Evidence 'Get-SmbServerConfiguration is not available.' `
            -Recommendation 'Verify SMB PowerShell cmdlet availability and Windows compatibility.'

        return $Results
    }

    # ========================================================
    # Collect SMB configuration
    # ========================================================

    try {
        $ServerConfig = Get-SmbServerConfiguration -ErrorAction Stop
    }
    catch {

        $Results += New-SMBResult `
            -Control 'SMB Server Configuration' `
            -Status 'ERROR' `
            -Severity 'Unknown' `
            -Score 0 `
            -MaxScore 0 `
            -Evidence $_.Exception.Message `
            -Recommendation 'Run WinSec Analyzer with sufficient privileges and verify SMB configuration.'

        return $Results
    }

    try {
        $ClientConfig = Get-SmbClientConfiguration -ErrorAction Stop
    }
    catch {
        $ClientConfig = $null
    }

    # ========================================================
    # 1. SMBv1 SERVER PROTOCOL
    # 25 points
    # ========================================================

    if ($ServerConfig.EnableSMB1Protocol -eq $false) {

        $Results += New-SMBResult `
            -Control 'SMBv1 Server Protocol' `
            -Status 'PASS' `
            -Severity 'High' `
            -Score 25 `
            -MaxScore 25 `
            -Evidence 'SMBv1 server protocol is disabled.' `
            -Recommendation 'No action required.'
    }
    else {

        $Results += New-SMBResult `
            -Control 'SMBv1 Server Protocol' `
            -Status 'FAIL' `
            -Severity 'High' `
            -Score 0 `
            -MaxScore 25 `
            -Evidence 'SMBv1 server protocol is enabled.' `
            -Recommendation 'Disable SMBv1 unless it is explicitly required for a legacy system.'
    }

    # ========================================================
    # 2. SMBv1 WINDOWS OPTIONAL FEATURE
    # 10 points
    # ========================================================

    if (Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue) {

        try {

            $SMB1Feature = Get-WindowsOptionalFeature `
                -Online `
                -FeatureName 'SMB1Protocol' `
                -ErrorAction Stop

            $FeatureState = [string]$SMB1Feature.State

            if ($FeatureState -like 'Disabled*') {

                $Results += New-SMBResult `
                    -Control 'SMBv1 Windows Feature' `
                    -Status 'PASS' `
                    -Severity 'High' `
                    -Score 10 `
                    -MaxScore 10 `
                    -Evidence "SMB1Protocol feature state: $FeatureState" `
                    -Recommendation 'No action required.'
            }
            else {

                $Results += New-SMBResult `
                    -Control 'SMBv1 Windows Feature' `
                    -Status 'FAIL' `
                    -Severity 'High' `
                    -Score 0 `
                    -MaxScore 10 `
                    -Evidence "SMB1Protocol feature state: $FeatureState" `
                    -Recommendation 'Disable the SMB1Protocol Windows optional feature if legacy compatibility is not required.'
            }
        }
        catch {

            $Results += New-SMBResult `
                -Control 'SMBv1 Windows Feature' `
                -Status 'INFO' `
                -Severity 'Info' `
                -Score 0 `
                -MaxScore 0 `
                -Evidence "SMBv1 optional feature state could not be determined: $($_.Exception.Message)" `
                -Recommendation 'Review the SMB1Protocol Windows feature manually if required.'
        }
    }
    else {

        $Results += New-SMBResult `
            -Control 'SMBv1 Windows Feature' `
            -Status 'INFO' `
            -Severity 'Info' `
            -Score 0 `
            -MaxScore 0 `
            -Evidence 'Get-WindowsOptionalFeature is not available in the current PowerShell environment.' `
            -Recommendation 'Review the SMB1Protocol Windows optional feature manually.'
    }

    # ========================================================
    # 3. SMBv2 / SMBv3
    # 15 points
    # ========================================================

    if ($ServerConfig.EnableSMB2Protocol -eq $true) {

        $Results += New-SMBResult `
            -Control 'SMBv2 and SMBv3 Protocols' `
            -Status 'PASS' `
            -Severity 'High' `
            -Score 15 `
            -MaxScore 15 `
            -Evidence 'SMBv2/SMBv3 protocol support is enabled.' `
            -Recommendation 'No action required.'
    }
    else {

        $Results += New-SMBResult `
            -Control 'SMBv2 and SMBv3 Protocols' `
            -Status 'FAIL' `
            -Severity 'High' `
            -Score 0 `
            -MaxScore 15 `
            -Evidence 'SMBv2/SMBv3 protocol support is disabled.' `
            -Recommendation 'Enable SMBv2/SMBv3 unless there is a documented compatibility requirement.'
    }

    # ========================================================
    # 4. SERVER SMB SIGNING
    # 15 points
    # ========================================================

    if ($ServerConfig.RequireSecuritySignature -eq $true) {

        $Results += New-SMBResult `
            -Control 'SMB Server Signing Required' `
            -Status 'PASS' `
            -Severity 'High' `
            -Score 15 `
            -MaxScore 15 `
            -Evidence 'The SMB server requires security signatures.' `
            -Recommendation 'No action required.'
    }
    else {

        $Results += New-SMBResult `
            -Control 'SMB Server Signing Required' `
            -Status 'WARNING' `
            -Severity 'High' `
            -Score 5 `
            -MaxScore 15 `
            -Evidence 'The SMB server does not require security signatures.' `
            -Recommendation 'Consider requiring SMB signing to reduce the risk of SMB relay and tampering attacks.'
    }

    # ========================================================
    # 5. CLIENT SMB SIGNING
    # 15 points
    # ========================================================

    if ($null -eq $ClientConfig) {

        $Results += New-SMBResult `
            -Control 'SMB Client Signing Required' `
            -Status 'ERROR' `
            -Severity 'Unknown' `
            -Score 0 `
            -MaxScore 0 `
            -Evidence 'SMB client configuration could not be queried.' `
            -Recommendation 'Review SMB client signing configuration manually.'
    }
    elseif ($ClientConfig.RequireSecuritySignature -eq $true) {

        $Results += New-SMBResult `
            -Control 'SMB Client Signing Required' `
            -Status 'PASS' `
            -Severity 'High' `
            -Score 15 `
            -MaxScore 15 `
            -Evidence 'The SMB client requires security signatures.' `
            -Recommendation 'No action required.'
    }
    else {

        $Results += New-SMBResult `
            -Control 'SMB Client Signing Required' `
            -Status 'WARNING' `
            -Severity 'High' `
            -Score 5 `
            -MaxScore 15 `
            -Evidence 'The SMB client does not require security signatures.' `
            -Recommendation 'Consider requiring SMB client signing according to the security baseline of the environment.'
    }

    # ========================================================
    # 6. INSECURE GUEST LOGONS
    # 10 points
    # ========================================================

    if ($null -eq $ClientConfig) {

        $Results += New-SMBResult `
            -Control 'Insecure Guest Logons' `
            -Status 'ERROR' `
            -Severity 'Unknown' `
            -Score 0 `
            -MaxScore 0 `
            -Evidence 'SMB client guest configuration could not be queried.' `
            -Recommendation 'Review insecure guest logon settings manually.'
    }
    elseif (
        $ClientConfig.PSObject.Properties.Name -contains
        'EnableInsecureGuestLogons'
    ) {

        if ($ClientConfig.EnableInsecureGuestLogons -eq $false) {

            $Results += New-SMBResult `
                -Control 'Insecure Guest Logons' `
                -Status 'PASS' `
                -Severity 'High' `
                -Score 10 `
                -MaxScore 10 `
                -Evidence 'Insecure SMB guest logons are disabled.' `
                -Recommendation 'No action required.'
        }
        else {

            $Results += New-SMBResult `
                -Control 'Insecure Guest Logons' `
                -Status 'FAIL' `
                -Severity 'High' `
                -Score 0 `
                -MaxScore 10 `
                -Evidence 'Insecure SMB guest logons are enabled.' `
                -Recommendation 'Disable insecure SMB guest logons unless explicitly required.'
        }
    }
    else {

        $Results += New-SMBResult `
            -Control 'Insecure Guest Logons' `
            -Status 'INFO' `
            -Severity 'Info' `
            -Score 0 `
            -MaxScore 0 `
            -Evidence 'EnableInsecureGuestLogons property is not available on this system.' `
            -Recommendation 'Review SMB guest authentication policy manually if required.'
    }

    # ========================================================
    # 7. REJECT UNENCRYPTED SMB ACCESS
    # 10 points
    # ========================================================

    if (
        $ServerConfig.PSObject.Properties.Name -contains
        'RejectUnencryptedAccess'
    ) {

        if ($ServerConfig.RejectUnencryptedAccess -eq $true) {

            $Results += New-SMBResult `
                -Control 'Reject Unencrypted SMB Access' `
                -Status 'PASS' `
                -Severity 'Medium' `
                -Score 10 `
                -MaxScore 10 `
                -Evidence 'The SMB server is configured to reject unencrypted access when encryption is required.' `
                -Recommendation 'No action required.'
        }
        else {

            $Results += New-SMBResult `
                -Control 'Reject Unencrypted SMB Access' `
                -Status 'WARNING' `
                -Severity 'Medium' `
                -Score 5 `
                -MaxScore 10 `
                -Evidence 'RejectUnencryptedAccess is disabled.' `
                -Recommendation 'Review SMB encryption requirements for this system and environment.'
        }
    }
    else {

        $Results += New-SMBResult `
            -Control 'Reject Unencrypted SMB Access' `
            -Status 'INFO' `
            -Severity 'Info' `
            -Score 0 `
            -MaxScore 0 `
            -Evidence 'RejectUnencryptedAccess property is not available.' `
            -Recommendation 'Review SMB encryption policy manually if required.'
    }

    # ========================================================
    # SMB ENCRYPTION
    # Informational
    # ========================================================

    if (
        $ServerConfig.PSObject.Properties.Name -contains
        'EncryptData'
    ) {

        $EncryptionRequired = $ServerConfig.EncryptData

        $Results += New-SMBResult `
            -Control 'SMB Server Encryption' `
            -Status 'INFO' `
            -Severity 'Info' `
            -Score 0 `
            -MaxScore 0 `
            -Evidence "Global SMB encryption requirement: $EncryptionRequired" `
            -Recommendation 'Review whether mandatory SMB encryption is appropriate for the environment.'
    }

    # ========================================================
    # SMB SHARES
    # Informational
    # ========================================================

    try {

        $Shares = @(
            Get-SmbShare -ErrorAction Stop
        )

        $NonAdministrativeShares = @(
            $Shares |
                Where-Object {
                    $_.Special -eq $false
                }
        )

        if ($NonAdministrativeShares.Count -gt 0) {

            $ShareNames = @(
                $NonAdministrativeShares |
                    ForEach-Object {
                        $_.Name
                    }
            ) -join ', '

            $Results += New-SMBResult `
                -Control 'SMB Shares' `
                -Status 'INFO' `
                -Severity 'Info' `
                -Score 0 `
                -MaxScore 0 `
                -Evidence "Non-administrative SMB shares detected: $ShareNames" `
                -Recommendation 'Review SMB share permissions and confirm that each share is required.'
        }
        else {

            $Results += New-SMBResult `
                -Control 'SMB Shares' `
                -Status 'INFO' `
                -Severity 'Info' `
                -Score 0 `
                -MaxScore 0 `
                -Evidence 'No non-administrative SMB shares were detected.' `
                -Recommendation 'No action required.'
        }
    }
    catch {

        $Results += New-SMBResult `
            -Control 'SMB Shares' `
            -Status 'INFO' `
            -Severity 'Info' `
            -Score 0 `
            -MaxScore 0 `
            -Evidence "SMB shares could not be enumerated: $($_.Exception.Message)" `
            -Recommendation 'Review SMB shares manually if required.'
    }

    return $Results
}
