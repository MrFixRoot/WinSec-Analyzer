function Test-WindowsDefender {
    [CmdletBinding()]
    param()

    $Results = @()

    # --------------------------------------------------------
    # Helper
    # --------------------------------------------------------

    function New-DefenderResult {
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
            Category       = 'Windows Defender'
            Status         = $Status
            Severity       = $Severity
            Score          = $Score
            MaxScore       = $MaxScore
            Evidence       = $Evidence
            Recommendation = $Recommendation
        }
    }

    # --------------------------------------------------------
    # Collect Defender information
    # --------------------------------------------------------

    try {
        $DefenderStatus = Get-MpComputerStatus -ErrorAction Stop
        $DefenderPreference = Get-MpPreference -ErrorAction Stop
    }
    catch {

        $Results += New-DefenderResult `
            -Control 'Microsoft Defender' `
            -Status 'ERROR' `
            -Severity 'Unknown' `
            -Score 0 `
            -MaxScore 100 `
            -Evidence $_.Exception.Message `
            -Recommendation 'Verify that Microsoft Defender Antivirus is installed and accessible.'

        return $Results
    }

    # ========================================================
    # 1. DEFENDER SERVICE
    # 10 points
    # ========================================================

    try {

        $DefenderService = Get-Service `
            -Name 'WinDefend' `
            -ErrorAction Stop

        if ($DefenderService.Status -eq 'Running') {

            $Results += New-DefenderResult `
                -Control 'Defender Antivirus Service' `
                -Status 'PASS' `
                -Severity 'High' `
                -Score 10 `
                -MaxScore 10 `
                -Evidence "WinDefend status: $($DefenderService.Status)" `
                -Recommendation 'No action required.'
        }
        else {

            $Results += New-DefenderResult `
                -Control 'Defender Antivirus Service' `
                -Status 'FAIL' `
                -Severity 'High' `
                -Score 0 `
                -MaxScore 10 `
                -Evidence "WinDefend status: $($DefenderService.Status)" `
                -Recommendation 'Ensure the Microsoft Defender Antivirus service is running.'
        }
    }
    catch {

        $Results += New-DefenderResult `
            -Control 'Defender Antivirus Service' `
            -Status 'ERROR' `
            -Severity 'Unknown' `
            -Score 0 `
            -MaxScore 10 `
            -Evidence $_.Exception.Message `
            -Recommendation 'Verify the WinDefend service manually.'
    }

    # ========================================================
    # 2. ANTIVIRUS ENABLED
    # 10 points
    # ========================================================

    if ($DefenderStatus.AntivirusEnabled -eq $true) {

        $Results += New-DefenderResult `
            -Control 'Defender Antivirus Enabled' `
            -Status 'PASS' `
            -Severity 'High' `
            -Score 10 `
            -MaxScore 10 `
            -Evidence 'Microsoft Defender Antivirus is enabled.' `
            -Recommendation 'No action required.'
    }
    else {

        $Results += New-DefenderResult `
            -Control 'Defender Antivirus Enabled' `
            -Status 'FAIL' `
            -Severity 'High' `
            -Score 0 `
            -MaxScore 10 `
            -Evidence 'Microsoft Defender Antivirus is not enabled.' `
            -Recommendation 'Enable Microsoft Defender Antivirus or verify that another approved antivirus product is protecting the system.'
    }

    # ========================================================
    # 3. REAL-TIME PROTECTION
    # 15 points
    # ========================================================

    if ($DefenderStatus.RealTimeProtectionEnabled -eq $true) {

        $Results += New-DefenderResult `
            -Control 'Real-Time Protection' `
            -Status 'PASS' `
            -Severity 'High' `
            -Score 15 `
            -MaxScore 15 `
            -Evidence 'Real-time protection is enabled.' `
            -Recommendation 'No action required.'
    }
    else {

        $Results += New-DefenderResult `
            -Control 'Real-Time Protection' `
            -Status 'FAIL' `
            -Severity 'High' `
            -Score 0 `
            -MaxScore 15 `
            -Evidence 'Real-time protection is disabled.' `
            -Recommendation 'Enable Microsoft Defender real-time protection.'
    }

    # ========================================================
    # 4. BEHAVIOR MONITORING
    # 10 points
    # ========================================================

    if ($DefenderStatus.BehaviorMonitorEnabled -eq $true) {

        $Results += New-DefenderResult `
            -Control 'Behavior Monitoring' `
            -Status 'PASS' `
            -Severity 'High' `
            -Score 10 `
            -MaxScore 10 `
            -Evidence 'Behavior monitoring is enabled.' `
            -Recommendation 'No action required.'
    }
    else {

        $Results += New-DefenderResult `
            -Control 'Behavior Monitoring' `
            -Status 'FAIL' `
            -Severity 'High' `
            -Score 0 `
            -MaxScore 10 `
            -Evidence 'Behavior monitoring is disabled.' `
            -Recommendation 'Enable Microsoft Defender behavior monitoring.'
    }

    # ========================================================
    # 5. IOAV PROTECTION
    # 5 points
    # ========================================================

    if ($DefenderStatus.IoavProtectionEnabled -eq $true) {

        $Results += New-DefenderResult `
            -Control 'Downloaded File Protection' `
            -Status 'PASS' `
            -Severity 'Medium' `
            -Score 5 `
            -MaxScore 5 `
            -Evidence 'IOAV protection is enabled.' `
            -Recommendation 'No action required.'
    }
    else {

        $Results += New-DefenderResult `
            -Control 'Downloaded File Protection' `
            -Status 'WARNING' `
            -Severity 'Medium' `
            -Score 0 `
            -MaxScore 5 `
            -Evidence 'IOAV protection is disabled.' `
            -Recommendation 'Enable scanning of downloaded files and attachments.'
    }

    # ========================================================
    # 6. NETWORK INSPECTION SYSTEM
    # 10 points
    # ========================================================

    if ($DefenderStatus.NISEnabled -eq $true) {

        $Results += New-DefenderResult `
            -Control 'Network Inspection System' `
            -Status 'PASS' `
            -Severity 'High' `
            -Score 10 `
            -MaxScore 10 `
            -Evidence 'Microsoft Defender Network Inspection System is enabled.' `
            -Recommendation 'No action required.'
    }
    else {

        $Results += New-DefenderResult `
            -Control 'Network Inspection System' `
            -Status 'WARNING' `
            -Severity 'High' `
            -Score 0 `
            -MaxScore 10 `
            -Evidence 'Microsoft Defender Network Inspection System is not enabled.' `
            -Recommendation 'Review Microsoft Defender network protection configuration.'
    }

    # ========================================================
    # 7. CLOUD-DELIVERED PROTECTION
    # 10 points
    # ========================================================

    $MAPSReporting = [int]$DefenderPreference.MAPSReporting

    if ($MAPSReporting -gt 0) {

        $Results += New-DefenderResult `
            -Control 'Cloud-Delivered Protection' `
            -Status 'PASS' `
            -Severity 'Medium' `
            -Score 10 `
            -MaxScore 10 `
            -Evidence "MAPSReporting value: $MAPSReporting" `
            -Recommendation 'No action required.'
    }
    else {

        $Results += New-DefenderResult `
            -Control 'Cloud-Delivered Protection' `
            -Status 'WARNING' `
            -Severity 'Medium' `
            -Score 0 `
            -MaxScore 10 `
            -Evidence "MAPSReporting value: $MAPSReporting" `
            -Recommendation 'Consider enabling Microsoft Defender cloud-delivered protection.'
    }

    # ========================================================
    # 8. PUA PROTECTION
    # 10 points
    # ========================================================

    $PUAProtection = [int]$DefenderPreference.PUAProtection

    switch ($PUAProtection) {

        1 {

            $Results += New-DefenderResult `
                -Control 'Potentially Unwanted Application Protection' `
                -Status 'PASS' `
                -Severity 'Medium' `
                -Score 10 `
                -MaxScore 10 `
                -Evidence 'PUA protection is enabled.' `
                -Recommendation 'No action required.'
        }

        2 {

            $Results += New-DefenderResult `
                -Control 'Potentially Unwanted Application Protection' `
                -Status 'WARNING' `
                -Severity 'Medium' `
                -Score 5 `
                -MaxScore 10 `
                -Evidence 'PUA protection is configured in audit mode.' `
                -Recommendation 'Consider changing PUA protection from Audit mode to Enabled.'
        }

        default {

            $Results += New-DefenderResult `
                -Control 'Potentially Unwanted Application Protection' `
                -Status 'WARNING' `
                -Severity 'Medium' `
                -Score 0 `
                -MaxScore 10 `
                -Evidence "PUAProtection value: $PUAProtection" `
                -Recommendation 'Enable Microsoft Defender potentially unwanted application protection.'
        }
    }

    # ========================================================
    # 9. ANTIVIRUS SIGNATURES
    # 10 points
    # ========================================================

    $SignatureAge = [int]$DefenderStatus.AntivirusSignatureAge
    $SignatureDate = $DefenderStatus.AntivirusSignatureLastUpdated

    if ($SignatureAge -le 1) {

        $Results += New-DefenderResult `
            -Control 'Defender Security Intelligence' `
            -Status 'PASS' `
            -Severity 'High' `
            -Score 10 `
            -MaxScore 10 `
            -Evidence "Signature age: $SignatureAge day(s); Last updated: $SignatureDate" `
            -Recommendation 'No action required.'
    }
    elseif ($SignatureAge -le 3) {

        $Results += New-DefenderResult `
            -Control 'Defender Security Intelligence' `
            -Status 'WARNING' `
            -Severity 'Medium' `
            -Score 5 `
            -MaxScore 10 `
            -Evidence "Signature age: $SignatureAge day(s); Last updated: $SignatureDate" `
            -Recommendation 'Update Microsoft Defender security intelligence.'
    }
    else {

        $Results += New-DefenderResult `
            -Control 'Defender Security Intelligence' `
            -Status 'FAIL' `
            -Severity 'High' `
            -Score 0 `
            -MaxScore 10 `
            -Evidence "Signature age: $SignatureAge day(s); Last updated: $SignatureDate" `
            -Recommendation 'Update Microsoft Defender security intelligence immediately.'
    }

    # ========================================================
    # 10. TAMPER PROTECTION
    # 10 points
    # ========================================================

    if (
        $DefenderStatus.PSObject.Properties.Name -contains
        'IsTamperProtected'
    ) {

        if ($DefenderStatus.IsTamperProtected -eq $true) {

            $Results += New-DefenderResult `
                -Control 'Tamper Protection' `
                -Status 'PASS' `
                -Severity 'High' `
                -Score 10 `
                -MaxScore 10 `
                -Evidence 'Microsoft Defender Tamper Protection is enabled.' `
                -Recommendation 'No action required.'
        }
        else {

            $Results += New-DefenderResult `
                -Control 'Tamper Protection' `
                -Status 'WARNING' `
                -Severity 'High' `
                -Score 0 `
                -MaxScore 10 `
                -Evidence 'Microsoft Defender Tamper Protection is not enabled.' `
                -Recommendation 'Enable Tamper Protection when supported by the environment.'
        }
    }
    else {

        $Results += New-DefenderResult `
            -Control 'Tamper Protection' `
            -Status 'INFO' `
            -Severity 'Info' `
            -Score 0 `
            -MaxScore 0 `
            -Evidence 'Tamper Protection status could not be determined through Get-MpComputerStatus.' `
            -Recommendation 'Review Tamper Protection manually if required.'
    }

    # ========================================================
    # ADDITIONAL INFORMATION
    # No score
    # ========================================================

    $RunningMode = [string]$DefenderStatus.AMRunningMode

    $Results += New-DefenderResult `
        -Control 'Defender Operating Mode' `
        -Status 'INFO' `
        -Severity 'Info' `
        -Score 0 `
        -MaxScore 0 `
        -Evidence "AMRunningMode: $RunningMode" `
        -Recommendation 'Review this value if Microsoft Defender is expected to operate as the primary antivirus.'

    return $Results
}