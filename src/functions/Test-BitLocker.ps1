function Test-BitLocker {
    [CmdletBinding()]
    param()

    $Results = @()

    function New-BitLockerResult {
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
            Category       = 'BitLocker'
            Status         = $Status
            Severity       = $Severity
            Score          = $Score
            MaxScore       = $MaxScore
            Evidence       = $Evidence
            Recommendation = $Recommendation
        }
    }

    # ========================================================
    # Verify BitLocker cmdlet
    # ========================================================

    if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) {

        $Results += New-BitLockerResult `
            -Control 'BitLocker Availability' `
            -Status 'ERROR' `
            -Severity 'Unknown' `
            -Score 0 `
            -MaxScore 0 `
            -Evidence 'Get-BitLockerVolume is not available on this system.' `
            -Recommendation 'Verify the Windows edition and BitLocker PowerShell module availability.'

        return $Results
    }

    # ========================================================
    # Collect OS volume
    # ========================================================

    try {

        $SystemDrive = $env:SystemDrive

        $Volume = Get-BitLockerVolume `
            -MountPoint $SystemDrive `
            -ErrorAction Stop
    }
    catch {

        $Results += New-BitLockerResult `
            -Control 'BitLocker OS Volume' `
            -Status 'ERROR' `
            -Severity 'Unknown' `
            -Score 0 `
            -MaxScore 100 `
            -Evidence $_.Exception.Message `
            -Recommendation 'Run WinSec Analyzer with sufficient privileges and verify BitLocker availability.'

        return $Results
    }

    # ========================================================
    # 1. PROTECTION STATUS
    # 30 points
    # ========================================================

    $ProtectionStatus = [string]$Volume.ProtectionStatus

    if ($ProtectionStatus -eq 'On') {

        $Results += New-BitLockerResult `
            -Control 'BitLocker Protection' `
            -Status 'PASS' `
            -Severity 'High' `
            -Score 30 `
            -MaxScore 30 `
            -Evidence "System drive $SystemDrive protection status: $ProtectionStatus" `
            -Recommendation 'No action required.'
    }
    else {

        $Results += New-BitLockerResult `
            -Control 'BitLocker Protection' `
            -Status 'FAIL' `
            -Severity 'High' `
            -Score 0 `
            -MaxScore 30 `
            -Evidence "System drive $SystemDrive protection status: $ProtectionStatus" `
            -Recommendation 'Enable BitLocker protection on the operating system volume.'
    }

    # ========================================================
    # 2. ENCRYPTION STATUS
    # 25 points
    # ========================================================

    $VolumeStatus = [string]$Volume.VolumeStatus
    $EncryptionPercentage = [int]$Volume.EncryptionPercentage

    if (
        $VolumeStatus -eq 'FullyEncrypted' -and
        $EncryptionPercentage -eq 100
    ) {

        $Results += New-BitLockerResult `
            -Control 'OS Volume Encryption' `
            -Status 'PASS' `
            -Severity 'High' `
            -Score 25 `
            -MaxScore 25 `
            -Evidence "Volume status: $VolumeStatus; Encryption: $EncryptionPercentage%" `
            -Recommendation 'No action required.'
    }
    elseif ($EncryptionPercentage -gt 0) {

        $Results += New-BitLockerResult `
            -Control 'OS Volume Encryption' `
            -Status 'WARNING' `
            -Severity 'High' `
            -Score 12 `
            -MaxScore 25 `
            -Evidence "Volume status: $VolumeStatus; Encryption: $EncryptionPercentage%" `
            -Recommendation 'Verify that BitLocker encryption completes successfully.'
    }
    else {

        $Results += New-BitLockerResult `
            -Control 'OS Volume Encryption' `
            -Status 'FAIL' `
            -Severity 'High' `
            -Score 0 `
            -MaxScore 25 `
            -Evidence "Volume status: $VolumeStatus; Encryption: $EncryptionPercentage%" `
            -Recommendation 'Encrypt the operating system volume using BitLocker.'
    }

    # ========================================================
    # 3. ENCRYPTION METHOD
    # 15 points
    # ========================================================

    $EncryptionMethod = [string]$Volume.EncryptionMethod

    switch ($EncryptionMethod) {

        'XtsAes256' {

            $Results += New-BitLockerResult `
                -Control 'Encryption Method' `
                -Status 'PASS' `
                -Severity 'Medium' `
                -Score 15 `
                -MaxScore 15 `
                -Evidence "Encryption method: $EncryptionMethod" `
                -Recommendation 'No action required.'
        }

        'XtsAes128' {

            $Results += New-BitLockerResult `
                -Control 'Encryption Method' `
                -Status 'PASS' `
                -Severity 'Medium' `
                -Score 15 `
                -MaxScore 15 `
                -Evidence "Encryption method: $EncryptionMethod" `
                -Recommendation 'No action required.'
        }

        'Aes256' {

            $Results += New-BitLockerResult `
                -Control 'Encryption Method' `
                -Status 'WARNING' `
                -Severity 'Low' `
                -Score 10 `
                -MaxScore 15 `
                -Evidence "Encryption method: $EncryptionMethod" `
                -Recommendation 'The volume is encrypted. Consider XTS-AES for modern Windows deployments when appropriate.'
        }

        'Aes128' {

            $Results += New-BitLockerResult `
                -Control 'Encryption Method' `
                -Status 'WARNING' `
                -Severity 'Low' `
                -Score 10 `
                -MaxScore 15 `
                -Evidence "Encryption method: $EncryptionMethod" `
                -Recommendation 'The volume is encrypted. Consider XTS-AES for modern Windows deployments when appropriate.'
        }

        'None' {

            $Results += New-BitLockerResult `
                -Control 'Encryption Method' `
                -Status 'FAIL' `
                -Severity 'High' `
                -Score 0 `
                -MaxScore 15 `
                -Evidence 'No BitLocker encryption method is configured.' `
                -Recommendation 'Enable BitLocker encryption on the operating system volume.'
        }

        default {

            $Results += New-BitLockerResult `
                -Control 'Encryption Method' `
                -Status 'WARNING' `
                -Severity 'Medium' `
                -Score 8 `
                -MaxScore 15 `
                -Evidence "Encryption method: $EncryptionMethod" `
                -Recommendation 'Review the BitLocker encryption algorithm used by this system.'
        }
    }

    # ========================================================
    # 4. KEY PROTECTORS
    # 15 points
    # ========================================================

    $KeyProtectorTypes = @(
        $Volume.KeyProtector |
            ForEach-Object {
                [string]$_.KeyProtectorType
            }
    )

    if ($KeyProtectorTypes.Count -gt 0) {

        $KeyProtectorEvidence = $KeyProtectorTypes -join ', '

        $Results += New-BitLockerResult `
            -Control 'BitLocker Key Protectors' `
            -Status 'PASS' `
            -Severity 'High' `
            -Score 15 `
            -MaxScore 15 `
            -Evidence "Configured key protectors: $KeyProtectorEvidence" `
            -Recommendation 'No action required.'
    }
    else {

        $Results += New-BitLockerResult `
            -Control 'BitLocker Key Protectors' `
            -Status 'FAIL' `
            -Severity 'High' `
            -Score 0 `
            -MaxScore 15 `
            -Evidence 'No BitLocker key protectors were detected.' `
            -Recommendation 'Configure an appropriate BitLocker key protector.'
    }

    # ========================================================
    # 5. RECOVERY PROTECTOR
    # 5 points
    # ========================================================

    $HasRecoveryProtector = $false

    foreach ($ProtectorType in $KeyProtectorTypes) {

        if ($ProtectorType -eq 'RecoveryPassword') {
            $HasRecoveryProtector = $true
        }
    }

    if ($HasRecoveryProtector) {

        $Results += New-BitLockerResult `
            -Control 'BitLocker OS Volume' `
            -Status 'ERROR' `
            -Severity 'Unknown' `
            -Score 0 `
            -MaxScore 0 `
            -Evidence $_.Exception.Message `
            -Recommendation 'Run WinSec Analyzer with sufficient privileges and verify BitLocker availability.'
    }
    else {

        $Results += New-BitLockerResult `
            -Control 'BitLocker Recovery Protector' `
            -Status 'WARNING' `
            -Severity 'Medium' `
            -Score 0 `
            -MaxScore 5 `
            -Evidence 'No RecoveryPassword protector was detected.' `
            -Recommendation 'Review the BitLocker recovery strategy and ensure an approved recovery mechanism exists.'
    }

    # ========================================================
    # 6. TPM STATUS
    # 10 points
    # ========================================================

    try {

        if (Get-Command Get-Tpm -ErrorAction SilentlyContinue) {

            $Tpm = Get-Tpm -ErrorAction Stop

            if (
                $Tpm.TpmPresent -eq $true -and
                $Tpm.TpmReady -eq $true
            ) {

                $Results += New-BitLockerResult `
                    -Control 'Trusted Platform Module' `
                    -Status 'PASS' `
                    -Severity 'Medium' `
                    -Score 10 `
                    -MaxScore 10 `
                    -Evidence "TPM Present: $($Tpm.TpmPresent); TPM Ready: $($Tpm.TpmReady)" `
                    -Recommendation 'No action required.'
            }
            elseif ($Tpm.TpmPresent -eq $true) {

                $Results += New-BitLockerResult `
                    -Control 'Trusted Platform Module' `
                    -Status 'WARNING' `
                    -Severity 'Medium' `
                    -Score 5 `
                    -MaxScore 10 `
                    -Evidence "TPM Present: $($Tpm.TpmPresent); TPM Ready: $($Tpm.TpmReady)" `
                    -Recommendation 'Review TPM provisioning and readiness.'
            }
            else {

                $Results += New-BitLockerResult `
                    -Control 'Trusted Platform Module' `
                    -Status 'WARNING' `
                    -Severity 'Medium' `
                    -Score 0 `
                    -MaxScore 10 `
                    -Evidence 'A TPM was not detected.' `
                    -Recommendation 'Review whether TPM-backed BitLocker protection is required for this system.'
            }
        }
        else {

            $Results += New-BitLockerResult `
                -Control 'Trusted Platform Module' `
                -Status 'INFO' `
                -Severity 'Info' `
                -Score 0 `
                -MaxScore 0 `
                -Evidence 'Get-Tpm is not available in the current PowerShell environment.' `
                -Recommendation 'Review TPM status manually if required.'
        }
    }
    catch {

        $Results += New-BitLockerResult `
            -Control 'Trusted Platform Module' `
            -Status 'INFO' `
            -Severity 'Info' `
            -Score 0 `
            -MaxScore 0 `
            -Evidence $_.Exception.Message `
            -Recommendation 'TPM status could not be determined automatically.'
    }

    # ========================================================
    # ADDITIONAL FIXED VOLUMES
    # Informational only
    # ========================================================

    try {

        $OtherVolumes = @(
            Get-BitLockerVolume -ErrorAction Stop |
                Where-Object {
                    $_.MountPoint -ne $SystemDrive
                }
        )

        foreach ($OtherVolume in $OtherVolumes) {

            $OtherMountPoint = [string]$OtherVolume.MountPoint
            $OtherStatus = [string]$OtherVolume.VolumeStatus
            $OtherProtection = [string]$OtherVolume.ProtectionStatus
            $OtherMethod = [string]$OtherVolume.EncryptionMethod
            $OtherPercentage = [int]$OtherVolume.EncryptionPercentage

            $Results += New-BitLockerResult `
                -Control "Additional Volume $OtherMountPoint" `
                -Status 'INFO' `
                -Severity 'Info' `
                -Score 0 `
                -MaxScore 0 `
                -Evidence "Status=$OtherStatus; Protection=$OtherProtection; Encryption=$OtherPercentage%; Method=$OtherMethod" `
                -Recommendation 'Review additional volumes according to organizational encryption requirements.'
        }
    }
    catch {
        # Additional volume enumeration is informational only.
    }

    return $Results
}