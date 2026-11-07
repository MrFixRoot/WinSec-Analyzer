function Get-WinSecWindowsDefenderEvidence {
    [CmdletBinding()]
    param([switch]$Deep)
    $data=[ordered]@{}
    $warnings=New-Object 'System.Collections.Generic.List[string]'
    try {
        $mp=Get-MpComputerStatus -ErrorAction Stop
        $data.computerStatus=Select-WinSecProperties $mp @('AMServiceEnabled','AntivirusEnabled','AntispywareEnabled','RealTimeProtectionEnabled','BehaviorMonitorEnabled','IoavProtectionEnabled','NISEnabled','OnAccessProtectionEnabled','AMRunningMode','AntivirusSignatureVersion','AntivirusSignatureLastUpdated','AntispywareSignatureVersion','NISSignatureVersion','QuickScanAge','FullScanAge','IsTamperProtected','DeviceControlState')
    } catch { $warnings.Add('Get-MpComputerStatus: '+$_.Exception.Message) }
    try {
        $pref=Get-MpPreference -ErrorAction Stop
        $data.preferences=Select-WinSecProperties $pref @('DisableRealtimeMonitoring','DisableBehaviorMonitoring','DisableIOAVProtection','DisableScriptScanning','DisableArchiveScanning','DisableEmailScanning','DisableRemovableDriveScanning','DisableScanningMappedNetworkDrivesForFullScan','DisableScanningNetworkFiles','MAPSReporting','SubmitSamplesConsent','PUAProtection','CloudBlockLevel','CloudExtendedTimeout','EnableControlledFolderAccess','ScanScheduleDay','ScanScheduleTime','SignatureUpdateInterval','SignatureFallbackOrder','HighThreatDefaultAction','ModerateThreatDefaultAction','LowThreatDefaultAction','SevereThreatDefaultAction','AttackSurfaceReductionRules_Ids','AttackSurfaceReductionRules_Actions','EnableNetworkProtection','DisableBlockAtFirstSeen')
        # ExclusionPath / ExclusionProcess se omiten por posibles nombres sensibles de usuario.
        $data.exclusionsCollected=$false
    } catch { $warnings.Add('Get-MpPreference: '+$_.Exception.Message) }
    $state=if ($data.Count -eq 0) { 'ERROR' } else { 'COMPLETED' }
    return (New-WinSecPayload -Data $data -Sources @('Get-MpComputerStatus','Get-MpPreference') -Warnings @($warnings.ToArray()) -Status $state)
}
