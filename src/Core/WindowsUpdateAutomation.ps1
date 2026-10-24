# Pure automation interpretation. No source is upgraded by a caller's flag.
. (Join-Path $PSScriptRoot 'WindowsUpdateServicing.ps1')

function Get-WinSecWindowsUpdateAutomationReview {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Catalog,[Parameter(Mandatory)][object]$ControlResult)
    $result=[pscustomobject]@{State='UNKNOWN';Reason='PLATFORM_OR_SERVICE_UNVERIFIED'}
    $platform=ConvertTo-WinSecWindowsUpdateServicingPlatform $Catalog $ControlResult
    if($platform.State -cne 'OBSERVED'){return $result}
    $evidence=Get-WinSecWindowsUpdateReferenceValue $ControlResult 'Evidence'
    $service=Get-WinSecWindowsUpdateReferenceValue $evidence 'UpdateService'
    try {Assert-WinSecWindowsUpdateReferenceFields $service @('Name','State','StartMode','Source')} catch {return $result}
    if($service.Name -isnot [string] -or $service.Name -cne 'wuauserv' -or $service.Source -isnot [string] -or
        $service.Source -cne 'CIM:Win32_Service' -or $service.StartMode -isnot [string]){return $result}
    # A verified disabled service is sufficient to disprove availability, even
    # if a separate policy source is unavailable. Stopped/Manual alone is not.
    if($service.StartMode -ceq 'DISABLED') {
        $result.State='NOT_AUTOMATIC';$result.Reason='UPDATE_SERVICE_DISABLED';return $result
    }
    if($service.StartMode -cnotin @('MANUAL','AUTO')){return $result}
    $result.Reason='POLICY_SOURCES_UNVERIFIED'
    if((Get-WinSecWindowsUpdateReferenceValue $evidence 'SchemaVersion') -cne '1.2.0'){return $result}
    # Policy CSP lists managed editions. Unsupported provider != control N/A.
    if($platform.OperatingSystemSKU -in @(98,99,100,101)) {
        $result.Reason='POLICY_PROVIDER_EDITION_UNVERIFIED';return $result
    }
    $registry=Get-WinSecWindowsUpdateReferenceValue $evidence 'PolicyRegistry'
    $gp=Get-WinSecWindowsUpdateReferenceValue $registry 'AutomaticUpdates'
    $update=Get-WinSecWindowsUpdateReferenceValue $registry 'WindowsUpdate'
    $named=Get-WinSecWindowsUpdateReferenceValue $evidence 'AutomationPolicy'
    try {
        Assert-WinSecWindowsUpdateReferenceFields $gp @('Source','ReadState','NoAutoUpdate','AUOptions','UseWUServer')
        Assert-WinSecWindowsUpdateReferenceFields $update @('Source','ReadState','DeferQualityUpdates','DeferQualityUpdatesPeriodInDays',
            'SetDisableUXWUAccess','DoNotConnectToWindowsUpdateInternetLocations','SetPolicyDrivenUpdateSourceForQualityUpdates',
            'ConfigureDeadlineForQualityUpdates','ConfigureDeadlineForFeatureUpdates',
            'SetComplianceDeadline','SetComplianceDeadlineForQU','SetComplianceDeadlineForFU','SetEDURestart')
        Assert-WinSecWindowsUpdateReferenceFields $named @('AllowAutoUpdate','ConfigureDeadlineForQualityUpdates','ConfigureDeadlineForFeatureUpdates',
            'IgnoreWindowsUpdateGroupPolicies','SetEDURestart')
    } catch {return $result}
    if($gp.Source -isnot [string] -or $gp.Source -cne 'REGISTRY64:HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -or
        $update.Source -isnot [string] -or $update.Source -cne 'REGISTRY64:HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate') {return $result}
    foreach($area in @($gp,$update)) {
        if($area.ReadState -isnot [string] -or $area.ReadState -cnotin @('READ','NOT_CONFIGURED')){return $result}
        $fields=if($area -eq $gp){@('NoAutoUpdate','AUOptions')}else{@('ConfigureDeadlineForQualityUpdates','ConfigureDeadlineForFeatureUpdates',
            'SetComplianceDeadline','SetComplianceDeadlineForQU','SetComplianceDeadlineForFU','SetEDURestart')}
        foreach($field in $fields) {
            $value=$area.$field
            try {Assert-WinSecWindowsUpdateReferenceFields $value @('State','Value')} catch {return $result}
            if($value.State -isnot [string]){return $result}
            if($value.State -ceq 'NOT_CONFIGURED') {if($null -ne $value.Value){return $result}}
            elseif($value.State -ceq 'CONFIGURED' -and $area.ReadState -ceq 'READ') {
                if(-not (Test-WinSecWindowsUpdateReferenceInteger $value.Value)){return $result}
            } else {return $result}
        }
    }
    foreach($field in @('SetComplianceDeadline','SetComplianceDeadlineForQU','SetComplianceDeadlineForFU')) {
        if($update.$field.State -ceq 'CONFIGURED'){$result.Reason='DEADLINE_POLICY_REQUIRES_REVIEW';return $result}
    }
    if($update.SetEDURestart.State -ceq 'CONFIGURED'){$result.Reason='OVERRIDE_POLICY_REQUIRES_REVIEW';return $result}
    foreach($name in @('AllowAutoUpdate','ConfigureDeadlineForQualityUpdates','ConfigureDeadlineForFeatureUpdates',
        'IgnoreWindowsUpdateGroupPolicies','SetEDURestart')) {
        $policy=$named.$name
        try {Assert-WinSecWindowsUpdateReferenceFields $policy @('Source','Area','Name','State','Kind','Managed','Value')} catch {return $result}
        if($policy.Source -isnot [string] -or $policy.Source -cne 'WINRT:NamedPolicy' -or $policy.Area -isnot [string] -or $policy.Area -cne 'Update' -or
            $policy.Name -isnot [string] -or $policy.Name -cne $name -or $policy.State -isnot [string] -or $policy.State -cne 'OBSERVED' -or
            $policy.Kind -isnot [string] -or $policy.Kind -cnotin @('Invalid','Binary','Boolean','Int32','Int64','String') -or
            $policy.Managed -isnot [bool] -or ($policy.Kind -ceq 'Int32' -and $policy.Value -isnot [int]) -or
            ($policy.Kind -cne 'Int32' -and $null -ne $policy.Value)){return $result}
        if($name -cin @('ConfigureDeadlineForQualityUpdates','ConfigureDeadlineForFeatureUpdates') -and
            ($policy.Managed -or $update.$name.State -ceq 'CONFIGURED')) {
            $result.Reason='DEADLINE_POLICY_REQUIRES_REVIEW';return $result
        }
        if($name -cin @('IgnoreWindowsUpdateGroupPolicies','SetEDURestart') -and
            ($policy.Managed -or $policy.Kind -cne 'Int32' -or $policy.Value -ne 0)) {
            $result.Reason='OVERRIDE_POLICY_REQUIRES_REVIEW';return $result
        }
    }
    $auto=$named.AllowAutoUpdate
    if($auto.Kind -cne 'Int32' -or $auto.Value -lt 0 -or $auto.Value -gt 5){return $result}
    $gpMode=$null
    if($gp.NoAutoUpdate.State -ceq 'CONFIGURED' -and $gp.NoAutoUpdate.Value -eq 1) {$gpMode=$false}
    elseif($gp.NoAutoUpdate.State -ceq 'CONFIGURED' -and $gp.NoAutoUpdate.Value -eq 0 -and $gp.AUOptions.State -ceq 'CONFIGURED') {
        if($gp.AUOptions.Value -eq 4){$gpMode=$true}
        elseif($gp.AUOptions.Value -in @(2,3)){$gpMode=$false}
        else {$result.Reason='GROUP_POLICY_MODE_UNREVIEWED';return $result}
    } elseif($gp.NoAutoUpdate.State -cne 'NOT_CONFIGURED' -or $gp.AUOptions.State -cne 'NOT_CONFIGURED') {
        $result.Reason='GROUP_POLICY_MODE_UNRESOLVED';return $result
    }
    $enabled=$null
    if($auto.Managed) {
        $mdmMode=($auto.Value -in @(1,2,3,4))
        if($null -ne $gpMode -and $gpMode -ne $mdmMode) {$result.Reason='GROUP_POLICY_MDM_CONFLICT';return $result}
        $enabled=$mdmMode;$result.Reason='MANAGED_POLICY_RESOLVED'
    } elseif($null -ne $gpMode) {
        $enabled=$gpMode;$result.Reason='GROUP_POLICY_RESOLVED'
    } elseif($auto.Value -eq 2) {
        # The CSP's documented default is used only after successful reads prove
        # no active MDM policy, no GPO value and no managed deadline override.
        $enabled=$true;$result.Reason='OBSERVED_UNMANAGED_DEFAULT'
    } else {$result.Reason='UNMANAGED_DEFAULT_UNRESOLVED';return $result}
    $result.State=if($enabled){'AUTOMATIC'}else{'NOT_AUTOMATIC'}
    return $result
}
