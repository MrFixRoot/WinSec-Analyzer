# Pure automation interpretation. No source is upgraded by a caller's flag.
. (Join-Path $PSScriptRoot 'WindowsUpdateServicing.ps1')
. (Join-Path $PSScriptRoot 'WindowsUpdatePolicyApplicability.ps1')

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
    $schema=Get-WinSecWindowsUpdateReferenceValue $evidence 'SchemaVersion'
    if($schema -cnotin @('1.2.0','1.3.0')){return $result}
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
    foreach($name in @('AllowAutoUpdate','ConfigureDeadlineForQualityUpdates','ConfigureDeadlineForFeatureUpdates',
        'IgnoreWindowsUpdateGroupPolicies','SetEDURestart')) {
        $policy=$named.$name
        try {Assert-WinSecWindowsUpdateReferenceFields $policy @('Source','Area','Name','State','Kind','Managed','Value')} catch {return $result}
        if($name -ceq 'IgnoreWindowsUpdateGroupPolicies' -and $schema -ceq '1.3.0' -and
            (Test-WinSecWindowsUpdateLegacyPolicyPlatform $platform)) {
            foreach($field in @('Source','Area','Name','State','Kind')) {
                if($policy.$field -isnot [string]){return $result}
            }
            if($policy.Source -cne 'WINRT:NamedPolicy' -or $policy.Area -cne 'Update' -or $policy.Name -cne $name -or
                $policy.State -cne 'NOT_APPLICABLE' -or $policy.Kind -cne 'UNKNOWN' -or
                $null -ne $policy.Managed -or $null -ne $policy.Value){return $result}
            continue
        }
        if($policy.Source -isnot [string] -or $policy.Source -cne 'WINRT:NamedPolicy' -or $policy.Area -isnot [string] -or $policy.Area -cne 'Update' -or
            $policy.Name -isnot [string] -or $policy.Name -cne $name -or $policy.State -isnot [string] -or $policy.State -cne 'OBSERVED' -or
            $policy.Kind -isnot [string] -or $policy.Kind -cnotin @('Invalid','Binary','Boolean','Int32','Int64','String') -or
            $policy.Managed -isnot [bool] -or ($policy.Kind -ceq 'Int32' -and $policy.Value -isnot [int]) -or
            ($policy.Kind -cne 'Int32' -and $null -ne $policy.Value)){return $result}
        if($name -cin @('ConfigureDeadlineForQualityUpdates','ConfigureDeadlineForFeatureUpdates') -and
            ($policy.Kind -cne 'Int32' -or $policy.Value -lt 0 -or $policy.Value -gt 30)) {
            $result.Reason='DEADLINE_POLICY_INVALID';return $result
        }
        if($name -cin @('IgnoreWindowsUpdateGroupPolicies','SetEDURestart') -and
            ($policy.Kind -cne 'Int32' -or $policy.Value -notin @(0,1) -or
             (-not $policy.Managed -and $policy.Value -ne 0))) {
            $result.Reason='OVERRIDE_POLICY_REQUIRES_REVIEW';return $result
        }
    }
    $ignoreGp=($named.IgnoreWindowsUpdateGroupPolicies.State -ceq 'OBSERVED' -and
        $named.IgnoreWindowsUpdateGroupPolicies.Managed -and $named.IgnoreWindowsUpdateGroupPolicies.Value -eq 1)
    if($ignoreGp -and ($platform.BuildNumber -cnotin @('26100','26200') -or
        $platform.RevisionState -cne 'OBSERVED' -or $platform.Revision -lt 8973)) {
        # KB5101684 documents these exact two branches. Do not transpose UBR
        # thresholds to 26H1/26H2 or infer support from an MDM declaration.
        $result.Reason='GROUP_POLICY_OVERRIDE_PLATFORM_UNVERIFIED';return $result
    }
    if($named.SetEDURestart.Value -ne 0 -or (-not $ignoreGp -and
        $update.SetEDURestart.State -ceq 'CONFIGURED' -and $update.SetEDURestart.Value -ne 0)) {
        $result.Reason='OVERRIDE_POLICY_REQUIRES_REVIEW';return $result
    }
    if(-not $ignoreGp) {
        # Legacy combined policy is not mapped by the reviewed current ADMX.
        if($update.SetComplianceDeadline.State -ceq 'CONFIGURED') {
            $result.Reason='DEADLINE_POLICY_REQUIRES_REVIEW';return $result
        }
        $allDisabled=$true
        foreach($field in @('SetComplianceDeadlineForQU','SetComplianceDeadlineForFU')) {
            if($update.$field.State -ceq 'CONFIGURED' -and $update.$field.Value -ne 0) {
                $result.Reason='DEADLINE_POLICY_REQUIRES_REVIEW';return $result
            }
            if($update.$field.State -cne 'CONFIGURED'){$allDisabled=$false}
        }
        foreach($field in @('ConfigureDeadlineForQualityUpdates','ConfigureDeadlineForFeatureUpdates')) {
            if($update.$field.State -ceq 'CONFIGURED' -and (-not $allDisabled -or $update.$field.Value -gt 30)) {
                # A detached registry value is not proof of an active deadline.
                # Only explicit disabled parent policies resolve stale values.
                $result.Reason='DEADLINE_POLICY_REQUIRES_REVIEW';return $result
            }
        }
    }
    $auto=$named.AllowAutoUpdate
    if($auto.Kind -cne 'Int32' -or $auto.Value -lt 0 -or $auto.Value -gt 5){return $result}
    $qualityDeadline=$named.ConfigureDeadlineForQualityUpdates.Managed
    $featureDeadline=$named.ConfigureDeadlineForFeatureUpdates.Managed
    $gpMode=$null
    if($ignoreGp) {
        if(-not $auto.Managed -and -not ($qualityDeadline -and $featureDeadline)) {
            $result.Reason='MDM_EQUIVALENT_POLICY_UNVERIFIED';return $result
        }
    }
    elseif($gp.NoAutoUpdate.State -ceq 'CONFIGURED' -and $gp.NoAutoUpdate.Value -eq 1) {$gpMode=$false}
    elseif($gp.NoAutoUpdate.State -ceq 'CONFIGURED' -and $gp.NoAutoUpdate.Value -eq 0 -and $gp.AUOptions.State -ceq 'CONFIGURED') {
        if($gp.AUOptions.Value -eq 4){$gpMode=$true}
        elseif($gp.AUOptions.Value -in @(2,3)){$gpMode=$false}
        else {$result.Reason='GROUP_POLICY_MODE_UNREVIEWED';return $result}
    } elseif($gp.NoAutoUpdate.State -cne 'NOT_CONFIGURED' -or $gp.AUOptions.State -cne 'NOT_CONFIGURED') {
        $result.Reason='GROUP_POLICY_MODE_UNRESOLVED';return $result
    }
    $enabled=$null
    if($qualityDeadline -or $featureDeadline) {
        $bothDeadlines=($qualityDeadline -and $featureDeadline)
        $baseMode=if($auto.Managed){$auto.Value -in @(1,2,3,4)}
            elseif($null -ne $gpMode){$gpMode}
            elseif($auto.Value -eq 2){$true}else{$null}
        if(-not $bothDeadlines -and ($null -eq $baseMode -or -not $baseMode)) {
            $result.Reason='PARTIAL_DEADLINE_COVERAGE';return $result
        }
        if($null -ne $gpMode -and -not $gpMode) {$result.Reason='GROUP_POLICY_MDM_CONFLICT';return $result}
        # Deadlines guarantee configured automation for their own update type,
        # including day zero. They do not prove patch installation or a 7-day SLA.
        $enabled=$true;$result.Reason='MANAGED_DEADLINES_RESOLVED'
    }
    elseif($auto.Managed) {
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
