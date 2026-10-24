# No native policy queries: providers are simulated. C# is compiled only.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Checks/System/WindowsUpdatePolicyReader.ps1')
. (Join-Path $root 'src/Checks/System/Test-WindowsUpdate.ps1')
. (Join-Path $root 'src/Services/WindowsUpdateReferenceService.ps1')
. (Join-Path $root 'src/Core/WindowsUpdateAutomation.ps1')
. (Join-Path $root 'tests/Fixtures/WindowsUpdateMemory.ps1')
$catalog=(Get-WinSecWindowsUpdateReferenceCatalog $root).Catalog
$script:passed=0;$script:failed=0
function Assert-WinSecWUAutomation {param([bool]$Value);if(-not $Value){throw 'Windows Update automation assertion failed.'}}
function Assert-WinSecWUAutomationThrows {
    param([scriptblock]$Action)
    $message=$null;try{$null=& $Action}catch{$message=$_.Exception.Message}
    Assert-WinSecWUAutomation (-not [string]::IsNullOrEmpty($message) -and $message -notmatch 'PRIVATE-WU')
}
function New-WinSecWUAutomationControl {Test-WinSecWindowsUpdate -DeviceId $script:WU.DeviceId -ScanId 'wu-auto-unit-1' -CheckId WSA-SYS-003}
function Test-WinSecWUAutomation {
    param([string]$Name,[scriptblock]$Action)
    Reset-WinSecWindowsUpdateFixture
    try{$null=& $Action;$script:passed++;[Console]::WriteLine('[PASS] '+$Name)}
    catch{$script:failed++;[Console]::WriteLine('[FAIL] '+$Name+' : '+$_.Exception.Message);[Console]::WriteLine($_.ScriptStackTrace)}
}
Test-WinSecWUAutomation 'Native ABI compiles on this runtime without reading policies or registering system components' {
    Initialize-WinSecWindowsUpdateNamedPolicyReader
    Initialize-WinSecWindowsUpdateNamedPolicyReader
    Assert-WinSecWUAutomation ($null -ne ('WinSec.Native.UpdateNamedPolicyV1' -as [type]) -and $script:WU.NamedPolicyReads -eq 0 -and
        $script:WU.CimReads -eq 0 -and $script:WU.KeyReads -eq 0 -and $script:WU.IdentityReads -eq 0)
    foreach($name in @('DeviceName','../Update','UpdateServiceUrl')) {
        Assert-WinSecWUAutomationThrows {[WinSec.Native.UpdateNamedPolicyV1]::Read($name)}
        Assert-WinSecWUAutomationThrows {Get-WinSecWindowsUpdateNamedPolicy -Name $name}
    }
}
Test-WinSecWUAutomation 'Named policy boundary publishes only copied metadata and no private/provider object' {
    $script:WU.NamedPolicies.AllowAutoUpdate|Add-Member NoteProperty Secret 'PRIVATE-WU-SECRET'
    $value=Get-WinSecWindowsUpdateNamedPolicy AllowAutoUpdate
    $script:WU.NamedPolicies.AllowAutoUpdate.Value=5
    Assert-WinSecWUAutomation ($value.Source -ceq 'WINRT:NamedPolicy' -and $value.Kind -ceq 'Int32' -and $value.Value -eq 2 -and
        -not $value.Managed -and @($value.PSObject.Properties).Count -eq 7 -and (ConvertTo-Json $value) -notmatch 'PRIVATE-WU|Secret|UserPolicy')
}
foreach($fault in @('Null','Array','Area','Name','KindType','KindRange','Managed','User','Value','Missing','Getter','Provider')) {
    Test-WinSecWUAutomation ('Named policy metadata fails closed without leaking provider data: '+$fault) {
        $data=$script:WU.NamedPolicies.AllowAutoUpdate
        switch($fault) {
            Null {$script:WU.NamedPolicies.AllowAutoUpdate=$null};Array {$script:WU.NamedPolicies.AllowAutoUpdate=@($data,$data)}
            Area {$data.Area='PRIVATE-WU-AREA'};Name {$data.Name='Other'};KindType {$data.Kind='3'};KindRange {$data.Kind=6}
            Managed {$data.Managed='False'};User {$data.UserPolicy=$true};Value {$data.Value='2'}
            Missing {$data.PSObject.Properties.Remove('Value')}
            Getter {$data.PSObject.Properties.Remove('Value');$data|Add-Member ScriptProperty Value {throw 'PRIVATE-WU-GETTER'}}
            Provider {$script:WU.NamedPolicyFailures=@('AllowAutoUpdate')}
        }
        Assert-WinSecWUAutomationThrows {Get-WinSecWindowsUpdateNamedPolicy AllowAutoUpdate}
    }
}
Test-WinSecWUAutomation 'Stopped with Manual startup and explicitly automatic policy is not a failure' {
    $control=New-WinSecWUAutomationControl;$before=ConvertTo-Json $control -Depth 16
    $reads=$script:WU.CimReads+$script:WU.NamedPolicyReads+$script:WU.KeyReads
    function Get-CimInstance {throw 'Unexpected pure resolver query.'};function Get-Item {throw 'Unexpected resolver file read.'}
    $r=Get-WinSecWindowsUpdateAutomationReview $catalog $control
    Assert-WinSecWUAutomation ($r.State -ceq 'AUTOMATIC' -and $r.Reason -ceq 'GROUP_POLICY_RESOLVED' -and
        $before -ceq (ConvertTo-Json $control -Depth 16) -and $reads -eq ($script:WU.CimReads+$script:WU.NamedPolicyReads+$script:WU.KeyReads))
}
Test-WinSecWUAutomation 'A disabled service disproves availability even if every policy provider fails' {
    $script:WU.Services[0].StartMode='Disabled';$script:WU.FailKeys=@('AutomaticUpdates','WindowsUpdate')
    $script:WU.NamedPolicyFailures=@('AllowAutoUpdate','ConfigureDeadlineForQualityUpdates','ConfigureDeadlineForFeatureUpdates',
        'IgnoreWindowsUpdateGroupPolicies','SetEDURestart')
    $r=Get-WinSecWindowsUpdateAutomationReview $catalog (New-WinSecWUAutomationControl)
    Assert-WinSecWUAutomation ($r.State -ceq 'NOT_AUTOMATIC' -and $r.Reason -ceq 'UPDATE_SERVICE_DISABLED')
}
foreach($mode in @(2,3,4,5,7)) {
    Test-WinSecWUAutomation ('GPO options use only reviewed Windows client meanings: '+$mode) {
        $script:WU.Values.AutomaticUpdates.AUOptions=$mode
        $r=Get-WinSecWindowsUpdateAutomationReview $catalog (New-WinSecWUAutomationControl)
        $expected=switch($mode){4 {'AUTOMATIC'};{$_ -in @(2,3)} {'NOT_AUTOMATIC'};default {'UNKNOWN'}}
        Assert-WinSecWUAutomation ($r.State -ceq $expected)
    }
}
Test-WinSecWUAutomation 'NoAutoUpdate disabled policy wins over its stale AUOptions without inventing a conflict' {
    $script:WU.Values.AutomaticUpdates.NoAutoUpdate=1
    $r=Get-WinSecWindowsUpdateAutomationReview $catalog (New-WinSecWUAutomationControl)
    Assert-WinSecWUAutomation ($r.State -ceq 'NOT_AUTOMATIC')
}
foreach($mode in @(0,1,2,3,4,5)) {
    Test-WinSecWUAutomation ('MDM mode is interpreted only after proving GPO and deadline absence: '+$mode) {
        $script:WU.MissingKeys=@('AutomaticUpdates','WindowsUpdate')
        $script:WU.NamedPolicies.AllowAutoUpdate.Managed=$true;$script:WU.NamedPolicies.AllowAutoUpdate.Value=$mode
        $r=Get-WinSecWindowsUpdateAutomationReview $catalog (New-WinSecWUAutomationControl)
        $expected=if($mode -in @(1,2,3,4)){'AUTOMATIC'}else{'NOT_AUTOMATIC'}
        Assert-WinSecWUAutomation ($r.State -ceq $expected -and $r.Reason -ceq 'MANAGED_POLICY_RESOLVED')
    }
}
foreach($gpMode in @(2,3,4)) {
    foreach($mdmMode in @(0,2,5)) {
        Test-WinSecWUAutomation ('GPO/MDM agreement is resolved and contradiction stays unknown: '+$gpMode+'/'+$mdmMode) {
            $script:WU.Values.AutomaticUpdates.AUOptions=$gpMode
            $script:WU.NamedPolicies.AllowAutoUpdate.Managed=$true;$script:WU.NamedPolicies.AllowAutoUpdate.Value=$mdmMode
            $r=Get-WinSecWindowsUpdateAutomationReview $catalog (New-WinSecWUAutomationControl)
            $gp=($gpMode -eq 4);$mdm=($mdmMode -eq 2)
            if($gp -ne $mdm){Assert-WinSecWUAutomation ($r.State -ceq 'UNKNOWN' -and $r.Reason -ceq 'GROUP_POLICY_MDM_CONFLICT')}
            else {Assert-WinSecWUAutomation ($r.State -ceq $(if($gp){'AUTOMATIC'}else{'NOT_AUTOMATIC'}))}
        }
    }
}
Test-WinSecWUAutomation 'Default automation requires successful unmanaged API observations and no GPO settings' {
    $script:WU.MissingKeys=@('AutomaticUpdates','WindowsUpdate')
    $r=Get-WinSecWindowsUpdateAutomationReview $catalog (New-WinSecWUAutomationControl)
    Assert-WinSecWUAutomation ($r.State -ceq 'AUTOMATIC' -and $r.Reason -ceq 'OBSERVED_UNMANAGED_DEFAULT')
    $script:WU.NamedPolicyFailures=@('AllowAutoUpdate')
    $r=Get-WinSecWindowsUpdateAutomationReview $catalog (New-WinSecWUAutomationControl)
    Assert-WinSecWUAutomation ($r.State -ceq 'UNKNOWN')
}
foreach($policy in @('AllowAutoUpdate','ConfigureDeadlineForQualityUpdates','ConfigureDeadlineForFeatureUpdates',
    'IgnoreWindowsUpdateGroupPolicies','SetEDURestart')) {
    Test-WinSecWUAutomation ('Each missing API observation blocks policy effectiveness: '+$policy) {
        $script:WU.NamedPolicyFailures=@($policy)
        $control=New-WinSecWUAutomationControl;$r=Get-WinSecWindowsUpdateAutomationReview $catalog $control
        Assert-WinSecWUAutomation ($r.State -ceq 'UNKNOWN' -and -not $control.Evidence.CollectionComplete -and
            $control.Evidence.CollectionIssues -ccontains ('UPDATE_POLICY_'+$policy+'_QUERY_FAILED') -and
            (ConvertTo-Json $control -Depth 16) -notmatch 'PRIVATE-WU')
    }
}
foreach($policy in @('ConfigureDeadlineForQualityUpdates','ConfigureDeadlineForFeatureUpdates')) {
    Test-WinSecWUAutomation ('Managed deadline overrides are not ignored when interpreting AllowAutoUpdate: '+$policy) {
        $script:WU.NamedPolicies[$policy].Managed=$true
        $r=Get-WinSecWindowsUpdateAutomationReview $catalog (New-WinSecWUAutomationControl)
        Assert-WinSecWUAutomation ($r.State -ceq 'UNKNOWN' -and $r.Reason -ceq 'DEADLINE_POLICY_REQUIRES_REVIEW')
    }
}
foreach($policy in @('IgnoreWindowsUpdateGroupPolicies','SetEDURestart')) {
    Test-WinSecWUAutomation ('Unresolved policy overrides cannot silently reverse a GPO verdict: '+$policy) {
        $script:WU.NamedPolicies[$policy].Managed=$true;$script:WU.NamedPolicies[$policy].Value=1
        $r=Get-WinSecWindowsUpdateAutomationReview $catalog (New-WinSecWUAutomationControl)
        Assert-WinSecWUAutomation ($r.State -ceq 'UNKNOWN' -and $r.Reason -ceq 'OVERRIDE_POLICY_REQUIRES_REVIEW')
    }
}
Test-WinSecWUAutomation 'Observed GPO education override requires separate review even when its value is zero' {
    $script:WU.Values.WindowsUpdate.SetEDURestart=0
    $r=Get-WinSecWindowsUpdateAutomationReview $catalog (New-WinSecWUAutomationControl)
    Assert-WinSecWUAutomation ($r.State -ceq 'UNKNOWN' -and $r.Reason -ceq 'OVERRIDE_POLICY_REQUIRES_REVIEW')
}
foreach($field in @('ConfigureDeadlineForQualityUpdates','ConfigureDeadlineForFeatureUpdates','SetComplianceDeadline','SetComplianceDeadlineForQU','SetComplianceDeadlineForFU')) {
    Test-WinSecWUAutomation ('Any observed GPO deadline data requires separate interpretation: '+$field) {
        $script:WU.Values.WindowsUpdate[$field]=0
        $r=Get-WinSecWindowsUpdateAutomationReview $catalog (New-WinSecWUAutomationControl)
        Assert-WinSecWUAutomation ($r.State -ceq 'UNKNOWN' -and $r.Reason -ceq 'DEADLINE_POLICY_REQUIRES_REVIEW')
    }
}
foreach($fault in @('MissingNoAuto','MissingOption','NoAutoRange','UnknownGpo','FutureMdm','InvalidMdm','UnmanagedNonDefault','OldSchema','Source','Type','Flag')) {
    Test-WinSecWUAutomation ('Incomplete automation evidence does not become compliance: '+$fault) {
        switch($fault) {
            MissingNoAuto {$script:WU.Values.AutomaticUpdates.Remove('NoAutoUpdate')}
            MissingOption {$script:WU.Values.AutomaticUpdates.Remove('AUOptions')}
            NoAutoRange {$script:WU.Values.AutomaticUpdates.NoAutoUpdate=9};UnknownGpo {$script:WU.FailKeys=@('AutomaticUpdates')}
            FutureMdm {$script:WU.NamedPolicies.AllowAutoUpdate.Value=6};InvalidMdm {$script:WU.NamedPolicies.AllowAutoUpdate.Kind=0;$script:WU.NamedPolicies.AllowAutoUpdate.Value=$null}
            UnmanagedNonDefault {$script:WU.MissingKeys=@('AutomaticUpdates','WindowsUpdate');$script:WU.NamedPolicies.AllowAutoUpdate.Value=0}
        }
        $control=New-WinSecWUAutomationControl
        switch($fault) {
            OldSchema {$control.Evidence.SchemaVersion='1.1.0'}
            Source {$control.Evidence.AutomationPolicy.AllowAutoUpdate.Source='OTHER'}
            Type {$control.Evidence.AutomationPolicy.AllowAutoUpdate.Managed='False'}
            Flag {$control.Evidence.EffectivePolicyVerified=$true;$control.Evidence.AutomationPolicy.AllowAutoUpdate.State='UNKNOWN'}
        }
        $r=Get-WinSecWindowsUpdateAutomationReview $catalog $control
        Assert-WinSecWUAutomation ($r.State -ceq 'UNKNOWN')
    }
}
foreach($sku in @(98,99,100,101)) {
    Test-WinSecWUAutomation ('Home provider applicability is not inferred from a Pro policy: '+$sku) {
        $script:WU.Systems[0].OperatingSystemSKU=[uint32]$sku
        $r=Get-WinSecWindowsUpdateAutomationReview $catalog (New-WinSecWUAutomationControl)
        Assert-WinSecWUAutomation ($r.State -ceq 'UNKNOWN' -and $r.Reason -ceq 'POLICY_PROVIDER_EDITION_UNVERIFIED')
    }
}
foreach($field in @('DeviceId','ScanId','CheckId')) {
    Test-WinSecWUAutomation ('Foreign evidence aborts automation review: '+$field) {
        $control=New-WinSecWUAutomationControl;$control.Evidence.$field='FOREIGN'
        Assert-WinSecWUAutomationThrows {Get-WinSecWindowsUpdateAutomationReview $catalog $control}
    }
}
[Console]::WriteLine(('Windows Update automation: {0} passed, {1} failed.' -f $script:passed,$script:failed))
if($script:failed){throw 'Windows Update automation tests failed.'}
