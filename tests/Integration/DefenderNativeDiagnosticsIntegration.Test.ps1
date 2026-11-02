# Real validation helper with synthetic Windows, inventory, coordinator and fault providers.
[CmdletBinding()]param([string]$CasePattern='*')
$requestedCases=$CasePattern
. (Join-Path $PSScriptRoot 'ConfigurationAssessmentIntegration.Test.ps1') -CasePattern '__DIAGNOSTIC_FIXTURE_ONLY__'
$CasePattern=$requestedCases
. (Join-Path $root 'tests/Fixtures/NativeValidationDiagnostics.ps1')
$script:passed=0;$script:failed=0
$helper=Join-Path $root 'tests/Integration/Invoke-DefenderNativeValidation.ps1'
function Invoke-SyntheticNativeProbe {
    param($Plan,[string]$Phase='',[string]$Category='',[string]$Reason='UNCLASSIFIED')
    $state=[pscustomobject]@{Diagnostic=$null};$caught=$null;$published=New-Object 'Collections.Generic.List[object]'
    try{
        Invoke-WinSecValidationDiagnosticAttempt -ExpectedOperationId $Plan.Request.OperationId -ExpectedRuntime $PSVersionTable.PSVersion.ToString() -AttemptState $state -ValidatorAction {
            . $helper -OperationId $Plan.Request.OperationId -ApprovedRequestHash $Plan.RequestHash -DiagnosticState $state
        }|ForEach-Object{$published.Add($_)}
    }catch{$caught=$_}
    if(-not $Phase){
        Assert-WinSecConfigIntegration ($null -eq $caught -and $null -eq $state.Diagnostic -and $published.Count -eq 1)
        $summary=$published[0]|ConvertFrom-Json
        Assert-WinSecConfigIntegration ($summary.InMemoryReports -eq 3 -and $summary.PublicHistoryRoundtripValidated -ceq $true -and
            $summary.WindowsChanges -ceq $false -and $summary.PublicHistoryPersisted -ceq $false -and $summary.RawEvidencePersisted -ceq $false)
    }else{
        Assert-WinSecConfigIntegration ($null -ne $caught -and $published.Count -eq 0 -and $state.Diagnostic.Phase -ceq $Phase -and
            $state.Diagnostic.Category -ceq $Category -and $state.Diagnostic.Reason -ceq $Reason -and
            $state.Diagnostic.SchemaVersion -ceq 'WinSec.ValidationDiagnostic1.1' -and $null -eq $caught.Exception.InnerException) `
            ('Unexpected closed diagnostic: '+$state.Diagnostic.Phase+'/'+$state.Diagnostic.Category+'/'+$state.Diagnostic.Reason)
        $exposed=($caught|Format-List * -Force|Out-String)+(Microsoft.PowerShell.Utility\ConvertTo-Json $state.Diagnostic -Depth 5)
        Assert-WinSecConfigIntegration (-not $exposed.Contains('PRIVATE_NATIVE_DIAGNOSTIC'))
    }
    Assert-WinSecConfigIntegration ($script:store.Count -eq 0 -and $script:reports.Count -eq 0)
}
Test-WinSecConfigIntegration 'Native diagnostics preserve successful three-framework acceptance and restore the normalizer' {
    $plan=(. $helper -PlanOnly)|ConvertFrom-Json
    $before=(Get-Command ConvertTo-WinSecAuditRecord -CommandType Function).ScriptBlock.ToString()
    Invoke-SyntheticNativeProbe $plan
    Assert-WinSecConfigIntegration ($script:metrics.Reads -eq 1 -and
        (Get-Command ConvertTo-WinSecAuditRecord -CommandType Function).ScriptBlock.ToString() -ceq $before)
}
Test-WinSecConfigIntegration 'Native identity provider failure is not relabeled as a scan failure' {
    $plan=(. $helper -PlanOnly)|ConvertFrom-Json
    function FailIdentity {throw [UnauthorizedAccessException]::new('PRIVATE_NATIVE_DIAGNOSTIC')}
    Set-Alias New-WinSecLocalTarget FailIdentity -Scope Local
    Invoke-SyntheticNativeProbe $plan NATIVE_IDENTITY ACCESS_DENIED
    Assert-WinSecConfigIntegration ($script:metrics.Reads -eq 0)
}
Test-WinSecConfigIntegration 'Revoked inventory authorization stays rejected before any collector' {
    $plan=(. $helper -PlanOnly)|ConvertFrom-Json
    function RevokedTarget {param($Inventory,$DeviceId);$true}
    Set-Alias Test-WinSecDeviceInventoryRemoval RevokedTarget -Scope Local
    Invoke-SyntheticNativeProbe $plan NATIVE_INVENTORY AUTHORIZATION_REVOKED TARGET_REMOVED
    Assert-WinSecConfigIntegration ($script:metrics.Reads -eq 0)
}
Test-WinSecConfigIntegration 'Coordinator initialization timeout has its own phase' {
    $plan=(. $helper -PlanOnly)|ConvertFrom-Json
    function FailCoordinator {param($ProjectRoot);throw [TimeoutException]::new('PRIVATE_NATIVE_DIAGNOSTIC')}
    Set-Alias New-WinSecScanCoordinator FailCoordinator -Scope Local
    Invoke-SyntheticNativeProbe $plan NATIVE_COORDINATOR TIMEOUT
    Assert-WinSecConfigIntegration ($script:metrics.Reads -eq 0)
}
Test-WinSecConfigIntegration 'Scan execution binding failure is distinguished from data validation' {
    $plan=(. $helper -PlanOnly)|ConvertFrom-Json
    function FailScan {throw [Management.Automation.ParameterBindingException]::new('PRIVATE_NATIVE_DIAGNOSTIC')}
    Set-Alias Invoke-WinSecCoordinatedScan FailScan -Scope Local
    Invoke-SyntheticNativeProbe $plan NATIVE_SCAN PARAMETER_BINDING
}
Test-WinSecConfigIntegration 'Missing control result is rejected without claiming a provider error' {
    $plan=(. $helper -PlanOnly)|ConvertFrom-Json
    function EmptyScan {}
    Set-Alias Invoke-WinSecCoordinatedScan EmptyScan -Scope Local
    Invoke-SyntheticNativeProbe $plan NATIVE_CONTROL_VALIDATION CONTROL_RESULT_REJECTED CONTROL_RESULT_REJECTED
}
Test-WinSecConfigIntegration 'A numeric assessment is still rejected before history or reports' {
    $plan=(. $helper -PlanOnly)|ConvertFrom-Json
    $originalScan=(Get-Command Invoke-WinSecCoordinatedScan).ScriptBlock
    function InjectRating {
        [CmdletBinding()]param($Coordinator,$DeviceId,$ScanId,$ScopeType,$ScopeKey,$AssessmentProfile,$ConfirmAction)
        $result=& $originalScan @PSBoundParameters
        (@($Coordinator.Sessions.Values)[0]).Session|Add-Member -NotePropertyName ConfigurationAssessment -NotePropertyValue ([pscustomobject]@{Forbidden=42})
        $result
    }
    Set-Alias Invoke-WinSecCoordinatedScan InjectRating -Scope Local
    Invoke-SyntheticNativeProbe $plan NATIVE_CONTROL_VALIDATION POLICY_REJECTED RATING_PRESENT
}
Test-WinSecConfigIntegration 'Unavailable status and failed fallback retain provider origin through AuditEngine' {
    $plan=(. $helper -PlanOnly)|ConvertFrom-Json;$script:collectionError=$true
    Invoke-SyntheticNativeProbe $plan NATIVE_STATUS_PROVIDER PROVIDER_UNAVAILABLE STATUS_UNAVAILABLE
}
Test-WinSecConfigIntegration 'An observed unusable provider object is distinguished from provider unavailability' {
    $plan=(. $helper -PlanOnly)|ConvertFrom-Json
    function Get-MpComputerStatus {[CmdletBinding()]param();$script:metrics.Reads++;[pscustomobject]@{Unreviewed=$true}}
    Invoke-SyntheticNativeProbe $plan NATIVE_STATUS_PROVIDER TELEMETRY_UNUSABLE STATUS_UNUSABLE
}
Test-WinSecConfigIntegration 'Recovered CIM fallback does not fabricate a terminal failure' {
    $plan=(. $helper -PlanOnly)|ConvertFrom-Json;$script:collectionError=$true
    $originalCim=(Get-Command Get-CimInstance).ScriptBlock
    function Get-CimInstance {
        [CmdletBinding()]param($Namespace,$ClassName,$Property,$OperationTimeoutSec)
        if($ClassName -ceq 'MSFT_MpComputerStatus'){return [pscustomobject]@{AMRunningMode='Normal';AMServiceEnabled=$true;AntivirusEnabled=$true;RealTimeProtectionEnabled=$false}}
        & $originalCim @PSBoundParameters
    }
    Invoke-SyntheticNativeProbe $plan
}
Test-WinSecConfigIntegration 'Optional missing preferences remain a coverage gap, not a terminal provider error' {
    $plan=(. $helper -PlanOnly)|ConvertFrom-Json
    function Get-MpPreference {[CmdletBinding()]param();throw 'PRIVATE_NATIVE_DIAGNOSTIC'}
    Invoke-SyntheticNativeProbe $plan
}
Test-WinSecConfigIntegration 'Normalization identity rejection survives the engines generic execution record' {
    $plan=(. $helper -PlanOnly)|ConvertFrom-Json
    $originalField=(Get-Command Get-WinSecAuditField).ScriptBlock
    function CorruptRawIdentity {param($InputObject,$Name)
        if($Name -ceq 'CheckId' -and $null -ne $InputObject.PSObject.Properties['TimestampUTC'] -and
            $null -ne $InputObject.PSObject.Properties['Evidence']){return 'SYNTHETIC_WRONG_CHECK'}
        & $originalField @PSBoundParameters
    }
    Set-Alias Get-WinSecAuditField CorruptRawIdentity -Scope Local
    Invoke-SyntheticNativeProbe $plan NATIVE_NORMALIZATION NORMALIZATION_REJECTED NORMALIZATION_REJECTED
}
Test-WinSecConfigIntegration 'History encoding failure is distinct from reading and framework evaluation' {
    $plan=(. $helper -PlanOnly)|ConvertFrom-Json
    function FailHistoryWrite {param($Session);throw [IO.IOException]::new('PRIVATE_NATIVE_DIAGNOSTIC')}
    Set-Alias New-WinSecPublicHistoryRecord FailHistoryWrite -Scope Local
    Invoke-SyntheticNativeProbe $plan NATIVE_HISTORY_WRITE IO_ERROR
}
Test-WinSecConfigIntegration 'Engine execution failure without a raw record is separated from normalization' {
    $plan=(. $helper -PlanOnly)|ConvertFrom-Json
    function FailImplementation {param($Check);throw [InvalidOperationException]::new('PRIVATE_NATIVE_DIAGNOSTIC')}
    Set-Alias Get-WinSecAuditImplementation FailImplementation -Scope Local
    Invoke-SyntheticNativeProbe $plan NATIVE_CHECK_EXECUTION EXECUTION_REJECTED CHECK_EXECUTION_FAILED
}
Test-WinSecConfigIntegration 'History decoding failure preserves its phase' {
    $plan=(. $helper -PlanOnly)|ConvertFrom-Json
    $originalRead=(Get-Command ConvertFrom-WinSecPublicHistoryRecord).ScriptBlock
    function FailHistoryRead {param($Record)
        if($nativePhase -ceq 'NATIVE_HISTORY_READ'){throw [IO.InvalidDataException]::new('PRIVATE_NATIVE_DIAGNOSTIC')}
        & $originalRead @PSBoundParameters
    }
    Set-Alias ConvertFrom-WinSecPublicHistoryRecord FailHistoryRead -Scope Local
    Invoke-SyntheticNativeProbe $plan NATIVE_HISTORY_READ INVALID_DATA
}
foreach($frameworkSpec in @(@{Id='nist-csf';Tag='NIST'},@{Id='cis-controls';Tag='CIS'},@{Id='mitre-attack';Tag='MITRE'})){
    Test-WinSecConfigIntegration ('Framework analysis failure identifies only its reviewed framework: '+$frameworkSpec.Tag) {
        $plan=(. $helper -PlanOnly)|ConvertFrom-Json
        $originalAnalysis=(Get-Command New-WinSecFrameworkAnalysis).ScriptBlock
        function FailFrameworkAnalysis {
            [CmdletBinding()]param($ProjectRoot,$DeviceId,$DeviceName,$ScopeType,$ScopeKey,$FrameworkId,$Sources,$Reports)
            if($FrameworkId -ceq $frameworkSpec.Id){throw [IO.InvalidDataException]::new('PRIVATE_NATIVE_DIAGNOSTIC')}
            & $originalAnalysis @PSBoundParameters
        }
        Set-Alias New-WinSecFrameworkAnalysis FailFrameworkAnalysis -Scope Local
        Invoke-SyntheticNativeProbe $plan ('NATIVE_'+$frameworkSpec.Tag+'_ANALYSIS') INVALID_DATA
    }
}
Test-WinSecConfigIntegration 'Markdown failure is separated from a successful framework analysis' {
    $plan=(. $helper -PlanOnly)|ConvertFrom-Json
    function FailMarkdown {param($Analysis);throw [IO.IOException]::new('PRIVATE_NATIVE_DIAGNOSTIC')}
    Set-Alias New-WinSecFrameworkMarkdown FailMarkdown -Scope Local
    Invoke-SyntheticNativeProbe $plan NATIVE_NIST_MARKDOWN IO_ERROR
}
Test-WinSecConfigIntegration 'Native summary serialization error never becomes a successful summary' {
    $plan=(. $helper -PlanOnly)|ConvertFrom-Json
    function FailSummaryJson {
        [CmdletBinding()]param([Parameter(ValueFromPipeline)]$InputObject,[int]$Depth=2,[switch]$Compress)
        process{
            if($nativePhase -ceq 'NATIVE_SERIALIZATION'){throw [IO.IOException]::new('PRIVATE_NATIVE_DIAGNOSTIC')}
            Microsoft.PowerShell.Utility\ConvertTo-Json @PSBoundParameters
        }
    }
    Set-Alias ConvertTo-Json FailSummaryJson -Scope Local
    Invoke-SyntheticNativeProbe $plan NATIVE_SERIALIZATION IO_ERROR
}
[Console]::WriteLine(('Defender internal diagnostics: {0} passed, {1} failed.' -f $script:passed,$script:failed))
if($script:failed){throw 'Defender internal diagnostic integration failed.'}
