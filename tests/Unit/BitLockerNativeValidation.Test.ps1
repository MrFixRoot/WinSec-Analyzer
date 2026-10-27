# Validador nativo con CIM simulado. No ejecuta una auditoría real ni escribe datos.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$validator=Join-Path $root 'tests/Integration/Invoke-BitLockerNativeValidation.ps1'
$script:passed=0;$script:failed=0
$global:WinSecBitLockerNativeTest=@{}
$checksPath=Join-Path $root 'config/checks.json';$scoringPath=Join-Path $root 'config/scoring.json'
$checksHash=(Get-FileHash $checksPath -Algorithm SHA256).Hash;$scoreHash=(Get-FileHash $scoringPath -Algorithm SHA256).Hash
function Assert-WinSecNativeBitLocker {param([bool]$Condition);if(-not $Condition){throw 'Native BitLocker assertion failed.'}}
function Get-CimInstance {
    [CmdletBinding()]param($Namespace,$ClassName,$Property,$Filter,$OperationTimeoutSec)
    if($ClassName -ceq 'Win32_ComputerSystemProduct'){
        $global:WinSecBitLockerNativeTest.identities++
        return [pscustomobject]@{UUID='12345678-1234-4567-89ab-123456789abc'}
    }
    $global:WinSecBitLockerNativeTest.queries++
    if($ClassName -ceq 'Win32_OperatingSystem') {
        if(($Property -join ',') -ceq 'SystemDrive'){return [pscustomobject]@{SystemDrive='D:'}}
        return [pscustomobject]@{Caption='Microsoft Windows 11';Version=$global:WinSecBitLockerNativeTest.version;BuildNumber=$global:WinSecBitLockerNativeTest.version.Split('.')[2];OperatingSystemSKU=48;ProductType=1}
    }
    Assert-WinSecNativeBitLocker ($ClassName -ceq 'Win32_EncryptableVolume' -and $Namespace -ceq 'root/cimv2/Security/MicrosoftVolumeEncryption' -and
        $Filter -ceq "DriveLetter = 'D:'" -and $OperationTimeoutSec -eq 10)
    if($global:WinSecBitLockerNativeTest.providerFails){throw 'PRIVATE-NATIVE-BITLOCKER'}
    if($global:WinSecBitLockerNativeTest.providerDenied){throw [System.UnauthorizedAccessException]::new('PRIVATE-NATIVE-BITLOCKER')}
    [pscustomobject]@{DeviceID='\\?\Volume{12345678-1234-4567-89ab-123456789abc}\';DriveLetter='D:';VolumeType=[uint32]0}
}
function Invoke-CimMethod {
    [CmdletBinding()]param($InputObject,$MethodName,$OperationTimeoutSec)
    $global:WinSecBitLockerNativeTest.methods++
    Assert-WinSecNativeBitLocker ($InputObject.DriveLetter -ceq 'D:' -and $OperationTimeoutSec -eq 10)
    switch -CaseSensitive ($MethodName) {
        GetProtectionStatus {[pscustomobject]@{ReturnValue=0;ProtectionStatus=1;RecoveryPassword='PRIVATE-NATIVE-BITLOCKER'}}
        GetConversionStatus {[pscustomobject]@{ReturnValue=0;ConversionStatus=$global:WinSecBitLockerNativeTest.conversion;EncryptionPercentage=100}}
        GetEncryptionMethod {[pscustomobject]@{ReturnValue=0;EncryptionMethod=6}}
        GetLockStatus {[pscustomobject]@{ReturnValue=0;LockStatus=0}}
        default {throw 'Forbidden native validation method.'}
    }
}
function Get-FileHash {
    [CmdletBinding(DefaultParameterSetName='Path')]
    param([Parameter(ParameterSetName='Path',Position=0)][string]$Path,[Parameter(ParameterSetName='LiteralPath')][string]$LiteralPath,[string]$Algorithm='SHA256')
    $result=Microsoft.PowerShell.Utility\Get-FileHash @PSBoundParameters
    if($global:WinSecBitLockerNativeTest.changedCollector -and ($LiteralPath -replace '\\','/') -like '*/Checks/BitLocker/Test-BitLocker.ps1'){$result.Hash='F'*64}
    return $result
}
function Test-WinSecNativeBitLocker {
    param([string]$Name,[scriptblock]$Action)
    # El script validado usa un ámbito hijo. Los dobles comparten un objeto de prueba
    # explícito; script: resolvería el ámbito hijo y perdería las condiciones inyectadas.
    $global:WinSecBitLockerNativeTest=@{identities=0;queries=0;methods=0;version='10.0.22631';conversion=1;providerFails=$false;providerDenied=$false;changedCollector=$false}
    $script:lastNativeResult=$null
    try{$null=& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}
    catch{
        $script:failed++;Write-Host ('[FAIL] '+$Name+' : '+$_.Exception.Message);Write-Host $_.ScriptStackTrace
        # Sólo fixtures sintéticas; conservar la causa que el validador oculta al usuario.
        foreach($detail in @($Error|Select-Object -First 3)){Write-Host $detail.Exception.Message;Write-Host $detail.ScriptStackTrace}
        Write-Host ('Synthetic counters: queries='+$global:WinSecBitLockerNativeTest.queries+'; methods='+$global:WinSecBitLockerNativeTest.methods)
        if($null -ne $script:lastNativeResult){Write-Host ($script:lastNativeResult|ConvertTo-Json -Depth 5)}
    }
}
Test-WinSecNativeBitLocker 'Default invocation has no consent and performs no identity or security query' {
    $caught=$false;try{$null=& $validator}catch{$caught=$true}
    Assert-WinSecNativeBitLocker ($caught -and $global:WinSecBitLockerNativeTest.identities -eq 0 -and $global:WinSecBitLockerNativeTest.queries -eq 0 -and $global:WinSecBitLockerNativeTest.methods -eq 0)
}
Test-WinSecNativeBitLocker 'Preparing a request reads only hashed hardware identity and binds runtime, scope and code' {
    $plan=(& $validator -PlanOnly -OperationId ('a'*32))|ConvertFrom-Json
    $again=(& $validator -PlanOnly -OperationId ('a'*32))|ConvertFrom-Json
    Assert-WinSecNativeBitLocker ($global:WinSecBitLockerNativeTest.queries -eq 0 -and $global:WinSecBitLockerNativeTest.methods -eq 0 -and $plan.RequestHash -ceq $again.RequestHash -and
        $plan.Request.ScopeKey -ceq 'WSA-SYS-002' -and $plan.Request.VolumeScope -ceq 'OS_VOLUME_ONLY' -and
        $plan.Request.Runtime -ceq $PSVersionTable.PSVersion.ToString() -and $plan.Request.Checks.Count -eq 1 -and
        $plan.Request.ProcessElevated -is [bool] -and
        $plan.Request.ReadOnly -and -not $plan.Request.PersistRawEvidence -and -not $plan.Request.PersistPublicHistory -and
        $plan.Request.ValidatorSha256 -cmatch '\A[A-F0-9]{64}\z')
}
foreach($fault in @('NoHash','WrongHash','DifferentOperation','DifferentProfile','ChangedCollector')) {
    Test-WinSecNativeBitLocker ('Rejects unapproved or changed native request before security queries: '+$fault) {
        $plan=(& $validator -PlanOnly -OperationId ('b'*32))|ConvertFrom-Json
        $arguments=@{OperationId=$plan.Request.OperationId;ApprovedRequestHash=$plan.RequestHash}
        switch($fault){NoHash {$arguments.Remove('ApprovedRequestHash')};WrongHash {$arguments.ApprovedRequestHash='A'*64};
            DifferentOperation {$arguments.OperationId='c'*32};DifferentProfile {$arguments.Profile='WSA-W11-24H2-PRO-DEF-BASE'};
            ChangedCollector {$global:WinSecBitLockerNativeTest.changedCollector=$true}}
        $caught=$false;try{$null=& $validator @arguments}catch{$caught=$true}
        Assert-WinSecNativeBitLocker ($caught -and $global:WinSecBitLockerNativeTest.queries -eq 0 -and $global:WinSecBitLockerNativeTest.methods -eq 0)
    }
}
Test-WinSecNativeBitLocker 'An approved synthetic operation validates collection, two criteria, history and reports without persistence' {
    $plan=(& $validator -PlanOnly -OperationId ('d'*32))|ConvertFrom-Json
    $json=& $validator -OperationId $plan.Request.OperationId -ApprovedRequestHash $plan.RequestHash
    $result=$json|ConvertFrom-Json
    $script:lastNativeResult=$result
    Assert-WinSecNativeBitLocker ($result.CollectionValidated -and $result.AssessmentMode -ceq 'FRAMEWORK_REVIEW' -and $result.CriterionCount -eq 2 -and
        $result.InformationalObservations -eq 3 -and $result.InMemoryReports -eq 3 -and $result.PublicHistoryRoundtripValidated -and
        -not $result.RawEvidencePersisted -and -not $result.PublicHistoryPersisted -and -not $result.WindowsChanges -and
        -not $result.ProductionPermissionsChanged -and $global:WinSecBitLockerNativeTest.methods -eq 4 -and ($json -join '') -notmatch 'PRIVATE|DriveLetter|RecoveryPassword|XTS_AES|SystemVolume|ConfigurationScore|ConfigurationStatus')
}
Test-WinSecNativeBitLocker 'Real OS applicability is checked only after confirmation; mismatches do not manufacture a score' {
    $plan=(& $validator -PlanOnly -OperationId ('e'*32))|ConvertFrom-Json
    $global:WinSecBitLockerNativeTest.version='10.0.26100'
    $result=(& $validator -OperationId $plan.Request.OperationId -ApprovedRequestHash $plan.RequestHash)|ConvertFrom-Json
    $script:lastNativeResult=$result
    Assert-WinSecNativeBitLocker ($result.CollectionValidated -and $null -eq $result.ConfigurationScore -and
        $result.ApplicabilityDiagnostics -ccontains 'WINDOWS_SCOPE_MISMATCH' -and $result.InMemoryReports -eq 3)
}
Test-WinSecNativeBitLocker 'Provider failure reports closed diagnostics without claiming collection validation or exposing exceptions' {
    $plan=(& $validator -PlanOnly -OperationId ('f'*32))|ConvertFrom-Json
    $global:WinSecBitLockerNativeTest.providerFails=$true
    $json=& $validator -OperationId $plan.Request.OperationId -ApprovedRequestHash $plan.RequestHash
    $result=$json|ConvertFrom-Json
    $script:lastNativeResult=$result
    Assert-WinSecNativeBitLocker (-not $result.CollectionValidated -and $null -eq $result.ConfigurationScore -and
        $result.CollectionIssues -ccontains 'BITLOCKER_PROVIDER_UNAVAILABLE' -and ($json -join '') -notmatch 'PRIVATE|RecoveryPassword')
}
Test-WinSecNativeBitLocker 'Typed access denial survives the native validator as a bounded diagnostic without persistence or score' {
    $plan=(& $validator -PlanOnly -OperationId ('1'*32))|ConvertFrom-Json
    $global:WinSecBitLockerNativeTest.providerDenied=$true
    $json=& $validator -OperationId $plan.Request.OperationId -ApprovedRequestHash $plan.RequestHash
    $result=$json|ConvertFrom-Json
    Assert-WinSecNativeBitLocker (-not $result.CollectionValidated -and $null -eq $result.ConfigurationScore -and
        $result.CollectionIssues -ccontains 'BITLOCKER_PROVIDER_ACCESS_DENIED' -and $result.InformationalObservations -eq 0 -and
        $result.PublicHistoryRoundtripValidated -and $result.InMemoryReports -eq 3 -and ($json -join '') -notmatch 'PRIVATE|Exception|HResult')
}
Assert-WinSecNativeBitLocker ($checksHash -ceq (Get-FileHash $checksPath -Algorithm SHA256).Hash -and
    $scoreHash -ceq (Get-FileHash $scoringPath -Algorithm SHA256).Hash)
Write-Host ('BitLocker native validator: {0} passed, {1} failed.' -f $script:passed,$script:failed)
Remove-Variable -Name WinSecBitLockerNativeTest -Scope Global
if($script:failed){throw 'BitLocker native validation unit tests failed.'}
