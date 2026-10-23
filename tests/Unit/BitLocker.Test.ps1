# Recolector BitLocker: proveedores e identidad simulados, sin consultas Windows.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
Import-Module CimCmdlets # Sólo tipos CIM locales para excepciones sintéticas; sin consultas.
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$collector=Join-Path $root 'src/Checks/BitLocker/Test-BitLocker.ps1'
$script:passed=0;$script:failed=0;$script:queries=0;$script:identityReads=0
$script:methods=New-Object 'System.Collections.Generic.List[string]'
$script:id='local:hw1-'+('a'*64)
function Assert-WinSecBitLocker {param([bool]$Condition);if(-not $Condition){throw 'BitLocker assertion failed.'}}
function Assert-WinSecBitLockerRejects {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-WinSecBitLocker $caught}
function Get-WinSecLocalHardwareDeviceId {
    [CmdletBinding()]param()
    $script:identityReads++
    if($script:identityFails){throw 'PRIVATE-BITLOCKER-ERROR'}
    $script:localIds
}
function Get-CimInstance {
    [CmdletBinding()]param($Namespace,$ClassName,$Property,$Filter,$OperationTimeoutSec)
    $script:queries++
    Assert-WinSecBitLocker ($OperationTimeoutSec -eq 10)
    if($script:queryFailure -ceq $ClassName){throw 'PRIVATE-BITLOCKER-ERROR'}
    if($null -ne $script:queryException -and $ClassName -ceq $script:exceptionClass){throw $script:queryException}
    if($ClassName -ceq 'Win32_OperatingSystem') {
        Assert-WinSecBitLocker ($Namespace -ceq 'root/cimv2' -and ($Property -join ',') -ceq 'SystemDrive' -and -not $Filter)
        return $script:systems
    }
    Assert-WinSecBitLocker ($ClassName -ceq 'Win32_EncryptableVolume' -and
        $Namespace -ceq 'root/cimv2/Security/MicrosoftVolumeEncryption' -and
        ($Property -join ',') -ceq 'DeviceID,DriveLetter,VolumeType' -and
        $Filter -ceq ("DriveLetter = '"+$script:expectedDrive+"'"))
    $script:volumes
}
function Invoke-CimMethod {
    [CmdletBinding()]param($InputObject,$MethodName,$OperationTimeoutSec)
    Assert-WinSecBitLocker ([object]::ReferenceEquals($InputObject,$script:volumes[0]) -and $OperationTimeoutSec -eq 10 -and
        $MethodName -cin @('GetProtectionStatus','GetConversionStatus','GetEncryptionMethod','GetLockStatus'))
    $script:methods.Add($MethodName)
    if($script:methodFailures -ccontains $MethodName){throw 'PRIVATE-BITLOCKER-ERROR'}
    if($null -ne $script:methodException -and $MethodName -ceq $script:exceptionMethod){throw $script:methodException}
    $script:responses[$MethodName]
}
. $collector
$importQueries=$script:queries;$importMethods=$script:methods.Count
function Invoke-WinSecBitLockerFixture {Test-WinSecBitLocker -DeviceId $script:id -ScanId 'bitlocker-unit-1' -CheckId WSA-SYS-002}
function Test-WinSecBitLockerCase {
    param([string]$Name,[scriptblock]$Action)
    $script:queries=0;$script:identityReads=0;$script:methods.Clear()
    $script:localIds=@($script:id);$script:identityFails=$false;$script:queryFailure='';$script:methodFailures=@()
    $script:queryException=$null;$script:methodException=$null;$script:exceptionClass='';$script:exceptionMethod=''
    $script:expectedDrive='C:';$script:systems=@([pscustomobject]@{SystemDrive='C:'})
    $script:volumes=@([pscustomobject]@{DriveLetter='C:';VolumeType=[uint32]0;
        DeviceID='\\?\Volume{12345678-1234-4567-89ab-123456789abc}\';PersistentVolumeID='PRIVATE-BITLOCKER-ID'})
    $script:volumes[0]|Add-Member -MemberType ScriptProperty -Name KeyProtector -Value {throw 'Key protector must never be read.'}
    $script:responses=@{
        GetProtectionStatus=[pscustomobject]@{ReturnValue=[uint32]0;ProtectionStatus=[uint32]1;RecoveryPassword='PRIVATE-BITLOCKER-SECRET'}
        GetConversionStatus=[pscustomobject]@{ReturnValue=0;ConversionStatus=1;EncryptionPercentage=[uint32]100}
        GetEncryptionMethod=[pscustomobject]@{ReturnValue=0;EncryptionMethod=6;SelfEncryptionDriveEncryptionMethod='PRIVATE-BITLOCKER-TEXT'}
        GetLockStatus=[pscustomobject]@{ReturnValue=0;LockStatus=0}
    }
    try{$null=& $Action;$script:passed++;[Console]::WriteLine('[PASS] '+$Name)}
    catch{$script:failed++;[Console]::WriteLine('[FAIL] '+$Name+' : '+$_.Exception.Message);[Console]::WriteLine($_.ScriptStackTrace)}
}
Test-WinSecBitLockerCase 'Import has no provider or method side effects' {Assert-WinSecBitLocker ($importQueries -eq 0 -and $importMethods -eq 0)}
Test-WinSecBitLockerCase 'Healthy OS telemetry remains informational with exact identities and no security verdict' {
    $r=Invoke-WinSecBitLockerFixture;$e=$r.Evidence;$v=$e.SystemVolume
    Assert-WinSecBitLocker ($r.CheckId -ceq 'WSA-SYS-002' -and $r.DeviceId -ceq $script:id -and $r.ScanId -ceq 'bitlocker-unit-1' -and
        $r.SectionKey -ceq 'SystemSecurity' -and $r.Status -ceq 'INFORMATIONAL' -and $e.CollectionSuccessful -and $e.CollectionComplete -and
        $e.Scope -ceq 'OS_VOLUME_ONLY' -and $v.ProtectionStatus -ceq 'ON' -and $v.ConversionStatus -ceq 'FULLY_ENCRYPTED' -and
        $v.EncryptionMethod -ceq 'XTS_AES_128' -and $v.LockStatus -ceq 'UNLOCKED' -and $v.EncryptionPercentage -eq 100 -and
        -not $e.ScoringEligible -and $e.ComplianceAssessment -ceq 'NOT_EVALUATED' -and $script:queries -eq 2 -and $script:methods.Count -eq 4 -and
        ($e.DeviceId -ceq $r.DeviceId) -and $e.ScanId -ceq $r.ScanId -and $e.CheckId -ceq $r.CheckId)
    Assert-WinSecBitLocker ((ConvertTo-Json $r -Depth 12) -notmatch 'PRIVATE-BITLOCKER|RecoveryPassword|KeyProtector|PersistentVolumeID|SelfEncryptionDrive|12345678|PASS|FAIL')
}
Test-WinSecBitLockerCase 'Windows installed on D is the only volume queried' {
    $script:systems[0].SystemDrive='d:';$script:volumes[0].DriveLetter='D:';$script:expectedDrive='D:'
    Assert-WinSecBitLocker ((Invoke-WinSecBitLockerFixture).Evidence.SystemVolume.DriveLetter -ceq 'D:' -and $script:queries -eq 2)
}
Test-WinSecBitLockerCase 'Fully encrypted with protection off is recorded without pretending protection is on' {
    $script:responses.GetProtectionStatus.ProtectionStatus=0
    $r=Invoke-WinSecBitLockerFixture
    Assert-WinSecBitLocker ($r.Evidence.SystemVolume.ProtectionStatus -ceq 'OFF' -and $r.Evidence.SystemVolume.ConversionStatus -ceq 'FULLY_ENCRYPTED' -and $r.Status -ceq 'INFORMATIONAL')
}
foreach($conversion in 0..5) {
    Test-WinSecBitLockerCase ('Conversion state is preserved independently of rounded percentage: '+$conversion) {
        $script:responses.GetConversionStatus.ConversionStatus=$conversion
        $v=(Invoke-WinSecBitLockerFixture).Evidence.SystemVolume
        $names=@('FULLY_DECRYPTED','FULLY_ENCRYPTED','ENCRYPTION_IN_PROGRESS','DECRYPTION_IN_PROGRESS','ENCRYPTION_PAUSED','DECRYPTION_PAUSED')
        Assert-WinSecBitLocker ($v.ConversionStatus -ceq $names[$conversion] -and $v.EncryptionPercentage -eq 100)
    }
}
foreach($algorithm in 0..7) {
    Test-WinSecBitLockerCase ('Encryption method is inventoried without judging its strength: '+$algorithm) {
        $script:responses.GetEncryptionMethod.EncryptionMethod=$algorithm
        $names=@('NONE','AES_128_WITH_DIFFUSER','AES_256_WITH_DIFFUSER','AES_128','AES_256','HARDWARE_ENCRYPTION','XTS_AES_128','XTS_AES_256')
        Assert-WinSecBitLocker ((Invoke-WinSecBitLockerFixture).Evidence.SystemVolume.EncryptionMethod -ceq $names[$algorithm])
    }
}
foreach($bad in @($null,$true,'1',1.5,-1,99,[uint64]4294967296)) {
    Test-WinSecBitLockerCase 'Malformed or future status never becomes ON' {
        $script:responses.GetProtectionStatus.ProtectionStatus=$bad
        $r=Invoke-WinSecBitLockerFixture
        Assert-WinSecBitLocker ($r.Evidence.SystemVolume.ProtectionStatus -ceq 'UNKNOWN' -and -not $r.Evidence.CollectionComplete -and $r.Evidence.CollectionIssues -ccontains 'ProtectionStatus_UNKNOWN')
    }
}
foreach($bad in @($null,$false,'100',100.5,-1,101)) {
    Test-WinSecBitLockerCase 'Invalid percentages stay null rather than being coerced or clamped' {
        $script:responses.GetConversionStatus.EncryptionPercentage=$bad
        $r=Invoke-WinSecBitLockerFixture
        Assert-WinSecBitLocker ($null -eq $r.Evidence.SystemVolume.EncryptionPercentage -and -not $r.Evidence.CollectionComplete)
    }
}
foreach($method in @('GetProtectionStatus','GetConversionStatus','GetEncryptionMethod','GetLockStatus')) {
    Test-WinSecBitLockerCase ('A method failure preserves other telemetry and redacts provider errors: '+$method) {
        $script:methodFailures=@($method)
        $r=Invoke-WinSecBitLockerFixture
        Assert-WinSecBitLocker ($r.Evidence.CollectionSuccessful -and -not $r.Evidence.CollectionComplete -and
            $r.Evidence.CollectionIssues -ccontains ($method+'_UNAVAILABLE') -and (ConvertTo-Json $r -Depth 10) -notmatch 'PRIVATE-BITLOCKER')
    }
}
foreach($bad in @($null,'0',$false,[uint32]2150694912,42)) {
    Test-WinSecBitLockerCase 'A nonzero or malformed method return code cannot publish its apparent success value' {
        $script:responses.GetProtectionStatus.ReturnValue=$bad
        Assert-WinSecBitLocker ((Invoke-WinSecBitLockerFixture).Evidence.SystemVolume.ProtectionStatus -ceq 'UNKNOWN')
    }
}
Test-WinSecBitLockerCase 'All methods unavailable is unknown and never a failure finding or nonapplicability' {
    $script:methodFailures=@($script:responses.Keys)
    $r=Invoke-WinSecBitLockerFixture
    Assert-WinSecBitLocker ($r.Status -ceq 'UNKNOWN' -and -not $r.Evidence.CollectionSuccessful -and -not $r.Evidence.CollectionComplete -and
        $null -eq $r.NotApplicableReason -and (ConvertTo-Json $r -Depth 10) -notmatch 'PRIVATE-BITLOCKER')
}
Test-WinSecBitLockerCase 'Unknown protection and unknown algorithm do not get fabricated values' {
    $script:responses.GetProtectionStatus.ProtectionStatus=2;$script:responses.GetEncryptionMethod.EncryptionMethod=[uint32]::MaxValue
    $v=(Invoke-WinSecBitLockerFixture).Evidence.SystemVolume
    Assert-WinSecBitLocker ($v.ProtectionStatus -ceq 'UNKNOWN' -and $v.EncryptionMethod -ceq 'UNKNOWN')
}
foreach($bad in @('C:\','\\server\share',"C:' OR 1=1",'C:', $null)) {
    Test-WinSecBitLockerCase 'Invalid or ambiguous Windows drive cannot query other volumes' {
        if($bad -ceq 'C:'){$script:systems+=@($script:systems[0])}else{$script:systems[0].SystemDrive=$bad}
        $r=Invoke-WinSecBitLockerFixture
        Assert-WinSecBitLocker ($r.Status -ceq 'ERROR' -and $script:queries -eq 1 -and $script:methods.Count -eq 0)
    }
}
foreach($fault in @('WrongLetter','DataVolume','BadIdentifier','Duplicate','Empty')) {
    Test-WinSecBitLockerCase ('BitLocker response must identify exactly the Windows volume: '+$fault) {
        switch($fault) {
            WrongLetter {$script:volumes[0].DriveLetter='D:'}
            DataVolume {$script:volumes[0].VolumeType=1}
            BadIdentifier {$script:volumes[0].DeviceID='PRIVATE-BITLOCKER-INVALID'}
            Duplicate {$script:volumes+=@($script:volumes[0])}
            Empty {$script:volumes=@()}
        }
        $r=Invoke-WinSecBitLockerFixture
        Assert-WinSecBitLocker (-not $r.Evidence.CollectionSuccessful -and $script:methods.Count -eq 0 -and $null -eq $r.NotApplicableReason -and
            $r.Status -cin @('ERROR','UNKNOWN') -and (ConvertTo-Json $r -Depth 10) -notmatch 'PRIVATE-BITLOCKER')
    }
}
foreach($class in @('Win32_OperatingSystem','Win32_EncryptableVolume')) {
    Test-WinSecBitLockerCase ('Access denied or missing provider cannot mean unsupported or unencrypted: '+$class) {
        $script:queryFailure=$class;$r=Invoke-WinSecBitLockerFixture
        Assert-WinSecBitLocker ($r.Status -ceq 'ERROR' -and $script:methods.Count -eq 0 -and -not $r.Evidence.CollectionSuccessful -and
            $null -eq $r.NotApplicableReason -and (ConvertTo-Json $r -Depth 10) -notmatch 'PRIVATE-BITLOCKER')
    }
}
foreach($fault in @('ForeignDevice','LegacyDevice','InvalidScan','WrongCheck','HardwareFailure','HardwareAmbiguous')) {
    Test-WinSecBitLockerCase ('Identity fails before querying OS or BitLocker: '+$fault) {
        $argsMap=@{DeviceId=$script:id;ScanId='unit-scan';CheckId='WSA-SYS-002'}
        switch($fault) {
            ForeignDevice {$argsMap.DeviceId='local:hw1-'+('b'*64)}
            LegacyDevice {$argsMap.DeviceId='local:HOST'}
            InvalidScan {$argsMap.ScanId="scan`nBAD"}
            WrongCheck {$argsMap.CheckId='WSA-SYS-001'}
            HardwareFailure {$script:identityFails=$true}
            HardwareAmbiguous {$script:localIds=@($script:id,$script:id)}
        }
        Assert-WinSecBitLockerRejects {Test-WinSecBitLocker @argsMap}
        Assert-WinSecBitLocker ($script:queries -eq 0 -and $script:methods.Count -eq 0)
    }
}
foreach($spec in @(
    @{Code=2147942405;Kind='ACCESS_DENIED'},@{Code=2147749891;Kind='ACCESS_DENIED'},
    @{Code=2147749902;Kind='NAMESPACE_NOT_FOUND'},@{Code=2147749904;Kind='CLASS_NOT_FOUND'},
    @{Code=2147749937;Kind='PROPERTY_NOT_FOUND'},@{Code=2147749911;Kind='INVALID_QUERY'},
    @{Code=2147749905;Kind='PROVIDER_NOT_REGISTERED'},@{Code=2147749907;Kind='PROVIDER_LOAD_FAILED'},
    @{Code=2147749908;Kind='PROVIDER_INITIALIZATION_FAILED'})) {
    Test-WinSecBitLockerCase ('Typed HRESULT classifies the failed provider query without raw text: '+$spec.Kind) {
        $signed=[int]([long]$spec.Code-4294967296L)
        $script:queryException=[System.Runtime.InteropServices.COMException]::new('PRIVATE-BITLOCKER-ERROR',$signed)
        $script:exceptionClass='Win32_EncryptableVolume'
        $r=Invoke-WinSecBitLockerFixture
        Assert-WinSecBitLocker ($r.Evidence.CollectionIssues.Count -eq 1 -and
            $r.Evidence.CollectionIssues[0] -ceq ('BITLOCKER_PROVIDER_'+$spec.Kind) -and $r.Status -ceq 'ERROR' -and
            -not $r.Evidence.CollectionSuccessful -and $script:methods.Count -eq 0 -and $null -eq $r.NotApplicableReason -and
            (ConvertTo-Json $r -Depth 12) -notmatch 'PRIVATE-BITLOCKER|COMException|HResult|ErrorData')
    }
}
foreach($class in @('Win32_OperatingSystem','Win32_EncryptableVolume')) {
    foreach($kind in @('ACCESS_DENIED','TIMEOUT')) {
        Test-WinSecBitLockerCase ('Distinguishes typed permission and timeout errors at their actual query stage: '+$class+' '+$kind) {
            $script:exceptionClass=$class
            $script:queryException=if($kind -ceq 'ACCESS_DENIED'){[System.UnauthorizedAccessException]::new('PRIVATE-BITLOCKER-ERROR')}
                else{[System.TimeoutException]::new('PRIVATE-BITLOCKER-ERROR')}
            $prefix=if($class -ceq 'Win32_OperatingSystem'){'OS_VOLUME_QUERY'}else{'BITLOCKER_PROVIDER'}
            $r=Invoke-WinSecBitLockerFixture
            Assert-WinSecBitLocker ($r.Evidence.CollectionIssues[0] -ceq ($prefix+'_'+$kind) -and $r.Status -ceq 'ERROR' -and
                $script:methods.Count -eq 0 -and $null -eq $r.NotApplicableReason -and
                (ConvertTo-Json $r -Depth 12) -notmatch 'PRIVATE-BITLOCKER')
        }
    }
}
foreach($spec in @(@{Code=2;Kind='ACCESS_DENIED'},@{Code=3;Kind='NAMESPACE_NOT_FOUND'},@{Code=4;Kind='INVALID_PARAMETER'},
    @{Code=5;Kind='CLASS_NOT_FOUND'},@{Code=7;Kind='OPERATION_UNSUPPORTED'},@{Code=12;Kind='PROPERTY_NOT_FOUND'},
    @{Code=14;Kind='QUERY_UNSUPPORTED'},@{Code=15;Kind='INVALID_QUERY'},@{Code=16;Kind='METHOD_UNAVAILABLE'},
    @{Code=17;Kind='METHOD_UNAVAILABLE'},@{Code=2147749891;Kind='ACCESS_DENIED'},@{Code=999;Kind='UNAVAILABLE'})) {
    Test-WinSecBitLockerCase ('Actual CimException type preserves MI and WBEM distinctions without a provider query: '+$spec.Code) {
        $errorData=[Microsoft.Management.Infrastructure.CimInstance]::new('CIM_Error')
        try {
            $errorData.CimInstanceProperties.Add([Microsoft.Management.Infrastructure.CimProperty]::Create('CIMStatusCode',[uint32]$spec.Code,
                [Microsoft.Management.Infrastructure.CimType]::UInt32,[Microsoft.Management.Infrastructure.CimFlags]::Property))
            $script:queryException=[Microsoft.Management.Infrastructure.CimException]::new($errorData)
            $script:exceptionClass='Win32_EncryptableVolume'
            $r=Invoke-WinSecBitLockerFixture
            Assert-WinSecBitLocker ($r.Evidence.CollectionIssues[0] -ceq ('BITLOCKER_PROVIDER_'+$spec.Kind) -and
                $r.Status -ceq 'ERROR' -and $null -eq $r.NotApplicableReason -and $script:methods.Count -eq 0 -and
                (ConvertTo-Json $r -Depth 12) -notmatch 'CIM_Error|CIMStatusCode|CimException|ErrorData')
        } finally {$errorData.Dispose();if($null -ne $script:queryException){$script:queryException.Dispose()}}
    }
}
Test-WinSecBitLockerCase 'Provider error text and invented extended fields cannot manufacture a typed diagnosis' {
    $script:queryException=[System.Exception]::new('Access denied 0x80070005 namespace not found PRIVATE-BITLOCKER')
    $script:queryException|Add-Member -NotePropertyName NativeErrorCode -NotePropertyValue 2
    $script:queryException|Add-Member -NotePropertyName HResult -NotePropertyValue -2147024891 -Force
    $script:exceptionClass='Win32_EncryptableVolume'
    $r=Invoke-WinSecBitLockerFixture
    Assert-WinSecBitLocker ($r.Evidence.CollectionIssues[0] -ceq 'BITLOCKER_PROVIDER_UNAVAILABLE' -and
        (ConvertTo-Json $r -Depth 12) -notmatch 'PRIVATE-BITLOCKER|0x80070005|NativeErrorCode')
}
Test-WinSecBitLockerCase 'Nested typed failures are classified without exposing wrapper messages' {
    $cause=[System.UnauthorizedAccessException]::new('PRIVATE-BITLOCKER-ERROR')
    $script:queryException=[System.Exception]::new('PRIVATE-BITLOCKER-WRAPPER',$cause)
    $script:exceptionClass='Win32_EncryptableVolume'
    Assert-WinSecBitLocker ((Invoke-WinSecBitLockerFixture).Evidence.CollectionIssues[0] -ceq 'BITLOCKER_PROVIDER_ACCESS_DENIED')
}
Test-WinSecBitLockerCase 'Method permission failure preserves valid sibling telemetry with no inferred failure or score' {
    $script:methodException=[System.UnauthorizedAccessException]::new('PRIVATE-BITLOCKER-ERROR');$script:exceptionMethod='GetProtectionStatus'
    $r=Invoke-WinSecBitLockerFixture
    Assert-WinSecBitLocker ($r.Status -ceq 'INFORMATIONAL' -and $r.Evidence.CollectionSuccessful -and -not $r.Evidence.CollectionComplete -and
        $r.Evidence.CollectionIssues -ccontains 'GetProtectionStatus_ACCESS_DENIED' -and $r.Evidence.SystemVolume.ProtectionStatus -ceq 'UNKNOWN' -and
        $r.Evidence.SystemVolume.ConversionStatus -ceq 'FULLY_ENCRYPTED' -and $script:methods.Count -eq 4 -and
        (ConvertTo-Json $r -Depth 12) -notmatch 'PRIVATE-BITLOCKER')
}
foreach($spec in @(@{Code=2147942405;Kind='ACCESS_DENIED'},@{Code=2150694912;Kind='VOLUME_LOCKED'})) {
    Test-WinSecBitLockerCase ('A failed method return is categorized without trusting its apparent result: '+$spec.Kind) {
        $script:responses.GetProtectionStatus.ReturnValue=[uint32]$spec.Code
        $r=Invoke-WinSecBitLockerFixture
        Assert-WinSecBitLocker ($r.Evidence.SystemVolume.ProtectionStatus -ceq 'UNKNOWN' -and
            $r.Evidence.CollectionIssues -ccontains ('GetProtectionStatus_'+$spec.Kind) -and -not $r.Evidence.CollectionComplete)
    }
}
Test-WinSecBitLockerCase 'Unknown native return codes remain unclassified and never become applicability exclusions' {
    $script:responses.GetProtectionStatus.ReturnValue=[uint32]12345
    $r=Invoke-WinSecBitLockerFixture
    Assert-WinSecBitLocker ($r.Evidence.CollectionIssues -ccontains 'GetProtectionStatus_UNAVAILABLE' -and $null -eq $r.NotApplicableReason)
}
Test-WinSecBitLockerCase 'Read-only source has no recovery-key access, external tools, writes or remote parameters' {
    $tokens=$null;$errors=$null;$ast=[System.Management.Automation.Language.Parser]::ParseFile($collector,[ref]$tokens,[ref]$errors)
    $commands=@($ast.FindAll({param($n)$n -is [System.Management.Automation.Language.CommandAst]},$true))
    $allowed=@('Get-WinSecBitLockerProperty','ConvertTo-WinSecBitLockerUInt32','Get-WinSecBitLockerFailureKind','Get-WinSecLocalHardwareDeviceId','New-Object','Get-CimInstance','Invoke-CimMethod','Where-Object')
    foreach($command in $commands) {
        Assert-WinSecBitLocker ($command.GetCommandName() -cin $allowed)
        Assert-WinSecBitLocker (@($command.CommandElements|Where-Object {$_ -is [System.Management.Automation.Language.CommandParameterAst] -and
            $_.ParameterName -in @('ComputerName','CimSession','Credential')}).Count -eq 0)
    }
    Assert-WinSecBitLocker ($errors.Count -eq 0 -and $ast.Extent.Text -notmatch 'GetKeyProtector|GetExternalKey|GetKeyPackage|Get-BitLockerVolume|manage-bde|Enable-BitLocker|Unlock-BitLocker')
}
[Console]::WriteLine(('BitLocker unit: {0} passed, {1} failed.' -f $script:passed,$script:failed))
if($script:failed){throw 'BitLocker unit tests failed.'}
