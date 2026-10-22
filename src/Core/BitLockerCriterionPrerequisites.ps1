# Prerrequisitos puros compartidos por evaluación y validación de procedencia.
function Resolve-WinSecBitLockerDependencies {
    [CmdletBinding()]
    param([object]$ControlResult,[System.Collections.IDictionary]$DeclaredDependencies)
    $dependencies=if($null -eq $DeclaredDependencies){@{}}else{Copy-WinSecResultData $DeclaredDependencies}
    $allowed=@{}
    foreach($key in @('bitlocker-os-volume','bitlocker-stable-conversion','bitlocker-valid-protection')) {
        $allowed[$key]=(-not $dependencies.Contains($key) -or ($dependencies[$key] -is [bool] -and $dependencies[$key] -ceq $true))
        $dependencies[$key]=$false
    }
    $control=Copy-WinSecResultData $ControlResult;$evidence=Get-WinSecResultField $control 'Evidence';$complete=$true
    foreach($field in @('CheckId','DeviceId','ScanId')) {
        $expected=Get-WinSecResultField $control $field;$actual=Get-WinSecResultField $evidence $field
        if(-not (Test-WinSecTargetIdentifier $expected)){throw 'Invalid BitLocker prerequisite identity.'}
        if($null -ne $actual -and ($actual -isnot [string] -or $actual -cne $expected)){throw 'Foreign BitLocker prerequisite evidence.'}
        if($null -eq $actual){$complete=$false}
    }
    $successful=Get-WinSecResultField $evidence 'CollectionSuccessful'
    $observed=Get-WinSecResultField $control 'ObservedStatus'
    if(-not $complete -or $control.CheckId -cne 'WSA-SYS-002' -or $control.Status -isnot [string] -or $control.Status -cne 'INFORMATIONAL' -or
        ($null -ne $observed -and ($observed -isnot [string] -or $observed -cne 'INFORMATIONAL')) -or $successful -isnot [bool] -or -not $successful -or
        $evidence.SchemaVersion -isnot [string] -or $evidence.SchemaVersion -cne '1.0.0' -or
        $evidence.Scope -isnot [string] -or $evidence.Scope -cne 'OS_VOLUME_ONLY'){return ,$dependencies}
    $volume=Get-WinSecResultField $evidence 'SystemVolume'
    if($volume.DriveLetter -isnot [string] -or $volume.DriveLetter -cnotmatch '\A[A-Z]:\z'){return ,$dependencies}
    $dependencies['bitlocker-os-volume']=$allowed['bitlocker-os-volume']
    $dependencies['bitlocker-stable-conversion']=($allowed['bitlocker-stable-conversion'] -and
        $volume.ConversionStatus -is [string] -and $volume.ConversionStatus -cin @('FULLY_DECRYPTED','FULLY_ENCRYPTED') -and
        -not ($volume.ConversionStatus -ceq 'FULLY_DECRYPTED' -and $volume.ProtectionStatus -ceq 'ON'))
    $dependencies['bitlocker-valid-protection']=($allowed['bitlocker-valid-protection'] -and
        $volume.ProtectionStatus -is [string] -and $volume.ProtectionStatus -cin @('ON','OFF'))
    return ,$dependencies
}

function Assert-WinSecBitLockerScoredCollection {
    [CmdletBinding()]
    param([object]$ControlResult)
    $dependencies=Resolve-WinSecBitLockerDependencies -ControlResult $ControlResult
    foreach($key in @('bitlocker-os-volume','bitlocker-stable-conversion','bitlocker-valid-protection')) {
        if($dependencies[$key] -isnot [bool] -or -not $dependencies[$key]) {
            throw 'BitLocker scored results require verified stable OS volume telemetry.'
        }
    }
}
