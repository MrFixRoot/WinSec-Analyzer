# WinSec Analyzer
# Archivo: src\Checks\Policies\Test-PasswordPolicy.ps1
function Test-WinSecPasswordPolicy {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$DeviceId,[Parameter(Mandatory)][string]$ScanId,[string]$CheckId='WSA-IAM-003',
        [scriptblock]$ProgressCallback,[scriptblock]$CancellationAction)
    if($CheckId -cne 'WSA-IAM-003'){throw 'Invalid Password Policies identity.'}
    Invoke-WinSecIdentityAccessCollection $DeviceId $ScanId $CheckId $ProgressCallback $CancellationAction
}
