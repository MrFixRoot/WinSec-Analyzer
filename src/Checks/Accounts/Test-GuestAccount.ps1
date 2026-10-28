# WinSec Analyzer
# Archivo: src\Checks\Accounts\Test-GuestAccount.ps1
function Test-WinSecGuestAccount {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$DeviceId,[Parameter(Mandatory)][string]$ScanId,[string]$CheckId='WSA-IAM-002',
        [scriptblock]$ProgressCallback,[scriptblock]$CancellationAction)
    if($CheckId -cne 'WSA-IAM-002'){throw 'Invalid Guest identity.'}
    Invoke-WinSecIdentityAccessCollection $DeviceId $ScanId $CheckId $ProgressCallback $CancellationAction
}
