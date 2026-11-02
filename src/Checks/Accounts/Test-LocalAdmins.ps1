# WinSec Analyzer
# Archivo: src\Checks\Accounts\Test-LocalAdmins.ps1
function Test-WinSecLocalAdmins {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$DeviceId,[Parameter(Mandatory)][string]$ScanId,[string]$CheckId='WSA-IAM-001',
        [scriptblock]$ProgressCallback,[scriptblock]$CancellationAction)
    if($CheckId -cne 'WSA-IAM-001'){throw 'Invalid Local Administrators identity.'}
    Invoke-WinSecIdentityAccessCollection $DeviceId $ScanId $CheckId $ProgressCallback $CancellationAction
}
