# Synthetic identity boundary for integration tests. No hardware/inventory reads.
function Get-CimInstance {
    [CmdletBinding()]
    param($Namespace,$ClassName,$Property,$OperationTimeoutSec)
    if($Namespace -cne 'root/cimv2' -or $ClassName -cne 'Win32_ComputerSystemProduct') {
        throw 'Unexpected Windows query in local identity fixture.'
    }
    [pscustomobject]@{UUID='12345678-1234-4567-89ab-123456789abc'}
}
function Import-WinSecDeviceInventory {
    param($ProjectRoot)
    [pscustomobject]@{schemaVersion='1.2.0';targets=@(New-WinSecLocalTarget);removedDeviceHashes=@()}
}
