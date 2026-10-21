# WinSec Analyzer
# Archivo: src\Services\SystemInfoService.ps1
# Contexto local de aplicabilidad; importar este archivo no consulta Windows.
# Dependencia: TargetRegistry. Sólo ScanCoordinator lo invoca tras confirmar.

function Get-WinSecLocalAssessmentContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DeviceId,
        [Parameter(Mandatory)][string]$ScanId
    )

    if ($DeviceId -cnotmatch '\Alocal:hw1-[a-f0-9]{64}\z' -or
        -not (Test-WinSecTargetIdentifier -Value $ScanId)) {
        throw 'Invalid local assessment context identity.'
    }
    try { $localIds = @(Get-WinSecLocalHardwareDeviceId -ErrorAction Stop) }
    catch { throw 'Unable to validate local assessment context identity.' }
    if ($localIds.Count -ne 1 -or $localIds[0] -isnot [string] -or $localIds[0] -cne $DeviceId) {
        throw 'Assessment context is restricted to the current local hardware.'
    }

    $context = [pscustomobject]@{
        DeviceId = $DeviceId
        ScanId = $ScanId
        OSFamily = 'Windows'
        OSRelease = 'UNRESOLVED'
        Edition = 'UNRESOLVED'
        Profile = 'UNRESOLVED'
    }
    # Request only applicability metadata. No remote/session parameters, registry,
    # product keys, registered users, machine names or security-product queries.
    try {
        $systems = @(Get-CimInstance -Namespace 'root/cimv2' -ClassName 'Win32_OperatingSystem' `
            -Property @('Caption','Version','BuildNumber','OperatingSystemSKU','ProductType') `
            -OperationTimeoutSec 10 -ErrorAction Stop)
    }
    catch { return $context }
    if ($systems.Count -ne 1 -or $null -eq $systems[0]) { return $context }

    $os = $systems[0]
    $caption = $os.Caption
    $version = $os.Version
    $build = $os.BuildNumber
    $productType = $os.ProductType
    $sku = $os.OperatingSystemSKU
    # ProductType=1 is a workstation. A build threshold alone must not classify
    # Server or a future Windows product as Windows 11. Keep the precise version,
    # rather than guessing a marketing release such as 24H2 from a mutable table.
    if ($caption -isnot [string] -or $caption.Length -gt 128 -or $caption -match '[\p{C}]' -or
        $caption.Trim() -notmatch '\A(?:Microsoft )?Windows 11(?: .*)?\z' -or
        $version -isnot [string] -or $version -cnotmatch '\A10\.0\.([1-9][0-9]{0,8})\z' -or
        $build -isnot [string] -or $build -cnotmatch '\A[1-9][0-9]{0,8}\z' -or
        $version -cne ('10.0.' + $build) -or [long]$build -lt 22000 -or
        ($productType -isnot [uint32] -and $productType -isnot [int]) -or $productType -ne 1) {
        return $context
    }
    $context.OSRelease = 'Windows 11 ' + $version
    # SKU is the native edition identifier. Do not translate it using an
    # incomplete name table or infer a CIS/local-policy profile from the edition.
    if (($sku -is [uint32] -or $sku -is [int]) -and $sku -gt 0) {
        $context.Edition = 'SKU:' + $sku.ToString([Globalization.CultureInfo]::InvariantCulture)
    }
    return $context
}
