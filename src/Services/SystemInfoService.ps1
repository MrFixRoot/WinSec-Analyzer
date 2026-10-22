# WinSec Analyzer
# Archivo: src\Services\SystemInfoService.ps1
# Contexto local de aplicabilidad; importar este archivo no consulta Windows.
# Dependencias: TargetRegistry y lector de matriz. El contexto de evaluación
# exige escaneo confirmado; el resumen informativo local se consulta al iniciar.

function Get-WinSecLocalSystemSummary {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$DeviceId,[Parameter(Mandatory)][string]$ProjectRoot)

    if ($DeviceId -cnotmatch '\Alocal:hw1-[a-f0-9]{64}\z') { throw 'Invalid local system identity.' }
    try { $localIds = @(Get-WinSecLocalHardwareDeviceId -ErrorAction Stop) }
    catch { throw 'Unable to validate local system identity.' }
    if ($localIds.Count -ne 1 -or $localIds[0] -isnot [string] -or $localIds[0] -cne $DeviceId) {
        throw 'System information is restricted to the current local hardware.'
    }
    $summary = [pscustomobject]@{DeviceId=$DeviceId;Label='Unavailable'}
    try {
        $systems = @(Get-CimInstance -Namespace 'root/cimv2' -ClassName 'Win32_OperatingSystem' `
            -Property @('Caption','Version','BuildNumber','OperatingSystemSKU','ProductType') -OperationTimeoutSec 10 -ErrorAction Stop)
    }
    catch { return $summary }
    if ($systems.Count -ne 1 -or $null -eq $systems[0]) { return $summary }
    $os = $systems[0]
    if ($os.Caption -isnot [string] -or $os.Caption.Length -gt 128 -or $os.Caption -match '[\p{C}]' -or
        $os.Caption.Trim() -notmatch '\A(?:Microsoft )?Windows 11(?: .*)?\z' -or
        $os.BuildNumber -isnot [string] -or $os.BuildNumber -cnotmatch '\A[1-9][0-9]{0,8}\z' -or
        [long]$os.BuildNumber -lt 22000 -or $os.Version -isnot [string] -or $os.Version -cne ('10.0.'+$os.BuildNumber) -or
        ($os.ProductType -isnot [uint32] -and $os.ProductType -isnot [int]) -or $os.ProductType -ne 1 -or
        ($os.OperatingSystemSKU -isnot [uint32] -and $os.OperatingSystemSKU -isnot [int]) -or $os.OperatingSystemSKU -le 0) {
        return $summary
    }
    # The validated matrix supplies labels only, never an evaluation profile.
    try { $matrix = (Get-WinSecDefenderProfileMatrix -ProjectRoot $ProjectRoot).Matrix }
    catch { return $summary }
    $editions = @($matrix.Editions | Where-Object {$_.Sku -eq $os.OperatingSystemSKU})
    $releases = @($matrix.Releases | Where-Object {$_.Build -eq [long]$os.BuildNumber})
    $edition = if ($editions.Count -eq 1) {$editions[0].Name} else {'Edition unknown (SKU:{0})' -f $os.OperatingSystemSKU}
    $release = if ($releases.Count -eq 1) {$releases[0].Name} else {'Version unknown'}
    $summary.Label = '{0} {1} | build: {2}' -f $edition,$release,$os.BuildNumber
    return $summary
}

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
