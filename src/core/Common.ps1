function Get-WinSecRoot { return $script:WinSecRoot }

function Assert-WinSecWindows11 {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'Solo se admite Windows 11 cliente. Este sistema no es Windows.'
    }
    try { $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop }
    catch { throw ('No se pudo verificar el sistema operativo: ' + $_.Exception.Message) }
    $build = 0
    if (-not [int]::TryParse([string]$os.BuildNumber, [ref]$build)) {
        throw 'No se pudo comprobar la compilacion de Windows.'
    }
    if ([int]$os.ProductType -ne 1 -or $build -lt 22000) {
        throw ('SO no admitido: solamente Windows 11 cliente (ProductType=1, build>=22000). Detectado: ' + $os.Caption + ', build ' + $build)
    }
    $edition = 'Unknown'
    try {
        $reg = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
        if ($reg.EditionID) { $edition = [string]$reg.EditionID }
    } catch { }
    return [pscustomobject]@{
        Caption=[string]$os.Caption; Build=$build; Version=[string]$os.Version;
        Edition=$edition; ProductType=[int]$os.ProductType; Arch=[string]$os.OSArchitecture
    }
}

function Test-WinSecElevated {
    try {
        $id=[Security.Principal.WindowsIdentity]::GetCurrent()
        $principal=New-Object Security.Principal.WindowsPrincipal($id)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function ConvertTo-WinSecSafeName {
    param([Parameter(Mandatory)][string]$Value)
    return ([regex]::Replace($Value, '[^a-zA-Z0-9._-]', '_'))
}

function Select-WinSecProperties {
    param($InputObject, [string[]]$Names)
    $out=[ordered]@{}
    if ($null -eq $InputObject) { return $out }
    foreach ($n in $Names) {
        $p=$InputObject.PSObject.Properties[$n]
        if ($null -ne $p) {
            $v=$p.Value
            if ($v -is [System.Enum]) { $v=[string]$v }
            elseif ($v -is [DateTime]) { $v=$v.ToUniversalTime().ToString('o') }
            $out[$n]=$v
        }
    }
    return $out
}

function Get-WinSecRegistryValues {
    param([string]$Path,[string[]]$Names)
    $out=[ordered]@{ path=$Path; exists=$false; values=[ordered]@{} }
    if (-not (Test-Path -LiteralPath $Path)) { return $out }
    $out.exists=$true
    $obj=Get-ItemProperty -LiteralPath $Path -ErrorAction Stop
    foreach ($name in $Names) {
        if ($null -ne $obj.PSObject.Properties[$name]) {
            $out.values[$name]=$obj.PSObject.Properties[$name].Value
        }
    }
    return $out
}

function Test-WinSecCommand {
    param([string]$Name)
    return ($null -ne (Get-Command -Name $Name -ErrorAction SilentlyContinue))
}

function New-WinSecPayload {
    param(
        [Parameter(Mandatory)]$Data,
        [string[]]$Sources=@(),
        [string[]]$Warnings=@(),
        [ValidateSet('COMPLETED','PARTIAL','NOT_APPLICABLE','ERROR')][string]$Status='COMPLETED'
    )
    $clean=@($Warnings | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    if ($clean.Count -gt 0 -and $Status -eq 'COMPLETED') { $Status='PARTIAL' }
    return [pscustomobject]@{ status=$Status; data=$Data; sources=@($Sources); warnings=$clean }
}

function Get-WinSecCatalog {
    $path=Join-Path $script:WinSecRoot 'catalog/collectors.json'
    return @((Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json).collectors)
}

function Resolve-WinSecDomain {
    param([string]$Name)
    switch (([regex]::Replace($Name.ToLowerInvariant(), '[^a-z0-9*]', ''))) {
        { $_ -in @('all','*') } { return 'all' }
        { $_ -in @('system','systemsecurity','1') } { return 'SystemSecurity' }
        { $_ -in @('network','networksecurity','networkingsecurity','2') } { return 'NetworkSecurity' }
        { $_ -in @('identity','identityaccess','3') } { return 'IdentityAccess' }
        { $_ -in @('services','serviceshardening','hardening','4') } { return 'ServicesHardening' }
        { $_ -in @('logging','loggingauditing','5') } { return 'LoggingAuditing' }
        { $_ -in @('patch','patchmanagement','update','6') } { return 'PatchManagement' }
        default { throw "Dominio no reconocido: $Name" }
    }
}
