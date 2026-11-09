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
    $displayVersion=$null; $ubr=$null; $installationType=$null; $warnings=@()
    try {
        $reg = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
        foreach ($name in @('EditionID','DisplayVersion','InstallationType')) {
            $property=$reg.PSObject.Properties[$name]
            if ($null -eq $property -or $property.Value -isnot [string] -or [string]::IsNullOrWhiteSpace($property.Value)) {
                $warnings+=('CurrentVersion.'+$name+': valor no disponible o invalido.')
                continue
            }
            switch ($name) {
                'EditionID' { $edition=$property.Value.Trim() }
                'DisplayVersion' { $displayVersion=$property.Value.Trim() }
                'InstallationType' { $installationType=$property.Value.Trim() }
            }
        }
        $property=$reg.PSObject.Properties['UBR']
        $revision=0
        if ($null -ne $property -and [int]::TryParse([string]$property.Value,[ref]$revision) -and $revision -ge 0) { $ubr=$revision }
        else { $warnings+=('CurrentVersion.UBR: valor no disponible o invalido.') }
    } catch { $warnings+=('CurrentVersion: '+$_.Exception.Message) }
    return [pscustomobject]@{
        Caption=[string]$os.Caption; Build=$build; Version=[string]$os.Version;
        Edition=$edition; ProductType=[int]$os.ProductType; Arch=[string]$os.OSArchitecture
        DisplayVersion=$displayVersion; UBR=$ubr; InstallationType=$installationType
        Status=$(if ($warnings.Count -gt 0) {'PARTIAL'} else {'COMPLETED'}); Warnings=$warnings
    }
}

function ConvertTo-WinSecOSMetadata {
    param($OS)
    $safe=Select-WinSecProperties -InputObject $OS -Names @('Caption','Build','Version','Edition','Arch','DisplayVersion','UBR','InstallationType','Warnings')
    $warnings=@($safe['Warnings'] | Where-Object {-not [string]::IsNullOrWhiteSpace([string]$_)})
    return [ordered]@{
        family='Windows11'; caption=$safe['Caption']; build=$safe['Build']; version=$safe['Version']
        edition=$safe['Edition']; arch=$safe['Arch']; productType=1
        displayVersion=$safe['DisplayVersion']; ubr=$safe['UBR']; installationType=$safe['InstallationType']
        status=$(if ($warnings.Count -gt 0) {'PARTIAL'} else {'COMPLETED'}); warnings=$warnings
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

function ConvertTo-WinSecControlName {
    param([string]$Name)
    $prefix=[regex]::Match($Name,'^[A-Z]+(?=[A-Z][a-z]|$)|^[A-Z]')
    if ($prefix.Success) { return $prefix.Value.ToLowerInvariant()+$Name.Substring($prefix.Length) }
    return $Name
}

function Format-WinSecSnapshotPath {
    param([Parameter(Mandatory)][string]$Snapshot)
    $path=[IO.Path]::GetFullPath($Snapshot)
    if (Test-Path -LiteralPath $path -PathType Container) { $path=Join-Path $path 'manifest.json' }
    $run=[IO.Path]::GetDirectoryName($path)
    $device=[IO.Path]::GetDirectoryName($run)
    return ('../'+[IO.Path]::GetFileName($device)+'\'+[IO.Path]::GetFileName($run)+'\'+[IO.Path]::GetFileName($path))
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
        { $_ -in @('logging','login','loggingauditing','5') } { return 'LoggingAuditing' }
        { $_ -in @('patch','patchmanagement','update','6') } { return 'PatchManagement' }
        default { throw "Dominio no reconocido: $Name" }
    }
}
