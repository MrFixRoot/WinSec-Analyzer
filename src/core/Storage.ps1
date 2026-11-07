function Get-WinSecOutputRoot {
    param([string]$OutputRoot)
    if ($OutputRoot) {
        $requested=[System.IO.Path]::GetFullPath($OutputRoot)
        $project=[System.IO.Path]::GetFullPath($script:WinSecRoot).TrimEnd([IO.Path]::DirectorySeparatorChar)+[IO.Path]::DirectorySeparatorChar
        if ($requested.TrimEnd([IO.Path]::DirectorySeparatorChar) -eq $project.TrimEnd([IO.Path]::DirectorySeparatorChar)) {
            throw 'OutputRoot no puede ser la raiz del repositorio.'
        }
        if ($requested.StartsWith($project,[StringComparison]::OrdinalIgnoreCase)) {
            $relative=$requested.Substring($project.Length)
            $first=($relative -split '[\\/]')[0].ToLowerInvariant()
            if ($first -notin @('device','devices','scans','snapshots','evidence','output','reports','logs','tmp','temp','artifacts')) {
                throw 'OutputRoot apunta a un directorio del repositorio no excluido por .gitignore. Usa device/ o una ruta fuera del repositorio.'
            }
        }
        return $requested
    }
    return (Join-Path $script:WinSecRoot 'device')
}

function Save-WinSecJson {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)]$Value)
    $parent=Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent)) { [void](New-Item -ItemType Directory -Path $parent -Force) }
    $json=ConvertTo-Json -InputObject $Value -Depth 40
    $temp=Join-Path $parent ('.'+[guid]::NewGuid().ToString('N')+'.tmp')
    $utf8=New-Object System.Text.UTF8Encoding($false)
    try {
        [System.IO.File]::WriteAllText($temp, $json + [Environment]::NewLine, $utf8)
        [void](Get-Content -LiteralPath $temp -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop)
        for ($attempt=0; ; $attempt++) {
            try {
                if (Test-Path -LiteralPath $Path) {
                    [System.IO.File]::Replace($temp, $Path, [NullString]::Value)
                } else {
                    [System.IO.File]::Move($temp, $Path)
                }
                break
            } catch {
                $cause=$_.Exception.GetBaseException()
                $code=$cause.HResult -band 0xffff
                # Windows readers can briefly block replacement. Keep the validated
                # temporary JSON and retry only sharing/locking/replace conflicts.
                if ($attempt -ge 3 -or $cause -isnot [IO.IOException] -or $code -notin @(32,33,1175) -or -not (Test-Path -LiteralPath $temp)) { throw }
                Start-Sleep -Milliseconds (25*[math]::Pow(2,$attempt))
            }
        }
    } finally {
        if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue }
    }
    return (Get-Item -LiteralPath $Path)
}

function Get-WinSecHash {
    param([string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
}

function Get-WinSecSnapshotManifest {
    param([string]$Snapshot,[string]$OutputRoot)
    if ($Snapshot) {
        $p=[System.IO.Path]::GetFullPath($Snapshot)
        if ((Test-Path -LiteralPath $p -PathType Container)) { $p=Join-Path $p 'manifest.json' }
        if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { throw "Snapshot no encontrado: $p" }
        $m=Get-Content -LiteralPath $p -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($m.schemaVersion -ne '1') { throw 'Version de esquema de snapshot no compatible.' }
        return [pscustomobject]@{ Path=$p; Base=Split-Path -Parent $p; Manifest=$m }
    }
    $root=Get-WinSecOutputRoot -OutputRoot $OutputRoot
    if (-not (Test-Path -LiteralPath $root)) { throw 'No existen snapshots. Ejecuta primero un escaneo.' }
    # Por seguridad, el snapshot automatico solamente pertenece al host actual.
    $hostDir=ConvertTo-WinSecSafeName $env:COMPUTERNAME
    $candidates=@(Get-ChildItem -LiteralPath $root -Filter manifest.json -File -Recurse -ErrorAction Stop |
        Where-Object { $_.Directory.Parent.Name -eq $hostDir } | Sort-Object LastWriteTimeUtc -Descending)
    if ($candidates.Count -eq 0) { throw 'No se encontraron snapshots del equipo actual.' }
    $p=$candidates[0].FullName
    $m=Get-Content -LiteralPath $p -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($m.schemaVersion -ne '1') { throw 'Version de esquema de snapshot no compatible.' }
    return [pscustomobject]@{ Path=$p; Base=Split-Path -Parent $p; Manifest=$m }
}

function Get-WinSecEvidenceFile {
    param($Context,[string]$CollectorId)
    $entry=@($Context.Manifest.collectors | Where-Object { $_.id -eq $CollectorId } | Select-Object -First 1)
    if ($entry.Count -eq 0) { return $null }
    $rel=[string]$entry[0].path
    if ([string]::IsNullOrEmpty($rel)) { return $null }
    if ([IO.Path]::IsPathRooted($rel) -or $rel.Contains('..') -or $rel.Contains(':')) { throw 'Ruta de evidencia no segura.' }
    $full=[IO.Path]::GetFullPath((Join-Path $Context.Base ($rel -replace '/', [IO.Path]::DirectorySeparatorChar)))
    $basePrefix=[IO.Path]::GetFullPath($Context.Base).TrimEnd([IO.Path]::DirectorySeparatorChar)+[IO.Path]::DirectorySeparatorChar
    if (-not $full.StartsWith($basePrefix,[StringComparison]::OrdinalIgnoreCase)) { throw 'Evidencia fuera del snapshot.' }
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { return $null }
    $actual=Get-WinSecHash -Path $full
    if ($entry[0].sha256 -and ($actual -ne [string]$entry[0].sha256)) { throw "Integridad invalida para $CollectorId" }
    return (Get-Content -LiteralPath $full -Raw -Encoding UTF8 | ConvertFrom-Json)
}
