function New-WinSecSession {
    param([string]$OutputRoot,[string]$Snapshot)
    return [pscustomobject]@{
        OutputRoot=(Get-WinSecOutputRoot -OutputRoot $OutputRoot)
        Snapshot=$Snapshot; RunId=$null; Context=$null; Closed=$false; HintIndex=0
        DeviceId=$null; DeviceName=$null; Notice=$null
        SavedContexts=@()
    }
}

function Get-WinSecSessionContexts {
    param($Session)
    if ($null -ne $Session.Context) { $Session.Context }
    foreach ($context in $Session.SavedContexts) {
        if ($context.Path -ne $Session.Snapshot) { $context }
    }
}

function Get-WinSecSessionSnapshot {
    param($Session,[string]$Collector,[string]$Domain)
    if ($Collector -or ($Domain -and $Domain -ne 'all')) {
        $ids=if ($Collector) {@($Collector)} else {@(Get-WinSecCatalog | Where-Object {$_.domain -eq $Domain} | ForEach-Object {$_.id})}
        foreach ($context in @(Get-WinSecSessionContexts $Session)) {
            if (@($context.Manifest.collectors | Where-Object {$_.id -in $ids}).Count -gt 0) { return [string]$context.Path }
        }
    }
    if (-not $Session.Snapshot) {
        throw 'No hay evidencia en esta sesion. Escribe winsec -s o winsec -s <seccion>.'
    }
    return [string]$Session.Snapshot
}

function Close-WinSecSession {
    param($Session)
    if ($null -eq $Session -or $Session.Closed) { return }
    if ($null -ne $Session.Context -and $Session.RunId) {
        $context=Get-WinSecSnapshotManifest -Snapshot $Session.Snapshot
        if ($context.Manifest.runId -ne $Session.RunId -or $context.Manifest.sessionState -ne 'OPEN') {
            throw 'La captura no pertenece a esta sesion abierta.'
        }
        $context.Manifest.sessionState='CLOSED'
        if ($context.Manifest.status -eq 'RUNNING') { $context.Manifest.status='PARTIAL' }
        $context.Manifest.finishedAtUtc=(Get-Date).ToUniversalTime().ToString('o')
        [void](Save-WinSecJson -Path $context.Path -Value $context.Manifest)
        $Session.Context=$context
    }
    $Session.Closed=$true
}

function New-WinSecCollectionContext {
    param($OS,[string]$OutputRoot,[string]$Domain,[string]$Collector,[switch]$Deep,[switch]$Interactive)
    $root=Get-WinSecOutputRoot -OutputRoot $OutputRoot
    $osFolder='Windows11_'+(ConvertTo-WinSecSafeName $OS.Edition)+'_'+$OS.Build
    $hostFolder=ConvertTo-WinSecSafeName $env:COMPUTERNAME
    $stamp=(Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $runId=[guid]::NewGuid().ToString('N')
    $base=Join-Path (Join-Path (Join-Path $root $osFolder) $hostFolder) ($stamp+'_'+$runId)
    [void](New-Item -ItemType Directory -Path $base -ErrorAction Stop)
    $manifest=[ordered]@{
        schemaVersion='1'; runId=$runId; startedAtUtc=(Get-Date).ToUniversalTime().ToString('o')
        finishedAtUtc=$null; status='RUNNING'; host=$env:COMPUTERNAME
        os=[ordered]@{ family='Windows11'; caption=$OS.Caption; build=$OS.Build; edition=$OS.Edition; arch=$OS.Arch; productType=1 }
        elevated=(Test-WinSecElevated); mode=$(if ($Deep) { 'DEEP' } else { 'STANDARD' })
        scope=[ordered]@{ domain=$(if ($Interactive) {'all'} else {$Domain}); collector=$(if ($Interactive) {$null} else {$Collector}) }
        sessionState=$(if ($Interactive) {'OPEN'} else {'CLOSED'}); collectors=@()
    }
    $manifestPath=Join-Path $base 'manifest.json'
    [void](Save-WinSecJson -Path $manifestPath -Value $manifest)
    return [pscustomobject]@{ Path=$manifestPath; Base=$base; Manifest=$manifest }
}
