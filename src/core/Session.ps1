function New-WinSecSession {
    param([string]$OutputRoot,[string]$Snapshot)
    return [pscustomobject]@{
        OutputRoot=(Get-WinSecOutputRoot -OutputRoot $OutputRoot)
        Snapshot=$Snapshot; RunId=$null; Context=$null; Closed=$false; HintIndex=0
        DeviceId=$null; DeviceName=$null; Warning=$null; Notifications=@(); MessageArea=$null
        SavedContexts=@()
    }
}

function Add-WinSecNotification {
    param($Session,[string]$Message)
    if ($null -ne $Session -and $Message) { $Session.Notifications=@($Session.Notifications)+@($Message) }
}

function Add-WinSecWarning {
    param($Session,[string]$Message)
    if ($null -ne $Session -and $Message) {
        $Session.Warning=@(@($Session.Warning)+@($Message) | Where-Object { $_ } | Select-Object -Unique)
    }
}

function Get-WinSecOptionalField {
    param($Object,[string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { return $Object[$Name] }
    $property=$Object.PSObject.Properties[$Name]
    if ($null -ne $property) { return $property.Value }
    return $null
}

function Get-WinSecContextTime {
    param($Context,[string[]]$Ids)
    $latest=[DateTime]::MinValue
    foreach ($entry in @($Context.Manifest.collectors | Where-Object {$_.id -in $Ids})) {
        $stamp=Get-WinSecOptionalField $entry 'collectedAtUtc'
        $parsed=[DateTime]::MinValue
        if ($stamp -and [DateTime]::TryParse([string]$stamp,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind,[ref]$parsed)) {
            if ($parsed.ToUniversalTime() -gt $latest) { $latest=$parsed.ToUniversalTime() }
        }
    }
    if ($latest -ne [DateTime]::MinValue) { return $latest }
    $stamp=Get-WinSecOptionalField $Context.Manifest 'startedAtUtc'
    $parsed=[DateTime]::MinValue
    if ($stamp -and [DateTime]::TryParse([string]$stamp,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind,[ref]$parsed)) { return $parsed.ToUniversalTime() }
    $path=Get-WinSecOptionalField $Context 'Path'
    if ($path -and (Test-Path -LiteralPath $path -PathType Leaf)) { return [IO.File]::GetLastWriteTimeUtc($path) }
    return $latest
}

function Get-WinSecSessionContexts {
    param($Session,[string]$Collector,[string]$Domain,[switch]$Refresh,[switch]$IncludeMissing)
    if ($Refresh) {
        $missing=@($Session.SavedContexts | Where-Object {-not (Test-Path -LiteralPath $_.Path -PathType Leaf)})
        $deviceId=if ($Session.DeviceId) {$Session.DeviceId} else {Get-WinSecDeviceId $env:COMPUTERNAME}
        $Session.SavedContexts=@(foreach ($file in @(Get-WinSecDeviceSnapshots -OutputRoot $Session.OutputRoot -DeviceId $deviceId)) {
            Get-WinSecSnapshotManifest -Snapshot $file.FullName
        })+$missing
    }
    $seen=@{}
    $contexts=@(foreach ($context in @($Session.Context)+@($Session.SavedContexts)) {
        if ($null -eq $context) { continue }
        $path=Get-WinSecOptionalField $context 'Path'
        if ($path) {
            $exists=Test-Path -LiteralPath $path -PathType Leaf
            if ($seen.ContainsKey($path) -or (-not $exists -and -not $IncludeMissing)) { continue }
            $seen[$path]=$true
            if ($Refresh -and $exists) { $context=Get-WinSecSnapshotManifest -Snapshot $path }
        }
        $context
    })
    if ($Collector -or ($Domain -and $Domain -ne 'all')) {
        $ids=if ($Collector) {@($Collector)} else {@(Get-WinSecCatalog | Where-Object {$_.domain -eq $Domain} | ForEach-Object {$_.id})}
        return @($contexts | Where-Object {@($_.Manifest.collectors | Where-Object {$_.id -in $ids}).Count -gt 0} |
            Sort-Object @{Expression={Get-WinSecContextTime -Context $_ -Ids $ids};Descending=$true})
    }
    return $contexts
}

function Get-WinSecSessionSnapshot {
    param($Session,[string]$Collector,[string]$Domain)
    if ($Collector -or ($Domain -and $Domain -ne 'all')) {
        $contexts=@(Get-WinSecSessionContexts -Session $Session -Collector $Collector -Domain $Domain -Refresh -IncludeMissing)
        if ($contexts.Count -gt 0) { return [string]$contexts[0].Path }
        throw 'No hay una captura guardada para este objetivo. Ejecuta un escaneo.'
    }
    if (-not $Session.Snapshot) {
        $ids=@(Get-WinSecCatalog | ForEach-Object {$_.id})
        $contexts=@(Get-WinSecSessionContexts -Session $Session -Refresh | Sort-Object @{Expression={Get-WinSecContextTime -Context $_ -Ids $ids};Descending=$true})
        if ($contexts.Count -gt 0) { return [string]$contexts[0].Path }
        throw 'No hay evidencia en esta sesion. Escribe winsec -s o winsec -s <seccion>.'
    }
    if (-not (Test-Path -LiteralPath $Session.Snapshot)) { throw 'La captura guardada fue eliminada. Ejecuta un nuevo escaneo.' }
    return [string]$Session.Snapshot
}

function Close-WinSecSession {
    param($Session)
    if ($null -eq $Session -or $Session.Closed) { return }
    if ($null -ne $Session.Context -and $Session.RunId -and (Test-Path -LiteralPath $Session.Snapshot -PathType Leaf)) {
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

function Reset-WinSecSessionForRescan {
    param($Session)
    Close-WinSecSession $Session
    $Session.Snapshot=$null; $Session.RunId=$null; $Session.Context=$null; $Session.Closed=$false
}

function Get-WinSecAnalysisReadiness {
    param($Session,$Target,[string]$Snapshot)
    $result=[pscustomobject]@{Available=$false;Path=$null;Reason='No saved evidence for this target.'}
    try {
        $path=if ($Snapshot) {$Snapshot} else {Get-WinSecSessionSnapshot -Session $Session -Collector $Target.Collector -Domain $Target.Domain}
        $context=Get-WinSecSnapshotManifest -Snapshot $path
        $ids=@(Get-WinSecCatalog | Where-Object {($Target.Domain -eq 'all' -or $_.domain -eq $Target.Domain) -and (-not $Target.Collector -or $_.id -eq $Target.Collector)} | ForEach-Object {$_.id})
        $entries=@($context.Manifest.collectors | Where-Object {$_.id -in $ids})
        if ($entries.Count -eq 0) { return $result }
        foreach ($entry in $entries) {
            if (-not $entry.sha256 -or $null -eq (Get-WinSecEvidenceFile -Context $context -CollectorId $entry.id)) {
                $result.Reason='Missing saved evidence: '+$entry.id
                return $result
            }
        }
        $result.Available=$true; $result.Path=$context.Path; $result.Reason=$null
    } catch { $result.Reason=$_.Exception.Message }
    return $result
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
