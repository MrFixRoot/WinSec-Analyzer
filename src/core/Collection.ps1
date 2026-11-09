function Invoke-WinSecCollection {
    param([string]$Domain='all',[string]$Collector,[string]$OutputRoot,[switch]$Deep,$Session)
    $os=Assert-WinSecWindows11
    $newSnapshot=$false; $createdFiles=0
    $resolved=Resolve-WinSecDomain $Domain
    $entries=@(Get-WinSecCatalog | Where-Object { ($resolved -eq 'all' -or $_.domain -eq $resolved) -and (-not $Collector -or $_.id -eq $Collector) })
    if ($entries.Count -eq 0) { throw 'No hay collectors registrados para la seleccion.' }
    if ($null -ne $Session -and $Session.Closed) { throw 'La sesion esta cerrada. Abre una nueva sesion.' }
    if ($null -ne $Session -and $null -ne $Session.Context -and $Session.RunId) {
        $context=Get-WinSecSnapshotManifest -Snapshot $Session.Snapshot
        $m=$context.Manifest
        if ($m.runId -ne $Session.RunId -or $m.sessionState -ne 'OPEN' -or
            $m.host -ne $env:COMPUTERNAME -or $m.os.family -ne 'Windows11' -or
            $m.os.build -ne $os.Build -or $m.os.edition -ne $os.Edition) {
            throw 'No se puede agregar evidencia: la captura no pertenece a la sesion local abierta.'
        }
        foreach ($field in @('displayVersion','ubr','installationType')) {
            $saved=Get-WinSecOptionalField $m.os $field
            $current=Get-WinSecOptionalField $os $field
            if ($null -ne $saved -and $null -ne $current -and [string]$saved -cne [string]$current) {
                throw ('El contexto de Windows ha cambiado ('+$field+'). Abre una nueva sesion para crear otro snapshot.')
            }
        }
    } else {
        if ($null -ne $Session) { $OutputRoot=$Session.OutputRoot }
        $context=New-WinSecCollectionContext -OS $os -OutputRoot $OutputRoot -Domain $resolved -Collector $Collector -Deep:$Deep -Interactive:($null -ne $Session)
        $newSnapshot=$true
        if ($null -ne $Session) {
            $Session.Context=$context; $Session.Snapshot=$context.Path; $Session.RunId=$context.Manifest.runId
            Add-WinSecNotification -Session $Session -Message ('Snapshot created: '+(Format-WinSecSnapshotPath $context.Path))
        }
    }
    $manifest=$context.Manifest
    $contextWarnings=@(@(Get-WinSecOptionalField $manifest 'warnings')+@(Get-WinSecOptionalField $os 'Warnings') | Where-Object {-not [string]::IsNullOrWhiteSpace([string]$_)} | Select-Object -Unique)
    if ($manifest -is [System.Collections.IDictionary]) { $manifest['warnings']=$contextWarnings }
    else { $manifest | Add-Member -NotePropertyName warnings -NotePropertyValue $contextWarnings -Force }
    Write-Host '  Scanning local Windows 11...' -ForegroundColor Cyan
    $index=0
    try {
        foreach ($agent in $entries) {
            $index++
            if ($null -eq $Session) {
                Write-Progress -Activity 'WinSec: recopilando configuraciones Windows 11' -Status $agent.id -PercentComplete ([int](100*$index/$entries.Count))
            }
            $previous=@($manifest.collectors | Where-Object { $_.id -eq $agent.id })
            if ($previous.Count -gt 0 -and $previous[0].path) {
                if (-not $previous[0].sha256 -or $null -eq (Get-WinSecEvidenceFile -Context $context -CollectorId $agent.id)) {
                    throw ('Evidencia guardada incompleta: '+$agent.id+'. Abre una nueva sesion; no se sobrescribira.')
                }
                Write-WinSecCollectionState -Text ('  [{0}/{1}] Cached: {2} | {3}' -f $index,$entries.Count,$agent.id,$previous[0].status) -Color DarkGray -Session $Session
                continue
            }
            $manifest.status='RUNNING'
            $manifest.finishedAtUtc=$null
            if ($Deep -and $manifest.mode -eq 'STANDARD') { $manifest.mode='MIXED' }
            if (-not $Deep -and $manifest.mode -eq 'DEEP') { $manifest.mode='MIXED' }
            [void](Save-WinSecJson -Path $context.Path -Value $manifest)
            Write-WinSecCollectionState -Text ('  [{0}/{1}] Scanning {2}...' -f $index,$entries.Count,(ConvertTo-WinSecControlName $agent.id)) -Session $Session
            $collectorWarnings=@()
            try {
                $fn=Get-Command -Name $agent.function -CommandType Function -ErrorAction Stop
                $payload=& $fn.Name -Deep:$Deep -ErrorAction Stop -WarningAction SilentlyContinue -WarningVariable collectorWarnings
                if ($null -eq $payload -or $null -eq $payload.status) { throw 'Collector devolvio una estructura invalida.' }
                $payload=New-WinSecPayload -Data $payload.data -Sources @($payload.sources) -Warnings @(@($payload.warnings)+@($collectorWarnings) | Select-Object -Unique) -Status $payload.status
            } catch {
                $payload=New-WinSecPayload -Data ([ordered]@{}) -Sources @() -Warnings @(@($collectorWarnings)+@($_.Exception.Message)) -Status 'ERROR'
            }
            $evidence=[ordered]@{
                schemaVersion='1'; runId=$manifest.runId; collector=$agent.id; domain=$agent.domain; description=$agent.description
                collectedAtUtc=(Get-Date).ToUniversalTime().ToString('o'); mode=$(if ($Deep) {'DEEP'} else {'STANDARD'})
                status=$payload.status; sources=@($payload.sources); data=$payload.data
                warnings=@($payload.warnings); redactedFields=@('passwords','tokens','bitlockerRecoveryKeys','privateKeys')
            }
            $relative=$agent.domain+'/'+$agent.id+'.json'
            $file=Join-Path $context.Base ($relative -replace '/', [IO.Path]::DirectorySeparatorChar)
            if (Test-Path -LiteralPath $file) { throw ('Ya existe evidencia para '+$agent.id+'. Abre una nueva sesion.') }
            $sha=$null
            try {
                [void](Save-WinSecJson -Path $file -Value $evidence)
                $createdFiles++
                $sha=Get-WinSecHash -Path $file
                $status=[string]$payload.status
                Write-WinSecCollectionState -Text ('  [{0}/{1}] {2} | {3}' -f $index,$entries.Count,$agent.id,$status) -Color $(if ($status -eq 'COMPLETED') {'Green'} elseif ($status -eq 'PARTIAL') {'Yellow'} else {'DarkYellow'}) -Session $Session
            } catch {
                $status='ERROR'; $relative=$null
                Write-Warning ('No se pudo guardar '+$agent.id+': '+$_.Exception.Message)
            }
            $manifest.collectors=@($manifest.collectors | Where-Object { $_.id -ne $agent.id })+
                @([ordered]@{ id=$agent.id; domain=$agent.domain; status=$status; path=$relative; sha256=$sha; collectedAtUtc=$evidence.collectedAtUtc })
            [void](Save-WinSecJson -Path $context.Path -Value $manifest)
        }
        $failures=@($manifest.collectors | Where-Object { $_.status -ne 'COMPLETED' })
        $manifest.status=if ($failures.Count -eq 0 -and $contextWarnings.Count -eq 0) { 'COMPLETED' } else { 'PARTIAL' }
        if ($null -eq $Session) { $manifest.finishedAtUtc=(Get-Date).ToUniversalTime().ToString('o') }
        [void](Save-WinSecJson -Path $context.Path -Value $manifest)
        if ($null -ne $Session) { Write-Host '' }
        Write-Host ('Finalizado: '+$manifest.status+' | '+@($manifest.collectors).Count+' collectors guardados') -ForegroundColor Cyan
        if ($null -eq $Session) { Write-Host ('Snapshot saved: '+(Format-WinSecSnapshotPath $context.Path)) -ForegroundColor DarkGray }
        return $context.Path
    } finally {
        if ($null -eq $Session) { Write-Progress -Activity 'WinSec: recopilando configuraciones Windows 11' -Completed }
        else { Write-Host '' }
        if ($null -ne $Session) { $Session.Context=$context }
        if (-not $newSnapshot -and $createdFiles -gt 0) {
            Add-WinSecNotification -Session $Session -Message ('Evidence created: '+$createdFiles+' file(s)')
        }
    }
}

function Write-WinSecCollectionState {
    param([string]$Text,[ConsoleColor]$Color='Cyan',$Session)
    if ($null -eq $Session) { Write-Host $Text -ForegroundColor $Color; return }
    # A single progress line below the banner avoids RawUI's overlay on the logo.
    $width=74
    try { $width=[math]::Max(1,[math]::Min($width,$Host.UI.RawUI.BufferSize.Width-1)) } catch { }
    $line=if ($Text.Length -gt $width) {$Text.Substring(0,$width)} else {$Text.PadRight($width)}
    Write-Host (([string][char]13)+$line) -NoNewline -ForegroundColor $Color
}
