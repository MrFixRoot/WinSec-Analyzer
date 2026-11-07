function Invoke-WinSecCollection {
    param([string]$Domain='all',[string]$Collector,[string]$OutputRoot,[switch]$Deep,$Session)
    $os=Assert-WinSecWindows11
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
    } else {
        if ($null -ne $Session) { $OutputRoot=$Session.OutputRoot }
        $context=New-WinSecCollectionContext -OS $os -OutputRoot $OutputRoot -Domain $resolved -Collector $Collector -Deep:$Deep -Interactive:($null -ne $Session)
        if ($null -ne $Session) {
            $Session.Context=$context; $Session.Snapshot=$context.Path; $Session.RunId=$context.Manifest.runId
        }
    }
    $manifest=$context.Manifest
    Write-Host ('Snapshot: '+$context.Base) -ForegroundColor DarkGray
    $index=0
    try {
        foreach ($agent in $entries) {
            $index++
            Write-Progress -Activity 'WinSec: recopilando configuraciones Windows 11' -Status $agent.id -PercentComplete ([int](100*$index/$entries.Count))
            $previous=@($manifest.collectors | Where-Object { $_.id -eq $agent.id })
            if ($previous.Count -gt 0 -and $previous[0].path) {
                if (-not $previous[0].sha256 -or $null -eq (Get-WinSecEvidenceFile -Context $context -CollectorId $agent.id)) {
                    throw ('Evidencia guardada incompleta: '+$agent.id+'. Abre una nueva sesion; no se sobrescribira.')
                }
                Write-Host ('  [Cached: {0}] {1}' -f $previous[0].status,$agent.id) -ForegroundColor DarkGray
                continue
            }
            $manifest.status='RUNNING'
            $manifest.finishedAtUtc=$null
            if ($Deep -and $manifest.mode -eq 'STANDARD') { $manifest.mode='MIXED' }
            if (-not $Deep -and $manifest.mode -eq 'DEEP') { $manifest.mode='MIXED' }
            [void](Save-WinSecJson -Path $context.Path -Value $manifest)
            try {
                $fn=Get-Command -Name $agent.function -CommandType Function -ErrorAction Stop
                $payload=& $fn.Name -Deep:$Deep -ErrorAction Stop
                if ($null -eq $payload -or $null -eq $payload.status) { throw 'Collector devolvio una estructura invalida.' }
            } catch {
                $payload=New-WinSecPayload -Data ([ordered]@{}) -Sources @() -Warnings @($_.Exception.Message) -Status 'ERROR'
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
                $sha=Get-WinSecHash -Path $file
                $status=[string]$payload.status
                Write-Host ('  [{0}] {1}' -f $status,$agent.id) -ForegroundColor $(if ($status -eq 'COMPLETED') {'Green'} elseif ($status -eq 'PARTIAL') {'Yellow'} else {'DarkYellow'})
            } catch {
                $status='ERROR'; $relative=$null
                Write-Warning ('No se pudo guardar '+$agent.id+': '+$_.Exception.Message)
            }
            $manifest.collectors=@($manifest.collectors | Where-Object { $_.id -ne $agent.id })+
                @([ordered]@{ id=$agent.id; domain=$agent.domain; status=$status; path=$relative; sha256=$sha })
            [void](Save-WinSecJson -Path $context.Path -Value $manifest)
        }
        $failures=@($manifest.collectors | Where-Object { $_.status -ne 'COMPLETED' })
        $manifest.status=if ($failures.Count -eq 0) { 'COMPLETED' } else { 'PARTIAL' }
        if ($null -eq $Session) { $manifest.finishedAtUtc=(Get-Date).ToUniversalTime().ToString('o') }
        [void](Save-WinSecJson -Path $context.Path -Value $manifest)
        Write-Host ('Finalizado: '+$manifest.status+' | '+@($manifest.collectors).Count+' collectors guardados') -ForegroundColor Cyan
        return $context.Path
    } finally {
        Write-Progress -Activity 'WinSec: recopilando configuraciones Windows 11' -Completed
        if ($null -ne $Session) { $Session.Context=$context }
    }
}
