function Invoke-WinSecCollection {
    param([string]$Domain='all',[string]$Collector,[string]$OutputRoot,[switch]$Deep)
    $os=Assert-WinSecWindows11
    $resolved=Resolve-WinSecDomain $Domain
    $entries=@(Get-WinSecCatalog | Where-Object { ($resolved -eq 'all' -or $_.domain -eq $resolved) -and (-not $Collector -or $_.id -eq $Collector) })
    if ($entries.Count -eq 0) { throw 'No hay collectors registrados para la seleccion.' }
    $root=Get-WinSecOutputRoot -OutputRoot $OutputRoot
    $osFolder='Windows11_'+(ConvertTo-WinSecSafeName $os.Edition)+'_'+$os.Build
    $hostFolder=ConvertTo-WinSecSafeName $env:COMPUTERNAME
    $stamp=(Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $runId=[guid]::NewGuid().ToString('N')
    $runFolder=$stamp+'_'+$runId.Substring(0,8)
    $base=Join-Path (Join-Path (Join-Path $root $osFolder) $hostFolder) $runFolder
    [void](New-Item -ItemType Directory -Path $base -Force)
    $manifest=[ordered]@{
        schemaVersion='1'; runId=$runId; startedAtUtc=(Get-Date).ToUniversalTime().ToString('o');
        finishedAtUtc=$null; status='RUNNING'; host=$env:COMPUTERNAME;
        os=[ordered]@{ family='Windows11'; caption=$os.Caption; build=$os.Build; edition=$os.Edition; arch=$os.Arch };
        elevated=(Test-WinSecElevated); mode=$(if ($Deep) { 'DEEP' } else { 'STANDARD' });
        scope=[ordered]@{ domain=$resolved; collector=$Collector }; collectors=@()
    }
    $manifestPath=Join-Path $base 'manifest.json'
    [void](Save-WinSecJson -Path $manifestPath -Value $manifest)
    Write-Host ('Snapshot: '+$base) -ForegroundColor DarkGray
    $index=0
    foreach ($agent in $entries) {
        $index++
        Write-Progress -Activity 'WinSec: recopilando configuraciones Windows 11' -Status $agent.id -PercentComplete ([int](100*$index/$entries.Count))
        $payload=$null
        try {
            $fn=Get-Command -Name $agent.function -CommandType Function -ErrorAction Stop
            $payload=& $fn.Name -Deep:$Deep -ErrorAction Stop
            if ($null -eq $payload -or $null -eq $payload.status) { throw 'Collector devolvio una estructura invalida.' }
        } catch {
            $payload=New-WinSecPayload -Data ([ordered]@{}) -Sources @() -Warnings @($_.Exception.Message) -Status 'ERROR'
        }
        $evidence=[ordered]@{
            schemaVersion='1'; collector=$agent.id; domain=$agent.domain; description=$agent.description;
            collectedAtUtc=(Get-Date).ToUniversalTime().ToString('o');
            status=$payload.status; sources=@($payload.sources); data=$payload.data;
            warnings=@($payload.warnings); redactedFields=@('passwords','tokens','bitlockerRecoveryKeys','privateKeys')
        }
        $relative=$agent.domain+'/'+$agent.id+'.json'
        $file=Join-Path $base ($relative -replace '/', [IO.Path]::DirectorySeparatorChar)
        $sha=$null
        try {
            [void](Save-WinSecJson -Path $file -Value $evidence)
            $sha=Get-WinSecHash -Path $file
            $status=[string]$payload.status
            Write-Host ('  [{0}] {1}' -f $status,$agent.id) -ForegroundColor $(if ($status -eq 'COMPLETED') {'Green'} elseif ($status -eq 'PARTIAL') {'Yellow'} else {'DarkYellow'})
        } catch {
            $status='ERROR'
            $relative=$null
            Write-Warning ('No se pudo guardar '+$agent.id+': '+$_.Exception.Message)
        }
        $manifest.collectors+= [ordered]@{ id=$agent.id; domain=$agent.domain; status=$status; path=$relative; sha256=$sha }
        [void](Save-WinSecJson -Path $manifestPath -Value $manifest)
    }
    Write-Progress -Activity 'WinSec: recopilando configuraciones Windows 11' -Completed
    $manifest.finishedAtUtc=(Get-Date).ToUniversalTime().ToString('o')
    $failures=@($manifest.collectors | Where-Object { $_.status -ne 'COMPLETED' })
    $manifest.status=if ($failures.Count -eq 0) { 'COMPLETED' } else { 'PARTIAL' }
    [void](Save-WinSecJson -Path $manifestPath -Value $manifest)
    Write-Host ('Finalizado: '+$manifest.status+' | '+$entries.Count+' collectors') -ForegroundColor Cyan
    return $manifestPath
}
