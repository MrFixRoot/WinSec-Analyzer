function Get-WinSecSections {
    @(
        [pscustomobject]@{ Number=1; Domain='SystemSecurity'; Name='System Security'; Command='system' }
        [pscustomobject]@{ Number=2; Domain='NetworkSecurity'; Name='Network Security'; Command='network' }
        [pscustomobject]@{ Number=3; Domain='IdentityAccess'; Name='Identity & Access'; Command='identity' }
        [pscustomobject]@{ Number=4; Domain='ServicesHardening'; Name='Services & Hardening'; Command='services' }
        [pscustomobject]@{ Number=5; Domain='LoggingAuditing'; Name='Logging & Auditing'; Command='logging' }
        [pscustomobject]@{ Number=6; Domain='PatchManagement'; Name='Patch Management'; Command='patch' }
    )
}

function Get-WinSecHelpLines {
    param([string]$Domain='all')
    $resolved=Resolve-WinSecDomain $Domain
    $sections=@(Get-WinSecSections)
    if ($resolved -eq 'all') {
        @('# Ayuda de secciones','','Escanear todas las secciones:','    winsec -s','','Escanear secciones individuales (elige una):',
          ('    winsec -s ['+(($sections | ForEach-Object {$_.Command}) -join '|')+']'),
          '','Marcos de referencia:','    -c [c]is benchmarks','    -n [n]ist csf 2.0',
          '','Analizar una seccion (elige un marco):','    winsec -a network -n','    winsec -a network -c',
          '','Correlacion PLUS [+]:','    -r co[r]relation','')
        $config=Get-Content -LiteralPath (Join-Path $script:WinSecRoot 'config/correlation-rules/cross-domain.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($rule in $config.correlations) {
            'Correlacion {0}: {1}' -f $rule.id,$rule.title
            '    winsec -r {0}' -f $rule.id
        }
        @('Correlacion 5: Ejecuta las correlaciones 1, 2, 3 y 4','    winsec -r')
        return
    }
    $section=@($sections | Where-Object {$_.Domain -eq $resolved})[0]
    $controls=@(Get-WinSecCatalog | Where-Object {$_.domain -eq $resolved})
    if ($controls.Count -eq 0) { throw 'No hay controles registrados en esta seccion.' }
    $names=@(foreach ($control in $controls) {
        $name=[string]$control.id
        $prefix=[regex]::Match($name,'^[A-Z]+(?=[A-Z][a-z]|$)|^[A-Z]')
        if ($prefix.Success) { $prefix.Value.ToLowerInvariant()+$name.Substring($prefix.Length) } else { $name }
    })
    @(('# Ayuda de controles: '+$section.Name),'','Escanear esta seccion:',('    winsec -s '+$section.Command),
      '','Escanear un solo control:',('    winsec -s '+$names[0]),
      '','Marcos de referencia:','    -c [c]is benchmarks','    -n [n]ist csf 2.0',
      '','Analizar esta seccion (elige un marco):',('    winsec -a '+$section.Command+' -c'),('    winsec -a '+$section.Command+' -n'),
      '','Ejemplos de analisis por control (un framework por comando):')
    foreach ($name in $names) { @(('    winsec -a '+$name+' -n'),('    winsec -a '+$name+' -c')) }
}

function Show-WinSecHelp {
    param([string]$Domain='all')
    $resolved=Resolve-WinSecDomain $Domain
    $file=if ($resolved -eq 'all') {'README.md'} else {$resolved+'.md'}
    $path=Join-Path (Join-Path $script:WinSecRoot 'help') $file
    Write-Host ''
    $lines=if (Test-Path -LiteralPath $path -PathType Leaf) {
        Get-Content -LiteralPath $path -Encoding UTF8 -ErrorAction Stop
    } else { Get-WinSecHelpLines -Domain $resolved }
    $lines | ForEach-Object {
        if ($_ -match '^#{1,6}\s+') { Write-Host ('  '+($_ -replace '^#{1,6}\s+','')) -ForegroundColor Cyan }
        else { Write-Host ('  '+$_) }
    }
}

function Get-WinSecHint {
    param($Session,[string]$Domain='all',[string]$Collector)
    $section=@(Get-WinSecSections | Where-Object { $_.Domain -eq $Domain })
    $scan=if ($section.Count -gt 0) {'winsec -s '+$section[0].Command} else {'winsec -s'}
    $target=if ($Collector) {$Collector} elseif ($section.Count -gt 0) {$section[0].Command} else {'all'}
    $hints=@(
        [pscustomobject]@{ Lines=@($(if ($section.Count -gt 0) {'Scan this section:'} else {'Scan all sections on this device:'}),$scan) }
        [pscustomobject]@{ Lines=@('Type help for commands and navigation.','Esc = back / cancel   |   Q = quit') }
        [pscustomobject]@{ Lines=@('Analyze saved evidence with NIST CSF:',('winsec -a {0} -n' -f $target)) }
        [pscustomobject]@{ Lines=@('Analyze saved evidence with CIS Benchmarks:',('winsec -a {0} -c' -f $target)) }
        [pscustomobject]@{ Lines=@('Scan all sections on this device:','winsec -s') }
    )
    $hint=$hints[$Session.HintIndex % $hints.Count]
    $Session.HintIndex++
    return $hint.Lines
}

function Get-WinSecCollectorState {
    param($Session,[string]$Collector)
    $entry=@()
    if ($null -ne $Session.Context) { $entry=@($Session.Context.Manifest.collectors | Where-Object { $_.id -eq $Collector }) }
    if ($entry.Count -eq 0) { return [pscustomobject]@{ Text='Not yet'; Color='DarkGray' } }
    switch ($entry[0].status) {
        'COMPLETED' { return [pscustomobject]@{ Text='Scanned'; Color='Green' } }
        'PARTIAL' { return [pscustomobject]@{ Text='Scanned (partial)'; Color='Yellow' } }
        'NOT_APPLICABLE' { return [pscustomobject]@{ Text='Not applicable'; Color='DarkYellow' } }
        default { return [pscustomobject]@{ Text='Scan error'; Color='Red' } }
    }
}
