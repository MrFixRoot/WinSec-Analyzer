function Get-WinSecSections {
    @(
        [pscustomobject]@{ Number=1; Domain='SystemSecurity'; Name='System Security'; Command='system' }
        [pscustomobject]@{ Number=2; Domain='NetworkSecurity'; Name='Network Security'; Command='network' }
        [pscustomobject]@{ Number=3; Domain='IdentityAccess'; Name='Identity & Access'; Command='identity' }
        [pscustomobject]@{ Number=4; Domain='ServicesHardening'; Name='Services & Hardening'; Command='servicesHardening' }
        [pscustomobject]@{ Number=5; Domain='LoggingAuditing'; Name='Logging & Auditing'; Command='login' }
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
    param([string]$Domain='all',[string]$Collector)
    $resolved=Resolve-WinSecDomain $Domain
    $file=if ($resolved -eq 'all') {'README.md'} else {$resolved+'.md'}
    $path=Join-Path (Join-Path $script:WinSecRoot 'help') $file
    $example=$null; $selected=$null
    if ($Collector) {
        $agents=@(Get-WinSecCatalog | Where-Object { $_.domain -eq $resolved })
        $control=@($agents | Where-Object { $_.id -eq $Collector })
        if ($control.Count -ne 1) { throw 'Control no registrado en esta seccion.' }
        $example=ConvertTo-WinSecControlName $agents[0].id
        $selected=ConvertTo-WinSecControlName $control[0].id
    }
    $inSectionExamples=$false
    Write-Host ''
    $lines=if (Test-Path -LiteralPath $path -PathType Leaf) {
        Get-Content -LiteralPath $path -Encoding UTF8 -ErrorAction Stop
    } else { Get-WinSecHelpLines -Domain $resolved }
    $lines | ForEach-Object {
        $line=$_
        if ($line -match '^Analizar esta seccion') { $inSectionExamples=$true }
        elseif ($line -match '^Ejemplos de analisis por control') { $inSectionExamples=$false }
        if ($selected -and $inSectionExamples) { return }
        if ($selected) { $line=$line -replace ('(?<=winsec -s )'+[regex]::Escape($example)+'(?=\s|$)'),$selected }
        if ($line -match '^#{1,6}\s+') { Write-Host ('  '+($line -replace '^#{1,6}\s+','')) -ForegroundColor Cyan }
        elseif ($selected -and $line -match ('^\s*winsec -(?:s|a) '+[regex]::Escape($selected)+'(?:\s|$)')) {
            Write-Host ('  '+$line) -ForegroundColor Cyan
        }
        else { Write-Host ('  '+$line) }
    }
}

function Get-WinSecHint {
    param($Session,[string]$Domain='all',[string]$Collector,[string]$View='main')
    $section=@(Get-WinSecSections | Where-Object { $_.Domain -eq $Domain })
    if ($View -eq 'correlations') {
        $config=Get-Content -LiteralPath (Join-Path $script:WinSecRoot 'config/correlation-rules/cross-domain.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        $hints=@()
        foreach ($rule in $config.correlations) {
            $hints+= [pscustomobject]@{ Lines=@(('Correlacion {0}: {1}' -f $rule.id,$rule.title),('winsec -r {0}' -f $rule.id)) }
        }
        $hints+= [pscustomobject]@{ Lines=@('Correlacion 5: Ejecuta las correlaciones 1, 2, 3 y 4','winsec -r') }
    } elseif ($Collector) {
        $name=ConvertTo-WinSecControlName $Collector
        $hints=@(
            [pscustomobject]@{ Lines=@('Escanear este control:',('winsec -s {0}' -f $name)) }
            [pscustomobject]@{ Lines=@('Analizar este control con NIST CSF:',('winsec -a {0} -n' -f $name)) }
            [pscustomobject]@{ Lines=@('Analizar este control con CIS Benchmarks:',('winsec -a {0} -c' -f $name)) }
        )
    } elseif ($section.Count -gt 0) {
        $name=$section[0].Command
        $hints=@([pscustomobject]@{ Lines=@('Escanear esta seccion:',('winsec -s {0}' -f $name)) })
        foreach ($agent in @(Get-WinSecCatalog | Where-Object { $_.domain -eq $Domain })) {
            $controlName=ConvertTo-WinSecControlName $agent.id
            $hints+= [pscustomobject]@{ Lines=@(('Analizar {0} con NIST CSF:' -f $controlName),('winsec -a {0} -n' -f $controlName)) }
            $hints+= [pscustomobject]@{ Lines=@(('Analizar {0} con CIS Benchmarks:' -f $controlName),('winsec -a {0} -c' -f $controlName)) }
        }
    } else {
        $hints=@([pscustomobject]@{ Lines=@('Escanear todas las secciones:','winsec -s') })
        foreach ($item in @(Get-WinSecSections)) {
            $hints+= [pscustomobject]@{ Lines=@(('Escanear {0}:' -f $item.Name),('winsec -s {0}' -f $item.Command)) }
        }
        $hints+= [pscustomobject]@{ Lines=@('Analizar Network Security con NIST CSF:','winsec -a network -n') }
        $hints+= [pscustomobject]@{ Lines=@('Analizar Network Security con CIS Benchmarks:','winsec -a network -c') }
    }
    $hint=$hints[$Session.HintIndex % $hints.Count]
    $Session.HintIndex++
    return $hint.Lines
}

function Get-WinSecCollectorState {
    param($Session,[string]$Collector)
    $entry=@()
    $saved=$false
    foreach ($context in @(Get-WinSecSessionContexts -Session $Session -Collector $Collector)) {
        $entry=@($context.Manifest.collectors | Where-Object { $_.id -eq $Collector })
        if ($entry.Count -gt 0) {
            $saved=(-not $Session.RunId -or $context.Manifest.runId -ne $Session.RunId)
            break
        }
    }
    if ($entry.Count -eq 0) { return [pscustomobject]@{ Text='Not yet'; Color='DarkGray'; Status=$null } }
    $suffix=if ($saved) {' (saved)'} else {''}
    switch ($entry[0].status) {
        'COMPLETED' { return [pscustomobject]@{ Text=('Scanned'+$suffix); Color='Green'; Status='COMPLETED' } }
        'PARTIAL' { return [pscustomobject]@{ Text=('Scanned (partial)'+$suffix); Color='Yellow'; Status='PARTIAL' } }
        'NOT_APPLICABLE' { return [pscustomobject]@{ Text=('Not applicable'+$suffix); Color='DarkYellow'; Status='NOT_APPLICABLE' } }
        default { return [pscustomobject]@{ Text=('Scan error'+$suffix); Color='Red'; Status='ERROR' } }
    }
}
