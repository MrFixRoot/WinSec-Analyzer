function Resolve-WinSecJsonPath {
    param($Root,[Parameter(Mandatory)][string]$Path)
    $current=$Root
    foreach ($part in ($Path -split '\.')) {
        if ($null -eq $current) { return [pscustomobject]@{found=$false;value=$null} }
        $prop=$null
        if ($current -is [System.Collections.IDictionary]) {
            if (-not $current.Contains($part)) { return [pscustomobject]@{found=$false;value=$null} }
            $current=$current[$part]
        } else {
            $prop=$current.PSObject.Properties[$part]
            if ($null -eq $prop) { return [pscustomobject]@{found=$false;value=$null} }
            $current=$prop.Value
        }
    }
    return [pscustomobject]@{found=$true;value=$current}
}

function Test-WinSecRuleValue {
    param($Observed,[string]$Operator,$Expected)
    switch ($Operator.ToLowerInvariant()) {
        'equals' { return ([string]$Observed -ceq [string]$Expected) }
        'notequals' { return ([string]$Observed -cne [string]$Expected) }
        'istrue' { return ($Observed -eq $true) }
        'isfalse' { return ($Observed -eq $false) }
        'contains' { return (@($Observed) -contains $Expected) }
        'gte' { return ([double]$Observed -ge [double]$Expected) }
        'lte' { return ([double]$Observed -le [double]$Expected) }
        default { throw "Operador no permitido: $Operator" }
    }
}

function Invoke-WinSecCISAnalysis {
    param($Context,[string]$CollectorFilter,[string]$DomainFilter)
    $eligible=@(Get-WinSecCatalog | Where-Object { (-not $CollectorFilter -or $_.id -eq $CollectorFilter) -and (-not $DomainFilter -or $DomainFilter -eq 'all' -or $_.domain -eq $DomainFilter) } | ForEach-Object { $_.id })
    $localDir=Join-Path $script:WinSecRoot 'config/benchmarks/local'
    $packs=@()
    if (Test-Path -LiteralPath $localDir) {
        foreach ($file in @(Get-ChildItem -LiteralPath $localDir -Filter '*.json' -File)) {
            try {
                $pack=Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
                if ($pack.framework -ne 'CIS Benchmarks' -or $pack.schemaVersion -ne '1' -or $pack.verified -ne $true -or $pack.benchmark.targetOS -ne 'Windows11') { continue }
                # Solo usar packs con metadatos completos y edicion exacta, nunca versiones genericas.
                if ([string]::IsNullOrWhiteSpace($pack.benchmark.version) -or [string]::IsNullOrWhiteSpace($pack.benchmark.profile) -or [string]::IsNullOrWhiteSpace($pack.benchmark.source)) { continue }
                if ($pack.benchmark.edition -ne $Context.Manifest.os.edition) { continue }
                $packs+=,$pack
            } catch { Write-Warning ('Pack CIS invalido: '+$file.Name+' '+$_.Exception.Message) }
        }
    }
    $results=@()
    if ($packs.Count -eq 0) {
        return [ordered]@{
            framework='CIS Benchmarks'; status='NOT_CONFIGURED'; benchmark=$null; findings=@(); score=$null;
            note='No se incluye contenido de CIS por defecto. Agrega packs locales licenciados, verificados y compatibles con la edicion de Windows 11.'
        }
    }
    foreach ($pack in $packs) {
        foreach ($rule in @($pack.rules)) {
            if ($rule.verified -ne $true -or [string]::IsNullOrWhiteSpace($rule.id) -or [string]::IsNullOrWhiteSpace($rule.collector) -or [string]::IsNullOrWhiteSpace($rule.path)) { continue }
            if ($rule.collector -notin $eligible) { continue }
            $status='NOT_ASSESSED'; $observed=$null; $note=''
            try {
                $evidence=Get-WinSecEvidenceFile -Context $Context -CollectorId $rule.collector
                if ($null -eq $evidence) { $note='Evidencia no recopilada.' }
                elseif ($evidence.status -notin @('COMPLETED','PARTIAL')) { $note='Evidencia no evaluable: '+$evidence.status }
                else {
                    $found=Resolve-WinSecJsonPath -Root $evidence -Path $rule.path
                    if (-not $found.found -or $null -eq $found.value) { $note='Propiedad no disponible.' }
                    else {
                        $observed=$found.value
                        $status=if (Test-WinSecRuleValue -Observed $observed -Operator $rule.operator -Expected $rule.expected) {'PASS'} else {'FAIL'}
                    }
                }
            } catch { $note=$_.Exception.Message }
            $results+= [ordered]@{ id=$rule.id; title=$rule.title; collector=$rule.collector; status=$status; observed=$observed; expected=$rule.expected; evidencePath=$rule.path; note=$note; benchmark=$pack.benchmark.name; benchmarkVersion=$pack.benchmark.version; profile=$pack.benchmark.profile }
        }
    }
    $passed=@($results | Where-Object { $_.status -eq 'PASS' }).Count
    $failed=@($results | Where-Object { $_.status -eq 'FAIL' }).Count
    $score=$null
    if (($passed+$failed) -gt 0) { $score=[math]::Round(100*$passed/($passed+$failed),2) }
    return [ordered]@{ framework='CIS Benchmarks'; status=if ($results.Count -gt 0) {'EVALUATED'} else {'NOT_CONFIGURED'}; benchmark=@($packs | ForEach-Object { $_.benchmark }); findings=$results; score=$score; denominator=($passed+$failed); note='Porcentaje propio PASS/(PASS+FAIL), NO es una certificacion ni scoring oficial CIS.' }
}

function Invoke-WinSecNISTAnalysis {
    param($Context,[string]$CollectorFilter,[string]$DomainFilter)
    $eligible=@(Get-WinSecCatalog | Where-Object { (-not $CollectorFilter -or $_.id -eq $CollectorFilter) -and (-not $DomainFilter -or $DomainFilter -eq 'all' -or $_.domain -eq $DomainFilter) } | ForEach-Object { $_.id })
    $mapping=Get-Content -LiteralPath (Join-Path $script:WinSecRoot 'config/mappings/nist-csf-2.0.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $out=@()
    foreach ($category in $mapping.mappings) {
        $mappedIds=@($category.collectors | Where-Object { $_ -in $eligible })
        if ($mappedIds.Count -eq 0) { continue }
        $evidence=@()
        foreach ($collectorId in $mappedIds) {
            $entry=@($Context.Manifest.collectors | Where-Object { $_.id -eq $collectorId })
            $state=if ($entry.Count -eq 0) {'NOT_COLLECTED'} else { [string]$entry[0].status }
            if ($state -in @('COMPLETED','PARTIAL')) {
                try {
                    $file=Get-WinSecEvidenceFile -Context $Context -CollectorId $collectorId
                    if ($null -eq $file) { $state='MISSING_FILE' }
                } catch { $state='INTEGRITY_ERROR' }
            }
            $evidence+= [ordered]@{ collector=$collectorId; state=$state }
        }
        $complete=@($evidence | Where-Object { $_.state -eq 'COMPLETED' }).Count
        $available=@($evidence | Where-Object { $_.state -in @('COMPLETED','PARTIAL') }).Count
        $status=if ($complete -eq $evidence.Count) {'EVIDENCE_AVAILABLE'} elseif ($available -gt 0) {'PARTIAL_EVIDENCE'} else {'NO_EVIDENCE'}
        $out+= [ordered]@{ category=$category.category; name=$category.name; status=$status; collected=$available; complete=$complete; mapped=$evidence.Count; evidence=$evidence; limitation=$category.note }
    }
    return [ordered]@{ framework='NIST CSF 2.0'; status='EVIDENCE_MAPPING_ONLY'; score=$null; categories=$out; note='No es una certificacion ni una puntuacion de cumplimiento NIST; los resultados CSF son organizacionales.' }
}

function Invoke-WinSecCorrelation {
    param($Context,[int]$Id=5)
    $config=Get-Content -LiteralPath (Join-Path $script:WinSecRoot 'config/correlation-rules/cross-domain.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    # La opcion 5 ejecuta las correlaciones 1, 2, 3 y 4 del mismo snapshot;
    # es un selector conjunto, no una quinta regla de correlacion.
    $selected=@($config.correlations | Where-Object { $Id -eq 5 -or $_.id -eq $Id })
    if ($selected.Count -eq 0) { throw "Correlacion no encontrada: $Id" }
    $output=@()
    foreach ($rule in $selected) {
        $missing=@()
        foreach ($collectorId in $rule.required) {
            $entry=@($Context.Manifest.collectors | Where-Object { $_.id -eq $collectorId })
            if ($entry.Count -eq 0 -or $entry[0].status -notin @('COMPLETED','PARTIAL')) {
                $missing+= $collectorId
                continue
            }
            try {
                $file=Get-WinSecEvidenceFile -Context $Context -CollectorId $collectorId
                if ($null -eq $file) { $missing+= $collectorId }
            } catch { $missing+= $collectorId }
        }
        $facts=@()
        foreach ($fact in $rule.facts) {
            $found=$null
            $reason=$null
            try {
                $ev=Get-WinSecEvidenceFile -Context $Context -CollectorId $fact.collector
                if ($null -ne $ev -and $ev.status -in @('COMPLETED','PARTIAL')) {
                    $found=Resolve-WinSecJsonPath -Root $ev -Path $fact.path
                }
            } catch { $reason=$_.Exception.Message }
            $value=$null
            $available=($null -ne $found -and $found.found -and $null -ne $found.value)
            if ($available) {
                $display=$fact.PSObject.Properties['display']
                if ($null -ne $display -and $display.Value -eq 'count') { $value=@($found.value).Count }
                else { $value=$found.value }
            } else {
                $missing+= $fact.collector+':'+$fact.path
                if (-not $reason) { $reason='Propiedad requerida no disponible o evidencia no evaluable.' }
            }
            $facts+= [ordered]@{ label=$fact.label; collector=$fact.collector; available=$available; value=$value; reason=$reason }
        }
        $outStatus=if ($missing.Count -gt 0) {'INSUFFICIENT_EVIDENCE'} else {'REVIEW_REQUIRED'}
        $output+= [ordered]@{ id=$rule.id; title=$rule.title; domains=@($rule.domains); status=$outStatus; required=$rule.required; missing=$missing; facts=$facts; note=$rule.interpretation }
    }
    return [ordered]@{ analysis='Cross-Domain Correlations'; status='OBSERVATIONAL'; correlations=$output; note='No se asignan PASS/FAIL sin criterios evaluativos verificados.' }
}

function New-WinSecAnalysisDocument {
    param($Context,$Scope,[System.Collections.IDictionary]$Data)
    $document=[ordered]@{}
    foreach ($key in $Data.Keys) { $document[$key]=$Data[$key] }
    $document.schemaVersion='1'
    $document.sourceRunId=[string]$Context.Manifest.runId
    $document.generatedAtUtc=(Get-Date).ToUniversalTime().ToString('o')
    $document.scope=$Scope
    return $document
}

function Get-WinSecResultName {
    param([string]$Id)
    if ($Id -notmatch '^[a-zA-Z][a-zA-Z0-9]*$') { throw 'Identificador de resultado no seguro.' }
    return (ConvertTo-WinSecControlName $Id)
}

function Save-WinSecAnalysis {
    param($Context,[ValidateSet('cis','nist')][string]$Name,$Data,[string]$CollectorFilter,[string]$DomainFilter)
    if ($CollectorFilter) {
        $agents=@(Get-WinSecCatalog | Where-Object { $_.id -eq $CollectorFilter })
        if ($agents.Count -ne 1) { throw 'Control de exportacion no registrado.' }
        $scope=[ordered]@{ type='control'; id=$agents[0].id; name=(Get-WinSecResultName $agents[0].id) }
    } elseif ($DomainFilter -and $DomainFilter -ne 'all') {
        $domain=Resolve-WinSecDomain $DomainFilter
        if ($domain -eq 'all') { throw 'Se requiere una seccion concreta para esta exportacion.' }
        $scope=[ordered]@{ type='section'; id=$domain; name=(Get-WinSecResultName $domain) }
    } else {
        $scope=[ordered]@{ type='snapshot'; id='all'; name='all' }
    }
    $folder=if ($Name -eq 'nist') {'nistcsf'} else {'cisf'}
    $dir=Join-Path $Context.Base ('export/'+$folder)
    $path=Join-Path $dir ($scope.name+'.json')
    $document=New-WinSecAnalysisDocument -Context $Context -Scope $scope -Data $Data
    # Derived exports have stable names; replacing them never changes source evidence.
    [void](Save-WinSecJson -Path $path -Value $document)
    Write-Host ('Exportacion guardada: '+$path) -ForegroundColor Cyan
    return $path
}

function Save-WinSecCorrelations {
    param($Context,$Data)
    foreach ($item in $Data.correlations) {
        if (@($item.domains).Count -ne 2) { throw 'La correlacion debe identificar dos secciones.' }
        $domains=@(foreach ($domain in $item.domains) {
            $resolved=Resolve-WinSecDomain $domain
            if ($resolved -eq 'all') { throw 'Seccion de correlacion no valida.' }
            $resolved
        })
        $name=(@($domains | ForEach-Object { Get-WinSecResultName $_ }) -join '+')
        $scope=[ordered]@{ type='correlation'; id=$item.id; domains=$domains; name=$name }
        $result=[ordered]@{ analysis=$Data.analysis; status=$Data.status; correlations=@($item); note=$Data.note }
        $document=New-WinSecAnalysisDocument -Context $Context -Scope $scope -Data $result
        $path=Join-Path (Join-Path $Context.Base 'correlations') ($name+'.json')
        [void](Save-WinSecJson -Path $path -Value $document)
        Write-Host ('Correlacion guardada: '+$path) -ForegroundColor Cyan
        $path
    }
}

function Invoke-WinSecReport {
    param($Context)
    $analyses=@()
    $basePrefix=[IO.Path]::GetFullPath($Context.Base).TrimEnd([IO.Path]::DirectorySeparatorChar)+[IO.Path]::DirectorySeparatorChar
    # Read legacy results when present, without creating or modifying their directories.
    foreach ($relativeRoot in @('export','correlations','analysis')) {
        $root=Join-Path $Context.Base $relativeRoot
        if (Test-Path -LiteralPath $root) {
            $analyses+=@(Get-ChildItem -LiteralPath $root -Filter '*.json' -File -Recurse | ForEach-Object {
                $relative=$_.FullName.Substring($basePrefix.Length).Replace('\','/')
                [ordered]@{ name=$_.Directory.Name; file=$_.Name; path=$relative; sha256=(Get-WinSecHash -Path $_.FullName) }
            })
        }
    }
    $report=[ordered]@{
        reportType='WinSec Evidence Index'; generatedAtUtc=(Get-Date).ToUniversalTime().ToString('o');
        host=$Context.Manifest.host; sourceRunId=$Context.Manifest.runId;
        collectionStatus=$Context.Manifest.status; collectorCount=@($Context.Manifest.collectors).Count;
        collectors=$Context.Manifest.collectors; analyses=$analyses;
        note='Indice de evidencias; ninguna certificacion de cumplimiento es implicita.'
    }
    $path=Join-Path $Context.Base ('report-'+(Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')+'.report.json')
    [void](Save-WinSecJson -Path $path -Value $report)
    Write-Host ('Reporte guardado: '+$path) -ForegroundColor Cyan
    return $path
}
