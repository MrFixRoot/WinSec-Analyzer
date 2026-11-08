function Invoke-WinSecNamedAnalysis {
    param([ValidateSet('cis','nist')][string]$Framework,[int]$Correlation,[string]$Snapshot,[string]$OutputRoot,[string]$CollectorFilter,[string]$DomainFilter,$Session)
    $context=Get-WinSecSnapshotManifest -Snapshot $Snapshot -OutputRoot $OutputRoot
    if ($context.Manifest.os.family -ne 'Windows11' -or [int]$context.Manifest.os.build -lt 22000) {
        throw 'Solo se analizan snapshots de Windows 11.'
    }
    $productType=$context.Manifest.os.PSObject.Properties['productType']
    if ($null -ne $productType -and [int]$productType.Value -ne 1) { throw 'El snapshot no corresponde a Windows 11 cliente.' }
    if ($Framework) {
        if ($Framework -eq 'cis') { $data=Invoke-WinSecCISAnalysis -Context $context -CollectorFilter $CollectorFilter -DomainFilter $DomainFilter }
        else { $data=Invoke-WinSecNISTAnalysis -Context $context -CollectorFilter $CollectorFilter -DomainFilter $DomainFilter }
        [void](Save-WinSecAnalysis -Context $context -Name $Framework -Data $data -CollectorFilter $CollectorFilter -DomainFilter $DomainFilter -Session $Session)
        Write-Host ('  [{0}] {1}' -f $data.status,$Framework.ToUpperInvariant()) -ForegroundColor Yellow
        if ($Framework -eq 'cis') {
            foreach ($finding in @($data.findings)) {
                Write-Host ('  [{0}] {1} | {2}' -f $finding.status,$finding.id,$finding.title)
            }
            if ($null -ne $data.score) {
                Write-Host ('  CIS evaluated ratio: {0}% (n={1}, not official CIS scoring)' -f $data.score,$data.denominator) -ForegroundColor Cyan
            } else { Write-Host ('  '+$data.note) -ForegroundColor DarkYellow }
        } else {
            foreach ($category in @($data.categories)) {
                Write-Host ('  [{0}] {1} | {2}/{3} collectors' -f $category.status,$category.category,$category.collected,$category.mapped)
            }
            Write-Host '  NIST = evidencia disponible; no cumplimiento CSF confirmado.' -ForegroundColor DarkYellow
        }
    }
    if ($Correlation -gt 0) {
        $data=Invoke-WinSecCorrelation -Context $context -Id $Correlation
        [void](Save-WinSecCorrelations -Context $context -Data $data -Session $Session)
        foreach ($item in $data.correlations) {
            Write-Host ('  [{0}] {1}' -f $item.status,$item.title) -ForegroundColor Cyan
            if (@($item.missing).Count -gt 0) { Write-Host ('    Missing: '+(@($item.missing) -join ', ')) -ForegroundColor Yellow }
            foreach ($fact in @($item.facts)) {
                $value=if ($fact.available) { [string]$fact.value } else { '(unavailable)' }
                Write-Host ('    {0}: {1}' -f $fact.label,$value)
            }
        }
    }
}

function Resolve-WinSecTarget {
    param([string]$Target)
    $agents=@(Get-WinSecCatalog | Where-Object { $_.id -eq $Target })
    if ($agents.Count -eq 1) {
        return [pscustomobject]@{ Collector=$agents[0].id; Domain=$agents[0].domain }
    }
    try { $domain=Resolve-WinSecDomain $Target }
    catch { throw "Control o seccion no reconocido: $Target. Consulta la ayuda de comandos." }
    return [pscustomobject]@{ Collector=$null; Domain=$domain }
}

function winsec {
    [CmdletBinding()]
    param(
        [Alias('s')][switch]$Scan,
        [Alias('a')][string]$Analyze,
        [Alias('n')][switch]$Nist,
        [Alias('c')][switch]$Cis,
        [Alias('r')][switch]$Correlate,
        [ValidateRange(1,5)][int]$Correlation,
        [Parameter(Position=0)][string]$Domain='all',
        [string]$Collector,
        [string]$Snapshot,
        [string]$OutputRoot,
        [switch]$Deep,
        [switch]$List,
        [switch]$Report,
        [switch]$NoBanner,
        [Alias('h')][switch]$Help,
        [Parameter(DontShow=$true)]$Session
    )
    if ($Nist -and $Cis) { throw 'Selecciona un solo framework: -n para NIST CSF o -c para CIS.' }
    if ($Analyze -and -not ($Nist -or $Cis)) { throw 'Usa winsec -a <control|seccion> -n o -c; un solo framework por comando.' }
    if (($Nist -or $Cis) -and -not $Analyze) { throw 'Indica el objetivo con -a <control|seccion>.' }
    if ($Correlate) {
        if ($PSBoundParameters.ContainsKey('Correlation')) { throw 'Usa -r o -Correlation, sin combinarlos.' }
        if ($Scan -or $Analyze -or $Collector) { throw 'Ejecuta la correlacion en un comando separado: winsec -r [1-4].' }
        if ($Domain -eq 'all') { $Correlation=5 }
        elseif ($Domain -match '^[1-4]$') { $Correlation=[int]$Domain }
        else { throw 'Usa winsec -r para todas las correlaciones, o winsec -r 1, 2, 3 o 4.' }
        $Domain='all'
    }
    $target=$null
    if ($Analyze) {
        $target=Resolve-WinSecTarget -Target $Analyze
        if ($Collector -or $Domain -ne 'all') { throw 'El objetivo del analisis se indica solamente despues de -a.' }
    }
    if ($Scan) {
        $scanTarget=Resolve-WinSecTarget -Target $Domain
        if ($scanTarget.Collector) {
            if ($Collector) { throw 'Indica un solo control: winsec -s <control>.' }
            $Collector=$scanTarget.Collector
        }
        $Domain=$scanTarget.Domain
    }
    if ($null -ne $Session) {
        if ($OutputRoot -and (Get-WinSecOutputRoot $OutputRoot) -ne $Session.OutputRoot) {
            throw 'La sesion utiliza un unico OutputRoot. Abre otra sesion para cambiarlo.'
        }
        $OutputRoot=$Session.OutputRoot
    }
    if ($Help) {
        $helpTarget=Resolve-WinSecTarget -Target $(if ($Collector) {$Collector} else {$Domain})
        Show-WinSecHelp -Domain $helpTarget.Domain -Collector $helpTarget.Collector
        return
    }
    if (-not $NoBanner -and ($Scan -or $Analyze -or $Correlation -or $List -or $Report)) { Show-WinSecBanner }
    if ($List) {
        $base=Get-WinSecOutputRoot -OutputRoot $OutputRoot
        if (Test-Path -LiteralPath $base) {
            Get-ChildItem -LiteralPath $base -Filter manifest.json -File -Recurse | Sort-Object LastWriteTimeUtc -Descending |
                Select-Object LastWriteTimeUtc,FullName
        } else { Write-Host 'No hay snapshots disponibles.' }
        return
    }
    if ($Scan) {
        $Snapshot=Invoke-WinSecCollection -Domain $Domain -Collector $Collector -OutputRoot $OutputRoot -Deep:$Deep -Session $Session
    }
    if ($Analyze -or $Correlation -gt 0 -or $Report) {
        if (-not $Snapshot) {
            if ($Analyze) {
                $analysisSession=if ($null -ne $Session) {$Session} else {New-WinSecSession -OutputRoot $OutputRoot}
                $Snapshot=Get-WinSecSessionSnapshot -Session $analysisSession -Collector $target.Collector -Domain $target.Domain
            } elseif ($null -ne $Session) { $Snapshot=Get-WinSecSessionSnapshot $Session }
        }
    }
    if ($Analyze) {
        $framework=if ($Cis) {'cis'} else {'nist'}
        Invoke-WinSecNamedAnalysis -Framework $framework -Snapshot $Snapshot -OutputRoot $OutputRoot -CollectorFilter $target.Collector -DomainFilter $target.Domain -Session $Session
    }
    if ($Correlation -gt 0) { Invoke-WinSecNamedAnalysis -Correlation $Correlation -Snapshot $Snapshot -OutputRoot $OutputRoot -Session $Session }
    if ($Report) {
        $context=Get-WinSecSnapshotManifest -Snapshot $Snapshot -OutputRoot $OutputRoot
        [void](Invoke-WinSecReport -Context $context -Session $Session)
    }
    if (-not $Scan -and -not $Analyze -and -not $Correlation -and -not $Report) {
        $null=Assert-WinSecWindows11
        Invoke-WinSecMenu -OutputRoot $OutputRoot -Snapshot $Snapshot
    }
}

function Invoke-WinSecAgentAlias {
    param([string]$Target,[switch]$Scan,[switch]$Analyze,[switch]$Nist,[switch]$Cis,[string]$Snapshot,[string]$OutputRoot,[switch]$Deep,[switch]$Help)
    $parameters=@{ Scan=$Scan; Nist=$Nist; Cis=$Cis; NoBanner=$true; Deep=$Deep; Help=$Help }
    if ($Analyze) { $parameters.Analyze=$Target }
    else {
        $selection=Resolve-WinSecTarget $Target
        $parameters.Domain=$selection.Domain
        if ($selection.Collector) { $parameters.Collector=$selection.Collector }
    }
    if ($Snapshot) { $parameters.Snapshot=$Snapshot }
    if ($OutputRoot) { $parameters.OutputRoot=$OutputRoot }
    winsec @parameters
}

function win-defender {
    [CmdletBinding()]
    param([Alias('s')][switch]$Scan,[Alias('a')][switch]$Analyze,[Alias('n')][switch]$Nist,[Alias('c')][switch]$Cis,[string]$Snapshot,[string]$OutputRoot,[switch]$Deep,[Alias('h')][switch]$Help)
    Invoke-WinSecAgentAlias -Target 'WindowsDefender' @PSBoundParameters
}

function win-firewall {
    [CmdletBinding()]
    param([Alias('s')][switch]$Scan,[Alias('a')][switch]$Analyze,[Alias('n')][switch]$Nist,[Alias('c')][switch]$Cis,[string]$Snapshot,[string]$OutputRoot,[switch]$Deep,[Alias('h')][switch]$Help)
    Invoke-WinSecAgentAlias -Target 'WindowsFirewall' @PSBoundParameters
}

function win-bitlocker {
    [CmdletBinding()]
    param([Alias('s')][switch]$Scan,[Alias('a')][switch]$Analyze,[Alias('n')][switch]$Nist,[Alias('c')][switch]$Cis,[string]$Snapshot,[string]$OutputRoot,[switch]$Deep,[Alias('h')][switch]$Help)
    Invoke-WinSecAgentAlias -Target 'BitLocker' @PSBoundParameters
}

function win-update {
    [CmdletBinding()]
    param([Alias('s')][switch]$Scan,[Alias('a')][switch]$Analyze,[Alias('n')][switch]$Nist,[Alias('c')][switch]$Cis,[string]$Snapshot,[string]$OutputRoot,[switch]$Deep,[Alias('h')][switch]$Help)
    Invoke-WinSecAgentAlias -Target 'WindowsUpdate' @PSBoundParameters
}

function win-network {
    [CmdletBinding()]
    param([Alias('s')][switch]$Scan,[Alias('a')][switch]$Analyze,[Alias('n')][switch]$Nist,[Alias('c')][switch]$Cis,[string]$Snapshot,[string]$OutputRoot,[switch]$Deep,[Alias('h')][switch]$Help)
    Invoke-WinSecAgentAlias -Target 'network' @PSBoundParameters
}

function win-identity {
    [CmdletBinding()]
    param([Alias('s')][switch]$Scan,[Alias('a')][switch]$Analyze,[Alias('n')][switch]$Nist,[Alias('c')][switch]$Cis,[string]$Snapshot,[string]$OutputRoot,[switch]$Deep,[Alias('h')][switch]$Help)
    Invoke-WinSecAgentAlias -Target 'identity' @PSBoundParameters
}

function win-logging {
    [CmdletBinding()]
    param([Alias('s')][switch]$Scan,[Alias('a')][switch]$Analyze,[Alias('n')][switch]$Nist,[Alias('c')][switch]$Cis,[string]$Snapshot,[string]$OutputRoot,[switch]$Deep,[Alias('h')][switch]$Help)
    Invoke-WinSecAgentAlias -Target 'logging' @PSBoundParameters
}

function win-services {
    [CmdletBinding()]
    param([Alias('s')][switch]$Scan,[Alias('a')][switch]$Analyze,[Alias('n')][switch]$Nist,[Alias('c')][switch]$Cis,[string]$Snapshot,[string]$OutputRoot,[switch]$Deep,[Alias('h')][switch]$Help)
    Invoke-WinSecAgentAlias -Target 'ServicesHardening' @PSBoundParameters
}
