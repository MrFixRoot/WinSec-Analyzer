function Invoke-WinSecNamedAnalysis {
    param([string[]]$Framework,[int]$Correlation,[string]$Snapshot,[string]$OutputRoot,[string]$CollectorFilter,[string]$DomainFilter)
    $context=Get-WinSecSnapshotManifest -Snapshot $Snapshot -OutputRoot $OutputRoot
    # Snapshot metadata must itself indicate Windows 11; never analyze Server/Windows 10 captures.
    if ($context.Manifest.os.family -ne 'Windows11') { throw 'Solo se analizan snapshots de Windows 11.' }
    foreach ($name in @($Framework)) {
        if (-not $name) { continue }
        $name=$name.Trim().ToLowerInvariant()
        if ($name -notin @('cis','nist')) { throw "Framework no admitido: $name" }
        if ($name -eq 'cis') { $data=Invoke-WinSecCISAnalysis -Context $context -CollectorFilter $CollectorFilter -DomainFilter $DomainFilter }
        else { $data=Invoke-WinSecNISTAnalysis -Context $context -CollectorFilter $CollectorFilter -DomainFilter $DomainFilter }
        $resultPath=Save-WinSecAnalysis -Context $context -Name $name -Data $data
        Write-Host ('  [{0}] {1}' -f $data.status,$name.ToUpperInvariant()) -ForegroundColor Yellow
        if ($name -eq 'cis') {
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
        $resultPath=Save-WinSecAnalysis -Context $context -Name 'correlations' -Data $data
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

function winsec {
    [CmdletBinding()]
    param(
        [Alias('s')][switch]$Scan,
        [Alias('a')][ValidateSet('cis','nist')][string[]]$Analyze,
        [Alias('c')][ValidateRange(1,5)][int]$Correlation,
        [Parameter(Position=0)][string]$Domain='all',
        [string]$Collector,
        [string]$Snapshot,
        [string]$OutputRoot,
        [switch]$Deep,
        [switch]$List,
        [switch]$Report,
        [switch]$NoBanner
    )
    $null=Assert-WinSecWindows11
    if (-not $NoBanner -and ($Scan -or $Analyze -or $Correlation -or $List -or $Report)) { Show-WinSecBanner }
    if ($List) {
        $base=Get-WinSecOutputRoot -OutputRoot $OutputRoot
        if (Test-Path -LiteralPath $base) {
            Get-ChildItem -LiteralPath $base -Filter manifest.json -File -Recurse | Sort-Object LastWriteTimeUtc -Descending |
                Select-Object LastWriteTimeUtc,FullName
        } else { Write-Host 'No hay snapshots disponibles.' }
        return
    }
    if ($Scan) { $Snapshot=Invoke-WinSecCollection -Domain $Domain -Collector $Collector -OutputRoot $OutputRoot -Deep:$Deep }
    if ($Analyze -or $PSBoundParameters.ContainsKey('Correlation')) {
        Invoke-WinSecNamedAnalysis -Framework $Analyze -Correlation $Correlation -Snapshot $Snapshot -OutputRoot $OutputRoot -CollectorFilter $Collector -DomainFilter (Resolve-WinSecDomain $Domain)
    }
    if ($Report) {
        $context=Get-WinSecSnapshotManifest -Snapshot $Snapshot -OutputRoot $OutputRoot
        [void](Invoke-WinSecReport -Context $context)
    }
    if (-not $Scan -and -not $Analyze -and -not $PSBoundParameters.ContainsKey('Correlation') -and -not $Report) {
        Invoke-WinSecMenu -OutputRoot $OutputRoot
    }
}

function Invoke-WinSecAgentAlias {
    param([string]$CollectorId,[switch]$Scan,[string[]]$Analyze,[string]$Snapshot,[switch]$Deep)
    $params=@{ Collector=$CollectorId; Scan=$Scan; NoBanner=$true; Deep=$Deep }
    if ($Analyze) { $params.Analyze=$Analyze }
    if ($Snapshot) { $params.Snapshot=$Snapshot }
    winsec @params
}
function win-defender {
    [CmdletBinding()]param([Alias('s')][switch]$Scan,[Alias('a')][ValidateSet('cis','nist')][string[]]$Analyze,[string]$Snapshot,[switch]$Deep)
    Invoke-WinSecAgentAlias -CollectorId 'WindowsDefender' -Scan:$Scan -Analyze $Analyze -Snapshot $Snapshot -Deep:$Deep
}
function win-firewall {
    [CmdletBinding()]param([Alias('s')][switch]$Scan,[Alias('a')][ValidateSet('cis','nist')][string[]]$Analyze,[string]$Snapshot,[switch]$Deep)
    Invoke-WinSecAgentAlias -CollectorId 'WindowsFirewall' -Scan:$Scan -Analyze $Analyze -Snapshot $Snapshot -Deep:$Deep
}
function win-bitlocker {
    [CmdletBinding()]param([Alias('s')][switch]$Scan,[Alias('a')][ValidateSet('cis','nist')][string[]]$Analyze,[string]$Snapshot,[switch]$Deep)
    Invoke-WinSecAgentAlias -CollectorId 'BitLocker' -Scan:$Scan -Analyze $Analyze -Snapshot $Snapshot -Deep:$Deep
}
function win-update {
    [CmdletBinding()]param([Alias('s')][switch]$Scan,[Alias('a')][ValidateSet('cis','nist')][string[]]$Analyze,[string]$Snapshot,[switch]$Deep)
    Invoke-WinSecAgentAlias -CollectorId 'WindowsUpdate' -Scan:$Scan -Analyze $Analyze -Snapshot $Snapshot -Deep:$Deep
}
function win-network {
    [CmdletBinding()]param([Alias('s')][switch]$Scan,[Alias('a')][ValidateSet('cis','nist')][string[]]$Analyze,[string]$Snapshot,[switch]$Deep)
    $args=@{Scan=$Scan;Domain='network';NoBanner=$true;Deep=$Deep}
    if ($Analyze) {$args.Analyze=$Analyze}; if ($Snapshot) {$args.Snapshot=$Snapshot}
    winsec @args
}
function win-identity {
    [CmdletBinding()]param([Alias('s')][switch]$Scan,[Alias('a')][ValidateSet('cis','nist')][string[]]$Analyze,[string]$Snapshot,[switch]$Deep)
    $args=@{Scan=$Scan;Domain='identity';NoBanner=$true;Deep=$Deep}
    if ($Analyze) {$args.Analyze=$Analyze}; if ($Snapshot) {$args.Snapshot=$Snapshot}
    winsec @args
}
function win-logging {
    [CmdletBinding()]param([Alias('s')][switch]$Scan,[Alias('a')][ValidateSet('cis','nist')][string[]]$Analyze,[string]$Snapshot,[switch]$Deep)
    $args=@{Scan=$Scan;Domain='logging';NoBanner=$true;Deep=$Deep}
    if ($Analyze) {$args.Analyze=$Analyze}; if ($Snapshot) {$args.Snapshot=$Snapshot}
    winsec @args
}
function win-services {
    [CmdletBinding()]param([Alias('s')][switch]$Scan,[Alias('a')][ValidateSet('cis','nist')][string[]]$Analyze,[string]$Snapshot,[switch]$Deep)
    $args=@{Scan=$Scan;Domain='services';NoBanner=$true;Deep=$Deep}
    if ($Analyze) {$args.Analyze=$Analyze}; if ($Snapshot) {$args.Snapshot=$Snapshot}
    winsec @args
}
