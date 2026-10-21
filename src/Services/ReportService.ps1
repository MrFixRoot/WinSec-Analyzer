# WinSec Analyzer
# Archivo: src\Services\ReportService.ps1
# Informes públicos de hallazgos; no recolecta datos ni evalúa criterios.

function ConvertTo-WinSecMarkdownText {
    [CmdletBinding()]
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return 'NOT SET' }
    if ($Value -isnot [string] -or $Value.Length -gt 4096 -or $Value -match '[\x00-\x1f\x7f]') {
        throw 'Invalid public report text.'
    }
    return [regex]::Replace([System.Net.WebUtility]::HtmlEncode($Value), '([\\`*_{}\[\]()#+.!|>-])', '\$1')
}

function New-WinSecFindingsMarkdown {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Selection)
    $copy = Copy-WinSecResultData -Value $Selection
    $allowed = @('DeviceId','ScanId','SourceScopeType','SourceScopeKey','ScopeType','ScopeKey','CatalogVersion','Findings')
    if ($copy -isnot [pscustomobject]) { throw 'Invalid report selection.' }
    foreach ($p in $copy.PSObject.Properties) {
        if ($p.Name -cnotin $allowed) { throw 'Unexpected report field.' }
    }
    if (-not (Test-WinSecTargetIdentifier $copy.DeviceId) -or -not (Test-WinSecTargetIdentifier $copy.ScanId)) {
        throw 'Invalid report identity.'
    }
    Assert-WinSecResultScope $copy.SourceScopeType $copy.SourceScopeKey
    Assert-WinSecResultScope $copy.ScopeType $copy.ScopeKey
    if ($copy.ScopeType -cnotin @('SECTION','CONTROL') -or $copy.Findings -isnot [array] -or
        $copy.Findings.Count -eq 0 -or $copy.Findings.Count -gt 1000) { throw 'No exportable findings selection.' }
    $sections = @(Get-WinSecMainMenuSections)
    $catalogControls = @(foreach ($s in $sections) { Get-WinSecSectionControls -SectionKey $s.Key })
    $seen = @{}
    foreach ($finding in $copy.Findings) {
        if ($finding -isnot [pscustomobject]) { throw 'Invalid public finding.' }
        foreach ($p in $finding.PSObject.Properties) {
            if ($p.Name -cnotin @('FindingId','CheckId','DeviceId','ScanId','Kind','EvaluationStatus')) { throw 'Unsafe finding field.' }
        }
        if ($finding.DeviceId -cne $copy.DeviceId -or $finding.ScanId -cne $copy.ScanId -or
            -not (Test-WinSecTargetIdentifier $finding.FindingId) -or $seen.ContainsKey($finding.FindingId) -or
            $finding.Kind -cnotin @('CONFIGURATION_DEVIATION','EVIDENCE_GAP','EVALUATION_UNAVAILABLE','COLLECTION_ERROR',
                'CRITERION_PENDING','EVALUATION_PENDING','CATALOG_NOT_READY','EVALUATION_NOT_TRUSTED',
                'EVALUATION_DATA_ERROR','EVALUATION_IDENTITY_ERROR','DUPLICATE_CRITERION','UNCLASSIFIED') -or
            $finding.EvaluationStatus -cnotin @('NOT_EVALUATED','PASS','FAIL','UNKNOWN','NOT_APPLICABLE','ERROR',
                'PENDING','NOT_CHECKED','NOT_SELECTED','MANUAL','INFORMATIONAL')) {
            throw 'Inconsistent public finding.'
        }
        $control = @($catalogControls | Where-Object { $_.CheckId -ceq $finding.CheckId })
        if ($control.Count -ne 1 -or
            ($copy.ScopeType -ceq 'CONTROL' -and $copy.ScopeKey -cne $finding.CheckId) -or
            ($copy.ScopeType -ceq 'SECTION' -and $copy.ScopeKey -cne $control[0].SectionKey) -or
            ($copy.SourceScopeType -ceq 'CONTROL' -and $copy.SourceScopeKey -cne $finding.CheckId) -or
            ($copy.SourceScopeType -ceq 'SECTION' -and $copy.SourceScopeKey -cne $control[0].SectionKey)) {
            throw 'Finding outside report scope.'
        }
        $seen[$finding.FindingId] = $true
    }
    # Cargar los cuatro catálogos estrictamente, sin interpretar borradores como aprobación.
    $frameworks = @()
    $hashes = @()
    $installation=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
    foreach ($definition in @(Get-WinSecFrameworkDefinitions)) {
        $path = Join-Path $script:WinSecFrameworkDirectory $definition.FileName
        Assert-WinSecDeviceRemovalPath -ProjectRoot $installation -Path $path
        $file=Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if ($file.PSIsContainer -or $file.Length -gt 1048576) { throw 'Invalid framework file.' }
        $before = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash
        $document = ConvertFrom-WinSecStoredJson -Json (Get-Content -LiteralPath $path -Raw -Encoding UTF8 -ErrorAction Stop)
        $null = Test-WinSecFrameworkDocument $document $definition.Id
        if ((Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash -cne $before) { throw 'Framework changed during export.' }
        if ($document.enabled) { $frameworks += $document; $hashes += $before }
    }
    $lines = New-Object 'System.Collections.Generic.List[string]'
    foreach ($line in @('# WinSec Analyzer - Findings','',
        ('Device: ' + (ConvertTo-WinSecMarkdownText $copy.DeviceId)),
        ('Scan: ' + (ConvertTo-WinSecMarkdownText $copy.ScanId)),
        ('Source scope: ' + $copy.SourceScopeType + ' / ' + (ConvertTo-WinSecMarkdownText $copy.SourceScopeKey)),
        ('Exported selection: ' + $copy.ScopeType + ' / ' + (ConvertTo-WinSecMarkdownText $copy.ScopeKey)),
        ('Check catalog: ' + (ConvertTo-WinSecMarkdownText $copy.CatalogVersion)),
        ('Exported at UTC: ' + [DateTime]::UtcNow.ToString('o')),
        'Score: NOT_SCORED','Criteria: PENDING_APPROVED_CRITERIA; historical criteria versions: NOT RECORDED.','',
        'Public results only. Framework references provide context; they do not certify compliance.',
        'A partial selection does not replace a complete assessment.','', '## Configured frameworks','')) { $lines.Add($line) }
    for ($i=0; $i -lt $frameworks.Count; $i++) {
        $fw=$frameworks[$i]
        $lines.Add(('- {0}; version: {1}; schema: {2}; SHA256: {3}' -f
            (ConvertTo-WinSecMarkdownText $fw.name),(ConvertTo-WinSecMarkdownText $fw.frameworkVersion),
            (ConvertTo-WinSecMarkdownText $fw.schemaVersion),$hashes[$i]))
    }
    foreach ($finding in $copy.Findings) {
        $lines.Add(''); $lines.Add('## ' + (ConvertTo-WinSecMarkdownText $finding.FindingId))
        $lines.Add('Control: ' + (ConvertTo-WinSecMarkdownText $finding.CheckId))
        $lines.Add('Kind: ' + $finding.Kind + '; evaluation: ' + $finding.EvaluationStatus)
        $lines.Add('Severity: UNASSIGNED; priority: UNASSIGNED')
        $refs = @(Get-WinSecFrameworkMappings -CheckId $finding.CheckId -Platform Windows -Frameworks @($frameworks | Where-Object { $_.mappingRules.includeInReports -eq $true }))
        $lines.Add(''); $lines.Add('Framework references:')
        if ($refs.Count -eq 0) { $lines.Add('- PENDING: no validated framework references configured for this control.') }
        foreach ($ref in $refs) {
            $lines.Add(('- {0}; version: {1}; reference: {2}; {3}' -f
                (ConvertTo-WinSecMarkdownText $ref.FrameworkName),(ConvertTo-WinSecMarkdownText $ref.FrameworkVersion),
                (ConvertTo-WinSecMarkdownText $ref.ReferenceId),(ConvertTo-WinSecMarkdownText $ref.Title)))
        }
        $lines.Add(''); $lines.Add('Manual recommendations: PENDING_APPROVED_CRITERIA. No framework-specific remediation has been approved for export.')
    }
    return [pscustomobject]@{SchemaVersion='1.0.0';DeviceId=$copy.DeviceId;ScanId=$copy.ScanId;Markdown=($lines -join "`n") + "`n"}
}
