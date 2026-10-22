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
    param(
        [Parameter(Mandatory)][object]$Selection,
        [ValidateSet('cis-controls','nist-csf','mitre-attack')][string]$FrameworkId
    )
    $selectedFramework=$PSBoundParameters.ContainsKey('FrameworkId')
    if ($selectedFramework -and $FrameworkId -cnotin @('cis-controls','nist-csf','mitre-attack')) {
        throw 'Invalid report framework.'
    }
    $copy = Copy-WinSecResultData -Value $Selection
    $allowed = @('DeviceId','ScanId','SourceScopeType','SourceScopeKey','ScopeType','ScopeKey','CatalogVersion','Findings','ConfigurationAssessment')
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
            if ($p.Name -cnotin @('FindingId','CheckId','DeviceId','ScanId','Kind','EvaluationStatus','Guidance')) { throw 'Unsafe finding field.' }
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
        if ($null -ne $finding.Guidance) {
            $finding.Guidance = ConvertTo-WinSecPublicFindingGuidance -Finding $finding -Guidance $finding.Guidance
        }
    }
    $configuration=$null
    if ($null -ne $copy.ConfigurationAssessment) {
        $owner=[pscustomobject]@{DeviceId=$copy.DeviceId;ScanId=$copy.ScanId;ScopeType=$copy.SourceScopeType;ScopeKey=$copy.SourceScopeKey;CatalogVersion=$copy.CatalogVersion}
        $configuration=ConvertTo-WinSecPublicConfigurationAssessment $copy.ConfigurationAssessment $owner
        $visibleConfiguration=[pscustomobject]@{Controls=@($configuration.Controls|Where-Object {
            ($copy.ScopeType -ceq 'SECTION' -and $_.SectionKey -ceq $copy.ScopeKey) -or
            ($copy.ScopeType -ceq 'CONTROL' -and $_.CheckId -ceq $copy.ScopeKey)
        })}
        Assert-WinSecConfigurationProvenance ([pscustomobject]@{Findings=$copy.Findings;EvaluationResults=@();CriteriaSelections=@()}) $visibleConfiguration
    }
    # Leer sólo el marco elegido; el API anterior conserva la vista de los cuatro.
    $frameworks = @()
    $hashes = @()
    $installation=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
    foreach ($definition in @(Get-WinSecFrameworkDefinitions)) {
        if ($selectedFramework -and $definition.Id -cne $FrameworkId) { continue }
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
    if ($selectedFramework -and $frameworks.Count -ne 1) { throw 'Selected framework is unavailable.' }
    $referencesByFinding=@{}
    foreach ($finding in $copy.Findings) {
        # Diagnostics cannot imply a missing framework control.
        $refs=@()
        if ($finding.Kind -ceq 'CONFIGURATION_DEVIATION' -and $finding.EvaluationStatus -ceq 'FAIL' -and $null -ne $finding.Guidance) {
            $refs=@(Get-WinSecFrameworkMappings -CheckId $finding.CheckId -CriterionId $finding.Guidance.CriterionId -Platform Windows -Frameworks @($frameworks|Where-Object {$_.mappingRules.includeInReports -eq $true}))
        }
        $referencesByFinding[$finding.FindingId]=$refs
    }
    $lines = New-Object 'System.Collections.Generic.List[string]'
    foreach ($line in @('# WinSec Analyzer - Findings','',
        ('Device: ' + (ConvertTo-WinSecMarkdownText $copy.DeviceId)),
        ('Scan: ' + (ConvertTo-WinSecMarkdownText $copy.ScanId)),
        ('Source scope: ' + $copy.SourceScopeType + ' / ' + (ConvertTo-WinSecMarkdownText $copy.SourceScopeKey)),
        ('Exported selection: ' + $copy.ScopeType + ' / ' + (ConvertTo-WinSecMarkdownText $copy.ScopeKey)),
        ('Check catalog: ' + (ConvertTo-WinSecMarkdownText $copy.CatalogVersion)),
        ('Exported at UTC: ' + [DateTime]::UtcNow.ToString('o')),
        $(if ($null -ne $configuration) {'Overall device score: NOT_SCORED; individual configuration scores are recorded below.'} else {'Score: NOT_SCORED'}),
        $(if (@($copy.Findings|Where-Object {$null -ne $_.Guidance}).Count -gt 0) {
            'Criteria: original verified criterion snapshots are recorded per finding.'
        } else {'Criteria: PENDING_APPROVED_CRITERIA; historical criteria versions: NOT RECORDED.'}), '',
        'Public results only. Framework references provide context; they do not certify compliance.',
        'A partial selection does not replace a complete assessment.','', '## Configured frameworks','')) { $lines.Add($line) }
    if ($selectedFramework) { $lines.Add('Selected export framework: ' + $FrameworkId) }
    if ($null -ne $configuration) {
        $lines.Add('Configuration selection score: ' + (Get-WinSecConfigurationScoreText $configuration $copy.ScopeType $copy.ScopeKey))
        $lines.Add('Configuration methodology: ' + $configuration.MethodologyId + ' / ' + $configuration.MethodologyVersion)
        $lines.Add('Original scoring policy SHA256: ' + $configuration.PolicySha256)
        $lines.Add('Coverage and recorded criteria:')
        foreach ($control in @($configuration.Controls|Where-Object {$copy.ScopeType -ceq 'SECTION' -and $_.SectionKey -ceq $copy.ScopeKey -or $copy.ScopeType -ceq 'CONTROL' -and $_.CheckId -ceq $copy.ScopeKey})) {
            $lines.Add(('- {0}; score: {1}; criterion coverage: {2}/{3}' -f $control.CheckId,(Get-WinSecConfigurationScoreText $configuration 'CONTROL' $control.CheckId),$control.EvaluatedCriteria,$control.TotalCriteria))
            foreach ($criterion in $control.Criteria) {
                $lines.Add((ConvertTo-WinSecMarkdownText ('  Criterion: ' + $criterion.CriterionId + '; ' + $criterion.Status + '; catalog: ' + $criterion.CatalogId + ' / ' + $criterion.CatalogVersion + '; SHA256: ' + $criterion.CatalogSha256)))
            }
        }
    }
    for ($i=0; $i -lt $frameworks.Count; $i++) {
        $fw=$frameworks[$i]
        $lines.Add(('- {0}; version: {1}; schema: {2}; SHA256: {3}' -f
            (ConvertTo-WinSecMarkdownText $fw.name),(ConvertTo-WinSecMarkdownText $fw.frameworkVersion),
            (ConvertTo-WinSecMarkdownText $fw.schemaVersion),$hashes[$i]))
    }
    $lines.Add(''); $lines.Add('## Configuration deviations'); $lines.Add('')
    $lines.Add('| Finding | Configuration | Status | Original policy control | Referenced framework control |')
    $lines.Add('| --- | --- | --- | --- | --- |')
    $deviations=@($copy.Findings|Where-Object {$_.Kind -ceq 'CONFIGURATION_DEVIATION' -and $_.EvaluationStatus -ceq 'FAIL' -and $null -ne $_.Guidance})
    foreach ($finding in $deviations) {
        $refs=@($referencesByFinding[$finding.FindingId])
        $referenceText=if ($refs.Count) {($refs|ForEach-Object {$_.FrameworkName + ' / ' + $_.ReferenceId}) -join '; '} else {'PENDING: no validated mapping'}
        $values=@($finding.FindingId,$finding.Guidance.CriterionTitle,'MISCONFIGURED',
            ($finding.Guidance.Framework + ' / ' + $finding.Guidance.ReferenceId),$referenceText)
        $lines.Add('| ' + ((@($values|ForEach-Object {ConvertTo-WinSecMarkdownText $_})) -join ' | ') + ' |')
    }
    if ($deviations.Count -eq 0) { $lines.Add(''); $lines.Add('No verified configuration deviations in this selection. This does not confirm a successful audit.') }
    $diagnostics=@($copy.Findings|Where-Object {$_.Kind -cne 'CONFIGURATION_DEVIATION' -or $_.EvaluationStatus -cne 'FAIL' -or $null -eq $_.Guidance})
    if ($diagnostics.Count) {
        $lines.Add(''); $lines.Add('## Diagnostics - not confirmed misconfigurations'); $lines.Add('')
        $lines.Add('| Finding | Check | Kind | Evaluation |'); $lines.Add('| --- | --- | --- | --- |')
        foreach ($finding in $diagnostics) {
            $values=@($finding.FindingId,$finding.CheckId,$finding.Kind,$finding.EvaluationStatus)
            $lines.Add('| ' + ((@($values|ForEach-Object {ConvertTo-WinSecMarkdownText $_})) -join ' | ') + ' |')
        }
    }
    foreach ($finding in $copy.Findings) {
        $lines.Add(''); $lines.Add('## ' + (ConvertTo-WinSecMarkdownText $finding.FindingId))
        $lines.Add('Control: ' + (ConvertTo-WinSecMarkdownText $finding.CheckId))
        $lines.Add('Kind: ' + $finding.Kind + '; evaluation: ' + $finding.EvaluationStatus)
        $lines.Add('Severity: UNASSIGNED; priority: UNASSIGNED')
        $refs = @($referencesByFinding[$finding.FindingId])
        $lines.Add(''); $lines.Add('Framework references:')
        if ($refs.Count -eq 0) { $lines.Add('- PENDING: no validated framework references configured for this control.') }
        foreach ($ref in $refs) {
            $lines.Add(('- {0}; version: {1}; reference: {2}; {3}' -f
                (ConvertTo-WinSecMarkdownText $ref.FrameworkName),(ConvertTo-WinSecMarkdownText $ref.FrameworkVersion),
                (ConvertTo-WinSecMarkdownText $ref.ReferenceId),(ConvertTo-WinSecMarkdownText $ref.Title)))
            if ($ref.Url) { $lines.Add('  Source: ' + (ConvertTo-WinSecMarkdownText $ref.Url)) }
            if ($ref.Description) { $lines.Add('  Control context: ' + (ConvertTo-WinSecMarkdownText $ref.Description)) }
            if ($ref.Recommendation) { $lines.Add('  Framework-oriented manual guidance: ' + (ConvertTo-WinSecMarkdownText $ref.Recommendation)) }
        }
        $lines.Add('')
        if ($null -ne $finding.Guidance) {
            $g=$finding.Guidance
            $lines.Add('### Original criterion and manual recommendation')
            foreach ($entry in @(
                ('Criterion: ' + $g.CriterionId + ' / ' + $g.CriterionTitle),
                ('Criteria catalog: ' + $g.CatalogId + '; version: ' + $g.CatalogVersion + '; SHA256: ' + $g.CatalogSha256),
                ('Applicability: ' + $g.OSFamily + ' / ' + $g.OSRelease + ' / ' + $g.Edition + ' / ' + $g.Profile),
                ('Verified at UTC: ' + $g.VerifiedAtUTC),
                ('Source: ' + $g.Framework + '; version: ' + $g.FrameworkVersion + '; control: ' + $g.ReferenceId),
                ('Reference: ' + $g.ReferenceTitle + ' / ' + $g.ReferenceUrl),
                ('Manual recommendation: ' + $g.Recommendation)
            )) { $lines.Add((ConvertTo-WinSecMarkdownText $entry)) }
            $lines.Add('Original recommendation retained from the scan; configured framework context above is resolved at export time.')
        } else {
            $lines.Add('Manual recommendations: PENDING_APPROVED_CRITERIA. No framework-specific remediation has been approved for export.')
        }
    }
    return [pscustomobject]@{SchemaVersion='1.0.0';DeviceId=$copy.DeviceId;ScanId=$copy.ScanId;Markdown=($lines -join "`n") + "`n"}
}
