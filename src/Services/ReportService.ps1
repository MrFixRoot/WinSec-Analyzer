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
    $allowed = @('DeviceId','ScanId','SourceScopeType','SourceScopeKey','ScopeType','ScopeKey','CatalogVersion','Findings','ReviewItems','ConfigurationAssessment','DeviceName','CurrentSystemLabel')
    if ($copy -isnot [pscustomobject]) { throw 'Invalid report selection.' }
    foreach ($p in $copy.PSObject.Properties) {
        if ($p.Name -cnotin $allowed) { throw 'Unexpected report field.' }
    }
    if (-not (Test-WinSecTargetIdentifier $copy.DeviceId) -or -not (Test-WinSecTargetIdentifier $copy.ScanId)) {
        throw 'Invalid report identity.'
    }
    $deviceName='NOT_RECORDED'
    if($null -ne $copy.PSObject.Properties['DeviceName']) {
        if(-not (Test-WinSecDeviceDisplayName $copy.DeviceName)){throw 'Invalid report device name.'}
        $deviceName=$copy.DeviceName
    }
    if($null -ne $copy.PSObject.Properties['CurrentSystemLabel'] -and
        ($copy.CurrentSystemLabel -isnot [string] -or [string]::IsNullOrWhiteSpace($copy.CurrentSystemLabel) -or
        $copy.CurrentSystemLabel.Length -gt 256 -or $copy.CurrentSystemLabel -match '[\p{C}\p{Zl}\p{Zp}]')) {
        throw 'Invalid report system label.'
    }
    Assert-WinSecResultScope $copy.SourceScopeType $copy.SourceScopeKey
    Assert-WinSecResultScope $copy.ScopeType $copy.ScopeKey
    $reviews=@()
    if($null -ne $copy.ReviewItems) {
        if($copy.ReviewItems -isnot [array] -or $copy.ReviewItems.Count -gt 138){throw 'Invalid review export collection.'}
        $reviewIds=@{}
        $reviews=@(foreach($review in $copy.ReviewItems) {
            $safe=if($null -ne $review.BitLockerSetting){ConvertTo-WinSecBitLockerReviewItem $review $copy}
                elseif($null -ne $review.WindowsUpdateSetting){ConvertTo-WinSecWindowsUpdateReviewItem $review $copy}
                else{ConvertTo-WinSecDefenderReviewItem $review $copy}
            if($reviewIds.ContainsKey($safe.ReviewId) -or
                ($copy.ScopeType -ceq 'CONTROL' -and $copy.ScopeKey -cne $safe.CheckId) -or
                ($copy.ScopeType -ceq 'SECTION' -and $copy.ScopeKey -cne 'SystemSecurity') -or
                ($copy.SourceScopeType -ceq 'CONTROL' -and $copy.SourceScopeKey -cne $safe.CheckId) -or
                ($copy.SourceScopeType -ceq 'SECTION' -and $copy.SourceScopeKey -cne 'SystemSecurity')){throw 'Review outside report scope.'}
            $reviewIds[$safe.ReviewId]=$true
            $safe
        })
    }
    if ($copy.ScopeType -cnotin @('SECTION','CONTROL') -or $copy.Findings -isnot [array] -or
        ($copy.Findings.Count -eq 0 -and $reviews.Count -eq 0 -and $null -eq $copy.ConfigurationAssessment) -or $copy.Findings.Count -gt 1000) { throw 'No exportable findings selection.' }
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
    # Recorded applicability is not the current OS of the machine exporting history.
    $platforms=@(if($null -ne $configuration) {
        foreach($control in $visibleConfiguration.Controls){$control.Criteria|Select-Object OSRelease,Edition}
    } else {
        foreach($finding in $copy.Findings){if($null -ne $finding.Guidance){$finding.Guidance|Select-Object OSRelease,Edition}}
    })
    $platforms=@($platforms|Select-Object OSRelease,Edition -Unique)
    $recordedOS='NOT_RECORDED';$recordedBuild='NOT_RECORDED'
    if($platforms.Count -eq 1) {
        $recordedOS=$platforms[0].OSRelease+' / '+$platforms[0].Edition
        if($platforms[0].OSRelease -cmatch '\AWindows 11 10\.0\.([1-9][0-9]{0,8})\z'){$recordedBuild=$Matches[1]}
    } elseif($platforms.Count -gt 1) {
        $recordedOS='MULTIPLE: see original criteria';$recordedBuild='MULTIPLE: see original criteria'
    }
    $lines = New-Object 'System.Collections.Generic.List[string]'
    foreach ($line in @('# WinSec Analyzer - Findings','',
        ('- Device name (inventory at export): ' + (ConvertTo-WinSecMarkdownText $deviceName)),
        ('- Device: ' + (ConvertTo-WinSecMarkdownText $copy.DeviceId)),
        ('- Operating system (recorded criteria): ' + (ConvertTo-WinSecMarkdownText $recordedOS)),
        ('- Build (recorded criteria): ' + (ConvertTo-WinSecMarkdownText $recordedBuild)),
        $(if($null -ne $copy.CurrentSystemLabel){'- Current local OS (at application startup): Windows 11 ' + (ConvertTo-WinSecMarkdownText $copy.CurrentSystemLabel)}),
        ('- Scan: ' + (ConvertTo-WinSecMarkdownText $copy.ScanId)),
        ('- Source scope: ' + $copy.SourceScopeType + ' / ' + (ConvertTo-WinSecMarkdownText $copy.SourceScopeKey)),
        ('- Exported selection: ' + $copy.ScopeType + ' / ' + (ConvertTo-WinSecMarkdownText $copy.ScopeKey)),
        ('- Check catalog: ' + (ConvertTo-WinSecMarkdownText $copy.CatalogVersion)),
        ('- Report generated at UTC: ' + [DateTime]::UtcNow.ToString('o')),
        $(if ($null -ne $configuration) {'- Overall device score: NOT_SCORED; individual configuration scores are recorded below.'} else {'- Score: NOT_SCORED'}),
        $(if ($null -ne $configuration) {'- Criteria: complete original criterion manifest recorded, including PASS and unresolved checks.'}
        elseif (@($copy.Findings|Where-Object {$null -ne $_.Guidance}).Count -gt 0) {
            '- Criteria: original verified criterion snapshots are recorded per finding.'
        } else {'- Criteria: PENDING_APPROVED_CRITERIA; historical criteria versions: NOT RECORDED.'}), '',
        'Public results only. Framework references provide context; they do not certify compliance.',
        'A partial selection does not replace a complete assessment.','', '## Configured frameworks','')) { $lines.Add($line) }
    if ($selectedFramework) { $lines.Add('Selected export framework: ' + $FrameworkId) }
    if ($null -ne $configuration) {
        $lines.Add('Configuration selection score: ' + (Get-WinSecConfigurationScoreText $configuration $copy.ScopeType $copy.ScopeKey))
        $lines.Add('Configuration methodology: ' + $configuration.MethodologyId + ' / ' + $configuration.MethodologyVersion)
        $lines.Add('Original scoring policy SHA256: ' + $configuration.PolicySha256)
        $lines.Add('Coverage and recorded criteria:')
        foreach ($control in @($configuration.Controls|Where-Object {$copy.ScopeType -ceq 'SECTION' -and $_.SectionKey -ceq $copy.ScopeKey -or $copy.ScopeType -ceq 'CONTROL' -and $_.CheckId -ceq $copy.ScopeKey})) {
            $excluded=@($control.Criteria|Where-Object Status -CEQ NOT_APPLICABLE).Count
            $lines.Add(('- {0}; score: {1}; applicable criterion coverage: {2}/{3}; excluded: {4}; recorded: {5}' -f $control.CheckId,(Get-WinSecConfigurationScoreText $configuration 'CONTROL' $control.CheckId),$control.EvaluatedCriteria,($control.TotalCriteria-$excluded),$excluded,$control.TotalCriteria))
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
    if($null -ne $configuration) {
        $checkRows=@(Get-WinSecConfigurationRows $configuration $copy.ScopeType $copy.ScopeKey)
        $updateRows=@(ConvertTo-WinSecWindowsUpdateReviewRows @($reviews|Where-Object {$null -ne $_.WindowsUpdateSetting}))
        foreach($row in $checkRows|Where-Object CheckId -CEQ 'WSA-SYS-003') {
            $detail=@($updateRows|Where-Object CriterionId -CEQ $row.CriterionId)
            if($detail.Count -eq 1){$row.Finding=$detail[0].Finding}
        }
        if($checkRows.Count -eq 0 -and $copy.Findings.Count -eq 0 -and $reviews.Count -eq 0){throw 'No configuration checks in this report scope.'}
        $lines.Add('');$lines.Add('## Configuration checks');$lines.Add('')
        $lines.Add('| ID | Control | Configuration | State | Configuration % | Referenced framework control | Applicability |')
        $lines.Add('| --- | --- | --- | --- | --- | --- | --- |')
        $displayNumber=0
        foreach($row in $checkRows) {
            $displayNumber++
            $failed=@($copy.Findings|Where-Object {$null -ne $_.Guidance -and $_.CheckId -ceq $row.CheckId -and $_.Guidance.CriterionId -ceq $row.CriterionId})
            $refs=@(foreach($finding in $failed){$referencesByFinding[$finding.FindingId]})
            $refText=if($row.EvaluationStatus -ceq 'FAIL' -and $refs.Count){($refs|ForEach-Object {$_.FrameworkName+' / '+$_.ReferenceId}) -join '; '}else{'Not asserted'}
            $applicability=if($row.EvaluationStatus -ceq 'NOT_APPLICABLE'){$row.Description}else{'Applicable or unresolved; see recorded result'}
            $values=@(('{0:D2}' -f $displayNumber),($row.CheckId+' / '+$row.CriterionId),$row.Finding,$row.ConfigurationState,$row.ConfigurationPercent,$refText,$applicability)
            $lines.Add('| '+((@($values|ForEach-Object {ConvertTo-WinSecMarkdownText $_})) -join ' | ')+' |')
        }
        $lines.Add('')
        foreach($control in $configuration.Controls) {
            if(($copy.ScopeType -ceq 'CONTROL' -and $control.CheckId -cne $copy.ScopeKey) -or
                ($copy.ScopeType -ceq 'SECTION' -and $control.SectionKey -cne $copy.ScopeKey)){continue}
            foreach($criterion in @($control.Criteria|Where-Object Status -CEQ NOT_APPLICABLE)) {
                $lines.Add('Platform exclusion source: '+(ConvertTo-WinSecMarkdownText $criterion.ApplicabilitySourceUrl))
            }
        }
        $lines.Add('Percentages describe only recorded approved applicable configuration criteria. Verified NOT_APPLICABLE criteria are excluded from the denominator. UNKNOWN and NOT_EVALUATED are not exclusions or failures and receive no percentage.')
        if(@($visibleConfiguration.Controls|Where-Object CheckId -CEQ 'WSA-SYS-001').Count) {
            $lines.Add('ASR scoring covers only the vulnerable signed driver rule; other ASR rules remain inventory-only.')
        }
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
    $defenderReviews=@($reviews|Where-Object {$null -ne $_.DefenderSetting})
    if($defenderReviews.Count) {
        $lines.Add('');$lines.Add('## Defender observations - REVIEW_ONLY, excluded from scoring');$lines.Add('')
        $lines.Add('Observed configuration is not proof of effective enforcement or a confirmed policy deviation. Cloud connectivity is not tested. Unlisted ASR rules are not assessed.')
        $lines.Add('');$lines.Add('| Setting | Identifier | Observed mode | Inventory | Status |')
        $lines.Add('| --- | --- | --- | --- | --- |')
        foreach($review in $defenderReviews) {
            $s=$review.DefenderSetting
            $values=@($s.Topic,$s.SettingId,$s.Mode,$s.InventoryState,$review.Status)
            $lines.Add('| '+((@($values|ForEach-Object {ConvertTo-WinSecMarkdownText $_})) -join ' | ')+' |')
        }
        $lines.Add('')
        $lines.Add('Manual review: assess PUA blocking using a staged audit deployment; verify cloud protection policy and connectivity; review tamper protection support and management authority; select applicable ASR rules individually before recommending enforcement. No remediation is executed.')
        $lines.Add('No framework control is declared violated by these observations; approved criteria and reviewed mappings are required.')
        foreach($url in @('https://learn.microsoft.com/en-us/defender-endpoint/detect-block-potentially-unwanted-apps-microsoft-defender-antivirus',
            'https://learn.microsoft.com/en-us/defender-endpoint/cloud-protection-configure',
            'https://learn.microsoft.com/en-us/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection',
            'https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-overview')){$lines.Add('Technical reference: '+$url)}
    }
    $bitLockerReviews=@($reviews|Where-Object {$null -ne $_.BitLockerSetting})
    if($bitLockerReviews.Count) {
        $lines.Add('');$lines.Add('## BitLocker observations - REVIEW_ONLY, excluded from scoring');$lines.Add('')
        $lines.Add('Only the Windows volume is observed. These observations do not add approved criteria or configuration deviations. Native encryption progress is not the configuration score; 100% alone does not prove conversion has completed.')
        $lines.Add('');$lines.Add('| ID | Control | Configuration | State | Configuration % |')
        $lines.Add('| --- | --- | --- | --- | --- |')
        $number=if($null -ne $configuration){$checkRows.Count}else{0}
        $number+=$diagnostics.Count
        foreach($review in $bitLockerReviews) {
            $number++;$row=@(ConvertTo-WinSecBitLockerReviewRows @($review))[0]
            $values=@(('{0:D2}' -f $number),$review.CheckId,$row.Finding,'REVIEW_ONLY','N/A')
            $lines.Add('| '+((@($values|ForEach-Object {ConvertTo-WinSecMarkdownText $_})) -join ' | ')+' |')
        }
        $lines.Add('')
        $lines.Add('Algorithm guidance reviewed 2026-10-22: Microsoft recommends XTS-AES for software-encrypted Windows volumes. Choose 128 or 256 bits according to device performance and regulatory or organizational requirements. XTS-AES-128 is not automatically a failure. CBC/diffuser modes require a compatibility and policy review; HARDWARE_ENCRYPTION does not identify a verified cipher or key length. UNKNOWN is not a configuration failure.')
        $lines.Add('An unlocked Windows volume during normal use is expected; this report does not recommend locking the running OS volume. TPM/PIN, recovery-key custody and regulatory compliance are not assessed. Review recovery arrangements and obtain administrative authorization before any manual encryption change. WinSec never changes encryption.')
        $lines.Add('Technical source: https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/configure')
        $lines.Add('Cryptographic context: NIST SP 800-38E (2010 final) approves XTS-AES for storage confidentiality; it does not provide data or source authentication. This is distinct from NIST CSF and is not a certification of this device.')
        $lines.Add('Technical source: https://csrc.nist.gov/pubs/sp/800/38/e/final')
        $lines.Add('');$lines.Add('### Selected framework context for BitLocker');$lines.Add('')
        $contextRefs=@(Get-WinSecFrameworkMappings -CheckId WSA-SYS-002 -CriterionId WSA-BLK-BASE-001 -Platform Windows `
            -Frameworks @($frameworks|Where-Object {$_.mappingRules.includeInReports -eq $true}))
        if(-not $contextRefs.Count){$lines.Add('PENDING: no reviewed framework context available.')}
        foreach($ref in $contextRefs) {
            $lines.Add('- '+(ConvertTo-WinSecMarkdownText ($ref.FrameworkName+' / '+$ref.FrameworkVersion+' / '+$ref.ReferenceId+': '+$ref.Title)))
            $lines.Add('  Context: '+(ConvertTo-WinSecMarkdownText $ref.Description))
            $lines.Add('  Manual review: '+(ConvertTo-WinSecMarkdownText $ref.Recommendation))
            $lines.Add('  Source: '+$ref.Url)
        }
        $lines.Add('These references contextualize encryption at rest. They do not impose an automatic 128-versus-256-bit grade or declare a framework violation from an informational observation. Original historical scores and criteria remain unchanged on re-export.')
    }
    $updateReviews=@($reviews|Where-Object {$null -ne $_.WindowsUpdateSetting})
    if($updateReviews.Count) {
        $lines.Add('');$lines.Add('## Windows Update diagnostic context');$lines.Add('')
        $lines.Add('These observations explain the original three criteria; they add no findings or points. UNKNOWN is unresolved, not a confirmed failure. The patch criterion covers only the reviewed cumulative Windows OS security baseline, not every applicable update. Automation settings do not prove patches were installed.')
        $lines.Add('');$lines.Add('| Control | Observed state | Reason | Explanation |');$lines.Add('| --- | --- | --- | --- |')
        foreach($review in $updateReviews) {
            $s=$review.WindowsUpdateSetting
            $values=@(($review.CheckId+' / '+$s.CriterionId),$s.State,$s.Reason,
                (Get-WinSecWindowsUpdateReviewDescription $s.CriterionId $s.State $s.Reason))
            $lines.Add('| '+((@($values|ForEach-Object {ConvertTo-WinSecMarkdownText $_})) -join ' | ')+' |')
        }
        $lines.Add('')
        foreach($review in $updateReviews) {
            $s=$review.WindowsUpdateSetting
            $lines.Add((ConvertTo-WinSecMarkdownText ($s.CriterionId+'; reference version: '+$s.ReferenceVersion+
                '; SHA256: '+$s.ReferenceSha256+'; reference window UTC: '+$s.ReferenceAsOfUTC+' to '+$s.ReferenceValidUntilUTC+
                ' (exclusive); evaluated UTC: '+$s.EvaluatedAtUTC)))
        }
        $lines.Add('Re-export preserves the recorded diagnostic reasons and reference window. It does not query Windows or reassess historical results against current reference data. Framework mappings remain pending individual review.')
    }
    return [pscustomobject]@{SchemaVersion='1.0.0';DeviceId=$copy.DeviceId;ScanId=$copy.ScanId;Markdown=($lines -join "`n") + "`n"}
}
