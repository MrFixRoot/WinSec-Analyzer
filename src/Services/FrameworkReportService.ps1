# Export the exact selected framework view. No new evaluation or framework prompt.
. (Join-Path $PSScriptRoot 'FrozenFindingsStore.ps1')
function New-WinSecFrameworkMarkdown {
    param($Analysis)
    $a=Assert-WinSecFrameworkAnalysis $Analysis $Analysis.DeviceId $Analysis.ScopeType $Analysis.ScopeKey
    $lines=New-Object 'Collections.Generic.List[string]'
    $lines.Add('# WinSec Analyzer - Framework findings');$lines.Add('')
    foreach($field in @('DeviceName','DeviceId','ScopeType','ScopeKey','AnalysisId','FrameworkId','FrameworkVersion','FrameworkSha256',
        'RuleCatalogVersion','RuleCatalogSha256','GeneratedAtUTC')) {
        $lines.Add('- '+$field+': '+(ConvertTo-WinSecTechnicalCell $a.$field))
    }
    $lines.Add('');$lines.Add('Warnings are configuration review context, not certification or evidence of an attack. This report preserves the selected view; original scan sessions remain unchanged.')
    $lines.Add('');$lines.Add('## Source scans');$lines.Add('')
    $lines.Add('| Control | Scan | Original scope | Collected / completed UTC | Origin |');$lines.Add('| --- | --- | --- | --- | --- |')
    foreach($source in $a.Sources) {
        $cells=@($source.CheckId,$source.ScanId,($source.ScopeType+' / '+$source.ScopeKey),$source.CompletedAtUTC,$source.Origin)|ForEach-Object {ConvertTo-WinSecTechnicalCell $_}
        $lines.Add('| '+($cells -join ' | ')+' |')
    }
    $lines.Add('');$lines.Add('## Coverage');$lines.Add('')
    $lines.Add('Readings reviewed: '+$a.ReadingCount+'. Unknown/unavailable: '+$a.UnknownReadingCount+'. Warnings: '+$a.Rows.Count+'.')
    $lines.Add('A reading without a reviewed warning rule is informational. No warnings does not prove full framework coverage or compliance.')
    if($a.SchemaVersion -ceq '1.1.0'){
        $lines.Add('');$lines.Add('### Saved reading coverage');$lines.Add('')
        $lines.Add('Review engine: '+$a.ReadingReview.EngineVersion+'. Ledger SHA256: '+$a.ReadingReview.LedgerSha256+'.')
        $lines.Add('');$lines.Add('| Treatment | Readings |');$lines.Add('| --- | ---: |')
        foreach($treatment in @('EVALUATED','INFORMATIVE_NO_RULE','UNRESOLVED_RULE','UNKNOWN','ERROR','NOT_COLLECTED','NOT_CONFIGURED','NOT_APPLICABLE')){
            $lines.Add('| '+$treatment+' | '+$a.ReadingReview.Treatments.$treatment+' |')
        }
        $lines.Add('');$lines.Add('LIMITED_NOT_COMPLIANCE: source completion and framework coverage are separate. Original snapshot identities and digests are preserved in the frozen analysis record.')
    }
    if($a.ScopeType -ceq 'SECTION' -and $a.ScopeKey -ceq 'NetworkSecurity'){
        if($a.RuleCatalogVersion -ceq '1.1.0'){$lines.Add('Only Windows Firewall currently has a reviewed collector in this section. SMB and RDP remain pending; this is not a complete Network Security assessment.')}
        elseif($a.RuleCatalogVersion -ceq '1.2.0') {$lines.Add('Reviewed technical adapters: Windows Firewall and SMBv1. Only confirmed, executed controls supply readings; pending or unvalidated controls are not scanned. Remote Desktop, Open Ports and Network Configuration remain pending. This is not a complete Network Security assessment.')}
        elseif($a.RuleCatalogVersion -cin @('1.3.0','1.4.0')) {$lines.Add('Reviewed technical adapters: Windows Firewall, SMBv1 and Remote Desktop. Only confirmed, executed controls supply readings; pending or unvalidated controls are not scanned. Open Ports and Network Configuration remain pending. This is not a complete Network Security assessment.')}
        elseif($a.RuleCatalogVersion -ceq '1.5.0') {$lines.Add('Reviewed technical adapters: Windows Firewall, SMBv1, Remote Desktop and Open Ports. Only confirmed, executed controls supply readings; pending or unvalidated controls are not scanned. Network Configuration remains pending. Local bindings do not prove network reachability or vulnerability. This is not a complete Network Security assessment.')}
        else {$lines.Add('Reviewed technical adapters: Windows Firewall, SMBv1, Remote Desktop, Open Ports and Network Configuration. Only confirmed, executed controls supply readings; pending or unvalidated controls are not scanned. Local configuration and bindings do not prove reachability, vulnerability or complete framework coverage. Unknown and unreviewed readings remain explicitly limited.')}
    }
    $expected=@(Get-WinSecTechnicalScopeChecks $a.ScopeType $a.ScopeKey)
    if($a.RuleCatalogVersion -ceq '1.1.0' -and $a.ScopeType -ceq 'SECTION' -and $a.ScopeKey -ceq 'NetworkSecurity'){$expected=@('WSA-NET-001')}
    if($a.RuleCatalogVersion -ceq '1.2.0' -and $a.ScopeType -ceq 'SECTION' -and $a.ScopeKey -ceq 'NetworkSecurity'){$expected=@('WSA-NET-001','WSA-NET-002')}
    if($a.RuleCatalogVersion -cin @('1.3.0','1.4.0') -and $a.ScopeType -ceq 'SECTION' -and $a.ScopeKey -ceq 'NetworkSecurity'){$expected=@('WSA-NET-001','WSA-NET-002','WSA-NET-003')}
    if($a.RuleCatalogVersion -ceq '1.5.0' -and $a.ScopeType -ceq 'SECTION' -and $a.ScopeKey -ceq 'NetworkSecurity'){$expected=@('WSA-NET-001','WSA-NET-002','WSA-NET-003','WSA-NET-004')}
    if($a.RuleCatalogVersion -cne '1.7.0' -and $a.ScopeType -ceq 'SECTION' -and $a.ScopeKey -ceq 'IdentityAccess'){$expected=@()}
    $unscanned=@($expected|Where-Object {$_ -cnotin @($a.Sources.CheckId)})
    if($unscanned.Count){$lines.Add('Controls without a saved scan: '+($unscanned -join ', ')+'. Run a separately confirmed scan to collect them.')}
    if($a.MissingTechnicalCheckIds.Count){
        $limit=if($a.SchemaVersion -ceq '1.1.0'){'. No new warnings were evaluated for these controls.'}else{'. Only recorded, verified deviations could be reviewed for these controls.'}
        $lines.Add('Detailed snapshots not available: '+($a.MissingTechnicalCheckIds -join ', ')+$limit)
    }
    $lines.Add('');$lines.Add('## Findings');$lines.Add('')
    $lines.Add('| ID | Control / criterion | Configuration warning | State | Observed | Framework reference |');$lines.Add('| --- | --- | --- | --- | --- | --- |')
    foreach($row in $a.Rows) {
        $refs=if($row.References.Count){($row.References|ForEach-Object ReferenceId)-join '; '}else{'PENDING - no reviewed mapping'}
        $cells=@($row.Id,($row.CheckId+' / '+$row.CriterionId),$row.Title,$row.State,$row.Observed,$refs)|ForEach-Object {ConvertTo-WinSecTechnicalCell $_}
        $lines.Add('| '+($cells -join ' | ')+' |')
    }
    foreach($row in $a.Rows) {
        $lines.Add('');$lines.Add('## '+$row.Id+' - '+(ConvertTo-WinSecTechnicalCell $row.Title));$lines.Add('')
        $lines.Add('Source scan: '+(ConvertTo-WinSecTechnicalCell $row.ScanId)+'. Type: '+$row.Kind+'.')
        $lines.Add('');$lines.Add('Setting: '+(ConvertTo-WinSecTechnicalCell $row.SettingId))
        $lines.Add('');$lines.Add('Manual recommendation: '+(ConvertTo-WinSecTechnicalCell $row.Recommendation))
        foreach($ref in $row.References) {
            $lines.Add('');$lines.Add('- '+(ConvertTo-WinSecTechnicalCell ($ref.ReferenceId+' - '+$ref.Title)))
            $lines.Add('  '+(ConvertTo-WinSecTechnicalCell $ref.Description))
            $lines.Add('  Framework context: '+(ConvertTo-WinSecTechnicalCell $ref.Recommendation))
            $lines.Add('  Source: ['+(ConvertTo-WinSecTechnicalCell $ref.ReferenceId)+']('+$ref.Url+')')
        }
    }
    $lines.Add('');$lines.Add('## Analysis record');$lines.Add('');$lines.Add('```json');$lines.Add((Get-WinSecPublicHistoryJson $a));$lines.Add('```');$lines.Add('')
    $lines -join "`n"
}

function ConvertFrom-WinSecFrameworkMarkdownArtifact {
    param([string]$Text,[string]$DeviceId)
    if([Text.Encoding]::UTF8.GetByteCount($Text) -gt 1048576 -or $Text -match '[\x00-\x09\x0b-\x1f\x7f]' -or
        $Text -cnotmatch '\A<!-- WinSec framework findings\n([^\r\n]+)\n-->\n([\s\S]*)\z'){throw 'Unrecognized framework report.'}
    $meta=ConvertFrom-WinSecStoredJson $Matches[1];$body=$Matches[2]
    if($meta.SchemaVersion -ceq '2.0.0'){return (ConvertFrom-WinSecFrozenFindingsArtifact $Text $DeviceId).Metadata}
    Assert-WinSecConfigurationFields $meta @('SchemaVersion','DeviceId','AnalysisId','FrameworkId','ContentSha256')
    if($meta.SchemaVersion -cne '1.0.0' -or $meta.DeviceId -isnot [string] -or $meta.DeviceId -cne $DeviceId -or
        $meta.ContentSha256 -cne (Get-WinSecReportTextHash $body)){throw 'Invalid framework report ownership or digest.'}
    if($body -cnotmatch '\n## Analysis record\n\n```json\n([^\r\n]+)\n```\n\z'){throw 'Missing framework analysis record.'}
    $a=ConvertFrom-WinSecStoredJson $Matches[1]
    $a=Assert-WinSecFrameworkAnalysis $a $DeviceId $a.ScopeType $a.ScopeKey
    if($a.AnalysisId -cne $meta.AnalysisId -or $a.FrameworkId -cne $meta.FrameworkId -or (New-WinSecFrameworkMarkdown $a) -cne $body){throw 'Framework report contradicts its data.'}
    return $meta
}

function Export-WinSecFrameworkAnalysis {
    param([string]$ProjectRoot,[object]$Analysis,[scriptblock]$CancellationAction,[scriptblock]$ProgressCallback)
    Export-WinSecFrozenFindingsReport -ProjectRoot $ProjectRoot -Analysis $Analysis -CancellationAction $CancellationAction -ProgressCallback $ProgressCallback
}
