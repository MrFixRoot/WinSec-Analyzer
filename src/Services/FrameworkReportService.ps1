# Export the exact selected framework view. No new evaluation or framework prompt.
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
    $expected=if($a.ScopeType -ceq 'SECTION'){@('WSA-SYS-001','WSA-SYS-002','WSA-SYS-003')}else{@($a.ScopeKey)}
    $unscanned=@($expected|Where-Object {$_ -cnotin @($a.Sources.CheckId)})
    if($unscanned.Count){$lines.Add('Controls without a saved scan: '+($unscanned -join ', ')+'. Run a separately confirmed scan to collect them.')}
    if($a.MissingTechnicalCheckIds.Count){$lines.Add('Detailed snapshots not available: '+($a.MissingTechnicalCheckIds -join ', ')+'. Only recorded, verified deviations could be reviewed for these controls.')}
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
    param([string]$ProjectRoot,[object]$Analysis)
    $ProjectRoot=Get-WinSecReportInstallation $ProjectRoot
    $a=Assert-WinSecFrameworkAnalysis $Analysis $Analysis.DeviceId $Analysis.ScopeType $Analysis.ScopeKey
    $body=New-WinSecFrameworkMarkdown $a
    $meta=@{SchemaVersion='1.0.0';DeviceId=$a.DeviceId;AnalysisId=$a.AnalysisId;FrameworkId=$a.FrameworkId;ContentSha256=(Get-WinSecReportTextHash $body)}
    $text="<!-- WinSec framework findings`n"+(ConvertTo-Json $meta -Compress)+"`n-->`n"+$body
    $null=ConvertFrom-WinSecFrameworkMarkdownArtifact $text $a.DeviceId
    $directory=Join-Path $ProjectRoot ('reports/exports/'+(Get-WinSecEvidenceHash $a.DeviceId))
    $name='findings-'+[datetime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')+'-'+[guid]::NewGuid().ToString('N')+'.md'
    $path=Join-Path $directory $name;$temporary=Join-Path $directory ('.'+[guid]::NewGuid().ToString('N')+'.tmp')
    if($path.Length -gt 240){throw 'Framework report path is too long.'}
    Assert-WinSecDeviceRemovalPath $ProjectRoot $path;$null=[IO.Directory]::CreateDirectory($directory)
    Assert-WinSecDeviceRemovalPath $ProjectRoot $temporary;$owned=$false;$moved=$false
    try {
        $bytes=[Text.Encoding]::UTF8.GetBytes($text)
        $stream=[IO.File]::Open($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);$owned=$true
        try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
        Assert-WinSecDeviceRemovalPath $ProjectRoot $temporary
        if((Get-FileHash -LiteralPath $temporary -Algorithm SHA256).Hash -cne (Get-WinSecReportTextHash $text)){throw 'Framework write verification failed.'}
        Assert-WinSecDeviceRemovalPath $ProjectRoot $path;[IO.File]::Move($temporary,$path);$moved=$true
        Assert-WinSecDeviceRemovalPath $ProjectRoot $path
        if((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne (Get-WinSecReportTextHash $text)){throw 'Framework publication verification failed.'}
        [pscustomobject]@{DeviceId=$a.DeviceId;AnalysisId=$a.AnalysisId;Path=$path;RelativePath=('reports/exports/'+(Get-WinSecEvidenceHash $a.DeviceId)+'/'+$name)}
    } finally {if($owned -and -not $moved){Assert-WinSecDeviceRemovalPath $ProjectRoot $temporary;if([IO.File]::Exists($temporary)){[IO.File]::Delete($temporary)}}}
}
