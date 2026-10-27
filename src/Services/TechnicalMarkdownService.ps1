# Technical Markdown is a typed snapshot, independent of the findings report.
function ConvertTo-WinSecTechnicalCell {
    param([AllowNull()][object]$Value)
    if($null -eq $Value){return 'Not collected'}
    $text=[string]$Value
    if($text -match '[\x00-\x1f\x7f]' -or $text.Length -gt 4096){throw 'Invalid Markdown cell.'}
    $text=[Net.WebUtility]::HtmlEncode($text)
    return [regex]::Replace($text,'([\\`*_{}\[\]()#+.!|>-])','\$1')
}

function ConvertTo-WinSecTechnicalMarkdown {
    param([object]$Report)
    $r=ConvertTo-WinSecTechnicalReport $Report
    $defs=@(Get-WinSecTechnicalDefinitions $r.CheckId)
    $lines=New-Object 'Collections.Generic.List[string]'
    $lines.Add('# WinSec Analyzer - Technical snapshot');$lines.Add('')
    $lines.Add('This is a read-only configuration record, not a compliance decision. No numeric rating is calculated.')
    $lines.Add('');$lines.Add('| Field | Value |');$lines.Add('| --- | --- |')
    foreach($field in @('DeviceName','Hostname','DeviceId','CheckId','SectionKey','ScanId','ScopeType','ScopeKey',
        'ObservedOSRelease','ObservedEdition','Profile','CollectedAtUTC','GeneratedAtUTC','CollectorStatus','SchemaVersion','CatalogVersion')) {
        $lines.Add('| '+$field+' | '+(ConvertTo-WinSecTechnicalCell $r.$field)+' |')
    }
    $lines.Add('');$lines.Add('Values false and 0 are observations. Unknown, unavailable and not applicable remain distinct. Secrets, personal paths and free provider messages are excluded.')
    $lines.Add('');$lines.Add('## Interpretation notes');$lines.Add('')
    switch($r.CheckId) {
        'WSA-SYS-001' {
            $lines.Add('- Disable-prefixed preferences: true disables the named function. PUA: 0 disabled, 1 block, 2 audit. MAPS: 0 disabled, 1 basic, 2 advanced.')
            $lines.Add('- ASR BLOCK, AUDIT and WARN describe configured modes; they do not independently prove effective enforcement. Review applicability and approved exceptions.')
        }
        'WSA-SYS-002' {
            $lines.Add('- Only the Windows volume is included. EncryptionPercentage describes encrypted data; ProtectionStatus independently describes active protection.')
            $lines.Add('- EncryptionMethod and LockStatus are informative. Algorithm choice requires the device threat model and policy; no recovery keys or protectors are collected.')
        }
        'WSA-SYS-003' {
            $lines.Add('- A stopped service with Manual start is not equivalent to Disabled. NOT_CONFIGURED is not proof that automatic updates are disabled.')
            $lines.Add('- Build and UBR describe the installed revision; comparisons require an applicable, current reference. No update search, download or installation is performed.')
        }
    }
    $group=''
    foreach($row in $r.Rows) {
        $d=Get-WinSecTechnicalRowDefinition $row.SettingId $defs
        if($group -cne $d.Group){$group=$d.Group;$lines.Add('');$lines.Add('## '+$group);$lines.Add('');
            $lines.Add('| Setting | Value | Collection state | Reason | Type / source |');$lines.Add('| --- | --- | --- | --- | --- |')}
        $value=if($null -eq $row.Value){'Not available'}else{ConvertTo-Json -InputObject $row.Value -Compress}
        $source=$d.Source
        if($r.CheckId -ceq 'WSA-SYS-001' -and $source -cin @('Get-MpComputerStatus','Get-MpPreference')) {
            $field=if($source -ceq 'Get-MpComputerStatus'){'StatusSource'}else{'PreferenceSource'}
            $origin=@($r.Rows|Where-Object SettingId -CEQ $field)[0]
            $source=if($origin.State -ceq 'OBSERVED'){$origin.Value}else{'Defender provider unresolved'}
        }
        $cells=@($row.SettingId,$value,$row.State,$row.Reason,($d.Kind+' / '+$source))|ForEach-Object {ConvertTo-WinSecTechnicalCell $_}
        $lines.Add('| '+($cells -join ' | ')+' |')
    }
    $lines.Add('');$lines.Add('## Structured data');$lines.Add('');$lines.Add('```json')
    $lines.Add((Get-WinSecPublicHistoryJson $r));$lines.Add('```');$lines.Add('')
    return $lines -join "`n"
}

function ConvertFrom-WinSecTechnicalMarkdownArtifact {
    param([string]$Text,[string]$DeviceId,[switch]$IncludeReport)
    if([Text.Encoding]::UTF8.GetByteCount($Text) -gt 1048576 -or $Text -match '[\x00-\x09\x0b-\x1f\x7f]' -or
        $Text -cnotmatch '\A<!-- WinSec technical report\n([^\r\n]+)\n-->\n([\s\S]*)\z'){throw 'Unrecognized technical Markdown.'}
    $metadata=$Matches[1];$body=$Matches[2];$m=ConvertFrom-WinSecStoredJson $metadata
    Assert-WinSecConfigurationFields $m @('SchemaVersion','DeviceId','ScanId','CheckId','ScopeType','ScopeKey','ContentSha256')
    if($m.SchemaVersion -cne '2.0.0' -or $m.DeviceId -isnot [string] -or $m.DeviceId -cne $DeviceId -or
        $m.ContentSha256 -cne (Get-WinSecReportTextHash $body)){throw 'Invalid technical Markdown ownership or digest.'}
    if($body -cnotmatch '\n## Structured data\n\n```json\n([^\r\n]+)\n```\n\z'){throw 'Missing technical snapshot.'}
    $r=ConvertTo-WinSecTechnicalReport (ConvertFrom-WinSecStoredJson $Matches[1])
    foreach($field in @('DeviceId','ScanId','CheckId','ScopeType','ScopeKey')) {
        if($m.$field -isnot [string] -or $m.$field -cne $r.$field){throw 'Mixed technical Markdown identity.'}
    }
    if((ConvertTo-WinSecTechnicalMarkdown $r) -cne $body){throw 'Technical Markdown contradicts its snapshot.'}
    if($IncludeReport){return $r};return $m
}

function Read-WinSecTechnicalReport {
    param([string]$ProjectRoot,[string]$DeviceId,[string]$ScanId,[string]$CheckId)
    $directory=Join-Path $ProjectRoot ('reports/exports/'+(Get-WinSecEvidenceHash $DeviceId))
    Assert-WinSecDeviceRemovalPath $ProjectRoot $directory
    if(-not (Test-Path -LiteralPath $directory)){return $null}
    $files=@(Get-ChildItem -LiteralPath $directory -File -Force)
    if($files.Count -gt 10000){throw 'Too many stored reports.'}
    $found=@();$bytes=0
    foreach($file in $files) {
        if($file.Extension -cnotin @('.md','.txt')){continue}
        Assert-WinSecDeviceRemovalPath $ProjectRoot $file.FullName
        if($file.Length -gt 1048576 -or ($bytes+=$file.Length) -gt 67108864){throw 'Stored report limit exceeded.'}
        $hash=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
        $text=Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8
        if(-not ($text.StartsWith("<!-- WinSec technical report`n",[StringComparison]::Ordinal) -or
            $text.StartsWith("WinSec technical scan report`n",[StringComparison]::Ordinal))){continue}
        $report=ConvertFrom-WinSecTechnicalArtifact $text $DeviceId -IncludeReport
        if((Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash -cne $hash){throw 'Technical report changed while reading.'}
        if($report.ScanId -ceq $ScanId -and $report.CheckId -ceq $CheckId){$found+=,$report}
    }
    if($found.Count -gt 1){throw 'Ambiguous technical snapshots for this scan/control.'}
    if($found.Count){return $found[0]};return $null
}
