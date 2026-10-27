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
    $defs=@(Get-WinSecTechnicalDefinitions $r.CheckId $r.CatalogVersion)
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
        'WSA-NET-003' {
            if($r.CatalogVersion -ceq '1.1.0'){
                $coverage=@($r.Rows|Where-Object SettingId -CEQ CoverageComplete)[0]
                $lines.Add('- Scan completion and reading coverage are separate. Informational UNKNOWN values remain visible; they do not imply safe configuration or a complete framework assessment.')
                $lines.Add('- Reading coverage: '+$(if($coverage.State -ceq 'OBSERVED' -and $coverage.Value -ceq $true){'COMPLETE'}else{'LIMITED'})+'. Retired Windows 11 desktop-composition fields are NOT_APPLICABLE; other nulls stay UNKNOWN.')
            }
            $lines.Add('- Windows Home has no supported built-in RDP host. Only observed Windows edition can justify NOT_APPLICABLE for host providers; RDP client configuration remains relevant.')
            $lines.Add('- Effective host permission, listener authentication, encryption, session limits, redirection, services and explicit machine policies are separate readings. Missing registry values are NOT_CONFIGURED, not an inferred default.')
            $lines.Add('- General settings: UserAuthenticationRequired 1 requires NLA; MinEncryptionLevel 1 low, 2 client compatible, 3 high, 4 FIPS describes native RDP encryption, not TLS. WMI SecurityLayer is retained as a raw enum: Microsoft getter/setter documentation differs, so it is not silently interpreted using registry labels. Machine SecurityLayer policy 0 requires native RDP, 1 negotiate, 2 TLS. Native encryption warnings require an explicit native-only machine policy. These settings do not prove negotiated TLS, MFA or network reachability.')
            $lines.Add('- Every returned listener is retained within the explicit 64-record bound per provider. RDP_TCP is the standard listener; custom listener names are SHA256 tokens. Exceeding a bound is reported, never silently truncated.')
            $lines.Add('- Null inventory fields are UNKNOWN. Windows/provider-dependent missing fields limit completeness. No users, session identities, passwords, saved connections, certificates, security descriptors, remote targets or network probes are collected.')
        }
        'WSA-NET-002' {
            $lines.Add('- SMBv1 client installation, server configuration and driver dependencies are separate readings. Installed does not prove enabled, negotiated traffic or a reachable service.')
            $lines.Add('- Microsoft recommends removing SMBv1 across Windows 11 editions. Signing and encryption settings describe broader SMB context; defaults differ by release and edition.')
            $lines.Add('- Win32_OptionalFeature: ENABLED, DISABLED and ABSENT are observed provider states. A missing row remains UNKNOWN. Missing registry values are NOT_CONFIGURED; no default is invented.')
            $lines.Add('- Only reviewed scalar configuration and counts are retained. Shares, sessions, credentials, peer names, personal paths and free-text settings are not collected. No SMB connections or probes are made.')
            $lines.Add('- Signing/encryption audit fields absent on observed 21H2/22H2/23H2 remain NOT_APPLICABLE; other unavailable fields remain unknown. Context selection never changes observed Windows.')
        }
        'WSA-NET-001' {
            $lines.Add('- ActiveStore is the effective policy; PersistentStore is local configuration, not a second independent effective policy.')
            $lines.Add('- Every returned rule is inventoried. Custom names, program paths, addresses and identities use stable SHA256 tokens. This is normalized telemetry, not raw evidence.')
            $lines.Add('- Exceptions are not automatically vulnerabilities. Block precedence, interfaces and approved business needs require review; no network reachability test is performed.')
            $lines.Add('- Hyper-V Firewall starts with Windows 11 22H2. Missing providers or fields remain unknown; a selected profile cannot override observed Windows.')
        }
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
        if($d.Kind -ceq 'rdpInventory' -and $row.State -ceq 'OBSERVED'){
            $group='';$lines.Add('');$lines.Add('## '+$d.Group);$lines.Add('')
            $batch=ConvertTo-WinSecRdpInventory $row.Value
            foreach($item in $batch.Items){
                $lines.Add('### Listener / configuration '+$item.Id);$lines.Add('')
                $lines.Add('| Setting | Value | Collection state | Source |');$lines.Add('| --- | --- | --- | --- |')
                foreach($p in $item.Values.PSObject.Properties){
                    $excluded=if($null -ne $batch.PSObject.Properties['NotApplicableFields']){@($batch.NotApplicableFields)}else{@()}
                    $state=if($p.Name -cin $excluded){'NOT_APPLICABLE'}elseif($null -eq $p.Value){'UNKNOWN'}else{'OBSERVED'}
                    $value=if($null -eq $p.Value){'Not available'}else{[string]$p.Value}
                    $lines.Add('| '+(ConvertTo-WinSecTechnicalCell $p.Name)+' | '+$value+' | '+$state+' | '+$d.Source+' |')
                }
                $lines.Add('')
            }
            continue
        }
        if($d.Kind -cin @('firewallBatch','firewallMetadata')) {
            $group='';$lines.Add('');$lines.Add('## '+$row.SettingId);$lines.Add('')
            $items=if($d.Kind -ceq 'firewallBatch'){ConvertTo-WinSecFirewallBatch $row.Value}else{ConvertTo-WinSecFirewallMetadataBatch $row.Value}
            foreach($item in $items) {
                $lines.Add('### Record '+$item.Id);$lines.Add('');$lines.Add('| Setting | Value |');$lines.Add('| --- | --- |')
                $properties=if($d.Kind -ceq 'firewallBatch'){$item.PSObject.Properties}else{$item.Values.PSObject.Properties}
                foreach($p in $properties){$lines.Add('| '+(ConvertTo-WinSecTechnicalCell $p.Name)+' | '+(ConvertTo-WinSecTechnicalCell $p.Value)+' |')}
                $lines.Add('')
            }
            continue
        }
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
    if([Text.Encoding]::UTF8.GetByteCount($Text) -gt 16777216 -or $Text -match '[\x00-\x09\x0b-\x1f\x7f]' -or
        $Text -cnotmatch '\A<!-- WinSec technical report\n([^\r\n]+)\n-->\n([\s\S]*)\z'){throw 'Unrecognized technical Markdown.'}
    $metadata=$Matches[1];$body=$Matches[2];$m=ConvertFrom-WinSecStoredJson $metadata
    Assert-WinSecConfigurationFields $m @('SchemaVersion','DeviceId','ScanId','CheckId','ScopeType','ScopeKey','ContentSha256')
    $large=($m.SchemaVersion -ceq '3.0.0' -and $m.CheckId -ceq 'WSA-NET-001')
    if(($m.SchemaVersion -cne '2.0.0' -and -not $large) -or
        (-not $large -and [Text.Encoding]::UTF8.GetByteCount($Text) -gt 1048576) -or $m.DeviceId -isnot [string] -or $m.DeviceId -cne $DeviceId -or
        $m.ContentSha256 -cne (Get-WinSecReportTextHash $body)){throw 'Invalid technical Markdown ownership or digest.'}
    if($body -cnotmatch '\n## Structured data\n\n```json\n([^\r\n]+)\n```\n\z'){throw 'Missing technical snapshot.'}
    $json=$Matches[1]
    $snapshot=if($large){ConvertFrom-WinSecBoundedStoredJson $json -MaxBytes 16777216}else{ConvertFrom-WinSecStoredJson $json}
    $r=ConvertTo-WinSecTechnicalReport $snapshot
    if($large -and $r.CheckId -cne 'WSA-NET-001'){throw 'Foreign large technical artifact.'}
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
        if($file.Length -gt 16777216 -or ($bytes+=$file.Length) -gt 67108864){throw 'Stored report limit exceeded.'}
        $hash=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
        $text=Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8
        if(-not ($text.StartsWith("<!-- WinSec technical report`n",[StringComparison]::Ordinal) -or
            $text.StartsWith("WinSec technical scan report`n",[StringComparison]::Ordinal))){if($file.Length -gt 1048576){throw 'Unrecognized large report.'};continue}
        $report=ConvertFrom-WinSecTechnicalArtifact $text $DeviceId -IncludeReport
        if((Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash -cne $hash){throw 'Technical report changed while reading.'}
        if($report.ScanId -ceq $ScanId -and $report.CheckId -ceq $CheckId){$found+=,$report}
    }
    if($found.Count -gt 1){throw 'Ambiguous technical snapshots for this scan/control.'}
    if($found.Count){return $found[0]};return $null
}
