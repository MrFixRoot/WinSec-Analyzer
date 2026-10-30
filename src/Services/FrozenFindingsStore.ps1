# Self-contained frozen Findings artifacts. No evaluation, framework prompt or Windows collector.
. (Join-Path $PSScriptRoot 'TechnicalSnapshotStore.ps1')

function Open-WinSecFindingsDirectories {
    param([string]$ProjectRoot,[string]$DeviceId,[string]$SectionKey,[switch]$Create)
    $key=Get-WinSecSnapshotDeviceKey $DeviceId
    $null=Assert-WinSecSnapshotStoragePath $ProjectRoot ('reports/'+$key+'/'+$SectionKey+'/findings/check.md')
    Initialize-WinSecSnapshotFileIO;$held=New-Object 'Collections.Generic.List[IDisposable]'
    $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $sddl='O:'+$sid+'D:P(A;OICI;FA;;;'+$sid+')(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
    try{
        $parents=New-Object 'Collections.Generic.List[string]';$cursor=[IO.Path]::GetFullPath($ProjectRoot).TrimEnd('\')
        while($cursor){$parents.Insert(0,$cursor);$cursor=[IO.Path]::GetDirectoryName($cursor)}
        foreach($parent in $parents){$held.Add([WinSec.SnapshotIO3]::HoldDirectory($parent))}
        $dir=[IO.Path]::GetFullPath($ProjectRoot)
        foreach($segment in @('reports',$key,$SectionKey,'findings')){
            $dir=Join-Path $dir $segment
            if($Create){[WinSec.SnapshotIO3]::CreatePrivateDirectory($dir,$sddl)}
            $held.Add([WinSec.SnapshotIO3]::HoldDirectory($dir))
            if($segment -cne 'reports'){Assert-WinSecSnapshotPrivateAcl $dir -Directory}
        };return ,$held
    }catch{foreach($h in $held){$h.Dispose()};throw 'Cannot secure Findings directories.'}
}

function New-WinSecFrozenFindingsMarkdown {
    param($Analysis,[string]$ExportedAtUTC)
    $null=ConvertTo-WinSecSnapshotUtc $ExportedAtUTC
    $body=New-WinSecFrameworkMarkdown $Analysis
    $heading="# WinSec Analyzer - Framework findings`n`n"
    if(-not $body.StartsWith($heading,[StringComparison]::Ordinal)){throw 'Unrecognized frozen Findings renderer.'}
    $body=$heading+'Report generated UTC: '+$ExportedAtUTC+"`n`n"+$body.Substring($heading.Length)
    $lines=New-Object 'Collections.Generic.List[string]'
    $lines.Add('');$lines.Add('## Stored source details');$lines.Add('')
    if($Analysis.SchemaVersion -ceq '1.1.0'){
        $lines.Add('| Control | Snapshot | Platform / build / SKU | Snapshot / collector | Catalog | Original scope | Collected UTC |');$lines.Add('| --- | --- | --- | --- | --- | --- | --- |')
        foreach($s in $Analysis.ReadingReview.Sources){
            $snapshot=if($null -ne $s.Identity){$s.Identity.SnapshotId}else{'NOT_RECORDED'}
            $platform=(@($s.Platform.Version,$s.Platform.BuildNumber,$s.Platform.OperatingSystemSKU)|ForEach-Object {if($null -eq $_){'UNKNOWN'}else{[string]$_}})-join ' / '
            $cells=@($s.CheckId,$snapshot,$platform,($s.SnapshotSchemaVersion+' / '+$s.CollectorVersion),($s.CatalogId+' / '+$s.CatalogVersion),($s.ScopeType+' / '+$s.ScopeKey),$s.CollectedAtUTC)|ForEach-Object {ConvertTo-WinSecTechnicalCell $_}
            $lines.Add('| '+($cells -join ' | ')+' |')
        }
        $lines.Add('');$lines.Add('UNKNOWN means metadata was not recorded; it is not inferred from the selected profile. Source digests, applicability basis, rule versions and original scan IDs remain in the analysis record.')
    }else{$lines.Add('This legacy view did not record snapshot or observed platform metadata. No replacement metadata was inferred.')}
    $lines.Add('')
    return $body.Replace("`n## Coverage`n",(($lines -join "`n")+"`n## Coverage`n"))
}

function ConvertFrom-WinSecFrozenFindingsArtifact {
    param([string]$Text,[string]$DeviceId)
    if([Text.Encoding]::UTF8.GetByteCount($Text) -gt 1048576 -or $Text -match '[\x00-\x09\x0b-\x1f\x7f]' -or
        $Text -cnotmatch '\A<!-- WinSec framework findings\n([^\r\n]+)\n-->\n([\s\S]*)\z'){throw 'Unrecognized frozen Findings artifact.'}
    $meta=ConvertFrom-WinSecStoredJson $Matches[1];$body=$Matches[2]
    Assert-WinSecConfigurationFields $meta @('SchemaVersion','DeviceId','AnalysisId','FrameworkId','ScopeType','ScopeKey','ExportedAtUTC','AnalysisSha256','ContentSha256')
    if($meta.ExportedAtUTC -is [datetime]){$meta.ExportedAtUTC=$meta.ExportedAtUTC.ToUniversalTime().ToString('o')}
    foreach($field in @('SchemaVersion','DeviceId','AnalysisId','FrameworkId','ScopeType','ScopeKey','ExportedAtUTC','AnalysisSha256','ContentSha256')){
        if($meta.$field -isnot [string]){throw 'Invalid frozen Findings metadata type.'}
    }
    $null=ConvertTo-WinSecSnapshotUtc $meta.ExportedAtUTC
    if($meta.SchemaVersion -cne '2.0.0' -or $meta.DeviceId -cne $DeviceId -or $meta.ContentSha256 -cne (Get-WinSecReportTextHash $body) -or
        $body -cnotmatch '\n## Analysis record\n\n```json\n([^\r\n]+)\n```\n\z'){throw 'Invalid frozen Findings ownership or content.'}
    $a=Assert-WinSecFrameworkAnalysis (ConvertFrom-WinSecStoredJson $Matches[1]) $DeviceId $meta.ScopeType $meta.ScopeKey
    if((ConvertTo-WinSecSnapshotUtc $meta.ExportedAtUTC) -lt (ConvertTo-WinSecSnapshotUtc $a.GeneratedAtUTC)){throw 'Report predates its frozen analysis.'}
    if($a.AnalysisId -cne $meta.AnalysisId -or $a.FrameworkId -cne $meta.FrameworkId -or $a.ContentSha256 -cne $meta.AnalysisSha256 -or
        (New-WinSecFrozenFindingsMarkdown $a $meta.ExportedAtUTC) -cne $body){throw 'Frozen report contradicts its analysis.'}
    [pscustomobject]@{Metadata=$meta;Analysis=$a}
}

function Read-WinSecFrozenFindingsReport {
    param([string]$ProjectRoot,[string]$Path,[string]$DeviceId,[scriptblock]$CancellationAction)
    $root=[IO.Path]::GetFullPath($ProjectRoot).TrimEnd('\');$full=[IO.Path]::GetFullPath($Path)
    if(-not $full.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Foreign Findings path.'}
    $relative=$full.Substring($root.Length+1);$null=Assert-WinSecSnapshotStoragePath $root $relative -AllowExistingArtifact
    $parts=$relative.Replace('\','/').Split('/')
    if($parts.Count -ne 5 -or $parts[0] -cne 'reports' -or $parts[1] -cne (Get-WinSecSnapshotDeviceKey $DeviceId) -or $parts[3] -cne 'findings'){throw 'Unrecognized Findings layout.'}
    $held=$null
    try{
        $held=Open-WinSecFindingsDirectories $root $DeviceId $parts[2]
        $bytes=Read-WinSecSnapshotBytes $full 1048576 $CancellationAction;$utf8=New-Object Text.UTF8Encoding($false,$true)
        $r=ConvertFrom-WinSecFrozenFindingsArtifact ($utf8.GetString($bytes)) $DeviceId;$m=$r.Metadata
        $expected=Get-WinSecSnapshotFindingsPath $root $DeviceId $m.ScopeType $m.ScopeKey $m.AnalysisId $m.ExportedAtUTC -AllowExistingArtifact
        if(-not [string]::Equals($full,$expected,[StringComparison]::OrdinalIgnoreCase)){throw 'Findings filename contradicts its owner or scope.'}
        [pscustomobject]@{Path=$full;Metadata=$m;Analysis=$r.Analysis;FileSha256=(Get-WinSecSnapshotByteHash $bytes)}
    }finally{if($held){foreach($h in $held){$h.Dispose()}}}
}

function Export-WinSecFrozenFindingsReport {
    param([string]$ProjectRoot,$Analysis,[scriptblock]$CancellationAction,[scriptblock]$ProgressCallback,
        [string]$ExportedAtUTC=([datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture)))
    $ProjectRoot=Get-WinSecReportInstallation $ProjectRoot
    $clock=[Diagnostics.Stopwatch]::StartNew();Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
    $a=Assert-WinSecFrameworkAnalysis $Analysis $Analysis.DeviceId $Analysis.ScopeType $Analysis.ScopeKey
    $emit={param([string]$phase,[int]$completed)
        Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
        if($ProgressCallback){$null=& $ProgressCallback ([pscustomobject]@{Activity='EXPORT';Phase=$phase;Completed=$completed;Total=4;CanCancel=$true})}
        Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
    }
    $null=& $emit 'Validating frozen Findings' 0
    $path=Get-WinSecSnapshotFindingsPath $ProjectRoot $a.DeviceId $a.ScopeType $a.ScopeKey $a.AnalysisId $ExportedAtUTC
    $section=if($a.ScopeType -ceq 'CONTROL'){(Get-WinSecSnapshotControl $a.ScopeKey).SectionKey}else{$a.ScopeKey}
    $body=New-WinSecFrozenFindingsMarkdown $a $ExportedAtUTC
    $meta=[pscustomobject]@{SchemaVersion='2.0.0';DeviceId=$a.DeviceId;AnalysisId=$a.AnalysisId;FrameworkId=$a.FrameworkId;ScopeType=$a.ScopeType;ScopeKey=$a.ScopeKey;
        ExportedAtUTC=$ExportedAtUTC;AnalysisSha256=$a.ContentSha256;ContentSha256=(Get-WinSecReportTextHash $body)}
    $text="<!-- WinSec framework findings`n"+(ConvertTo-Json $meta -Compress)+"`n-->`n"+$body
    $null=ConvertFrom-WinSecFrozenFindingsArtifact $text $a.DeviceId;$bytes=[Text.Encoding]::UTF8.GetBytes($text)
    $temporary=Join-Path ([IO.Path]::GetDirectoryName($path)) ('.f'+[guid]::NewGuid().ToString('N')+'.tmp')
    $null=Assert-WinSecSnapshotStoragePath $ProjectRoot $temporary.Substring($ProjectRoot.TrimEnd('\').Length+1)
    $held=$null;$stream=$null;$owned=$false;$moved=$false;$ownedHash=$null;$lease=$null
    try{
        $lease=Open-WinSecDeviceInventoryStore $ProjectRoot
        $inventory=Import-WinSecDeviceInventory $ProjectRoot
        if(@($inventory.targets|Where-Object DeviceId -CEQ $a.DeviceId).Count -ne 1){throw 'Frozen report owner is no longer managed.'}
        $held=Open-WinSecFindingsDirectories $ProjectRoot $a.DeviceId $section -Create
        $stream=[WinSec.SnapshotIO3]::Create($temporary);$owned=$true;Assert-WinSecSnapshotPrivateAcl $temporary
        try{
            for($offset=0;$offset -lt $bytes.Length;$offset+=65536){Assert-WinSecSnapshotValidationBudget $clock $CancellationAction;$stream.Write($bytes,$offset,[Math]::Min(65536,$bytes.Length-$offset))}
            $stream.Flush($true)
        }finally{
            try{$stream.Position=0;$sha=[Security.Cryptography.SHA256]::Create();try{$ownedHash=([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-','')}finally{$sha.Dispose()}}
            finally{$stream.Dispose();$stream=$null}
        }
        $null=& $emit 'Verifying staged report' 2
        $staged=Read-WinSecSnapshotBytes $temporary 1048576 $CancellationAction
        if((Get-WinSecSnapshotByteHash $staged) -cne (Get-WinSecSnapshotByteHash $bytes)){throw 'Staged Findings verification failed.'}
        $null=& $emit 'Publishing report' 3
        [WinSec.SnapshotIO3]::MoveExclusive($temporary,$path);$moved=$true
        # Rename is the commit point. No cancellation can undo a published report.
        $saved=Read-WinSecFrozenFindingsReport $ProjectRoot $path $meta.DeviceId
        if($saved.FileSha256 -cne (Get-WinSecSnapshotByteHash $bytes)){throw 'Published Findings verification failed.'}
        if($ProgressCallback){try{$null=& $ProgressCallback ([pscustomobject]@{Activity='EXPORT';Phase='Report published';Completed=4;Total=4;CanCancel=$false})}catch{}}
        [pscustomobject]@{DeviceId=$meta.DeviceId;AnalysisId=$meta.AnalysisId;ScopeType=$meta.ScopeType;ScopeKey=$meta.ScopeKey;ExportedAtUTC=$ExportedAtUTC;
            Path=$path;RelativePath=$path.Substring($ProjectRoot.TrimEnd('\').Length+1).Replace('\','/');FileSha256=$saved.FileSha256}
    }finally{
        if($stream){$stream.Dispose()}
        try{
            if($owned -and -not $moved -and $ownedHash -and [IO.File]::Exists($temporary)){
                $remove=[WinSec.SnapshotIO3]::OpenRemoval($temporary)
                try{$sha=[Security.Cryptography.SHA256]::Create();try{$hash=([BitConverter]::ToString($sha.ComputeHash($remove))).Replace('-','')}finally{$sha.Dispose()}
                    if($hash -cne $ownedHash){throw 'Changed staged Findings cannot be removed.'};[WinSec.SnapshotIO3]::MarkRemoval($remove)
                }finally{$remove.Dispose()}
            }
        }finally{if($held){foreach($h in $held){$h.Dispose()}};if($lease){$lease.Lock.Dispose()}}
    }
}
