[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Services/TechnicalSnapshotStore.ps1')
. (Join-Path $root 'tests/Fixtures/TechnicalSnapshotMemory.ps1')
function Get-CimInstance {throw 'Native queries prohibited.'}
$passed=0;$failed=0
function Assert-WinSecSnapshotUnit {param([bool]$Condition);if(-not $Condition){throw 'Snapshot Markdown assertion failed.'}}
function Reject-WinSecSnapshotUnit {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-WinSecSnapshotUnit $caught}
function Test-WinSecSnapshotUnit {param($Label,[scriptblock]$Action);$f=New-WinSecSnapshotFixture;try{& $Action;$script:passed++;Write-Host ('[PASS] '+$Label)}catch{$script:failed++;Write-Host ('[FAIL] '+$Label+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}
Test-WinSecSnapshotUnit 'Technical Markdown includes identity, platform, source and every retained reading' {
    $md=ConvertTo-WinSecSnapshotMarkdown $f.Snapshot $f.Catalog $f.Hash $f.Identity
    Assert-WinSecSnapshotUnit ($md.Contains('Guest.Disabled') -and $md.Contains('Guest.Flags') -and $md.Contains('Guest.Name') -and $md.Contains('22631') -and $md.Contains('CatalogSha256') -and $md.Contains('| false |') -and $md.Contains('| 0 |'))
    Assert-WinSecSnapshotUnit ($md -notmatch 'Score|NOT_SCORED|/100' -and $md -notmatch "(?<!`n)`n\| Field \|" )
}
Test-WinSecSnapshotUnit 'Markup and table separators are inert and deterministic' {
    $f.Snapshot.Batches[0].Records[0].Readings[2].Value='<script>x</script>|[link](https://invalid/)*'
    $a=ConvertTo-WinSecSnapshotMarkdown $f.Snapshot $f.Catalog $f.Hash $f.Identity
    $b=ConvertTo-WinSecSnapshotMarkdown $f.Snapshot $f.Catalog $f.Hash $f.Identity
    Assert-WinSecSnapshotUnit ($a -ceq $b -and $a -notmatch '<script>|\[link\]' -and $a.Contains('&#124;') -and $a.Contains('&lt;script&gt;'))
}
Test-WinSecSnapshotUnit 'Unknown observations and limited coverage remain explicit' {
    $r=$f.Snapshot.Batches[0].Records[0].Readings[2];$r.Value=$null;$r.State='UNKNOWN';$r.Reason='PROVIDER_UNAVAILABLE'
    $f.Snapshot.Collection.Observed=2;$f.Snapshot.Collection.Unknown=1;$f.Snapshot.Collection.Coverage='LIMITED'
    $md=ConvertTo-WinSecSnapshotMarkdown $f.Snapshot $f.Catalog $f.Hash $f.Identity
    Assert-WinSecSnapshotUnit ($md.Contains('UNKNOWN') -and $md.Contains('LIMITED') -and $md.Contains('&#40;null&#41;'))
}
Test-WinSecSnapshotUnit 'Cancellation or unreviewed data never renders a report' {
    Reject-WinSecSnapshotUnit {ConvertTo-WinSecSnapshotMarkdown $f.Snapshot $f.Catalog $f.Hash $f.Identity -CancellationAction {$true}}
    $f.Snapshot | Add-Member -NotePropertyName Secret -NotePropertyValue 'SYNTHETIC'
    Reject-WinSecSnapshotUnit {ConvertTo-WinSecSnapshotMarkdown $f.Snapshot $f.Catalog $f.Hash $f.Identity}
}
Test-WinSecSnapshotUnit 'Pair manifest is strict, owned, bounded and independent of paths' {
    $m=[pscustomobject]@{ArtifactType='WinSec.TechnicalSnapshotPair';SchemaVersion='1.0.0';State='PREPARED';Identity=$f.Identity;CollectedAtUTC=$f.Snapshot.CollectedAtUTC;CatalogSha256=$f.Hash;JsonSha256=('A'*64);MarkdownSha256=('B'*64);JsonBytes=12;MarkdownBytes=20}
    Assert-WinSecSnapshotPairManifest $m $f.Identity $f.Snapshot.CollectedAtUTC $f.Hash PREPARED
    $roundtrip=ConvertFrom-WinSecSnapshotPairJson (ConvertTo-Json -InputObject $m -Depth 8 -Compress)
    Assert-WinSecSnapshotPairManifest $roundtrip $f.Identity $f.Snapshot.CollectedAtUTC $f.Hash PREPARED
    $m | Add-Member -NotePropertyName JsonPath -NotePropertyValue '../foreign';Reject-WinSecSnapshotUnit {Assert-WinSecSnapshotPairManifest $m $f.Identity $f.Snapshot.CollectedAtUTC $f.Hash PREPARED}
}
Test-WinSecSnapshotUnit 'Importing storage declares functions without compiling filesystem interop' {
    Assert-WinSecSnapshotUnit ($null -eq ('WinSec.SnapshotIO3' -as [type]))
}
Write-Host ("Snapshot Markdown: $passed passed; $failed failed.");if($failed){exit 1}
