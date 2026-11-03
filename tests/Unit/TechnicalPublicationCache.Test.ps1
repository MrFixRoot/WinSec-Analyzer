[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Services/TechnicalSourceRestoration.ps1')
foreach($command in @('Get-CimInstance','Get-CimClass','Get-MpComputerStatus','Get-MpPreference','Start-Job')){Set-Item ('Function:script:'+$command) {throw 'Native acquisition forbidden.'}}
$passed=0;$failed=0;$device='local:hw1-'+('a'*64)
# Unit-only installation provider; physical installation checks are exercised by integration.
function Get-WinSecReportInstallation {param([string]$ProjectRoot);[IO.Path]::GetFullPath($ProjectRoot)}
$testRoot=[IO.Path]::GetFullPath((Join-Path ([IO.Path]::GetTempPath()) 'publication-unit'))
$owner=[pscustomobject]@{DeviceId=$device;ScanId='publication-unit';ScopeType='CONTROL';ScopeKey='WSA-SYS-001'}
function New-PU {
    $d=[pscustomobject]@{ArtifactType='WinSec.TechnicalSourceDiscovery';SchemaVersion='1.0.0';DeviceId=$device;Sessions=@()}
    $index=Copy-WinSecTechnicalIndexMetadata $testRoot $d $device DISCOVERY $null
    [pscustomobject]@{ProjectRoot=$testRoot;TechnicalSourceIndexes=@{$device=$index}}
}
function Assert-PU {param([bool]$Value);if(-not $Value){throw 'Technical publication cache assertion failed.'}}
function Reject-PU {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-PU $caught}
function Test-PU {param([string]$Case,[scriptblock]$Action);try{& $Action;$script:passed++;Write-Host ('[PASS] '+$Case)}catch{$script:failed++;Write-Host ('[FAIL] '+$Case+': '+$_.Exception.Message)}}
Test-PU 'A publication stamp preserves the single map and exact previous index' {
    $c=New-PU;$s=New-WinSecTechnicalPublicationCacheStamp $c $testRoot $owner
    Assert-WinSecTechnicalPublicationCacheStamp $s
    Assert-PU ($s.HadIndex -and [object]::ReferenceEquals($s.Map,$c.TechnicalSourceIndexes) -and [object]::ReferenceEquals($s.Previous,$c.TechnicalSourceIndexes[$device]))
}
Test-PU 'A first scan or previously invalidated device may have no index' {
    $c=New-PU;$c.TechnicalSourceIndexes.Remove($device);$s=New-WinSecTechnicalPublicationCacheStamp $c $testRoot $owner
    Assert-WinSecTechnicalPublicationCacheStamp $s -Invalidated;Assert-PU (-not $s.HadIndex)
}
foreach($kind in @('Missing','Array','ForeignRoot','ScriptProperty','InvalidIndex')){
    Test-PU ('Invalid coordinator binding rejects before publication: '+$kind) {
        $c=New-PU;$script:getterCalled=$false
        switch($kind){
            Missing {$c.PSObject.Properties.Remove('TechnicalSourceIndexes')}
            Array {$c.TechnicalSourceIndexes=@()}
            ForeignRoot {$c.ProjectRoot=Join-Path $testRoot 'foreign'}
            ScriptProperty {$c.PSObject.Properties.Remove('TechnicalSourceIndexes');$c|Add-Member ScriptProperty TechnicalSourceIndexes {$script:getterCalled=$true;@{}}}
            InvalidIndex {$c.TechnicalSourceIndexes[$device]=[pscustomobject]@{ArtifactType='WinSec.StoredSession'}}
        }
        Reject-PU {New-WinSecTechnicalPublicationCacheStamp $c $testRoot $owner};Assert-PU (-not $script:getterCalled)
    }
}
foreach($kind in @('Map','Entry','Digest','Root','Removal')){
    Test-PU ('Concurrent cache changes cannot pass the precommit stamp: '+$kind) {
        $c=New-PU;$s=New-WinSecTechnicalPublicationCacheStamp $c $testRoot $owner
        switch($kind){
            Map {$c.TechnicalSourceIndexes=@{$device=$s.Previous}}
            Entry {$c.TechnicalSourceIndexes[$device]=$s.Previous.PSObject.Copy()}
            Digest {$c.TechnicalSourceIndexes[$device].ContentSha256='F'*64}
            Root {$c.ProjectRoot=Join-Path $testRoot 'foreign'}
            Removal {$c.TechnicalSourceIndexes.Remove($device)}
        }
        Reject-PU {Assert-WinSecTechnicalPublicationCacheStamp $s}
    }
}
Test-PU 'A completed invalidation is required before reload publication' {
    $c=New-PU;$s=New-WinSecTechnicalPublicationCacheStamp $c $testRoot $owner
    Reject-PU {Assert-WinSecTechnicalPublicationCacheStamp $s -Invalidated}
    $c.TechnicalSourceIndexes.Remove($device);Assert-WinSecTechnicalPublicationCacheStamp $s -Invalidated
}
Test-PU 'An out-of-order reload cannot evict a cache without a committed writer invalidation' {
    $c=New-PU;$prior=$c.TechnicalSourceIndexes[$device];$s=New-WinSecTechnicalPublicationCacheStamp $c $testRoot $owner
    Reject-PU {Restore-WinSecTechnicalCacheAfterPublication $s ([pscustomobject]@{PublicationStatus='PENDING'})}
    Assert-PU ([object]::ReferenceEquals($prior,$c.TechnicalSourceIndexes[$device]))
}
Write-Host ("Technical publication cache unit: $passed passed; $failed failed.");if($failed){exit 1}
