[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
. (Join-Path $root 'src/Services/TechnicalSourceRestoration.ps1')
. (Join-Path $root 'tests/Fixtures/TechnicalSourceMemory.ps1')
foreach($name in @('Get-CimInstance','Get-CimClass','Get-MpComputerStatus','Get-MpPreference','Start-Job')){Set-Item ('Function:script:'+$name) {throw 'Native acquisition forbidden.'}}
$passed=0;$failed=0
function Assert-SU {param([bool]$Value);if(-not $Value){throw 'Stored publication assertion failed.'}}
function Test-SU {param([string]$Name,[scriptblock]$Action);try{& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}catch{$script:failed++;Write-Host ('[FAIL] '+$Name+': '+$_.Exception.Message)}}
foreach($scope in @('CONTROL','SECTION','DEVICE')){
    $f=New-WinSecTechnicalSourceFixture -Family PROJECTION -ScopeType $scope;$id=$f.Identity;$s=$f.Package.Snapshot
    $owner=[pscustomobject]@{DeviceId=$id.DeviceId;ScanId=$id.ScanId;ScopeType=$scope;ScopeKey=$id.ScopeKey}
    $control=[pscustomobject]@{DeviceId=$id.DeviceId;ScanId=$id.ScanId;CheckId=$id.CheckId;SectionKey=$id.SectionKey;
        Status='INFORMATIONAL';ObservedStatus='INFORMATIONAL';TimestampUTC=$s.CollectedAtUTC;Evidence=[pscustomobject]@{}}
    $session=New-WinSecResultSession -DeviceId $id.DeviceId -ScanId $id.ScanId -CatalogVersion '1.0.0' -ExpectedCheckIds @($id.CheckId) `
        -ControlResults @($control) -StartedAtUTC $s.StartedAtUTC -CompletedAtUTC $s.CompletedAtUTC -ExecutionStatus COMPLETED -ScopeType $scope -ScopeKey $id.ScopeKey
    $original=[pscustomobject]@{ArtifactType='WinSec.StoredSession';SchemaVersion='1.0.0';Record=(New-WinSecPublicHistoryRecord $session);
        Sources=@((Get-WinSecLegacySourceFixtureReference $f));ContentSha256=''}
    $copy=Copy-WinSecResultData $original;$copy.PSObject.Properties.Remove('ContentSha256')
    $original.ContentSha256=Get-WinSecReportTextHash (Get-WinSecPublicHistoryJson $copy)
    foreach($damage in @('ORDER','OWNER','PATH','HASH','TYPE','VERSION','DIGEST','SOURCE')){
        Test-SU ($scope+': unsafe or premature stored notification rejected without evicting another device: '+$damage) {
            $discovery=[pscustomobject]@{ArtifactType='WinSec.TechnicalSourceDiscovery';SchemaVersion='1.0.0';DeviceId=$id.DeviceId;Sessions=@()}
            $index=Copy-WinSecTechnicalIndexMetadata $root $discovery $id.DeviceId DISCOVERY $null
            $c=[pscustomobject]@{ProjectRoot=$root;TechnicalSourceIndexes=@{}}
            $c.TechnicalSourceIndexes[$id.DeviceId]=$index;$c.TechnicalSourceIndexes['other']='KEEP'
            $stamp=New-WinSecTechnicalPublicationCacheStamp $c $root $owner
            $e=Copy-WinSecResultData $original;$path=(Get-WinSecTransitionSessionLayout $root $id.DeviceId $id.ScanId).Path;$hash='A'*64
            if($damage -cne 'ORDER'){$c.TechnicalSourceIndexes.Remove($id.DeviceId)}
            switch($damage){
                OWNER {$stamp.Identity.ScanId='different-session'}
                PATH {$path+='-foreign'}
                HASH {$hash='invalid'}
                TYPE {$e.ArtifactType='WinSec.TechnicalSourceSession'}
                VERSION {$e.SchemaVersion='99.0.0'}
                DIGEST {$e.ContentSha256='F'*64}
                SOURCE {$e.Sources[0]|Add-Member NoteProperty Candidate $true}
            }
            if($damage -ceq 'SOURCE'){
                $copy=Copy-WinSecResultData $e;$copy.PSObject.Properties.Remove('ContentSha256')
                $e.ContentSha256=Get-WinSecReportTextHash (Get-WinSecPublicHistoryJson $copy)
            }
            $caught=$false;try{Confirm-WinSecStoredSessionCachePublication $stamp $e $path $hash}catch{$caught=$true}
            Assert-SU ($caught -and $c.TechnicalSourceIndexes['other'] -ceq 'KEEP')
            if($damage -ceq 'ORDER'){Assert-SU ([object]::ReferenceEquals($index,$c.TechnicalSourceIndexes[$id.DeviceId]))}
            else{Assert-SU (-not $c.TechnicalSourceIndexes.ContainsKey($id.DeviceId))}
        }
    }
}
Write-Host ("Stored session publication unit: $passed passed; $failed failed.");if($failed){exit 1}
