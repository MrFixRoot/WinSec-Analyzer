[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Services/TechnicalSourceRestoration.ps1')
. (Join-Path $root 'tests/Fixtures/TechnicalSourceMemory.ps1')
foreach($name in @('Get-CimInstance','Get-CimClass','Get-MpComputerStatus','Get-MpPreference','Start-Job')){Set-Item ('Function:script:'+$name) {throw 'Native acquisition forbidden.'}}
$passed=0;$failed=0
$f=New-WinSecTechnicalSourceFixture -Family PROJECTION
$owner=[pscustomobject]@{DeviceId=$f.Identity.DeviceId;ScanId=$f.Identity.ScanId;ScopeType=$f.Identity.ScopeType;ScopeKey=$f.Identity.ScopeKey}
$pin=Get-WinSecTechnicalSourcePackageStamp $f.Package $f.Identity
$entry=[pscustomobject]@{ArtifactType='WinSec.StoredSession';SchemaVersion='1.0.0';PublicationStatus='COMMITTED';
    Path=(Get-WinSecTransitionSessionLayout $root $owner.DeviceId $owner.ScanId).Path;FileSha256=('A'*64);Identity=$owner;ContentSha256=('B'*64);
    Sources=@([pscustomobject]@{Reference=(Get-WinSecLegacySourceFixtureReference $f);SnapshotSha256=$pin.SnapshotSha256;Collection=$f.Package.Snapshot.Collection.PSObject.Copy()})}
function Assert-SI {param([bool]$Value);if(-not $Value){throw 'Stored index unit assertion failed.'}}
function Reject-SI {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-SI $caught}
function Test-SI {param([string]$Name,[scriptblock]$Action);try{& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}catch{$script:failed++;Write-Host ('[FAIL] '+$Name+': '+$_.Exception.Message)}}
function Input-SI {param($Stored)
    [pscustomobject]@{ArtifactType='WinSec.TechnicalSourceDiscovery';SchemaVersion='1.1.0';DeviceId=$owner.DeviceId;Sessions=@();StoredSessions=@($Stored)}
}
Test-SI 'Index 1.1 preserves StoredSession type, original reference and detached collection metadata' {
    $i=Copy-WinSecTechnicalIndexMetadata $root (Input-SI $entry) $owner.DeviceId DISCOVERY $null
    Assert-WinSecTechnicalSourceIndex $root $i $owner.DeviceId
    Assert-SI ($i.SchemaVersion -ceq '1.1.0' -and $i.Origin -ceq 'RECORDS' -and $i.Sessions.Count -eq 0 -and $i.StoredSessions.Count -eq 1 -and
        $i.StoredSessions[0].ArtifactType -ceq 'WinSec.StoredSession' -and @($i.StoredSessions[0].Sources[0].Reference.PSObject.Properties).Count -eq 3 -and
        -not [object]::ReferenceEquals($i.StoredSessions[0].Sources[0].Collection,$entry.Sources[0].Collection))
}
Test-SI 'Historical index 1.0 keeps its six-field contract and historical digest' {
    $d=[pscustomobject]@{ArtifactType='WinSec.TechnicalSourceDiscovery';SchemaVersion='1.0.0';DeviceId=$owner.DeviceId;Sessions=@()}
    $i=Copy-WinSecTechnicalIndexMetadata $root $d $owner.DeviceId DISCOVERY $null
    Assert-SI ($i.SchemaVersion -ceq '1.0.0' -and @($i.PSObject.Properties).Count -eq 6 -and $null -eq $i.PSObject.Properties['StoredSessions'])
}
foreach($damage in @('Version','Type','Path','Owner','Hash','SourceVersion','Collection','Count','Getter','Duplicate')){
    Test-SI ('Malformed stored metadata rejects without reinterpretation: '+$damage) {
        $e=Copy-WinSecResultData $entry;$metadataInput=Input-SI $e;$script:getterCalled=$false
        switch($damage){
            Version {$e.SchemaVersion='2.0.0'}
            Type {$e.ArtifactType='WinSec.TechnicalSourceSession'}
            Path {$e.Path+='-foreign'}
            Owner {$e.Identity.ScanId='another-scan'}
            Hash {$e.FileSha256='bad'}
            SourceVersion {$e.Sources[0].Reference|Add-Member NoteProperty SchemaVersion '99.0.0'}
            Collection {$e.Sources[0].Collection.Status='UNKNOWN'}
            Count {$e.Sources[0].Collection.RetainedRecords=-1}
            Getter {$e.PSObject.Properties.Remove('FileSha256');$e|Add-Member ScriptProperty FileSha256 {$script:getterCalled=$true;'A'*64}}
            Duplicate {$metadataInput.StoredSessions=@($e,$e)}
        }
        Reject-SI {Copy-WinSecTechnicalIndexMetadata $root $metadataInput $owner.DeviceId DISCOVERY $null};Assert-SI (-not $script:getterCalled)
    }
}
foreach($version in @('1.2.0','2.0.0','UNKNOWN')){
    Test-SI ('Unknown index version rejected: '+$version) {$d=Input-SI $entry;$d.SchemaVersion=$version;Reject-SI {Copy-WinSecTechnicalIndexMetadata $root $d $owner.DeviceId DISCOVERY $null}}
}
Test-SI 'Changed stored metadata invalidates the index digest' {
    $i=Copy-WinSecTechnicalIndexMetadata $root (Input-SI $entry) $owner.DeviceId DISCOVERY $null
    $i.StoredSessions[0].Sources[0].Collection.Coverage='LIMITED'
    $i.StoredSessions[0].FileSha256='C'*64
    Reject-SI {Assert-WinSecTechnicalSourceIndex $root $i $owner.DeviceId}
}
Test-SI 'Index preparation cancellation returns no successful index' {
    Reject-SI {Copy-WinSecTechnicalIndexMetadata $root (Input-SI $entry) $owner.DeviceId DISCOVERY {$true}}
}
Test-SI 'An index 1.1 cannot enter the older publication reload lifecycle and lose its stored sources' {
    $i=Copy-WinSecTechnicalIndexMetadata $root (Input-SI $entry) $owner.DeviceId DISCOVERY $null
    $c=[pscustomobject]@{ProjectRoot=$root;TechnicalSourceIndexes=@{}};$c.TechnicalSourceIndexes[$owner.DeviceId]=$i
    Reject-SI {New-WinSecTechnicalPublicationCacheStamp $c $root $owner}
    Assert-SI ([object]::ReferenceEquals($i,$c.TechnicalSourceIndexes[$owner.DeviceId]))
}
Write-Host ("Stored index unit: $passed passed; $failed failed.");if($failed){exit 1}
