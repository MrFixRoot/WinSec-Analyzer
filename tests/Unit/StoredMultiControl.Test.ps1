[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Services/TechnicalSourceRestoration.ps1')
. (Join-Path $root 'tests/Fixtures/TechnicalSourceMemory.ps1')
$f=New-WinSecTechnicalSourceFixture -Family PROJECTION;$passed=0;$failed=0
function Assert-MU {param([bool]$Value);if(-not $Value){throw 'Multi-control unit assertion failed.'}}
function Reject-MU {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-MU $caught}
function Test-MU {param([string]$Name,[scriptblock]$Action);try{& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}catch{$script:failed++;Write-Host ('[FAIL] '+$Name+': '+$_.Exception.Message)}}
function Ref-MU {param([string]$Check,[string]$Scope='CONTROL',[switch]$Versioned)
    $identity=$f.Identity.PSObject.Copy();$identity.CheckId=$Check;$identity.SnapshotId=[guid]::NewGuid().ToString('N');$identity.ScopeType=$Scope
    $identity.ScopeKey=switch($Scope){CONTROL {$Check};SECTION {'SystemSecurity'};DEVICE {'ALL'}}
    $r=[pscustomobject]@{Identity=$identity;CollectedAtUTC=$f.Reference.CollectedAtUTC;CatalogSha256=(Get-WinSecSnapshotCatalogHash (Get-WinSecProjectionCatalog $Check))}
    if($Versioned){$r|Add-Member NoteProperty ArtifactType 'WinSec.TechnicalSourceReference';$r|Add-Member NoteProperty SchemaVersion '1.0.0'
        foreach($property in (Get-WinSecProductiveTechnicalSourceSpecification $Check).PSObject.Properties){$r|Add-Member NoteProperty $property.Name $property.Value}}
    $r
}
function Entry-MU {param([string]$Scope='SECTION')
    $owner=[pscustomobject]@{DeviceId=$f.Identity.DeviceId;ScanId=$f.Identity.ScanId;ScopeType=$Scope;ScopeKey=$(if($Scope -ceq 'DEVICE'){'ALL'}else{'SystemSecurity'})}
    [pscustomobject]@{ArtifactType='WinSec.StoredSession';SchemaVersion='1.0.0';PublicationStatus='COMMITTED';Identity=$owner;
        Path=(Get-WinSecTransitionSessionLayout $root $owner.DeviceId $owner.ScanId).Path;FileSha256=('A'*64);ContentSha256=('B'*64);Sources=@(
            foreach($check in @('WSA-SYS-001','WSA-SYS-002','WSA-SYS-003')){[pscustomobject]@{Reference=(Ref-MU $check $Scope);SnapshotSha256=('C'*64);Collection=$f.Package.Snapshot.Collection.PSObject.Copy()}})}
}
foreach($check in @('WSA-SYS-001','WSA-SYS-002','WSA-SYS-003')){
    foreach($typed in @($false,$true)){
        Test-MU ('Reviewed transport resolves its exact control/catalog: '+$check+'/'+$typed) {
            $r=Ref-MU $check -Versioned:$typed;$resolved=Resolve-WinSecTechnicalSourceVersion $r $r.Identity
            Assert-MU ($resolved.Family -ceq 'REVIEWED_PROJECTION' -and $resolved.CatalogId -ceq ('WinSec.Reviewed.'+$check) -and $resolved.CollectorVersion -ceq '0.9.0')
        }
    }
}
Test-MU 'A known catalog cannot be reassigned to another control' {
    $r=Ref-MU WSA-SYS-002 -Versioned;$r.CatalogId='WinSec.Reviewed.WSA-SYS-001';Reject-MU {Resolve-WinSecTechnicalSourceVersion $r $r.Identity}
}
foreach($check in @('WSA-SYS-002','WSA-SYS-003')){
    Test-MU ('Candidate 2.0 cannot be relabelled as a productive control: '+$check) {
        $r=Copy-WinSecResultData (New-WinSecTechnicalSourceFixture).Reference;$r.Identity.CheckId=$check;$r.Identity.ScopeKey=$check
        Reject-MU {Resolve-WinSecTechnicalSourceVersion $r $r.Identity}
    }
}
foreach($scope in @('SECTION','DEVICE')){
    Test-MU ('Multi-source metadata preserves a single '+$scope+' owner and individual coverage') {
        $e=Entry-MU $scope;$e.Sources[1].Collection.Status='PARTIAL';$e.Sources[1].Collection.Coverage='LIMITED'
        $copy=Copy-WinSecStoredTechnicalIndexEntry $root $e $e.Identity.DeviceId
        Assert-MU ($copy.Sources.Count -eq 3 -and $copy.Identity.ScopeType -ceq $scope -and $copy.Sources[1].Collection.Status -ceq 'PARTIAL' -and
            $copy.Sources[0].Collection.Status -ceq 'COMPLETE' -and @($copy.Sources[0].Reference.PSObject.Properties).Count -eq 3)
    }
}
foreach($damage in @('DuplicateControl','DuplicateSnapshot','MissingSources','ForeignScan','ForeignScope','MixedControlScope','InvalidCoverage')){
    Test-MU ('Contradictory multi-source descriptors reject: '+$damage) {
        $e=Entry-MU
        switch($damage){
            DuplicateControl {$e.Sources[1]=Copy-WinSecResultData $e.Sources[0]}
            DuplicateSnapshot {$e.Sources[1].Reference.Identity.SnapshotId=$e.Sources[0].Reference.Identity.SnapshotId}
            MissingSources {$e.Sources=@()}
            ForeignScan {$e.Sources[1].Reference.Identity.ScanId='foreign'}
            ForeignScope {$e.Sources[1].Reference.Identity.ScopeType='DEVICE';$e.Sources[1].Reference.Identity.ScopeKey='ALL'}
            MixedControlScope {$e.Identity.ScopeType='CONTROL';$e.Identity.ScopeKey='WSA-SYS-001'}
            InvalidCoverage {$e.Sources[1].Collection.Status='PARTIAL';$e.Sources[1].Collection.Coverage='COMPLETE'}
        }
        Reject-MU {Copy-WinSecStoredTechnicalIndexEntry $root $e $e.Identity.DeviceId}
    }
}
Test-MU 'Other sections remain outside the reviewed productive transport matrix' {
    Reject-MU {Get-WinSecProductiveTechnicalSourceSpecification WSA-NET-001}
}
Write-Host ("Stored multi-control unit: $passed passed; $failed failed.");if($failed){exit 1}
