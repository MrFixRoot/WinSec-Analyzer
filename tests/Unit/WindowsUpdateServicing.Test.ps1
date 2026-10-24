# Public reference data and synthetic platform facts only. No native audit.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Services/WindowsUpdateReferenceService.ps1')
function Get-CimInstance {throw 'Unexpected Windows query.'}
function Get-MpPreference {throw 'Unexpected Defender query.'}
$script:passed=0;$script:failed=0
$snapshot=Get-WinSecWindowsUpdateReferenceCatalog $root
$script:catalog=$snapshot.Catalog
$script:at='2026-10-24T12:00:00Z'
function Assert-WinSecWUReference {param([bool]$Value);if(-not $Value){throw 'Windows Update reference assertion failed.'}}
function Assert-WinSecWUReferenceThrows {
    param([scriptblock]$Action)
    $caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-WinSecWUReference $caught
}
function Copy-WinSecWUReference {ConvertFrom-WinSecStoredJson (ConvertTo-Json $script:catalog -Depth 16)}
function New-WinSecWUReferencePlatform {
    [pscustomobject]@{State='OBSERVED';Version='10.0.26200';BuildNumber='26200';OperatingSystemSKU=48;ProductType=1
        Release='25H2';Channel='GAC';Revision=9711;RevisionState='OBSERVED';RestartState='NOT_PENDING'}
}
function Test-WinSecWUReference {
    param([string]$Name,[scriptblock]$Action)
    try{$null=& $Action;$script:passed++;[Console]::WriteLine('[PASS] '+$Name)}
    catch{$script:failed++;[Console]::WriteLine('[FAIL] '+$Name+' : '+$_.Exception.Message);[Console]::WriteLine($_.ScriptStackTrace)}
}
Test-WinSecWUReference 'Installed catalog has seven releases, seventeen exact SKUs and no executable criterion' {
    Assert-WinSecWUReference ($snapshot.Sha256 -cmatch '\A[A-F0-9]{64}\z' -and $script:catalog.Releases.Count -eq 7 -and
        @($script:catalog.EditionGroups.Skus).Count -eq 17 -and
        $script:catalog.Status -ceq 'REVIEWED_REFERENCE_DATA' -and
        $null -eq $script:catalog.PSObject.Properties['Criteria'])
}
Test-WinSecWUReference 'Comparison has no provider or filesystem reads and does not return scores or findings' {
    function Get-Item {throw 'Unexpected comparison I/O.'};function Get-Content {throw 'Unexpected comparison I/O.'}
    $r=Get-WinSecWindowsUpdateServicingReference $script:catalog (New-WinSecWUReferencePlatform) $script:at
    Assert-WinSecWUReference ($r.SecuritySupport.State -ceq 'SUPPORTED' -and $r.SecurityBaseline.State -ceq 'MET' -and
        (ConvertTo-Json $r -Depth 8) -notmatch '"Score"|"Findings"|"Evidence"|PASS|FAIL|NOT_APPLICABLE')
}
foreach($sku in @(48,49,98,99,100,101,161,162,164,165,4,27,121,122)) {
    Test-WinSecWUReference ('Reviewed general availability SKU remains distinct: '+$sku) {
        $p=New-WinSecWUReferencePlatform;$p.OperatingSystemSKU=$sku
        $r=Get-WinSecWindowsUpdateServicingReference $script:catalog $p $script:at
        Assert-WinSecWUReference ($r.SecuritySupport.State -ceq 'SUPPORTED' -and $r.SecurityBaseline.State -ceq 'MET')
    }
}
foreach($context in @(@('23H2','22631',7652),@('24H2','26100',9711),@('25H2','26200',9711),@('26H1','28000',3231),@('26H2','26300',9711))) {
    Test-WinSecWUReference ('Security baseline is branch-specific: '+$context[0]) {
        $p=New-WinSecWUReferencePlatform;$p.Release=$context[0];$p.BuildNumber=$context[1]
        $p.Version='10.0.'+$p.BuildNumber;$p.Revision=$context[2];$p.OperatingSystemSKU=4
        $r=Get-WinSecWindowsUpdateServicingReference $script:catalog $p $script:at
        Assert-WinSecWUReference ($r.SecuritySupport.State -ceq 'SUPPORTED' -and $r.SecurityBaseline.State -ceq 'MET' -and
            $r.SecurityBaseline.RequiredRevision -eq $context[2])
    }
}
foreach($context in @(@(125,'2029-10-09'),@(126,'2029-10-09'),@(191,'2034-10-10'))) {
    Test-WinSecWUReference ('LTSC support is not inherited from Pro or another LTSC edition: '+$context[0]) {
        $p=New-WinSecWUReferencePlatform;$p.Release='24H2';$p.BuildNumber='26100';$p.Version='10.0.26100'
        $p.Channel='LTSC';$p.OperatingSystemSKU=$context[0]
        $r=Get-WinSecWindowsUpdateServicingReference $script:catalog $p $script:at
        Assert-WinSecWUReference ($r.SecuritySupport.State -ceq 'SUPPORTED' -and
            $r.SecuritySupport.SupportEndsOn -ceq $context[1] -and $r.SecurityBaseline.State -ceq 'MET')
    }
}
foreach($context in @(@('21H2','22000',48),@('21H2','22000',4),@('22H2','22621',4),@('23H2','22631',48),@('24H2','26100',48))) {
    Test-WinSecWUReference ('Ended security support is not hidden by a recent revision: '+$context[0]+'/'+$context[2]) {
        $p=New-WinSecWUReferencePlatform;$p.Release=$context[0];$p.BuildNumber=$context[1]
        $p.Version='10.0.'+$p.BuildNumber;$p.OperatingSystemSKU=$context[2]
        $r=Get-WinSecWindowsUpdateServicingReference $script:catalog $p $script:at
        Assert-WinSecWUReference ($r.SecuritySupport.State -ceq 'OUT_OF_SUPPORT' -and $r.SecurityBaseline.State -ceq 'UNKNOWN')
    }
}
Test-WinSecWUReference 'An older same-branch revision identifies only the reviewed overdue cumulative baseline' {
    $p=New-WinSecWUReferencePlatform;$p.Revision=9550
    $r=Get-WinSecWindowsUpdateServicingReference $script:catalog $p $script:at
    Assert-WinSecWUReference ($r.SecurityBaseline.State -ceq 'MISSING' -and $r.SecurityBaseline.Kb -ceq 'KB5127648' -and
        $r.SecurityBaseline.Reason -ceq 'REVIEWED_BASELINE_OVERDUE')
}
Test-WinSecWUReference 'A numerically newer, unreviewed revision is not proof of installed security coverage' {
    $p=New-WinSecWUReferencePlatform;$p.Revision=10000
    $r=Get-WinSecWindowsUpdateServicingReference $script:catalog $p $script:at
    Assert-WinSecWUReference ($r.SecurityBaseline.State -ceq 'UNKNOWN' -and $r.SecurityBaseline.Reason -ceq 'NEWER_REVISION_NOT_REVIEWED')
}
Test-WinSecWUReference 'Missing baseline metadata cannot manufacture patch currency for a supported edition' {
    $c=Copy-WinSecWUReference;$c.Releases[4].SecurityBaseline=$null
    $r=Get-WinSecWindowsUpdateServicingReference $c (New-WinSecWUReferencePlatform) $script:at
    Assert-WinSecWUReference ($r.SecuritySupport.State -ceq 'SUPPORTED' -and $r.SecurityBaseline.State -ceq 'UNKNOWN' -and
        $r.SecurityBaseline.Reason -ceq 'NO_REVIEWED_SECURITY_BASELINE')
}
Test-WinSecWUReference 'A plausible numeric revision with unverified provenance remains unknown' {
    $p=New-WinSecWUReferencePlatform;$p.RevisionState='UNKNOWN'
    $r=Get-WinSecWindowsUpdateServicingReference $script:catalog $p $script:at
    Assert-WinSecWUReference ($r.SecurityBaseline.State -ceq 'UNKNOWN' -and $r.SecurityBaseline.Reason -ceq 'REVISION_UNVERIFIED')
}
foreach($restart in @('PENDING','UNKNOWN',$null,1,$false)) {
    Test-WinSecWUReference 'Completion is not inferred from a revision with pending or unknown restart state' {
        $p=New-WinSecWUReferencePlatform;$p.RestartState=$restart
        $r=Get-WinSecWindowsUpdateServicingReference $script:catalog $p $script:at
        Assert-WinSecWUReference ($r.SecurityBaseline.State -ceq 'UNKNOWN' -and
            $r.SecurityBaseline.Reason -ceq 'UPDATE_COMPLETION_UNVERIFIED' -and $r.SecuritySupport.State -ceq 'SUPPORTED')
    }
}
foreach($value in @($null,$true,'9711',9711.0,-1,4294967296L,@(9711))) {
    Test-WinSecWUReference 'Invalid revision types cannot manufacture patch completion or an overdue finding' {
        $p=New-WinSecWUReferencePlatform;$p.Revision=$value
        $r=Get-WinSecWindowsUpdateServicingReference $script:catalog $p $script:at
        Assert-WinSecWUReference ($r.SecurityBaseline.State -ceq 'UNKNOWN' -and $r.SecurityBaseline.Reason -ceq 'REVISION_UNVERIFIED')
    }
}
foreach($fault in @('Sku','SkuType','Channel','LtscRelease','Release','Build','Server','UnknownState','MissingField','ExtraField')) {
    Test-WinSecWUReference ('Unverified platform does not inherit another context: '+$fault) {
        $p=New-WinSecWUReferencePlatform
        switch($fault) {
            Sku {$p.OperatingSystemSKU=188};SkuType {$p.OperatingSystemSKU='48'};Channel {$p.Channel='LTSC'}
            LtscRelease {$p.Channel='LTSC';$p.OperatingSystemSKU=191};Release {$p.Release='24H2'}
            Build {$p.Version='10.0.26100'};Server {$p.ProductType=3};UnknownState {$p.State='UNKNOWN'}
            MissingField {$p.PSObject.Properties.Remove('Channel')};ExtraField {$p|Add-Member NoteProperty Private 'PRIVATE-WU'}
        }
        $r=Get-WinSecWindowsUpdateServicingReference $script:catalog $p $script:at
        Assert-WinSecWUReference ($r.SecuritySupport.State -ceq 'UNKNOWN' -and $r.SecurityBaseline.State -ceq 'UNKNOWN' -and
            (ConvertTo-Json $r -Depth 8) -notmatch 'PRIVATE-WU')
    }
}
Test-WinSecWUReference 'Script properties are rejected before their getters can run' {
    $p=New-WinSecWUReferencePlatform;$p.PSObject.Properties.Remove('Revision')
    $script:referenceGetterRan=$false
    $p|Add-Member ScriptProperty Revision {$script:referenceGetterRan=$true;return 9711}
    $r=Get-WinSecWindowsUpdateServicingReference $script:catalog $p $script:at
    Assert-WinSecWUReference (-not $script:referenceGetterRan -and $r.SecurityBaseline.State -ceq 'UNKNOWN')
}
foreach($context in @(@('2026-10-23T23:59:59Z','CATALOG_NOT_YET_VALID'),@('2026-10-31T00:00:00Z','CATALOG_EXPIRED'),@('2026-11-01T12:00:00Z','CATALOG_EXPIRED'))) {
    Test-WinSecWUReference ('Catalog freshness has an explicit exclusive limit: '+$context[0]) {
        $r=Get-WinSecWindowsUpdateServicingReference $script:catalog (New-WinSecWUReferencePlatform) $context[0]
        Assert-WinSecWUReference ($r.SecuritySupport.State -ceq 'UNKNOWN' -and $r.SecurityBaseline.State -ceq 'UNKNOWN' -and
            $r.SecuritySupport.Reason -ceq $context[1] -and $r.SecurityBaseline.Reason -ceq $context[1])
    }
}
Test-WinSecWUReference 'The catalog remains valid immediately before its exclusive expiry' {
    $r=Get-WinSecWindowsUpdateServicingReference $script:catalog (New-WinSecWUReferencePlatform) '2026-10-30T23:59:59Z'
    Assert-WinSecWUReference ($r.SecurityBaseline.State -ceq 'MET')
}
Test-WinSecWUReference 'The seven-day deadline never treats grace as proof that older patches were installed' {
    $c=Copy-WinSecWUReference;$c.AsOfUTC='2026-10-19T00:00:00Z';$c.ValidUntilUTC='2026-10-26T00:00:00Z';$c.CatalogVersion='2026.10.19.1'
    $p=New-WinSecWUReferencePlatform;$p.Revision=9550
    foreach($time in @('2026-10-19T12:00:00Z','2026-10-20T23:59:59Z')) {
        $r=Get-WinSecWindowsUpdateServicingReference $c $p $time
        Assert-WinSecWUReference ($r.SecurityBaseline.State -ceq 'UNKNOWN' -and
            $r.SecurityBaseline.Reason -ceq 'DEADLINE_OR_PRIOR_BASELINE_UNVERIFIED')
    }
    $r=Get-WinSecWindowsUpdateServicingReference $c $p '2026-10-21T00:00:00Z'
    Assert-WinSecWUReference ($r.SecurityBaseline.State -ceq 'MISSING')
}
Test-WinSecWUReference 'Calendar support boundaries stay unknown rather than inventing a UTC expiry' {
    $c=Copy-WinSecWUReference;$c.AsOfUTC='2026-10-13T00:00:00Z';$c.ValidUntilUTC='2026-10-20T00:00:00Z';$c.CatalogVersion='2026.10.13.1'
    $p=New-WinSecWUReferencePlatform;$p.Release='24H2';$p.BuildNumber='26100';$p.Version='10.0.26100'
    foreach($time in @('2026-10-13T00:00:00Z','2026-10-14T23:59:59Z')) {
        $r=Get-WinSecWindowsUpdateServicingReference $c $p $time
        Assert-WinSecWUReference ($r.SecuritySupport.State -ceq 'UNKNOWN' -and $r.SecuritySupport.Reason -ceq 'SUPPORT_DATE_BOUNDARY')
    }
    $r=Get-WinSecWindowsUpdateServicingReference $c $p '2026-10-15T00:00:00Z'
    Assert-WinSecWUReference ($r.SecuritySupport.State -ceq 'OUT_OF_SUPPORT')
}
foreach($fault in @('Version','Scope','Status','Extra','Validity','FuturePublication','Deadline','DeadlineType','DuplicateRelease','Build',
    'InvalidDate','SupportInterval','DuplicateSupport','LtscContext','SkuMapping','DuplicateGroup','KbSource','KbType','RevisionType','GroupSource','CatalogGetter')) {
    Test-WinSecWUReference ('Malformed reference catalogs fail closed: '+$fault) {
        $c=Copy-WinSecWUReference
        switch($fault) {
            Version {$c.SchemaVersion='2.0.0'};Scope {$c.Scope='ALL_SECURITY_UPDATES'};Status {$c.Status='APPROVED_CRITERIA'}
            Extra {$c|Add-Member NoteProperty Unknown $true};Validity {$c.ValidUntilUTC='2026-11-01T00:00:00Z'}
            FuturePublication {$c.Releases[2].SecurityBaseline.PublishedOn='2026-10-25'};Deadline {$c.PatchDeadlineDays=8}
            DeadlineType {$c.PatchDeadlineDays='7'};DuplicateRelease {$c.Releases[1]=$c.Releases[0]};Build {$c.Releases[0].Build=22621}
            InvalidDate {$c.Releases[0].AvailableOn='2021-02-30'};SupportInterval {$c.Releases[0].Support[0].SupportEndsOn='2020-01-01'}
            DuplicateSupport {$c.Releases[0].Support[1]=$c.Releases[0].Support[0]}
            LtscContext {$c.Releases[0].Support[0].EditionGroup='ENTERPRISE_LTSC'};SkuMapping {$c.EditionGroups[0].Skus[0]=4}
            DuplicateGroup {$c.EditionGroups[1]=$c.EditionGroups[0]}
            KbSource {$c.Releases[2].SecurityBaseline.SourceUrl='https://support.microsoft.com.evil.example/help/5126653'}
            KbType {$c.Releases[2].SecurityBaseline.Kb=@('KB5126653')};RevisionType {$c.Releases[2].SecurityBaseline.Revision=$true}
            GroupSource {$c.EditionGroups[0].SourceUrl+='?token=PRIVATE-WU'}
            CatalogGetter {$c.PSObject.Properties.Remove('Scope');$c|Add-Member ScriptProperty Scope {throw 'Getter must not execute.'}}
        }
        Assert-WinSecWUReferenceThrows {Assert-WinSecWindowsUpdateReferenceCatalog $c}
    }
}
foreach($time in @('2026-10-24','2026-10-24T12:00:00+00:00','PRIVATE-WU',$true,[datetime]::SpecifyKind([datetime]'2026-10-24',[DateTimeKind]::Unspecified))) {
    Test-WinSecWUReference 'Implicit local time and noncanonical evaluation times are rejected' {
        Assert-WinSecWUReferenceThrows {Get-WinSecWindowsUpdateServicingReference $script:catalog (New-WinSecWUReferencePlatform) $time}
    }
}
Test-WinSecWUReference 'Repeated comparisons leave the input catalog and platform unchanged' {
    $p=New-WinSecWUReferencePlatform;$beforeC=ConvertTo-Json $script:catalog -Depth 16;$beforeP=ConvertTo-Json $p
    $first=Get-WinSecWindowsUpdateServicingReference $script:catalog $p $script:at
    $first.SecuritySupport.State='PRIVATE-WU'
    $second=Get-WinSecWindowsUpdateServicingReference $script:catalog $p $script:at
    Assert-WinSecWUReference ($second.SecuritySupport.State -ceq 'SUPPORTED' -and
        (ConvertTo-Json $script:catalog -Depth 16) -ceq $beforeC -and (ConvertTo-Json $p) -ceq $beforeP)
}
[Console]::WriteLine(('Windows Update servicing: {0} passed, {1} failed.' -f $script:passed,$script:failed))
if($script:failed){throw 'Windows Update servicing tests failed.'}
