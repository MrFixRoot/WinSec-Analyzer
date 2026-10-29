# Explicit synthetic snapshots. No native provider or managed-device access.
. (Join-Path $PSScriptRoot '../../src/Checks/Accounts/GuestTechnicalStorage.ps1')
. (Join-Path $PSScriptRoot '../../src/Checks/Network/SmbTechnicalStorage.ps1')
. (Join-Path $PSScriptRoot '../../src/Checks/Services/WindowsServicesTechnicalStorage.ps1')
. (Join-Path $PSScriptRoot 'GuestTechnicalMemory.ps1')
. (Join-Path $PSScriptRoot 'SmbTechnicalMemory.ps1')
. (Join-Path $PSScriptRoot 'WindowsServicesTechnicalMemory.ps1')
function New-WinSecTechnicalFrameworkFixture {
    param([ValidateSet('Guest','SMB','Services')][string]$Control='SMB')
    $f=switch($Control){Guest {New-WinSecGuestCandidateFixture};SMB {New-WinSecSmbCandidateFixture};Services {New-WinSecWindowsServicesCandidateFixture}}
    $f.Identity.SnapshotId=[guid]::NewGuid().ToString('N')
    if($Control -ceq 'SMB'){$f.Sources[1].Data.EnableSMB1Protocol=$true;$f.Sources[1].Data.EnableSMB2Protocol=$true}
    if($Control -ceq 'Guest'){$f.Sources[1].Data[0].Disabled=$false}
    return $f
}
function New-WinSecTechnicalFrameworkSource {
    param($Fixture)
    $p=switch -CaseSensitive ($Fixture.Identity.CheckId){
        'WSA-IAM-002' {New-WinSecGuestFixturePackage $Fixture}
        'WSA-NET-002' {New-WinSecSmbFixturePackage $Fixture}
        'WSA-HRD-001' {New-WinSecWindowsServicesFixturePackage $Fixture}
    }
    [pscustomobject]@{Identity=$p.Identity;Origin='RECORDS';Snapshot=$p.Snapshot;Catalog=$p.Catalog;CatalogSha256=$p.CatalogSha256}
}
function New-WinSecTechnicalFrameworkSelection {
    param($Fixture,[switch]$Section)
    [pscustomobject]@{DeviceId=$Fixture.Identity.DeviceId;ScopeType=$(if($Section){'SECTION'}else{'CONTROL'});ScopeKey=$(if($Section){$Fixture.Identity.SectionKey}else{$Fixture.Identity.CheckId})}
}
