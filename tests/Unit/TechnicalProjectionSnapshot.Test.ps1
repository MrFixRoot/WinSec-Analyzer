[CmdletBinding()]param([switch]$Persist)
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
foreach($file in @('src/Checks/Firewall/Test-Firewall.ps1','src/Checks/Network/Test-SMBv1.ps1','src/Checks/Network/Test-RDP.ps1','src/Checks/Network/Test-OpenPorts.ps1','src/Checks/Network/Test-NetworkConfiguration.ps1','src/Checks/Accounts/IdentityAccessCollector.ps1',
    'tests/Fixtures/FirewallMemory.ps1','tests/Fixtures/SmbMemory.ps1','tests/Fixtures/RdpMemory.ps1','tests/Fixtures/OpenPortsMemory.ps1','tests/Fixtures/NetworkConfigurationMemory.ps1','tests/Fixtures/IdentityAccessMemory.ps1')){. (Join-Path $root $file)}
$t=$null;$e=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'tests/Unit/TechnicalReport.Test.ps1'),[ref]$t,[ref]$e)
$builder=$ast.Find({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'New-WinSecTechnicalFixture'},$true)
. ([scriptblock]::Create($builder.Extent.Text));$device='local:hw1-'+('b'*64)
function Get-CimInstance {throw 'Unmocked provider prohibited.'}
Set-Alias Invoke-WinSecFirewallQuery Invoke-WinSecFirewallFixtureQuery -Scope Script
Set-Alias Invoke-WinSecSmbQuery Invoke-WinSecSmbFixtureQuery -Scope Script
Set-Alias Read-WinSecSmbRegistryValue Read-WinSecSmbFixtureRegistry -Scope Script
Set-Alias Invoke-WinSecRdpQuery Invoke-WinSecRdpFixtureQuery -Scope Script
Set-Alias Read-WinSecRdpRegistryValue Read-WinSecRdpFixtureRegistry -Scope Script
Set-Alias Invoke-WinSecOpenPortsQuery Invoke-WinSecOpenPortsFixtureQuery -Scope Script
Set-Alias Invoke-WinSecNetworkConfigurationQuery Invoke-WinSecNetworkConfigurationFixtureQuery -Scope Script
Set-Alias Invoke-WinSecIdentityAccessQuery Invoke-WinSecIdentityFixtureQuery -Scope Script
$passed=0;$failed=0
$persistRoot=$null
if($Persist){$persistRoot=Join-Path ([IO.Path]::GetTempPath()) ('wpp-'+[guid]::NewGuid().ToString('N').Substring(0,12));$null=New-Item -ItemType Directory -Path $persistRoot}
try {
foreach($id in @(Get-WinSecTechnicalControls|ForEach-Object CheckId)){
    try {
        if(Test-Path Alias:Get-CimInstance){Remove-Item Alias:Get-CimInstance}
        $session=switch($id){
            WSA-NET-001 {Set-Alias Get-CimInstance Get-WinSecFirewallFixtureCim -Scope Script;Initialize-WinSecFirewallFixture;New-WinSecFirewallFixtureSession}
            WSA-NET-002 {Set-Alias Get-CimInstance Get-WinSecSmbFixtureCim -Scope Script;Initialize-WinSecSmbFixture;New-WinSecSmbFixtureSession}
            WSA-NET-003 {Initialize-WinSecRdpFixture;New-WinSecRdpFixtureSession}
            WSA-NET-004 {Initialize-WinSecOpenPortsFixture;New-WinSecOpenPortsFixtureSession}
            WSA-NET-005 {Initialize-WinSecNetworkConfigurationFixture;New-WinSecNetworkConfigurationFixtureSession}
            {$_ -clike 'WSA-IAM-*'} {Initialize-WinSecIdentityFixture;New-WinSecIdentityFixtureSession -CheckIds @($id)}
            default {New-WinSecTechnicalFixture $id}
        }
        $report=New-WinSecTechnicalReport $session $id SYNTHETIC SYNTHETIC
        $p=New-WinSecProjectionSnapshot $report
        $copy=ConvertFrom-WinSecTechnicalSnapshotJson (ConvertTo-Json -InputObject $p.Snapshot -Depth 24 -Compress) $p.Catalog $p.CatalogSha256 $p.Identity
        $restored=ConvertFrom-WinSecProjectionSnapshot $copy
        if((Get-WinSecPublicHistoryJson $restored) -cne (Get-WinSecPublicHistoryJson $report)){throw 'Projection roundtrip differs.'}
        $md=ConvertTo-WinSecSnapshotMarkdown $copy $p.Catalog $p.CatalogSha256 $p.Identity
        if($md -match 'PRIVATE-ACCOUNT|PRIVATE-DOMAIN|SYNTHETIC-SECRET' -or -not $md.Contains($id)){throw 'Projection disclosure or missing control.'}
        if($Persist){
            $saved=Write-WinSecTechnicalSnapshotPair $persistRoot $p.Snapshot $p.Catalog $p.CatalogSha256 $p.Identity
            $loaded=Read-WinSecTechnicalSnapshotPair $persistRoot $p.Identity $p.Snapshot.CollectedAtUTC $p.Catalog $p.CatalogSha256
            if($loaded.PublicationStatus -cne 'COMMITTED' -or (Get-WinSecPublicHistoryJson (ConvertFrom-WinSecProjectionSnapshot $loaded.Snapshot)) -cne (Get-WinSecPublicHistoryJson $report)){throw 'Persisted projection differs.'}
        }
        $passed++;Write-Host ('[PASS] Full reviewed projection roundtrip: '+$id)
    }catch{$failed++;Write-Host ('[FAIL] '+$id+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}
}
foreach($case in @('catalog','owner','platform','completion','row')){
    try {
        $bad=Copy-WinSecResultData $p.Snapshot;$caught=$false
        switch($case){
            catalog {$catalog=Get-WinSecProjectionCatalog $p.Identity.CheckId;$catalog.Fields[0].Type='String';try{$null=Get-WinSecSnapshotCatalogHash $catalog}catch{$caught=$true}}
            owner {$bad.Batches[0].Records[0].Readings[0].Value.DeviceId='local:hw1-'+('c'*64)}
            platform {$bad.Platform.Edition='Pro'}
            completion {$bad.Inventories[1].Complete=-not $bad.Inventories[1].Complete}
            row {$bad.Batches[1].Records[0].Readings[0].Value|Add-Member -NotePropertyName Evidence -NotePropertyValue 'SYNTHETIC-SECRET'}
        }
        if($case -cne 'catalog'){try{Assert-WinSecTechnicalSnapshot $bad $p.Catalog $p.CatalogSha256 $p.Identity}catch{$caught=$true}}
        if(-not $caught){throw 'Invalid transitional projection was accepted.'};$passed++;Write-Host ('[PASS] Transitional rejection: '+$case)
    }catch{$failed++;Write-Host ('[FAIL] '+$case+': '+$_.Exception.Message)}
}
}finally{
    if($persistRoot){$full=[IO.Path]::GetFullPath($persistRoot);$base=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\');if([IO.Path]::GetDirectoryName($full) -cne $base -or [IO.Path]::GetFileName($full) -cnotmatch '\Awpp-[a-f0-9]{12}\z'){throw 'Unsafe projection cleanup target.'};Remove-Item -LiteralPath $full -Recurse -Force}
}
Write-Host ("Projection snapshots: $passed passed; $failed failed.");if($failed){exit 1}
