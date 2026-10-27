[CmdletBinding()]param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
. (Join-Path $root 'src/Checks/Firewall/Test-Firewall.ps1')
. (Join-Path $root 'tests/Fixtures/FirewallMemory.ps1')
Set-Alias Get-CimInstance Get-WinSecFirewallFixtureCim -Scope Script
Set-Alias Invoke-WinSecFirewallQuery Invoke-WinSecFirewallFixtureQuery -Scope Script
$passed=0;$failed=0
function Assert-Firewall {param([bool]$Condition);if(-not $Condition){throw 'Firewall assertion failed.'}}
function Reject-Firewall {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-Firewall $caught}
function Test-FirewallCase {param($Name,[scriptblock]$Action);Initialize-WinSecFirewallFixture;try{$null=& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}catch{$script:failed++;Write-Host ('[FAIL] '+$Name+' : '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}
Test-FirewallCase 'Both stores, three profiles, all filters and optional inventories are collected' {
    $s=New-WinSecFirewallFixtureSession;$e=$s.ControlResults[0].Evidence
    Assert-Firewall ($e.CollectionComplete -and $e.Profiles.PSObject.Properties.Count -ne 0 -and $FirewallCalls.Count -eq 25 -and $e.Batches.Count -eq 6)
    Assert-Firewall (@($FirewallCalls|Where-Object {$_ -like '*Filter|PersistentStore'}).Count -eq 7)
}
Test-FirewallCase 'Progress reflects completed collection phases, not a timer' {
    $null=New-WinSecFirewallFixtureSession
    Assert-Firewall ($FirewallEvents[0].CompletedSteps -eq 0 -and $FirewallEvents[-1].CompletedSteps -eq $FirewallEvents[-1].TotalSteps)
    $last=0;foreach($event in $FirewallEvents){Assert-Firewall ($event.TotalSteps -eq 28 -and $event.CompletedSteps -ge $last);$last=$event.CompletedSteps}
}
Test-FirewallCase 'Observed 21H2 excludes Hyper-V without querying it' {
    $script:FirewallBuild=22000;$s=New-WinSecFirewallFixtureSession
    Assert-Firewall ($s.ControlResults[0].Evidence.HyperVState -ceq 'NOT_APPLICABLE' -and @($FirewallCalls|Where-Object {$_ -like '*HyperV*'}).Count -eq 0)
}
Test-FirewallCase 'Provider errors remain explicit and free provider messages never enter telemetry' {
    $script:FirewallFailure='Get-NetFirewallProfile';$s=New-WinSecFirewallFixtureSession
    Assert-Firewall (-not $s.ControlResults[0].Evidence.CollectionSuccessful -and -not $s.ControlResults[0].Evidence.CollectionComplete -and
        (ConvertTo-Json $s.ControlResults[0].Evidence -Depth 12 -Compress) -notmatch 'PRIVATE-PROVIDER-ERROR')
}
Test-FirewallCase 'Cancellation throws before collection and returns no result' {
    $script:FirewallCancel=$true;Reject-Firewall {New-WinSecFirewallFixtureSession};Assert-Firewall ($FirewallCalls.Count -eq 0)
}
Test-FirewallCase 'Technical snapshot keeps every rule and excludes private names, paths and addresses' {
    $s=New-WinSecFirewallFixtureSession;$r=New-WinSecTechnicalReport $s WSA-NET-001 SYNTHETIC SYNTHETIC
    $md=ConvertTo-WinSecTechnicalMarkdown $r
    Assert-Firewall ($md -notmatch 'PRIVATE-|10\.1\.2\.3|Users\\' -and $md.Contains('Inventory.ACTIVE.0001') -and $md.Contains('Inventory.LOCAL.0001'))
    $batch=@($r.Rows|Where-Object SettingId -CEQ Inventory.ACTIVE.0001)[0]
    Assert-Firewall (@(ConvertTo-WinSecFirewallBatch $batch.Value)[0].Count -eq 2)
}
Test-FirewallCase 'Inventory corruption or duplicate cross-batch identities fail closed' {
    $s=New-WinSecFirewallFixtureSession;$r=New-WinSecTechnicalReport $s WSA-NET-001 SYNTHETIC SYNTHETIC
    $row=Copy-WinSecResultData @($r.Rows|Where-Object SettingId -CEQ Inventory.ACTIVE.0001)[0]
    $row.SettingId='Inventory.ACTIVE.0002';$r.Rows+=@($row);Reject-Firewall {ConvertTo-WinSecTechnicalReport $r}
}
Test-FirewallCase 'Port/protocol token validation rejects invalid ranges and unsafe fields' {
    $s=New-WinSecFirewallFixtureSession;$batch=$s.ControlResults[0].Evidence.Batches[0].Json
    Reject-Firewall {ConvertTo-WinSecFirewallBatch ($batch.Replace('"LocalPort":"ANY"','"LocalPort":"99999"'))}
    Reject-Firewall {ConvertTo-WinSecFirewallBatch ($batch.Replace('"Protocol":"TCP"','"Protocol":"999"'))}
    Reject-Firewall {ConvertTo-WinSecFirewallBatch ($batch.Replace('"LocalPort":"ANY"','"LocalPort":"90-10"'))}
}
Test-FirewallCase 'Numeric ports, lists and ranges normalize without an ambiguous Split overload' {
    foreach($port in @('0','135','443','65535','135-139','80,443','0-65535')) {
        Assert-Firewall ((ConvertTo-WinSecFirewallToken $port ports) -ceq $port)
    }
    foreach($port in @('65536','444-80','80,99999')){Assert-Firewall ((ConvertTo-WinSecFirewallToken $port ports) -ceq 'UNKNOWN')}
    $script:FirewallLocalPort='135-139,443'
    $s=New-WinSecFirewallFixtureSession
    $r=New-WinSecTechnicalReport $s WSA-NET-001 SYNTHETIC SYNTHETIC
    $batch=@($r.Rows|Where-Object SettingId -CEQ Inventory.ACTIVE.0001)[0]
    $items=ConvertTo-WinSecFirewallBatch $batch.Value
    Assert-Firewall ($s.ControlResults[0].Evidence.CollectionComplete -and $items.Count -eq 2 -and $items[0].LocalPort -ceq '135-139,443')
}
Test-FirewallCase 'Collection profile choices share the installed Windows matrix without enabling scoring' {
    $options=@(Get-WinSecAssessmentProfileOptions $root @('WSA-NET-001'))
    Assert-Firewall ($options.Count -ge 20 -and @($options.Policies|Where-Object CatalogId -CNE WSA-FIREWALL-COLLECTION).Count -eq 0)
    Assert-Firewall ($null -eq (Get-WinSecAssessmentProfilePlan $root @('WSA-NET-001') $options[0].Profile).Catalogs['WSA-NET-001'])
}
foreach($framework in @('nist-csf','cis-controls','mitre-attack')) {
    Test-FirewallCase ('Framework warnings are derived from saved readings only: '+$framework) {
        $s=New-WinSecFirewallFixtureSession;$r=New-WinSecTechnicalReport $s WSA-NET-001 SYNTHETIC SYNTHETIC
        $source=[pscustomobject]@{CheckId='WSA-NET-001';ScanId=$s.ScanId;ScopeType=$s.ScopeType;ScopeKey=$s.ScopeKey;CompletedAtUTC=$s.CompletedAtUTC;
            Origin='LIVE';PublicResult=(ConvertTo-WinSecPublicScanResult $s);CatalogVersion=$s.CatalogVersion;ExpectedCheckIds=@($s.ExpectedCheckIds)}
        $count=$FirewallCalls.Count
        $a=New-WinSecFrameworkAnalysis $root $s.DeviceId SYNTHETIC CONTROL WSA-NET-001 $framework @($source) @($r)
        Assert-Firewall ($a.Rows.Count -eq 5 -and @($a.Rows|Where-Object {$_.References.Count -eq 0}).Count -eq 0 -and $FirewallCalls.Count -eq $count)
        Assert-Firewall ((New-WinSecFrameworkMarkdown $a) -notmatch 'NOT_SCORED|/100|PRIVATE-')
    }
}
Test-FirewallCase 'Pending controls retain an empty findings view without inventing a collector' {
    $id='local:hw1-'+('b'*64)
    $a=New-WinSecFrameworkAnalysis $root $id SYNTHETIC CONTROL WSA-NET-002 nist-csf @() @()
    Assert-Firewall ($a.Rows.Count -eq 0 -and $a.Sources.Count -eq 0 -and (New-WinSecFrameworkMarkdown $a).Contains('WSA-NET-002'))
}
Write-Host ('Firewall: '+$passed+' passed; '+$failed+' failed.');if($failed){throw 'Firewall tests failed.'}
