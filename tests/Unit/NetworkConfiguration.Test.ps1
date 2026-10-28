[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
. (Join-Path $root 'src/Checks/Network/Test-NetworkConfiguration.ps1')
. (Join-Path $root 'tests/Fixtures/NetworkConfigurationMemory.ps1')
function Get-CimInstance {throw 'Unmocked Windows query prohibited.'}
Set-Alias Invoke-WinSecNetworkConfigurationQuery Invoke-WinSecNetworkConfigurationFixtureQuery -Scope Script
$passed=0;$failed=0
function Assert-Network {param([bool]$Value);if(-not $Value){throw 'Network Configuration assertion failed.'}}
function Reject-Network {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-Network $caught}
function Test-Network {param($Name,[scriptblock]$Action);Initialize-WinSecNetworkConfigurationFixture;try{$null=& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}catch{$script:failed++;Write-Host ('[FAIL] '+$Name+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}
Test-Network 'Every reviewed provider produces typed technical Markdown without private fields or scores' {
    $s=New-WinSecNetworkConfigurationFixtureSession;$e=$s.ControlResults[0].Evidence;$r=New-WinSecTechnicalReport $s WSA-NET-005 SYNTHETIC SYNTHETIC
    $md=ConvertTo-WinSecTechnicalMarkdown $r
    Assert-Network ($e.CollectionComplete -and $e.CoverageComplete -and $NetworkCalls.Count -eq 11 -and $e.Batches.Count -eq 9 -and
        $md.Contains('Legacy-0002') -and $md.Contains('sha256:') -and $md -notmatch 'PRIVATE-|192\.0\.2\.|NOT_SCORED|/100')
}
Test-Network 'Observed empty interface inventories remain valid, singleton DNS global is retained' {
    $script:NetworkCount=0;$s=New-WinSecNetworkConfigurationFixtureSession;$r=New-WinSecTechnicalReport $s WSA-NET-005 SYNTHETIC SYNTHETIC
    Assert-Network ($s.ExecutionStatus -ceq 'COMPLETED' -and @($r.Rows|Where-Object SettingId -CLIKE Inventory.*).Count -eq 1)
}
Test-Network 'Optional unknowns remain visible with complete execution and limited coverage' {
    $script:NetworkOptionalMissing=$true;$s=New-WinSecNetworkConfigurationFixtureSession;$e=$s.ControlResults[0].Evidence
    $r=New-WinSecTechnicalReport $s WSA-NET-005 SYNTHETIC SYNTHETIC
    Assert-Network ($e.CollectionComplete -and -not $e.CoverageComplete -and $e.UnknownFieldCount -gt 0 -and (ConvertTo-WinSecTechnicalMarkdown $r).Contains('UNKNOWN'))
    $a=New-WinSecNetworkConfigurationFixtureAnalysis $root;Assert-Network ($a.UnknownReadingCount -gt 0)
}
foreach($role in @('Platform','Registry')+@(Get-WinSecNetworkConfigurationProviders|ForEach-Object Role)){Test-Network ('Failed provider keeps execution partial and diagnostic text closed: '+$role) {
    $script:NetworkFailure=$role;$s=New-WinSecNetworkConfigurationFixtureSession;$r=New-WinSecTechnicalReport $s WSA-NET-005 SYNTHETIC SYNTHETIC
    Assert-Network ($s.ExecutionStatus -ceq 'COMPLETED_WITH_ERRORS' -and (ConvertTo-WinSecTechnicalMarkdown $r) -notmatch 'PRIVATE-')
}}
foreach($field in @('InterfaceIndex','IPAddress','AddressFamily')){Test-Network ('Invalid required field rejects its full provider: '+$field) {
    $script:NetworkInvalid=$field;$s=New-WinSecNetworkConfigurationFixtureSession;$null=New-WinSecTechnicalReport $s WSA-NET-005 SYNTHETIC SYNTHETIC
    Assert-Network (-not $s.ControlResults[0].Evidence.CollectionComplete)
}}
Test-Network 'Esc before and during collection throws without a completed result' {
    Reject-Network {Test-WinSecNetworkConfiguration ('local:hw1-'+('b'*64)) cancelled -CancellationAction {$true}}
    Reject-Network {Test-WinSecNetworkConfiguration ('local:hw1-'+('b'*64)) cancelled -CancellationAction {$NetworkCalls.Count -ge 2}}
}
Test-Network 'Overflow rejects entire inventories without silently truncating at 64' {
    $script:NetworkCount=65;$s=New-WinSecNetworkConfigurationFixtureSession;$e=$s.ControlResults[0].Evidence
    $null=New-WinSecTechnicalReport $s WSA-NET-005 SYNTHETIC SYNTHETIC
    Assert-Network (-not $e.CollectionComplete -and $e.Availability.Adapter -ceq 'UNKNOWN' -and $null -eq $e.Counts.Adapter -and $e.Batches.Count -eq 1)
}
foreach($framework in @('nist-csf','cis-controls','mitre-attack')){Test-Network ('Saved warnings have traceable framework references without Windows rereads: '+$framework) {
    $a=New-WinSecNetworkConfigurationFixtureAnalysis $root $framework;$md=New-WinSecFrameworkMarkdown $a
    Assert-Network ($a.Rows.Count -eq 3 -and @($a.Rows|Where-Object {$_.References.Count -eq 0}).Count -eq 0 -and $NetworkCalls.Count -eq 11 -and $md -notmatch 'PRIVATE-')
}}
Test-Network 'No invented warning for unconfigured policy, Public profiles or disabled NetBIOS' {
    $script:NetworkWarn=$false;$script:NetworkRegistryMissing=$true;$a=New-WinSecNetworkConfigurationFixtureAnalysis $root
    Assert-Network ($a.Rows.Count -eq 0 -and $a.ReadingCount -gt 0)
}
Test-Network 'A Legacy required-field rejection reports only a closed diagnostic and remains partial' {
    $script:NetworkInvalid='IPEnabled';$s=New-WinSecNetworkConfigurationFixtureSession;$e=$s.ControlResults[0].Evidence
    $r=New-WinSecTechnicalReport $s WSA-NET-005 SYNTHETIC SYNTHETIC
    Assert-Network ($s.ExecutionStatus -ceq 'COMPLETED_WITH_ERRORS' -and $e.ProviderDiagnostics.Count -eq 1 -and
        $e.ProviderDiagnostics[0] -ceq 'Legacy:NORMALIZATION:NETWORK_REQUIRED_FIELD_IPEnabled' -and $null -eq $e.Counts.Legacy -and
        (ConvertTo-WinSecTechnicalMarkdown $r) -notmatch 'ProviderDiagnostics|PRIVATE-BAD-VALUE|NETWORK_REQUIRED_FIELD_IPEnabled')
}
Test-Network 'A raw provider error is replaced with a closed query-stage diagnostic' {
    $script:NetworkFailure='Legacy';$s=New-WinSecNetworkConfigurationFixtureSession;$e=$s.ControlResults[0].Evidence
    Assert-Network ($e.ProviderDiagnostics.Count -eq 1 -and $e.ProviderDiagnostics[0] -ceq 'Legacy:QUERY:UNAVAILABLE' -and
        (ConvertTo-Json $e -Depth 8 -Compress) -notmatch 'PRIVATE-PROVIDER-TEXT')
}
Test-Network 'A non-IP Legacy configuration retains its real key and UNKNOWN interface without being dropped' {
    $script:NetworkLegacyNoInterface=$true;$s=New-WinSecNetworkConfigurationFixtureSession;$e=$s.ControlResults[0].Evidence
    $r=New-WinSecTechnicalReport $s WSA-NET-005 SYNTHETIC SYNTHETIC
    $batch=ConvertTo-WinSecNetworkConfigurationBatch @($r.Rows|Where-Object SettingId -CEQ Inventory.Legacy.0001)[0].Value
    Assert-Network ($e.CollectionComplete -and -not $e.CoverageComplete -and $e.Counts.Legacy -eq 2 -and $e.UnknownFieldCount -eq 2 -and
        $r.CatalogVersion -ceq '1.1.0' -and $batch.Items.Count -eq 2 -and $batch.Items[0].Values.Index -eq 1 -and
        $null -eq $batch.Items[0].Values.InterfaceIndex -and $batch.Items[0].Values.IPEnabled -ceq $false -and
        (ConvertTo-WinSecTechnicalMarkdown $r).Contains('UNKNOWN'))
    $a=New-WinSecNetworkConfigurationFixtureAnalysis $root
    Assert-Network ($a.UnknownReadingCount -eq 1 -and @($a.Rows|Where-Object CriterionId -CEQ WSA-NCF-REVIEW-001).Count -eq 0)
}
Test-Network 'An IP-enabled Legacy configuration still cannot omit InterfaceIndex' {
    $script:NetworkLegacyNoInterface=$true;$script:NetworkLegacyIPEnabled=$true;$s=New-WinSecNetworkConfigurationFixtureSession;$e=$s.ControlResults[0].Evidence
    Assert-Network (-not $e.CollectionComplete -and $null -eq $e.Counts.Legacy -and $e.ProviderDiagnostics[0] -ceq 'Legacy:NORMALIZATION:NETWORK_REQUIRED_FIELD_InterfaceIndex')
}
Test-Network 'Malformed interface values are rejected even when Legacy IPEnabled is false' {
    $raw=[pscustomobject]@{Index=[uint32]1;InterfaceIndex='PRIVATE-BAD-INDEX';IPEnabled=$false}
    Reject-Network {ConvertTo-WinSecNetworkConfigurationRecord $raw Legacy 1}
    foreach($value in @($null,'PRIVATE-BAD-KEY',-1)){$raw=[pscustomobject]@{Index=$value;InterfaceIndex=$null;IPEnabled=$false};Reject-Network {ConvertTo-WinSecNetworkConfigurationRecord $raw Legacy 1}}
}
Test-Network 'Duplicate Legacy configuration keys reject the complete provider rather than hide records' {
    $script:NetworkLegacyDuplicateIndex=$true;$s=New-WinSecNetworkConfigurationFixtureSession;$e=$s.ControlResults[0].Evidence
    Assert-Network (-not $e.CollectionComplete -and $e.Availability.Legacy -ceq 'UNKNOWN' -and $null -eq $e.Counts.Legacy)
}
Test-Network 'The reader rejects an invented interface exclusion, duplicate keys and mixed catalog versions' {
    $script:NetworkLegacyNoInterface=$true;$r=New-WinSecTechnicalReport (New-WinSecNetworkConfigurationFixtureSession) WSA-NET-005 SYNTHETIC SYNTHETIC
    $row=@($r.Rows|Where-Object SettingId -CEQ Inventory.Legacy.0001)[0];$batch=ConvertTo-WinSecNetworkConfigurationBatch $row.Value
    $batch.Items[0].Values.IPEnabled=$true;Reject-Network {ConvertTo-WinSecNetworkConfigurationBatch (ConvertTo-Json $batch -Compress -Depth 6)}
    $batch=ConvertTo-WinSecNetworkConfigurationBatch $row.Value;$batch.Items[1].Values.Index=$batch.Items[0].Values.Index
    Reject-Network {ConvertTo-WinSecNetworkConfigurationBatch (ConvertTo-Json $batch -Compress -Depth 6)}
    $r.CatalogVersion='1.0.0';Reject-Network {ConvertTo-WinSecTechnicalReport $r}
}
Test-Network 'Historical 1.0 network batches remain strict and cannot acquire an invented Legacy key' {
    $r=New-WinSecTechnicalReport (New-WinSecNetworkConfigurationFixtureSession) WSA-NET-005 SYNTHETIC SYNTHETIC
    $r.CatalogVersion='1.0.0'
    foreach($row in @($r.Rows|Where-Object SettingId -CLIKE Inventory.*)){
        $b=ConvertTo-WinSecNetworkConfigurationBatch $row.Value;$b.SchemaVersion='1.0.0'
        if($b.Role -ceq 'Legacy'){foreach($item in $b.Items){$item.Values.PSObject.Properties.Remove('Index')}}
        $row.Value=ConvertTo-Json $b -Compress -Depth 6
    }
    $r=ConvertTo-WinSecTechnicalReport $r;$md=ConvertTo-WinSecTechnicalMarkdown $r
    Assert-Network (-not $md.Contains('Legacy configuration Index is the Win32 configuration key'))
    $row=@($r.Rows|Where-Object SettingId -CEQ Inventory.Legacy.0001)[0];$b=ConvertTo-WinSecNetworkConfigurationBatch $row.Value
    $b.Items[0].Values.InterfaceIndex=$null;$b.Items[0].Values.IPEnabled=$false
    Reject-Network {ConvertTo-WinSecNetworkConfigurationBatch (ConvertTo-Json $b -Compress -Depth 6)}
}
Test-Network 'Counts, diagnostics, scope, record identity and address tokens are strictly validated' {
    $r=New-WinSecTechnicalReport (New-WinSecNetworkConfigurationFixtureSession) WSA-NET-005 SYNTHETIC SYNTHETIC
    $copy=Copy-WinSecResultData $r;@($copy.Rows|Where-Object SettingId -CEQ Counts.Adapter)[0].Value=0;Reject-Network {ConvertTo-WinSecTechnicalReport $copy}
    $copy=Copy-WinSecResultData $r;$copy.ScopeKey='WSA-NET-004';Reject-Network {ConvertTo-WinSecTechnicalReport $copy}
    $row=@($r.Rows|Where-Object SettingId -CEQ Inventory.IPAddress.0001)[0];$b=ConvertTo-WinSecNetworkConfigurationBatch $row.Value
    $b.Items[1].Id=$b.Items[0].Id;Reject-Network {ConvertTo-WinSecNetworkConfigurationBatch (ConvertTo-Json $b -Compress -Depth 6)}
    $b=ConvertTo-WinSecNetworkConfigurationBatch $row.Value;$b.Items[0].Values.IPAddress='192.0.2.10';Reject-Network {ConvertTo-WinSecNetworkConfigurationBatch (ConvertTo-Json $b -Compress -Depth 6)}
}
Test-Network 'Common Windows context permits only the individually validated production control' {
    $plan=Get-WinSecAssessmentProfilePlan $root @('WSA-NET-005') WSA-W11-23H2-PRO-DEF-BASE
    $check=Get-WinSecRegisteredCheck (Get-WinSecCheckRegistry $root) WSA-NET-005
    Assert-Network ($plan.Preview.Policies[0].CatalogId -ceq 'WSA-NETWORK-COLLECTION' -and $check.ExecutionEnabled -and $check.ExecutionReady -and $check.ImplementationStatus -ceq 'VALIDATED')
}
Test-Network 'IPv6 addresses and routes preserve family with tokens; mixed families and invalid prefixes are rejected' {
    $raw=[pscustomobject]@{InterfaceIndex=[uint32]1;AddressFamily=[uint16]23;IPAddress='2001:db8::1';PrefixLength=[byte]64;SkipAsSource=$false}
    $record=ConvertTo-WinSecNetworkConfigurationRecord $raw IPAddress 1
    Assert-Network ($record.Values.AddressFamily -eq 23 -and $record.Values.IPAddress -cmatch '\Asha256:' -and $record.Values.SkipAsSource -ceq $false)
    $raw.IPAddress='192.0.2.1';Reject-Network {ConvertTo-WinSecNetworkConfigurationRecord $raw IPAddress 1}
    $raw.IPAddress='2001:db8::1';$raw.PrefixLength=[byte]129;Reject-Network {ConvertTo-WinSecNetworkConfigurationRecord $raw IPAddress 1}
    Reject-Network {ConvertTo-WinSecNetworkConfigurationAddress '2001:db8::/129' -Prefix}
}
Test-Network 'False, zero and multi-gigabit link speeds are retained; malformed DNS arrays reject the provider' {
    $r=ConvertTo-WinSecNetworkConfigurationRecord ([pscustomobject]@{InterfaceIndex=[uint32]0;Virtual=$false;TransmitLinkSpeed=[uint64]10000000000}) Adapter 1
    Assert-Network ($r.Values.InterfaceIndex -eq 0 -and $r.Values.Virtual -ceq $false -and $r.Values.TransmitLinkSpeed -eq 10000000000)
    Reject-Network {ConvertTo-WinSecNetworkConfigurationRecord ([pscustomobject]@{InterfaceIndex=[uint32]1;AddressFamily=[uint16]2;ServerAddresses='PRIVATE-DNS'}) DNSServer 1}
    Reject-Network {ConvertTo-WinSecNetworkConfigurationRecord ([pscustomobject]@{InterfaceIndex=[uint32]1;AddressFamily=[uint16]2;ServerAddresses=@('192.0.2.53')*9}) DNSServer 1}
}
Test-Network 'Historical 1.5 Network Security Markdown keeps the original adapter set and body' {
    $a=New-WinSecFrameworkAnalysis $root ('local:hw1-'+('b'*64)) SYNTHETIC SECTION NetworkSecurity nist-csf @() @()
    $a.RuleCatalogVersion='1.5.0';$a.ContentSha256=Get-WinSecFrameworkAnalysisDigest $a;$md=New-WinSecFrameworkMarkdown $a
    Assert-Network ($md.Contains('Network Configuration remains pending.') -and -not $md.Contains('WSA-NET-005'))
}
Test-Network 'Maximum inventories and eight DNS addresses fit the unchanged 1 MiB Markdown budget' {
    $script:NetworkCount=64;$s=New-WinSecNetworkConfigurationFixtureSession;$r=New-WinSecTechnicalReport $s WSA-NET-005 SYNTHETIC SYNTHETIC
    foreach($row in @($r.Rows|Where-Object SettingId -CLIKE Inventory.DNSServer.*)){
        $b=ConvertTo-WinSecNetworkConfigurationBatch $row.Value;foreach($i in $b.Items){$i.Values.ServerAddresses=@('sha256:'+('a'*64))*8};$row.Value=ConvertTo-Json $b -Compress -Depth 6
    }
    $body=ConvertTo-WinSecTechnicalMarkdown $r
    $meta=[ordered]@{SchemaVersion='2.0.0';DeviceId=$r.DeviceId;ScanId=$r.ScanId;CheckId=$r.CheckId;ScopeType=$r.ScopeType;ScopeKey=$r.ScopeKey;ContentSha256=(Get-WinSecReportTextHash $body)}
    $artifact="<!-- WinSec technical report`n"+(ConvertTo-Json $meta -Compress)+"`n-->`n"+$body
    $null=ConvertFrom-WinSecTechnicalMarkdownArtifact $artifact $r.DeviceId
    Assert-Network ([Text.Encoding]::UTF8.GetByteCount($artifact) -le 1048576 -and @($r.Rows|Where-Object SettingId -CLIKE Inventory.*).Count -eq 33)
}
Write-Host ('Network Configuration: '+$passed+' passed; '+$failed+' failed.');if($failed){throw 'Network Configuration tests failed.'}
