[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
. (Join-Path $root 'src/Checks/Network/Test-RDP.ps1')
. (Join-Path $root 'tests/Fixtures/RdpMemory.ps1')
function Get-CimInstance {throw 'Unmocked native provider prohibited.'}
Set-Alias Invoke-WinSecRdpQuery Invoke-WinSecRdpFixtureQuery -Scope Script
Set-Alias Read-WinSecRdpRegistryValue Read-WinSecRdpFixtureRegistry -Scope Script
$passed=0;$failed=0
function Assert-Rdp {param([bool]$Value);if(-not $Value){throw 'RDP assertion failed.'}}
function Reject-Rdp {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-Rdp $caught}
function Test-Rdp {param($Name,[scriptblock]$Action);Initialize-WinSecRdpFixture;try{$null=& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}catch{$script:failed++;Write-Host ('[FAIL] '+$Name+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}
Test-Rdp 'Every reviewed provider, listener, service and registry setting is normalized' {
    $s=New-WinSecRdpFixtureSession;$e=$s.ControlResults[0].Evidence
    Assert-Rdp ($e.CollectionSuccessful -and $e.CollectionComplete -and $e.HostEnabled -ceq $true -and $e.UnknownFieldCount -eq 0 -and
        $RdpCalls.Count -eq (9+@(Get-WinSecRdpRegistryDefinitions).Count) -and (ConvertTo-WinSecRdpInventory $e.Inventory.General).Items.Count -eq 2)
}
Test-Rdp 'Progress advances through real phases with a final complete count' {
    $null=New-WinSecRdpFixtureSession;$last=-1
    foreach($event in $RdpEvents){Assert-Rdp ($event.CompletedSteps -ge $last -and $event.TotalSteps -eq (10+@(Get-WinSecRdpRegistryDefinitions).Count));$last=$event.CompletedSteps}
    Assert-Rdp ($RdpEvents[0].CompletedSteps -eq 0 -and $last -eq $RdpEvents[-1].TotalSteps)
}
Test-Rdp 'Technical Markdown expands all inventories and excludes private provider material' {
    $s=New-WinSecRdpFixtureSession;$r=New-WinSecTechnicalReport $s WSA-NET-003 SYNTHETIC SYNTHETIC;$md=ConvertTo-WinSecTechnicalMarkdown $r
    Assert-Rdp ($r.Rows.Count -eq @(Get-WinSecRdpTechnicalDefinitions).Count -and $md.Contains('UserAuthenticationRequired') -and
        $md.Contains('RDP_TCP') -and $md.Contains('ClipboardMapping') -and $md -notmatch 'PRIVATE-|NOT_SCORED|/100')
}
Test-Rdp 'All Home variants exclude only host inventories using observed edition proof' {
    foreach($sku in @(98,99,100,101)){
        Initialize-WinSecRdpFixture;$script:RdpSku=$sku;$s=New-WinSecRdpFixtureSession;$r=New-WinSecTechnicalReport $s WSA-NET-003 SYNTHETIC SYNTHETIC
        Assert-Rdp (@($r.Rows|Where-Object State -CEQ NOT_APPLICABLE).Count -eq 8 -and $RdpCalls -notcontains 'General' -and
            @($r.Rows|Where-Object {$_.SettingId -ceq 'Registry.Policy_DisablePasswordSaving.Value' -and $_.State -ceq 'OBSERVED'}).Count -eq 1)
    }
}
Test-Rdp 'Unknown editions and unavailable platform never acquire Home exclusions' {
    foreach($failure in @('','Platform')){
        $script:RdpFailure=$failure;$script:RdpSku=999;$s=New-WinSecRdpFixtureSession;$r=New-WinSecTechnicalReport $s WSA-NET-003 SYNTHETIC SYNTHETIC
        Assert-Rdp (-not $s.ControlResults[0].Evidence.CollectionComplete -and @($r.Rows|Where-Object State -CEQ NOT_APPLICABLE).Count -eq 0)
    }
}
Test-Rdp 'Pro Enterprise Education IoT and their N variants share the reviewed collection schema' {
    foreach($sku in @(4,27,48,49,121,122,125,126,161,162,164,165,188,191)){Assert-Rdp ((Get-WinSecRdpHostSupport 22631 $sku 1) -ceq 'SUPPORTED')}
    $p=Get-WinSecAssessmentProfilePlan $root @('WSA-NET-003') WSA-W11-23H2-PRO-DEF-BASE
    Assert-Rdp ($p.Preview.Policies[0].CatalogId -ceq 'WSA-RDP-COLLECTION' -and $null -eq $p.Catalogs['WSA-NET-003'])
}
Test-Rdp 'Unavailable providers and fields remain explicit unknowns without leaked messages' {
    foreach($failure in @('General','Services','Policy_fDenyTSConnections')){
        $script:RdpFailure=$failure;$s=New-WinSecRdpFixtureSession
        Assert-Rdp (-not $s.ControlResults[0].Evidence.CollectionComplete -and (ConvertTo-Json $s -Depth 15 -Compress) -notmatch 'PRIVATE-')
    }
    $script:RdpFailure='';$script:RdpMissing='UserAuthenticationRequired';$s=New-WinSecRdpFixtureSession
    Assert-Rdp ($s.ControlResults[0].Evidence.UnknownFieldCount -eq 2 -and -not $s.ControlResults[0].Evidence.CollectionComplete)
}
Test-Rdp 'Duplicate and excessive listener sets are rejected without truncated publication' {
    foreach($size in @(2,65)){
        $script:RdpListeners=$size;$script:RdpDuplicate=($size -eq 2);$s=New-WinSecRdpFixtureSession
        Assert-Rdp (-not $s.ControlResults[0].Evidence.CollectionComplete -and $null -eq $s.ControlResults[0].Evidence.Inventory.General)
    }
}
Test-Rdp 'Conflicting effective and explicit policy permission stays unresolved' {
    $script:RdpConflict=$true;$s=New-WinSecRdpFixtureSession
    Assert-Rdp ($null -eq $s.ControlResults[0].Evidence.HostEnabled -and $s.ControlResults[0].Evidence.CollectionIssues -contains 'HOST_STATE_CONFLICT')
}
Test-Rdp 'Cancellation before collection and between providers publishes no result' {
    Reject-Rdp {Test-WinSecRDP ('local:hw1-'+('b'*64)) cancelled -CancellationAction {$true}}
    Assert-Rdp ($RdpCalls.Count -eq 0)
    Reject-Rdp {Test-WinSecRDP ('local:hw1-'+('b'*64)) cancelled -CancellationAction {return ($script:RdpCalls.Count -ge 2)}}
    Assert-Rdp ($RdpCalls.Count -eq 2)
}
Test-Rdp 'Tampered inventories, foreign classes and unsupported exclusions fail closed' {
    $s=New-WinSecRdpFixtureSession;$r=New-WinSecTechnicalReport $s WSA-NET-003 SYNTHETIC SYNTHETIC
    $row=@($r.Rows|Where-Object SettingId -CEQ Inventory.General)[0];$original=$row.Value
    $row.Value=$s.ControlResults[0].Evidence.Inventory.Session;Reject-Rdp {ConvertTo-WinSecTechnicalReport $r}
    $row.Value=$original.Replace('"SecurityLayer":0','"SecurityLayer":"PRIVATE"');Reject-Rdp {ConvertTo-WinSecTechnicalReport $r}
    $row.Value=$original.Replace('"SecurityLayer":0','"SecurityLayer":9999');Reject-Rdp {ConvertTo-WinSecTechnicalReport $r}
    $row.Value=$null;$row.State='NOT_APPLICABLE';$row.Reason='UNAVAILABLE';Reject-Rdp {ConvertTo-WinSecTechnicalReport $r}
}
foreach($framework in @('nist-csf','cis-controls','mitre-attack')){
    Test-Rdp ('Saved RDP data generates contextual warnings with reviewed references: '+$framework) {
        $a=New-WinSecRdpFixtureAnalysis $root $framework;$md=New-WinSecFrameworkMarkdown $a
        Assert-Rdp ($a.Rows.Count -eq 8 -and @($a.Rows|Where-Object {$_.References.Count -eq 0}).Count -eq 0 -and
            $md -notmatch 'PRIVATE-|NOT_SCORED|/100' -and $a.RuleCatalogVersion -ceq '1.4.0')
    }
}
Test-Rdp 'Disabled Home unknown and conflicting hosts cannot produce listener-security warnings' {
    foreach($case in @('disabled','home','unknown','conflict','safe')){
        Initialize-WinSecRdpFixture
        switch($case){disabled {$script:RdpEnabled=$false};home {$script:RdpSku=101};unknown {$script:RdpSku=999};conflict {$script:RdpConflict=$true};safe {$script:RdpSafe=$true}}
        $a=New-WinSecRdpFixtureAnalysis $root
        Assert-Rdp (@($a.Rows|Where-Object {$_.CriterionId -cin @('WSA-RDP-REVIEW-002','WSA-RDP-REVIEW-003','WSA-RDP-REVIEW-004')}).Count -eq 0)
    }
}
Test-Rdp 'Older Network Security Markdown coverage remains unchanged for catalogs 1.1 and 1.2' {
    $a=New-WinSecFrameworkAnalysis $root ('local:hw1-'+('b'*64)) SYNTHETIC SECTION NetworkSecurity nist-csf @() @()
    foreach($version in @('1.1.0','1.2.0')){
        $a.RuleCatalogVersion=$version;$a.ContentSha256=Get-WinSecFrameworkAnalysisDigest $a;$md=New-WinSecFrameworkMarkdown $a
        Assert-Rdp (-not $md.Contains('WSA-NET-003') -and $md.Contains($(if($version -ceq '1.1.0'){'Only Windows Firewall'}else{'Remote Desktop, Open Ports'})))
    }
}
Test-Rdp 'Raw WMI transport values and absent policy do not invent native-only or TLS encryption findings' {
    $script:RdpNativePolicy=$false;$a=New-WinSecRdpFixtureAnalysis $root
    Assert-Rdp (@($a.Rows|Where-Object {$_.CriterionId -cin @('WSA-RDP-REVIEW-003','WSA-RDP-REVIEW-004')}).Count -eq 0)
}
Test-Rdp 'Maximum reviewed listener inventory remains complete within the existing one MiB artifact limit' {
    $script:RdpListeners=64;$s=New-WinSecRdpFixtureSession;$r=New-WinSecTechnicalReport $s WSA-NET-003 SYNTHETIC SYNTHETIC
    $md=ConvertTo-WinSecTechnicalMarkdown $r
    Assert-Rdp ($s.ControlResults[0].Evidence.CollectionComplete -and [Text.Encoding]::UTF8.GetByteCount($md) -lt 1040000)
    foreach($row in @($r.Rows|Where-Object {$_.SettingId -clike 'Inventory.*' -and $_.SettingId -cne 'Inventory.Global'})){
        Assert-Rdp ((ConvertTo-WinSecRdpInventory $row.Value).Items.Count -eq 64)
    }
}
Test-Rdp 'Schema absence null values missing properties and booleans remain distinct unresolved diagnostics' {
    foreach($kind in @('schema','null','missing','boolean')){
        Initialize-WinSecRdpFixture
        $field='UserAuthenticationRequired'
        switch($kind){schema {$script:RdpSchemaMissing=$field};null {$script:RdpNullField=$field};missing {$script:RdpMissing=$field};boolean {$script:RdpBooleanField=$field}}
        $s=New-WinSecRdpFixtureSession;$e=$s.ControlResults[0].Evidence
        $reason=switch($kind){schema {'NOT_IN_PROVIDER_SCHEMA'};null {'NULL_VALUE'};missing {'MISSING_PROPERTY'};boolean {'BOOLEAN_VALUE'}}
        Assert-Rdp ($e.UnknownFieldCount -eq 2 -and -not $e.CollectionComplete -and $e.FieldDiagnostics -contains ('General.'+$field+':'+$reason))
        Assert-Rdp ((ConvertTo-Json $e -Depth 10 -Compress) -notmatch 'PRIVATE-')
    }
}
Test-Rdp 'Informational unknowns limit coverage without changing a successful collection into a failed scan' {
    $script:RdpNullField='NetworkAdapterLanaID';$s=New-WinSecRdpFixtureSession;$e=$s.ControlResults[0].Evidence
    Assert-Rdp ($e.CollectionComplete -and -not $e.CoverageComplete -and $s.ExecutionStatus -ceq 'COMPLETED' -and
        $e.UnknownFieldCount -eq 2 -and $e.InformationalUnknownFieldCount -eq 2 -and $e.RequiredUnknownFieldCount -eq 0 -and $e.CollectionIssues.Count -eq 0)
    $r=New-WinSecTechnicalReport $s WSA-NET-003 SYNTHETIC SYNTHETIC;$md=ConvertTo-WinSecTechnicalMarkdown $r
    Assert-Rdp ($r.CatalogVersion -ceq '1.1.0' -and $md.Contains('Reading coverage: LIMITED') -and $md.Contains('UNKNOWN'))
    $a=New-WinSecRdpFixtureAnalysis $root
    Assert-Rdp ($a.UnknownReadingCount -ge 1)
}
Test-Rdp 'Documented retired DWM fields are not applicable only with supported observed Windows context' {
    $script:RdpSchemaMissing='AllowDwm';$s=New-WinSecRdpFixtureSession;$e=$s.ControlResults[0].Evidence
    $batch=ConvertTo-WinSecRdpInventory $e.Inventory.Redirection
    Assert-Rdp ($e.CollectionComplete -and $e.CoverageComplete -and $e.UnknownFieldCount -eq 0 -and $e.NotApplicableFieldCount -eq 4 -and
        ($batch.NotApplicableFields -join '|') -ceq 'AllowDwm|PolicySourceAllowDwm')
    $r=New-WinSecTechnicalReport $s WSA-NET-003 SYNTHETIC SYNTHETIC
    Assert-Rdp ((ConvertTo-WinSecTechnicalMarkdown $r).Contains('NOT_APPLICABLE'))
    $row=@($r.Rows|Where-Object SettingId -CEQ Platform.BuildNumber)[0];$row.Value=99999
    Reject-Rdp {ConvertTo-WinSecTechnicalReport $r}
    $row.Value=22631;$row=@($r.Rows|Where-Object SettingId -CEQ Inventory.Redirection)[0]
    $row.Value=$row.Value.Replace('"AllowDwm","PolicySourceAllowDwm"','"ClipboardMapping"')
    Reject-Rdp {ConvertTo-WinSecTechnicalReport $r}
}
Test-Rdp 'Coverage claims and counters cannot hide unresolved readings' {
    $script:RdpNullField='NetworkAdapterLanaID';$s=New-WinSecRdpFixtureSession;$r=New-WinSecTechnicalReport $s WSA-NET-003 SYNTHETIC SYNTHETIC
    $row=@($r.Rows|Where-Object SettingId -CEQ CoverageComplete)[0];$row.Value=$true;Reject-Rdp {ConvertTo-WinSecTechnicalReport $r}
    $row.Value=$false;$row=@($r.Rows|Where-Object SettingId -CEQ UnknownFieldCount)[0];$row.Value=0;Reject-Rdp {ConvertTo-WinSecTechnicalReport $r}
    $script:RdpNullField='UserAuthenticationRequired';$s=New-WinSecRdpFixtureSession;$r=New-WinSecTechnicalReport $s WSA-NET-003 SYNTHETIC SYNTHETIC
    $row=@($r.Rows|Where-Object SettingId -CEQ CollectionComplete)[0];$row.Value=$true;Reject-Rdp {ConvertTo-WinSecTechnicalReport $r}
}
Test-Rdp 'Legacy 1.0 RDP snapshots remain readable without new coverage fields or invented exclusions' {
    $s=New-WinSecRdpFixtureSession;$r=New-WinSecTechnicalReport $s WSA-NET-003 SYNTHETIC SYNTHETIC
    $r.CatalogVersion='1.0.0';$ids=@(Get-WinSecRdpTechnicalDefinitions -Legacy|ForEach-Object Id)
    $r.Rows=@($r.Rows|Where-Object {$_.SettingId -cin $ids})
    foreach($row in @($r.Rows|Where-Object {$_.SettingId -clike 'Inventory.*' -and $_.State -ceq 'OBSERVED'})){
        $b=ConvertTo-WinSecRdpInventory $row.Value;$row.Value=ConvertTo-Json -InputObject ([pscustomobject]@{Class=$b.Class;Items=$b.Items}) -Depth 8 -Compress
    }
    $r=ConvertTo-WinSecTechnicalReport $r;$md=ConvertTo-WinSecTechnicalMarkdown $r
    Assert-Rdp ($r.Rows.Count -eq 115 -and -not $md.Contains('Reading coverage:') -and $md.Contains('UNKNOWN'))
}
Test-Rdp 'The reported native null pattern completes collection with seven explicit unknowns and two documented exclusions' {
    $script:RdpNullFields=@('NetworkAdapterLanaID','DenyAdminPermissionForCustomization','PolicySourceDenyAdminPermissionForCustomization','VideoPlaybackRedir','PolicySourceVideoPlaybackRedir')
    $script:RdpListenerCounts=@{Network=1;Permissions=2;Redirection=1}
    $s=New-WinSecRdpFixtureSession;$e=$s.ControlResults[0].Evidence
    Assert-Rdp ($s.ExecutionStatus -ceq 'COMPLETED' -and $e.CollectionComplete -and -not $e.CoverageComplete -and
        $e.UnknownFieldCount -eq 7 -and $e.InformationalUnknownFieldCount -eq 7 -and $e.RequiredUnknownFieldCount -eq 0 -and $e.NotApplicableFieldCount -eq 2)
    $a=New-WinSecRdpFixtureAnalysis $root
    Assert-Rdp ($a.UnknownReadingCount -eq 3 -and $a.Rows.Count -eq 8)
}
Test-Rdp 'Out-of-range principal configuration values cannot complete collection or manufacture warnings' {
    foreach($field in @('AllowTSConnections','UserAuthenticationRequired','SecurityLayer','MinEncryptionLevel')){
        Initialize-WinSecRdpFixture;$script:RdpInvalidField=$field;$s=New-WinSecRdpFixtureSession;$e=$s.ControlResults[0].Evidence
        Assert-Rdp (-not $e.CollectionComplete -and -not $e.CoverageComplete -and $e.RequiredUnknownFieldCount -ge 1 -and
            $s.ExecutionStatus -ceq 'COMPLETED_WITH_ERRORS' -and $e.CollectionIssues -contains 'CONFIGURATION_FIELDS_UNAVAILABLE')
    }
}
Write-Host ('RDP: '+$passed+' passed; '+$failed+' failed.');if($failed){throw 'RDP tests failed.'}
