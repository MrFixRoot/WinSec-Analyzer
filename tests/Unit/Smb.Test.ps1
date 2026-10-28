[CmdletBinding()]param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
. (Join-Path $root 'src/Checks/Network/Test-SMBv1.ps1')
. (Join-Path $root 'tests/Fixtures/SmbMemory.ps1')
. (Join-Path $root 'tests/Fixtures/FrameworkNativeValidationSupport.ps1')
Set-Alias Get-CimInstance Get-WinSecSmbFixtureCim -Scope Script
Set-Alias Invoke-WinSecSmbQuery Invoke-WinSecSmbFixtureQuery -Scope Script
Set-Alias Read-WinSecSmbRegistryValue Read-WinSecSmbFixtureRegistry -Scope Script
$passed=0;$failed=0
function Assert-Smb {param([bool]$Value);if(-not $Value){throw 'SMB assertion failed.'}}
function Reject-Smb {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-Smb $caught}
function Test-Smb {param($Name,[scriptblock]$Action);Initialize-WinSecSmbFixture;try{$null=& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}catch{$script:failed++;Write-Host ('[FAIL] '+$Name+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}
Test-Smb 'All reviewed server/client fields, features, services and registry values are normalized' {
    $s=New-WinSecSmbFixtureSession;$e=$s.ControlResults[0].Evidence
    Assert-Smb ($e.CollectionSuccessful -and $e.CollectionComplete -and $e.CollectionIssues.Count -eq 0 -and $SmbCalls.Count -eq 13 -and
        $e.Server.EnableSMB1Protocol -ceq $true -and $e.Client.RequireSecuritySignature -ceq $true -and
        $e.Features.'SMB1Protocol-Client' -ceq 'ENABLED' -and $e.Services.LanmanServer.State -ceq 'RUNNING')
}
Test-Smb 'Real phase progress is monotonic and reaches fourteen completed steps' {
    $null=New-WinSecSmbFixtureSession
    $last=-1;foreach($event in $SmbEvents){Assert-Smb ($event.TotalSteps -eq 14 -and $event.CompletedSteps -ge $last);$last=$event.CompletedSteps}
    Assert-Smb ($last -eq 14 -and $SmbEvents[0].CompletedSteps -eq 0)
}
Test-Smb 'Typed technical Markdown has every catalog row and no private strings' {
    $s=New-WinSecSmbFixtureSession;$r=New-WinSecTechnicalReport $s WSA-NET-002 SYNTHETIC SYNTHETIC
    $text=ConvertTo-WinSecTechnicalMarkdown $r
    Assert-Smb ($r.Rows.Count -eq @(Get-WinSecSmbTechnicalDefinitions).Count -and $r.Rows.Count -gt 100 -and
        $text -notmatch 'PRIVATE-|NOT_SCORED|/100' -and $text.Contains('SMBv1 optional features'))
}
Test-Smb 'Missing features remain UNKNOWN, never disabled or absent' {
    $script:SmbMissingFeature='SMB1Protocol-Client';$s=New-WinSecSmbFixtureSession;$e=$s.ControlResults[0].Evidence
    Assert-Smb ($e.Features.'SMB1Protocol-Client' -ceq 'UNKNOWN' -and -not $e.CollectionComplete -and $s.ExecutionStatus -ceq 'COMPLETED_WITH_ERRORS')
}
Test-Smb 'Disabled and absent optional features remain distinct observations' {
    foreach($v in @(2,3)){$script:SmbFeatureState=$v;$s=New-WinSecSmbFixtureSession;Assert-Smb ($s.ControlResults[0].Evidence.Features.SMB1Protocol -ceq $(if($v -eq 2){'DISABLED'}else{'ABSENT'}))}
}
Test-Smb 'Missing registry keys do not invent effective defaults' {
    $script:SmbRegistryMissing=$true;$s=New-WinSecSmbFixtureSession;$r=New-WinSecTechnicalReport $s WSA-NET-002 SYNTHETIC SYNTHETIC
    $row=@($r.Rows|Where-Object SettingId -CEQ Registry.ServerSMB1.Value)[0]
    Assert-Smb ($row.State -ceq 'NOT_CONFIGURED' -and $null -eq $row.Value)
}
Test-Smb 'Only missing modern audit fields on observed older builds are excluded' {
    foreach($build in @(22000,22621,22631,26100,26200)){
        $script:SmbBuild=$build;$s=New-WinSecSmbFixtureSession;$r=New-WinSecTechnicalReport $s WSA-NET-002 SYNTHETIC SYNTHETIC
        $row=@($r.Rows|Where-Object SettingId -CEQ Server.AuditClientDoesNotSupportSigning)[0]
        Assert-Smb ($row.State -ceq $(if($build -lt 26100){'NOT_APPLICABLE'}else{'UNKNOWN'}))
    }
}
Test-Smb 'Observed modern audit fields are retained even on an older selected context' {
    $script:SmbModernFields=$true;$s=New-WinSecSmbFixtureSession;$r=New-WinSecTechnicalReport $s WSA-NET-002 SYNTHETIC SYNTHETIC
    Assert-Smb (@($r.Rows|Where-Object {$_.SettingId -ceq 'Server.AuditClientDoesNotSupportSigning' -and $_.State -ceq 'OBSERVED' -and $_.Value -ceq $true}).Count -eq 1)
}
Test-Smb 'Provider errors stay partial and do not leak diagnostic text' {
    foreach($source in @('Server','Client','Win32_OperatingSystem','Win32_OptionalFeature','Win32_Service','ClientDriverStart')){
        $script:SmbFailure=$source;$s=New-WinSecSmbFixtureSession
        Assert-Smb (-not $s.ControlResults[0].Evidence.CollectionComplete -and
            (ConvertTo-Json $s.ControlResults[0].Evidence -Depth 8 -Compress) -notmatch 'PRIVATE-')
    }
}
Test-Smb 'Invalid scalars are not reinterpreted as enabled or disabled' {
    $script:SmbBadScalar=$true;$s=New-WinSecSmbFixtureSession
    Assert-Smb ($null -eq $s.ControlResults[0].Evidence.Server.RequireSecuritySignature -and -not $s.ControlResults[0].Evidence.CollectionComplete)
    foreach($v in @('evil-cipher','AES_128_GCM,evil','AES_128_GCM,AES_128_GCM')){Assert-Smb ($null -eq (ConvertTo-WinSecSmbValue $v smbCiphers))}
}
Test-Smb 'Cancellation before collection and between phases returns no session data' {
    Reject-Smb {Test-WinSecSMBv1 ('local:hw1-'+('b'*64)) cancel -CancellationAction {$true}}
    Assert-Smb ($SmbCalls.Count -eq 0)
    Reject-Smb {Test-WinSecSMBv1 ('local:hw1-'+('b'*64)) cancel -CancellationAction {return ($script:SmbCalls.Count -ge 2)}}
    Assert-Smb ($SmbCalls.Count -eq 2)
}
Test-Smb 'Unreviewed exclusions and injected fields fail closed' {
    $s=New-WinSecSmbFixtureSession;$r=New-WinSecTechnicalReport $s WSA-NET-002 SYNTHETIC SYNTHETIC
    $row=@($r.Rows|Where-Object SettingId -CEQ Server.EnableSMB1Protocol)[0];$row.State='NOT_APPLICABLE';$row.Value=$null;$row.Reason='UNAVAILABLE'
    Reject-Smb {ConvertTo-WinSecTechnicalReport $r}
    Reject-Smb {Read-WinSecSmbFixtureRegistry 'ForeignPath'}
}
Test-Smb 'Windows profile selection binds the reviewed SMB collection schema without scoring' {
    $p=Get-WinSecAssessmentProfilePlan $root @('WSA-NET-002') WSA-W11-23H2-PRO-DEF-BASE
    Assert-Smb ($p.Preview.Policies[0].CatalogId -ceq 'WSA-SMB-COLLECTION' -and $null -eq $p.Catalogs['WSA-NET-002'])
}
foreach($framework in @('nist-csf','cis-controls','mitre-attack')){
    Test-Smb ('Saved SMB observations produce contextual warnings: '+$framework) {
        $s=New-WinSecSmbFixtureSession;$technical=New-WinSecTechnicalReport $s WSA-NET-002 SYNTHETIC SYNTHETIC
        $record=New-WinSecPublicHistoryRecord $s
        $public=(ConvertFrom-WinSecPublicHistoryRecord (ConvertFrom-WinSecStoredJson (Get-WinSecPublicHistoryJson $record))).PublicResult
        $source=[pscustomobject]@{CheckId='WSA-NET-002';ScanId=$s.ScanId;ScopeType=$s.ScopeType;ScopeKey=$s.ScopeKey;
            CompletedAtUTC=$s.CompletedAtUTC;Origin='LIVE';PublicResult=$public;CatalogVersion=$s.CatalogVersion;ExpectedCheckIds=@($s.ExpectedCheckIds)}
        $a=New-WinSecFrameworkAnalysis $root $s.DeviceId SYNTHETIC CONTROL WSA-NET-002 $framework @($source) @($technical)
        $md=New-WinSecFrameworkMarkdown $a
        Assert-Smb ($a.Rows.Count -eq 4 -and @($a.Rows|Where-Object {$_.References.Count -eq 0}).Count -eq 0 -and
            $a.ReadingCount -eq $technical.Rows.Count -and $md -notmatch 'PRIVATE-|NOT_SCORED|/100')
    }
}
Test-Smb 'Disabled SMBv1 and unavailable observations cannot manufacture warnings' {
    $script:SmbServerEnabled=$false;$script:SmbFeatureState=2;$script:SmbDependency=$false
    foreach($failure in @('','Server')){
        $script:SmbFailure=$failure;$s=New-WinSecSmbFixtureSession;$technical=New-WinSecTechnicalReport $s WSA-NET-002 SYNTHETIC SYNTHETIC
        $source=[pscustomobject]@{CheckId='WSA-NET-002';ScanId=$s.ScanId;ScopeType=$s.ScopeType;ScopeKey=$s.ScopeKey;
            CompletedAtUTC=$s.CompletedAtUTC;Origin='LIVE';PublicResult=(ConvertTo-WinSecPublicScanResult $s);CatalogVersion=$s.CatalogVersion;ExpectedCheckIds=@($s.ExpectedCheckIds)}
        $a=New-WinSecFrameworkAnalysis $root $s.DeviceId SYNTHETIC CONTROL WSA-NET-002 nist-csf @($source) @($technical)
        Assert-Smb ($a.Rows.Count -eq 0)
    }
}
Test-Smb 'Legacy Network Security report coverage remains reproducible after adding SMB' {
    $a=New-WinSecFrameworkAnalysis $root ('local:hw1-'+('b'*64)) SYNTHETIC SECTION NetworkSecurity nist-csf @() @()
    $current=New-WinSecFrameworkMarkdown $a;Assert-Smb ($current.Contains('WSA-NET-001, WSA-NET-002'))
    $a.RuleCatalogVersion='1.1.0';$a.ContentSha256=Get-WinSecFrameworkAnalysisDigest $a
    $legacy=New-WinSecFrameworkMarkdown $a
    Assert-Smb ($legacy.Contains('Only Windows Firewall currently has a reviewed collector') -and
        $legacy.Contains('Controls without a saved scan: WSA-NET-001.') -and -not $legacy.Contains('WSA-NET-002'))
}
Write-Host ('SMB: '+$passed+' passed; '+$failed+' failed.');if($failed){throw 'SMB tests failed.'}
