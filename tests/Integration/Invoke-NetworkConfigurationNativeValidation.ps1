# PlanOnly reads identity and code metadata, never NetworkConfiguration configuration.
# Execution requires approval of this exact request, runtime and UTC date.
[CmdletBinding()]
param([switch]$PlanOnly,[string]$OperationId='',[string]$ApprovedRequestHash='',
    [string]$Profile='WSA-W11-23H2-PRO-DEF-BASE')
$ErrorActionPreference='Stop'
if(-not $OperationId){if(-not $PlanOnly){throw 'Prepare and approve a NetworkConfiguration request first.'};$OperationId=[guid]::NewGuid().ToString('N')}
if($OperationId -cnotmatch '\A[a-f0-9]{32}\z' -or
    ($PlanOnly -and $ApprovedRequestHash) -or (-not $PlanOnly -and $ApprovedRequestHash -cnotmatch '\A[A-F0-9]{64}\z')){throw 'Invalid NetworkConfiguration approval.'}
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'tests/Fixtures/NetworkConfigurationNativeValidationSupport.ps1')
. (Join-Path $root 'tests/Fixtures/FrameworkNativeValidationSupport.ps1')
$lease=Open-WinSecNetworkConfigurationValidationSnapshot $root
try {
    . (Join-Path $root 'src/Core/ScanCoordinator.ps1')
    $target=New-WinSecLocalTarget
    $profilePlan=Get-WinSecAssessmentProfilePlan $root @('WSA-NET-005') $Profile
    $request=[pscustomobject][ordered]@{
        Operation='VALIDATE_NETWORK_CONFIGURATION_READ_ONLY';OperationId=$OperationId;DeviceId=$target.DeviceId;Hostname=$target.Hostname
        ScopeType='CONTROL';ScopeKey='WSA-NET-005';Checks=@('Network Configuration / WSA-NET-005')
        Runtime=$PSVersionTable.PSVersion.ToString();Is64BitProcess=[Environment]::Is64BitProcess
        ProcessElevated=(Get-WinSecNetworkConfigurationNativeElevation);ApprovalDateUTC=([datetime]::UtcNow.ToString('yyyy-MM-dd'))
        Profile=$Profile;ProfileSha256=$profilePlan.Preview.Policies[0].CatalogSha256
        DependencyManifestSha256=$lease.Sha256;DependencyCount=$lease.Files.Count
        ReadOnly=$true;PersistPublicHistory=$false;PersistRawEvidence=$false;PersistReports=$false
        Note='Only Network Configuration runs in an isolated in-memory registry. Reads local Windows metadata, exact CIM class metadata and reviewed adapter, IPv4/IPv6 interface/address/route, DNS, connection profile and legacy NetBIOS settings plus three fixed Registry64 machine DNS policies. Up to 64 records per inventory, one DNS global record and eight DNS addresses per record; overflow remains partial. Addresses and prefixes are hashed; no adapter names, SSIDs, MACs, suffixes, DNS cache, users, credentials, connections, probes, resolution or Windows changes. Technical Markdown, public history and three framework views are checked in memory. No result persistence or production permission changes.'
    }
    $hash=Get-WinSecNetworkConfigurationValidationHash (ConvertTo-Json $request -Depth 6 -Compress)
    Assert-WinSecNetworkConfigurationValidationSnapshot $root $lease
    if($PlanOnly){[pscustomobject]@{Request=$request;RequestHash=$hash}|ConvertTo-Json -Depth 8;return}
    if($hash -cne $ApprovedRequestHash){throw 'NetworkConfiguration request changed or was not approved.'}
    $reader=(Get-Command Get-WinSecCheckRegistry -CommandType Function).ScriptBlock
    function Get-WinSecCheckRegistry {
        param($ProjectRoot)
        $registry=& $reader -ProjectRoot $ProjectRoot
        foreach($check in $registry.Checks) {
            $check.ExecutionEnabled=($check.CheckId -ceq 'WSA-NET-005')
            if($check.CheckId -ceq 'WSA-NET-005'){$check.ExecutionReady=$true;$check.ImplementationStatus='VALIDATED';$check.RegistryStatus='READY'}
        }
        return $registry
    }
    function Save-WinSecPublicHistory {throw 'Native NetworkConfiguration validation prohibits writes.'}
    function Save-WinSecEvidence {throw 'Native NetworkConfiguration validation prohibits writes.'}
    function Save-WinSecTechnicalReports {throw 'Native NetworkConfiguration validation prohibits writes.'}
    function Write-WinSecTechnicalArtifact {throw 'Native NetworkConfiguration validation prohibits writes.'}
    function Export-WinSecFrameworkAnalysis {throw 'Native NetworkConfiguration validation prohibits writes.'}
    $c=New-WinSecScanCoordinator -ProjectRoot $root
    $c.Registry=[pscustomobject]@{schemaVersion='1.0.0';targets=@($target)};$c.AssessmentEnabled=$true
    if($c.PublicHistoryEnabled -or $c.AutomaticEvidencePersistence -or $c.TechnicalReportsEnabled -or $c.RequireDeviceInventory){throw 'Persistent native validation is prohibited.'}
    $script:networkNativeEvents=New-Object 'Collections.Generic.List[object]'
    $public=Invoke-WinSecCoordinatedScan -Coordinator $c -DeviceId $target.DeviceId -ScanId ('native-network-'+$OperationId) `
        -ScopeType CONTROL -ScopeKey WSA-NET-005 -AssessmentProfile $Profile -ProgressCallback {param($event);$script:networkNativeEvents.Add($event)} -ConfirmAction {
            param($preview)
            Assert-WinSecNetworkConfigurationValidationSnapshot $root $lease
            return ($request.ApprovalDateUTC -ceq [datetime]::UtcNow.ToString('yyyy-MM-dd') -and $preview.DeviceId -ceq $request.DeviceId -and
                $preview.ScopeType -ceq 'CONTROL' -and $preview.ScopeKey -ceq 'WSA-NET-005' -and $preview.ReadOnly -ceq $true -and
                $preview.Checks.Count -eq 1 -and $preview.Checks[0].CheckId -ceq 'WSA-NET-005' -and
                $preview.EvaluationProfile.Policies.Count -eq 1 -and $preview.EvaluationProfile.Profile -ceq $request.Profile -and
                $preview.EvaluationProfile.Policies[0].CatalogSha256 -ceq $request.ProfileSha256)
        }
    if($null -eq $public){throw 'Native NetworkConfiguration validation was not executed.'}
    Assert-WinSecNetworkConfigurationValidationSnapshot $root $lease
    $session=$c.Sessions[(Get-WinSecScanSessionKey $target.DeviceId $public.ScanId)].Session
    $control=@($session.ControlResults|Where-Object CheckId -CEQ WSA-NET-005)[0]
    if(@($session.ControlResults|Where-Object {$_.Status -cne 'NOT_SELECTED' -and $_.CheckId -cne 'WSA-NET-005'}).Count){throw 'Unexpected executed control.'}
    $e=$control.Evidence
    $issues=@(Get-WinSecNetworkConfigurationNativeDiagnostics $control)
    $technical=New-WinSecTechnicalReport $session WSA-NET-005 $target.Hostname $target.Hostname
    $body=ConvertTo-WinSecTechnicalMarkdown $technical
    $meta=[ordered]@{SchemaVersion='2.0.0';DeviceId=$technical.DeviceId;ScanId=$technical.ScanId;CheckId=$technical.CheckId;
        ScopeType=$technical.ScopeType;ScopeKey=$technical.ScopeKey;ContentSha256=(Get-WinSecReportTextHash $body)}
    $artifact="<!-- WinSec technical report`n"+(ConvertTo-Json $meta -Compress)+"`n-->`n"+$body
    $null=ConvertFrom-WinSecTechnicalMarkdownArtifact $artifact $target.DeviceId
    $views=Test-WinSecNativeFrameworkViews $root $session WSA-NET-005 $target.Hostname
    [pscustomobject]@{OperationId=$OperationId;Runtime=$PSVersionTable.PSVersion.ToString();ExecutionStatus=$session.ExecutionStatus;
        CollectionValidated=($null -ne $e -and $e.CollectionSuccessful -ceq $true);
        CollectionSuccessful=$e.CollectionSuccessful;CollectionComplete=$e.CollectionComplete;CollectionIssues=$issues;
        ObservedStatus=$control.ObservedStatus;ActualBuild=$e.Platform.BuildNumber;CoverageComplete=$e.CoverageComplete;
        UnknownFieldCount=$e.UnknownFieldCount;InventoryCounts=$e.Counts;
        TechnicalMarkdownValidated=$true;PublicHistoryRoundtripValidated=$views.PublicHistoryRoundtripValidated;InMemoryFrameworkReports=$views.InMemoryReports;
        ProgressEvents=$script:networkNativeEvents.Count;PublicHistoryPersisted=$false;RawEvidencePersisted=$false;ReportsPersisted=$false;
        WindowsChanges=$false;ProductionPermissionsChanged=$false}|ConvertTo-Json -Depth 5
} finally {foreach($stream in $lease.Streams){$stream.Dispose()}}
