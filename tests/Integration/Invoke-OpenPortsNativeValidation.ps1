# PlanOnly reads identity and code metadata, never OpenPorts configuration.
# Execution requires approval of this exact request, runtime and UTC date.
[CmdletBinding()]
param([switch]$PlanOnly,[string]$OperationId='',[string]$ApprovedRequestHash='',
    [string]$Profile='WSA-W11-23H2-PRO-DEF-BASE')
$ErrorActionPreference='Stop'
if(-not $OperationId){if(-not $PlanOnly){throw 'Prepare and approve a OpenPorts request first.'};$OperationId=[guid]::NewGuid().ToString('N')}
if($OperationId -cnotmatch '\A[a-f0-9]{32}\z' -or
    ($PlanOnly -and $ApprovedRequestHash) -or (-not $PlanOnly -and $ApprovedRequestHash -cnotmatch '\A[A-F0-9]{64}\z')){throw 'Invalid OpenPorts approval.'}
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'tests/Fixtures/OpenPortsNativeValidationSupport.ps1')
. (Join-Path $root 'tests/Fixtures/FrameworkNativeValidationSupport.ps1')
$lease=Open-WinSecOpenPortsValidationSnapshot $root
try {
    . (Join-Path $root 'src/Core/ScanCoordinator.ps1')
    $target=New-WinSecLocalTarget
    $profilePlan=Get-WinSecAssessmentProfilePlan $root @('WSA-NET-004') $Profile
    $request=[pscustomobject][ordered]@{
        Operation='VALIDATE_OPEN_PORTS_READ_ONLY';OperationId=$OperationId;DeviceId=$target.DeviceId;Hostname=$target.Hostname
        ScopeType='CONTROL';ScopeKey='WSA-NET-004';Checks=@('Open Ports / WSA-NET-004')
        Runtime=$PSVersionTable.PSVersion.ToString();Is64BitProcess=[Environment]::Is64BitProcess
        ProcessElevated=(Get-WinSecOpenPortsNativeElevation);ApprovalDateUTC=([datetime]::UtcNow.ToString('yyyy-MM-dd'))
        Profile=$Profile;ProfileSha256=$profilePlan.Preview.Policies[0].CatalogSha256
        DependencyManifestSha256=$lease.Sha256;DependencyCount=$lease.Files.Count
        ReadOnly=$true;PersistPublicHistory=$false;PersistRawEvidence=$false;PersistReports=$false
        Note='Only Open Ports runs in an isolated in-memory registry. Reads local Windows metadata, reviewed NetTCPIP class metadata, TCP LISTEN endpoints and UDP bindings for IPv4/IPv6. Includes all returned permitted endpoint fields within the explicit 512-per-protocol limit; overflow is partial, not silently truncated. No remote addresses, process names, command lines, users, files, sockets, DNS lookups, connections, port probes or Windows changes. Local addresses are hashed. Technical Markdown, public-history roundtrip and three framework reports are checked in memory. No production permissions change or result persistence.'
    }
    $hash=Get-WinSecOpenPortsValidationHash (ConvertTo-Json $request -Depth 6 -Compress)
    Assert-WinSecOpenPortsValidationSnapshot $root $lease
    if($PlanOnly){[pscustomobject]@{Request=$request;RequestHash=$hash}|ConvertTo-Json -Depth 8;return}
    if($hash -cne $ApprovedRequestHash){throw 'OpenPorts request changed or was not approved.'}
    $reader=(Get-Command Get-WinSecCheckRegistry -CommandType Function).ScriptBlock
    function Get-WinSecCheckRegistry {
        param($ProjectRoot)
        $registry=& $reader -ProjectRoot $ProjectRoot
        foreach($check in $registry.Checks) {
            $check.ExecutionEnabled=($check.CheckId -ceq 'WSA-NET-004')
            if($check.CheckId -ceq 'WSA-NET-004'){$check.ExecutionReady=$true;$check.ImplementationStatus='VALIDATED';$check.RegistryStatus='READY'}
        }
        return $registry
    }
    function Save-WinSecPublicHistory {throw 'Native OpenPorts validation prohibits writes.'}
    function Save-WinSecEvidence {throw 'Native OpenPorts validation prohibits writes.'}
    function Save-WinSecTechnicalReports {throw 'Native OpenPorts validation prohibits writes.'}
    function Write-WinSecTechnicalArtifact {throw 'Native OpenPorts validation prohibits writes.'}
    function Export-WinSecFrameworkAnalysis {throw 'Native OpenPorts validation prohibits writes.'}
    $c=New-WinSecScanCoordinator -ProjectRoot $root
    $c.Registry=[pscustomobject]@{schemaVersion='1.0.0';targets=@($target)};$c.AssessmentEnabled=$true
    if($c.PublicHistoryEnabled -or $c.AutomaticEvidencePersistence -or $c.TechnicalReportsEnabled -or $c.RequireDeviceInventory){throw 'Persistent native validation is prohibited.'}
    $script:portsNativeEvents=New-Object 'Collections.Generic.List[object]'
    $public=Invoke-WinSecCoordinatedScan -Coordinator $c -DeviceId $target.DeviceId -ScanId ('native-ports-'+$OperationId) `
        -ScopeType CONTROL -ScopeKey WSA-NET-004 -AssessmentProfile $Profile -ProgressCallback {param($event);$script:portsNativeEvents.Add($event)} -ConfirmAction {
            param($preview)
            Assert-WinSecOpenPortsValidationSnapshot $root $lease
            return ($request.ApprovalDateUTC -ceq [datetime]::UtcNow.ToString('yyyy-MM-dd') -and $preview.DeviceId -ceq $request.DeviceId -and
                $preview.ScopeType -ceq 'CONTROL' -and $preview.ScopeKey -ceq 'WSA-NET-004' -and $preview.ReadOnly -ceq $true -and
                $preview.Checks.Count -eq 1 -and $preview.Checks[0].CheckId -ceq 'WSA-NET-004' -and
                $preview.EvaluationProfile.Policies.Count -eq 1 -and $preview.EvaluationProfile.Profile -ceq $request.Profile -and
                $preview.EvaluationProfile.Policies[0].CatalogSha256 -ceq $request.ProfileSha256)
        }
    if($null -eq $public){throw 'Native OpenPorts validation was not executed.'}
    Assert-WinSecOpenPortsValidationSnapshot $root $lease
    $session=$c.Sessions[(Get-WinSecScanSessionKey $target.DeviceId $public.ScanId)].Session
    $control=@($session.ControlResults|Where-Object CheckId -CEQ WSA-NET-004)[0]
    if(@($session.ControlResults|Where-Object {$_.Status -cne 'NOT_SELECTED' -and $_.CheckId -cne 'WSA-NET-004'}).Count){throw 'Unexpected executed control.'}
    $e=$control.Evidence
    $issues=@(Get-WinSecOpenPortsNativeDiagnostics $control)
    $technical=New-WinSecTechnicalReport $session WSA-NET-004 $target.Hostname $target.Hostname
    $body=ConvertTo-WinSecTechnicalMarkdown $technical
    $meta=[ordered]@{SchemaVersion='2.0.0';DeviceId=$technical.DeviceId;ScanId=$technical.ScanId;CheckId=$technical.CheckId;
        ScopeType=$technical.ScopeType;ScopeKey=$technical.ScopeKey;ContentSha256=(Get-WinSecReportTextHash $body)}
    $artifact="<!-- WinSec technical report`n"+(ConvertTo-Json $meta -Compress)+"`n-->`n"+$body
    $null=ConvertFrom-WinSecTechnicalMarkdownArtifact $artifact $target.DeviceId
    $views=Test-WinSecNativeFrameworkViews $root $session WSA-NET-004 $target.Hostname
    [pscustomobject]@{OperationId=$OperationId;Runtime=$PSVersionTable.PSVersion.ToString();ExecutionStatus=$session.ExecutionStatus;
        CollectionValidated=($null -ne $e -and $e.CollectionSuccessful -ceq $true);
        CollectionSuccessful=$e.CollectionSuccessful;CollectionComplete=$e.CollectionComplete;CollectionIssues=$issues;
        ObservedStatus=$control.ObservedStatus;ActualBuild=$e.Platform.BuildNumber;CoverageComplete=$e.CoverageComplete;
        UnknownFieldCount=$e.UnknownFieldCount;TcpEndpointCount=$e.Counts.TCP.Total;UdpEndpointCount=$e.Counts.UDP.Total;
        TechnicalMarkdownValidated=$true;PublicHistoryRoundtripValidated=$views.PublicHistoryRoundtripValidated;InMemoryFrameworkReports=$views.InMemoryReports;
        ProgressEvents=$script:portsNativeEvents.Count;PublicHistoryPersisted=$false;RawEvidencePersisted=$false;ReportsPersisted=$false;
        WindowsChanges=$false;ProductionPermissionsChanged=$false}|ConvertTo-Json -Depth 5
} finally {foreach($stream in $lease.Streams){$stream.Dispose()}}
