# Coordinador/AuditEngine/recolector reales, proveedores y persistencia simulados.
# El permiso de BitLocker existe sólo en una copia del catálogo en memoria.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
foreach($file in @('src/CLI/Invoke-WinSecCLI.ps1','src/UI/Core/NavigationController.ps1','src/UI/Core/TerminalRenderer.ps1',
    'src/UI/Core/LayoutManager.ps1','src/UI/Components/Table.ps1','src/UI/Components/Banner.ps1','src/UI/Components/KeyboardHelp.ps1',
    'src/UI/Screens/MainMenu.ps1','src/UI/Screens/Results.ps1','src/UI/Screens/Findings.ps1',
    'src/Services/FrameworkService.ps1','src/Core/FrameworkMappingEngine.ps1','src/Services/ReportService.ps1')){. (Join-Path $root $file)}
$script:production=Get-WinSecCheckRegistry -ProjectRoot $root
$catalogPath=Join-Path $root 'config/checks.json'
$scoringPath=Join-Path $root 'config/scoring.json'
$catalogHash=(Get-FileHash $catalogPath -Algorithm SHA256).Hash
$scoringHash=(Get-FileHash $scoringPath -Algorithm SHA256).Hash
$script:passed=0;$script:failed=0
function Assert-WinSecBitLockerIntegration {param([bool]$Condition);if(-not $Condition){throw 'BitLocker integration assertion failed.'}}
function Get-CimInstance {
    [CmdletBinding()]param($Namespace,$ClassName,$Property,$Filter,$OperationTimeoutSec)
    if($ClassName -ceq 'Win32_ComputerSystemProduct') {
        Assert-WinSecBitLockerIntegration ($Namespace -ceq 'root/cimv2')
        return [pscustomobject]@{UUID='12345678-1234-4567-89ab-123456789abc'}
    }
    $script:queries++
    if($ClassName -ceq 'Win32_OperatingSystem') {
        Assert-WinSecBitLockerIntegration ($Namespace -ceq 'root/cimv2' -and $OperationTimeoutSec -eq 10)
        if(($Property -join ',') -ceq 'SystemDrive'){return [pscustomobject]@{SystemDrive='D:'}}
        Assert-WinSecBitLockerIntegration (($Property -join ',') -ceq 'Caption,Version,BuildNumber,OperatingSystemSKU,ProductType')
        return [pscustomobject]@{Caption='Microsoft Windows 11';Version=$script:osVersion;BuildNumber=$script:osVersion.Split('.')[2];OperatingSystemSKU=$script:sku;ProductType=1}
    }
    Assert-WinSecBitLockerIntegration ($Namespace -ceq 'root/cimv2/Security/MicrosoftVolumeEncryption' -and
        $ClassName -ceq 'Win32_EncryptableVolume' -and $Filter -ceq "DriveLetter = 'D:'" -and $OperationTimeoutSec -eq 10)
    if($script:providerFails){throw 'PRIVATE-BITLOCKER-INTEGRATION'}
    if($script:providerDenied){throw [System.UnauthorizedAccessException]::new('PRIVATE-BITLOCKER-INTEGRATION')}
    [pscustomobject]@{DeviceID='\\?\Volume{12345678-1234-4567-89ab-123456789abc}\';DriveLetter='D:';VolumeType=[uint32]0}
}
function Invoke-CimMethod {
    [CmdletBinding()]param($InputObject,$MethodName,$OperationTimeoutSec)
    Assert-WinSecBitLockerIntegration ($InputObject.DriveLetter -ceq 'D:' -and $OperationTimeoutSec -eq 10)
    $script:methodCalls++
    switch -CaseSensitive ($MethodName) {
        GetProtectionStatus {[pscustomobject]@{ReturnValue=0;ProtectionStatus=$script:protection;RecoveryPassword='PRIVATE-BITLOCKER-INTEGRATION'}}
        GetConversionStatus {[pscustomobject]@{ReturnValue=0;ConversionStatus=$script:conversion;EncryptionPercentage=100}}
        GetEncryptionMethod {[pscustomobject]@{ReturnValue=0;EncryptionMethod=6}}
        GetLockStatus {[pscustomobject]@{ReturnValue=0;LockStatus=0}}
        default {throw 'Forbidden method in BitLocker integration.'}
    }
}
function Get-WinSecCheckRegistry {
    param($ProjectRoot)
    $copy=Copy-WinSecResultData $script:production
    foreach($check in $copy.Checks){$check.ExecutionEnabled=$false;$check.ExecutionReady=$false}
    if($script:ready) {
        $check=@($copy.Checks|Where-Object CheckId -CEQ 'WSA-SYS-002')[0]
        $check.ExecutionEnabled=$true;$check.ExecutionReady=$true;$check.ImplementationStatus='VALIDATED';$check.RegistryStatus='READY'
    }
    $copy
}
function Import-WinSecDeviceInventory {param($ProjectRoot);[pscustomobject]@{schemaVersion='1.2.0';targets=@(New-WinSecLocalTarget);removedDeviceHashes=@()}}
function Save-WinSecPublicHistory {
    param($ProjectRoot,$Session)
    if(-not $script:saveAllowed){throw 'Unexpected native history persistence.'}
    $script:saved=New-WinSecPublicHistoryRecord $Session
}
function Save-WinSecCoordinatedEvidence {throw 'Unexpected native evidence persistence.'}
function Get-WinSecTerminalSize {$script:terminal}
function Clear-WinSecScreen {$script:lines.Clear();$null=$script:fragment.Clear()}
function Write-Host {
    param([object[]]$Object,[switch]$NoNewline,$ForegroundColor,$BackgroundColor,[string]$Separator=' ')
    $null=$script:fragment.Append(($Object -join $Separator))
    if(-not $NoNewline){$script:lines.Add($script:fragment.ToString());$null=$script:fragment.Clear()}
}
function Test-WinSecBitLockerIntegrationCase {
    param([string]$Name,[scriptblock]$Action)
    $script:queries=0;$script:methodCalls=0;$script:confirmations=0;$script:ready=$true;$script:providerFails=$false
    $script:providerDenied=$false
    $script:conversion=2;$script:protection=0;$script:osVersion='10.0.26100';$script:sku=48;$script:saveAllowed=$false;$script:saved=$null
    $script:terminal=[pscustomobject]@{Width=120;ContentWidth=119;Height=55}
    $script:lines=New-Object 'System.Collections.Generic.List[string]';$script:fragment=New-Object Text.StringBuilder
    $script:coordinator=New-WinSecScanCoordinator -ProjectRoot $root
    $script:target=New-WinSecLocalTarget
    $script:coordinator.Registry=[pscustomobject]@{schemaVersion='1.0.0';targets=@($script:target)}
    try{$null=& $Action;$script:passed++;[Console]::WriteLine('[PASS] '+$Name)}
    catch{$script:failed++;[Console]::WriteLine('[FAIL] '+$Name+' : '+$_.Exception.Message);[Console]::WriteLine($_.ScriptStackTrace)}
}
$confirm={
    param($request)
    $script:confirmations++
    Assert-WinSecBitLockerIntegration ($request.DeviceId -ceq $script:target.DeviceId -and $request.ReadOnly -ceq $true -and
        $request.Checks.Count -eq 1 -and $request.Checks[0].CheckId -ceq 'WSA-SYS-002')
    $true
}
Test-WinSecBitLockerIntegrationCase 'Production BitLocker remains disabled and unvalidated' {
    $check=@($script:production.Checks|Where-Object CheckId -CEQ 'WSA-SYS-002')[0]
    Assert-WinSecBitLockerIntegration (-not $check.ExecutionEnabled -and -not $check.ExecutionReady -and $check.ImplementationStatus -ceq 'PENDING_VALIDATION')
}
Test-WinSecBitLockerIntegrationCase 'Initialization does not collect OS volume telemetry' {
    Assert-WinSecBitLockerIntegration ($script:queries -eq 0 -and $script:methodCalls -eq 0 -and $script:coordinator.Sessions.Count -eq 0)
}
Test-WinSecBitLockerIntegrationCase 'Cancellation before collection never publishes a session' {
    $r=Invoke-WinSecCoordinatedScan -Coordinator $script:coordinator -ScopeType CONTROL -ScopeKey WSA-SYS-002 -ConfirmAction {$false}
    Assert-WinSecBitLockerIntegration ($null -eq $r -and $script:queries -eq 0 -and $script:methodCalls -eq 0 -and $script:coordinator.Sessions.Count -eq 0)
}
Test-WinSecBitLockerIntegrationCase 'A disabled fixture cannot reach confirmation or collection' {
    $script:ready=$false;$caught=$false
    try{$null=Invoke-WinSecCoordinatedScan -Coordinator $script:coordinator -ScopeType CONTROL -ScopeKey WSA-SYS-002 -ConfirmAction $confirm}catch{$caught=$true}
    Assert-WinSecBitLockerIntegration ($caught -and $script:confirmations -eq 0 -and $script:queries -eq 0 -and $script:methodCalls -eq 0)
}
Test-WinSecBitLockerIntegrationCase 'Confirmed collection reaches AuditEngine and ResultModel without manufacturing findings or a score' {
    $public=Invoke-WinSecCoordinatedScan -Coordinator $script:coordinator -ScopeType CONTROL -ScopeKey WSA-SYS-002 -ConfirmAction $confirm
    $session=Get-WinSecCoordinatorSession $script:coordinator $public.DeviceId $public.ScanId
    $control=@($session.ControlResults|Where-Object CheckId -CEQ 'WSA-SYS-002')[0]
    Assert-WinSecBitLockerIntegration ($script:confirmations -eq 1 -and $script:queries -eq 2 -and $script:methodCalls -eq 4 -and
        $public.ScopeType -ceq 'CONTROL' -and $public.ScopeKey -ceq 'WSA-SYS-002' -and $control.ObservedStatus -ceq 'INFORMATIONAL' -and
        $control.Evidence.SystemVolume.DriveLetter -ceq 'D:' -and $control.Evidence.SystemVolume.ProtectionStatus -ceq 'OFF' -and
        $control.Evidence.SystemVolume.ConversionStatus -ceq 'ENCRYPTION_IN_PROGRESS' -and $control.Evidence.SystemVolume.EncryptionPercentage -eq 100 -and
        $null -eq $public.OverallScore -and $public.OverallStatus -ceq 'NOT_SCORED' -and $public.Findings.Count -eq 0)
    Assert-WinSecBitLockerIntegration ((ConvertTo-Json $public -Depth 24 -Compress) -notmatch 'PRIVATE-BITLOCKER|"Evidence"|"SystemVolume"|"DriveLetter"|"RecoveryPassword"')
    # Compatibilidad histórica pública, exclusivamente en memoria.
    $record=New-WinSecPublicHistoryRecord $session
    $json=Get-WinSecPublicHistoryJson $record
    $restored=ConvertFrom-WinSecPublicHistoryRecord (ConvertFrom-WinSecStoredJson $json)
    # Los metadatos transitorios de almacenamiento del coordinador no son historial.
    $expectedPublic=ConvertTo-WinSecPublicScanResult $session
    Assert-WinSecBitLockerIntegration ($restored.Record.DeviceId -ceq $public.DeviceId -and $restored.Record.ScanId -ceq $public.ScanId -and
        $restored.Record.ScopeKey -ceq 'WSA-SYS-002' -and (Get-WinSecPublicHistoryJson $restored.PublicResult) -ceq (Get-WinSecPublicHistoryJson $expectedPublic) -and
        $json -notmatch 'PRIVATE-BITLOCKER|"Evidence"|"SystemVolume"|"DriveLetter"')
}
Test-WinSecBitLockerIntegrationCase 'Provider failures stay technical and do not leak exception or recovery data' {
    $script:providerFails=$true
    $public=Invoke-WinSecCoordinatedScan -Coordinator $script:coordinator -ScopeType CONTROL -ScopeKey WSA-SYS-002 -ConfirmAction $confirm
    $session=Get-WinSecCoordinatorSession $script:coordinator $public.DeviceId $public.ScanId
    $control=@($session.ControlResults|Where-Object CheckId -CEQ 'WSA-SYS-002')[0]
    Assert-WinSecBitLockerIntegration ($control.ObservedStatus -ceq 'ERROR' -and -not $control.Evidence.CollectionSuccessful -and
        $script:methodCalls -eq 0 -and $null -eq $public.OverallScore -and $public.Findings.Count -eq 0 -and
        (ConvertTo-Json $public -Depth 24 -Compress) -notmatch 'PRIVATE-BITLOCKER')
}
Test-WinSecBitLockerIntegrationCase 'Access denial stays a typed internal collection error and does not become a false failure or public raw data' {
    $script:coordinator.AssessmentEnabled=$true;$script:providerDenied=$true
    $public=Invoke-WinSecCoordinatedScan -Coordinator $script:coordinator -ScopeType CONTROL -ScopeKey WSA-SYS-002 `
        -AssessmentProfile WSA-W11-24H2-PRO-DEF-BASE -ConfirmAction $confirm
    $session=Get-WinSecCoordinatorSession $script:coordinator $public.DeviceId $public.ScanId
    $control=@($session.ControlResults|Where-Object CheckId -CEQ 'WSA-SYS-002')[0]
    $record=New-WinSecPublicHistoryRecord $session
    $restored=ConvertFrom-WinSecPublicHistoryRecord (ConvertFrom-WinSecStoredJson (Get-WinSecPublicHistoryJson $record))
    Assert-WinSecBitLockerIntegration ($control.Evidence.CollectionIssues -ccontains 'BITLOCKER_PROVIDER_ACCESS_DENIED' -and
        $control.ErrorMessage -match 'administrator permissions' -and $null -eq $public.ConfigurationAssessment.Controls[0].Value -and
        @($public.Findings|Where-Object Kind -CEQ CONFIGURATION_DEVIATION).Count -eq 0 -and $public.ReviewItems.Count -eq 0 -and
        $script:methodCalls -eq 0 -and $restored.PublicResult.ScanId -ceq $public.ScanId -and
        (Get-WinSecPublicHistoryJson $record) -notmatch 'PRIVATE|Exception|HResult|CollectionIssues|BITLOCKER_PROVIDER_ACCESS_DENIED|administrator permissions')
}
Test-WinSecBitLockerIntegrationCase 'Cancellation after collection preserves the previous session and publishes no replacement' {
    $first=Invoke-WinSecCoordinatedScan -Coordinator $script:coordinator -ScopeType CONTROL -ScopeKey WSA-SYS-002 -ConfirmAction $confirm
    $sessionCount=$script:coordinator.Sessions.Count;$before=$script:methodCalls
    $result=Invoke-WinSecCoordinatedScan -Coordinator $script:coordinator -ScopeType CONTROL -ScopeKey WSA-SYS-002 -ConfirmAction $confirm `
        -CancellationAction {$script:methodCalls -gt $before}
    Assert-WinSecBitLockerIntegration ($null -eq $result -and $script:coordinator.Sessions.Count -eq $sessionCount -and
        $null -ne (Get-WinSecCoordinatorSession $script:coordinator $first.DeviceId $first.ScanId))
}
Test-WinSecBitLockerIntegrationCase 'Foreign hardware is rejected before confirmation or volume queries' {
    $caught=$false
    try{$null=Invoke-WinSecCoordinatedScan -Coordinator $script:coordinator -DeviceId ('local:hw1-'+('b'*64)) `
        -ScopeType CONTROL -ScopeKey WSA-SYS-002 -ConfirmAction $confirm}catch{$caught=$true}
    Assert-WinSecBitLockerIntegration ($caught -and $script:confirmations -eq 0 -and $script:queries -eq 0 -and $script:methodCalls -eq 0)
}
foreach($spec in @(@{P='WSA-W11-24H2-PRO-DEF-BASE';V='10.0.26100';S=48;C=1;Protection=1;Value=100;Failures=0},
    @{P='WSA-W11-25H2-ENT-DEF-BASE';V='10.0.26200';S=4;C=1;Protection=0;Value=50;Failures=1},
    @{P='WSA-W11-21H2-HOME-DEF-BASE';V='10.0.22000';S=101;C=0;Protection=0;Value=0;Failures=2})) {
    Test-WinSecBitLockerIntegrationCase ('Approved confirmed pipeline produces '+$spec.Value+' on '+$spec.P) {
        $script:coordinator.AssessmentEnabled=$true;$script:conversion=$spec.C;$script:protection=$spec.Protection
        $script:osVersion=$spec.V;$script:sku=$spec.S
        $public=Invoke-WinSecCoordinatedScan -Coordinator $script:coordinator -ScopeType CONTROL -ScopeKey WSA-SYS-002 -AssessmentProfile $spec.P -ConfirmAction $confirm
        Assert-WinSecBitLockerIntegration ($public.ConfigurationAssessment.Controls[0].Value -eq $spec.Value -and
            $public.ConfigurationAssessment.Controls[0].Criteria.Count -eq 2 -and $public.Findings.Count -eq $spec.Failures -and
            $script:confirmations -eq 1 -and $script:methodCalls -eq 4 -and $null -eq $public.OverallScore -and
            $public.ConfigurationAssessment.Controls[0].Criteria[0].Profile -ceq $spec.P)
    }
}
foreach($conversion in 2..5) {
    Test-WinSecBitLockerIntegrationCase 'A transitional or paused volume at 100 percent has no numeric score or configuration failures' {
        $script:coordinator.AssessmentEnabled=$true;$script:conversion=$conversion
        $public=Invoke-WinSecCoordinatedScan -Coordinator $script:coordinator -ScopeType CONTROL -ScopeKey WSA-SYS-002 `
            -AssessmentProfile WSA-W11-24H2-PRO-DEF-BASE -ConfirmAction $confirm
        Assert-WinSecBitLockerIntegration ($null -eq $public.ConfigurationAssessment.Controls[0].Value -and
            @($public.Findings|Where-Object Kind -CEQ CONFIGURATION_DEVIATION).Count -eq 0)
    }
}
Test-WinSecBitLockerIntegrationCase 'Unknown protection and mismatched Windows version never manufacture a zero or full score' {
    foreach($fault in @('UnknownProtection','WrongVersion','ProviderError')) {
        $script:coordinator.AssessmentEnabled=$true;$script:conversion=1;$script:protection=1
        $script:osVersion='10.0.26100';$script:providerFails=$false
        switch($fault){UnknownProtection {$script:protection=2};WrongVersion {$script:osVersion='10.0.22631'};ProviderError {$script:providerFails=$true}}
        $public=Invoke-WinSecCoordinatedScan -Coordinator $script:coordinator -ScopeType CONTROL -ScopeKey WSA-SYS-002 `
            -AssessmentProfile WSA-W11-24H2-PRO-DEF-BASE -ConfirmAction $confirm
        Assert-WinSecBitLockerIntegration ($null -eq $public.ConfigurationAssessment.Controls[0].Value -and
            @($public.Findings|Where-Object Kind -CEQ CONFIGURATION_DEVIATION).Count -eq 0)
    }
}
Test-WinSecBitLockerIntegrationCase 'Approved findings and score survive public history and re-export with no raw volume data or reevaluation' {
    $script:coordinator.AssessmentEnabled=$true;$script:coordinator.PublicHistoryEnabled=$true;$script:saveAllowed=$true;$script:conversion=1
    $public=Invoke-WinSecCoordinatedScan -Coordinator $script:coordinator -ScopeType CONTROL -ScopeKey WSA-SYS-002 `
        -AssessmentProfile WSA-W11-24H2-PRO-DEF-BASE -ConfirmAction $confirm
    $json=Get-WinSecPublicHistoryJson $script:saved
    $restored=ConvertFrom-WinSecPublicHistoryRecord (ConvertFrom-WinSecStoredJson $json)
    $canonical=ConvertTo-WinSecPublicScanResult (Get-WinSecCoordinatorSession $script:coordinator $public.DeviceId $public.ScanId)
    Assert-WinSecBitLockerIntegration ((Get-WinSecPublicHistoryJson $restored.PublicResult) -ceq (Get-WinSecPublicHistoryJson $canonical) -and
        $json -notmatch 'PRIVATE-BITLOCKER|"Evidence"|"SystemVolume"|"DriveLetter"|"EncryptionPercentage"')
    $key='{0}:{1}{2}:{3}' -f $public.DeviceId.Length,$public.DeviceId,$public.ScanId.Length,$public.ScanId
    $ctx=[pscustomobject]@{ProjectRoot=$root;Version='0.9.0';Devices=@($script:target);PublicScans=@{$key=$restored.PublicResult};
        ActiveScanByDevice=@{};ActiveScanByScope=@{(Get-WinSecCLIScopeKey $public.DeviceId CONTROL WSA-SYS-002)=$public.ScanId}}
    $state=New-WinSecNavigationState;$state.Screen='Findings';$state.FindingsScope='Control';$state.SelectedDeviceId=$public.DeviceId;$state.ControlIndex=1
    $queries=$script:queries;$calls=$script:methodCalls;$before=Get-WinSecPublicHistoryJson $restored.PublicResult
    foreach($size in @(@(120,55),@(80,26),@(40,20))) {
        $script:terminal=[pscustomobject]@{Width=$size[0];ContentWidth=$size[0]-1;Height=$size[1]}
        Show-WinSecCLICurrentScreen $state $ctx
        Assert-WinSecBitLockerIntegration ($script:lines.Count -le $size[1] -and
            @($script:lines|Where-Object {$_.Length -ge $size[0]}).Count -eq 0 -and ($script:lines -join '|') -notmatch 'PRIVATE-BITLOCKER')
        if($size[0] -eq 120){Assert-WinSecBitLockerIntegration (($script:lines -join '|').Contains('50/100') -and
            ($script:lines -join '|').Contains('PASS') -and ($script:lines -join '|').Contains('FAIL'))}
    }
    $selection=Get-WinSecCLIFindingsExportSelection $state $ctx
    $view=Get-WinSecSelectedFindings -NavigationState $state -ControlResults $restored.PublicResult.ControlResults `
        -Findings $restored.PublicResult.Findings -ReviewItems $restored.PublicResult.ReviewItems -ScanId $public.ScanId `
        -ConfigurationAssessment $restored.PublicResult.ConfigurationAssessment
    Assert-WinSecBitLockerIntegration ($selection.ReviewItems.Count -eq 3 -and $view.CheckRows.Count -eq 2 -and $view.Rows.Count -eq 5 -and
        @($view.Rows|Where-Object {$_.Kind -ceq 'REVIEW_ONLY' -and $_.ConfigurationPercent -ceq 'N/A'}).Count -eq 3 -and
        @($view.Rows|Where-Object {$_.Finding -ceq 'Volume lock state: UNLOCKED'}).Count -eq 1)
    foreach($framework in @('cis-controls','nist-csf','mitre-attack')) {
        $report=New-WinSecFindingsMarkdown $selection -FrameworkId $framework
        Assert-WinSecBitLockerIntegration ($report.Markdown.Contains('50/100') -and $report.Markdown.Contains('WSA\-BLK\-BASE\-001') -and
            $report.Markdown.Contains('WSA\-BLK\-BASE\-002') -and $report.Markdown.Contains('PASS') -and $report.Markdown.Contains('FAIL') -and
            $report.Markdown.Contains('Manual recommendation:') -and -not $report.Markdown.Contains('PENDING: no validated mapping') -and
            $report.Markdown.Contains('BitLocker observations') -and $report.Markdown.Contains('XTS\_AES\_128') -and
            $report.Markdown.Contains('REVIEW\_ONLY') -and $report.Markdown.Contains('XTS-AES-128 is not automatically a failure') -and
            $report.Markdown -notmatch 'PRIVATE-BITLOCKER|"Evidence"|"SystemVolume"|"DriveLetter"|ASR scoring|"RecoveryPassword"')
        $expectedRef=switch($framework){'cis-controls' {'3\.6'};'nist-csf' {'PR\.DS\-01'};default {'M1041'}}
        Assert-WinSecBitLockerIntegration ($report.Markdown.Contains($expectedRef))
        if($null -ne (Get-Command ConvertFrom-Markdown -CommandType Cmdlet -ErrorAction SilentlyContinue)) {
            $html=(ConvertFrom-Markdown -InputObject $report.Markdown).Html
            $tables=[regex]::Matches($html,'<table>[\s\S]*?</table>')
            Assert-WinSecBitLockerIntegration ($tables.Count -eq 3 -and [regex]::Matches($tables[0].Value,'<tr>').Count -eq 3 -and
                [regex]::Matches($tables[2].Value,'<tr>').Count -eq 4)
        }
    }
    Assert-WinSecBitLockerIntegration ($script:queries -eq $queries -and $script:methodCalls -eq $calls -and
        $before -ceq (Get-WinSecPublicHistoryJson $restored.PublicResult))
}
Test-WinSecBitLockerIntegrationCase 'Collection-only observations export without a profile, false deviations or a configuration score' {
    $public=Invoke-WinSecCoordinatedScan -Coordinator $script:coordinator -ScopeType CONTROL -ScopeKey WSA-SYS-002 -ConfirmAction $confirm
    $selection=[pscustomobject]@{DeviceId=$public.DeviceId;ScanId=$public.ScanId;SourceScopeType='CONTROL';SourceScopeKey='WSA-SYS-002';
        ScopeType='CONTROL';ScopeKey='WSA-SYS-002';CatalogVersion=$public.CatalogVersion;Findings=@();ReviewItems=$public.ReviewItems}
    $before=Get-WinSecPublicHistoryJson $public;$queries=$script:queries;$calls=$script:methodCalls
    $report=New-WinSecFindingsMarkdown $selection -FrameworkId nist-csf
    Assert-WinSecBitLockerIntegration ($selection.ReviewItems.Count -eq 3 -and $public.Findings.Count -eq 0 -and
        $report.Markdown.Contains('Score: NOT_SCORED') -and $report.Markdown.Contains('BitLocker observations') -and
        $report.Markdown.Contains('PR\.DS\-01') -and $report.Markdown.Contains('Native encryption progress: 100%') -and
        -not $report.Markdown.Contains('Configuration selection score:') -and -not $report.Markdown.Contains('MISCONFIGURED') -and
        $script:queries -eq $queries -and $script:methodCalls -eq $calls -and $before -ceq (Get-WinSecPublicHistoryJson $public))
    $selection.ReviewItems+=@($selection.ReviewItems[0]);$caught=$false
    try{$null=New-WinSecFindingsMarkdown $selection -FrameworkId nist-csf}catch{$caught=$true}
    Assert-WinSecBitLockerIntegration $caught
}
Test-WinSecBitLockerIntegrationCase 'Cancelling an approved profile never queries Windows applicability or the volume' {
    $script:coordinator.AssessmentEnabled=$true
    $r=Invoke-WinSecCoordinatedScan -Coordinator $script:coordinator -ScopeType CONTROL -ScopeKey WSA-SYS-002 `
        -AssessmentProfile WSA-W11-24H2-PRO-DEF-BASE -ConfirmAction {$false}
    Assert-WinSecBitLockerIntegration ($null -eq $r -and $script:queries -eq 0 -and $script:methodCalls -eq 0 -and $null -eq $script:saved)
}
Test-WinSecBitLockerIntegrationCase 'A changed BitLocker criteria fingerprint during confirmation aborts before collection' {
    $script:coordinator.AssessmentEnabled=$true;$script:changeBitLockerHash=$false
    $script:bitLockerReader=(Get-Command Get-WinSecBitLockerCriteriaTemplate).ScriptBlock
    function Get-WinSecBitLockerCriteriaTemplate {
        param($ProjectRoot)
        $r=& $script:bitLockerReader $ProjectRoot
        if($script:changeBitLockerHash){$r.Sha256='E'*64}
        $r
    }
    $caught=$false
    try {
        try{$null=Invoke-WinSecCoordinatedScan -Coordinator $script:coordinator -ScopeType CONTROL -ScopeKey WSA-SYS-002 `
            -AssessmentProfile WSA-W11-24H2-PRO-DEF-BASE -ConfirmAction {$script:changeBitLockerHash=$true;$true}}catch{$caught=$true}
    } finally {Set-Item -LiteralPath Function:Get-WinSecBitLockerCriteriaTemplate -Value $script:bitLockerReader}
    Assert-WinSecBitLockerIntegration ($caught -and $script:queries -eq 0 -and $script:methodCalls -eq 0 -and $script:coordinator.Sessions.Count -eq 0)
}
Assert-WinSecBitLockerIntegration ($catalogHash -ceq (Get-FileHash $catalogPath -Algorithm SHA256).Hash -and
    $scoringHash -ceq (Get-FileHash $scoringPath -Algorithm SHA256).Hash)
[Console]::WriteLine(('BitLocker coordinator integration: {0} passed, {1} failed.' -f $script:passed,$script:failed))
if($script:failed){throw 'BitLocker integration tests failed.'}
