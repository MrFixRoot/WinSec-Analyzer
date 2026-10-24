# Read-only collector tests; providers and identity are synthetic.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$path=Join-Path $root 'src/Checks/System/Test-WindowsUpdate.ps1'
$script:passed=0;$script:failed=0
. (Join-Path $root 'tests/Fixtures/WindowsUpdateMemory.ps1')
Reset-WinSecWindowsUpdateFixture
. $path
$importReads=$script:WU.IdentityReads+$script:WU.CimReads+$script:WU.KeyReads+$script:WU.VersionReads+$script:WU.RebootReads
$realKeyReader=(Get-Command Open-WinSecWindowsUpdatePolicyKey).ScriptBlock
$realVersionReader=(Get-Command Open-WinSecWindowsUpdateVersionKey).ScriptBlock
$realRebootReader=(Get-Command Get-WinSecWindowsUpdateRebootRequired).ScriptBlock
# Replace the native registry opener after importing the collector.
. (Join-Path $root 'tests/Fixtures/WindowsUpdateMemory.ps1')
function Assert-WinSecWindowsUpdate {param([bool]$Value);if(-not $Value){throw 'Windows Update assertion failed.'}}
function Assert-WinSecWindowsUpdateThrows {
    param([scriptblock]$Action)
    $caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-WinSecWindowsUpdate $caught
}
function Invoke-WinSecWindowsUpdateFixture {Test-WinSecWindowsUpdate -DeviceId $script:WU.DeviceId -ScanId 'wu-unit-1' -CheckId WSA-SYS-003}
function Test-WinSecWindowsUpdateCase {
    param([string]$Name,[scriptblock]$Action)
    Reset-WinSecWindowsUpdateFixture
    try{$null=& $Action;$script:passed++;[Console]::WriteLine('[PASS] '+$Name)}
    catch{$script:failed++;[Console]::WriteLine('[FAIL] '+$Name+' : '+$_.Exception.Message);[Console]::WriteLine($_.ScriptStackTrace)}
}
Test-WinSecWindowsUpdateCase 'Import has no identity, CIM or registry side effects' {Assert-WinSecWindowsUpdate ($importReads -eq 0)}
Test-WinSecWindowsUpdateCase 'Only allowlisted local metadata, update service, policies, revision and reboot state are collected' {
    $results=@(Invoke-WinSecWindowsUpdateFixture);$r=$results[0];$e=$r.Evidence
    Assert-WinSecWindowsUpdate ($results.Count -eq 1 -and $r.CheckId -ceq 'WSA-SYS-003' -and $r.DeviceId -ceq $script:WU.DeviceId -and
        $r.ScanId -ceq 'wu-unit-1' -and $r.SectionKey -ceq 'SystemSecurity' -and $r.Status -ceq 'INFORMATIONAL' -and
        $e.SchemaVersion -ceq '1.1.0' -and $e.Scope -ceq 'LOCAL_CONFIGURATION_ONLY' -and $e.CollectionSuccessful -and $e.CollectionComplete -and
        $e.DeviceId -ceq $r.DeviceId -and $e.ScanId -ceq $r.ScanId -and $e.CheckId -ceq $r.CheckId -and
        $e.CollectedAtUTC -ceq $r.TimestampUTC -and $e.Platform.BuildNumber -ceq '26100' -and $e.Platform.OperatingSystemSKU -eq 48 -and
        $script:WU.IdentityReads -eq 1 -and $script:WU.CimReads -eq 2 -and $script:WU.KeyReads -eq 2 -and
        $script:WU.ValueReads.Count -eq 8 -and $script:WU.Closed.Count -eq 2 -and
        $script:WU.VersionReads -eq 1 -and ($script:WU.VersionValueReads -join ',') -ceq 'CurrentBuildNumber,UBR' -and
        $script:WU.VersionClosed -eq 1 -and $script:WU.RebootReads -eq 1 -and
        $e.VersionRegistry.UBR.State -ceq 'OBSERVED' -and $e.VersionRegistry.UBR.Value -eq 9711 -and
        $e.RestartInformation.State -ceq 'OBSERVED' -and $e.RestartInformation.Value -is [bool] -and -not $e.RestartInformation.Value)
    Assert-WinSecWindowsUpdate ([datetime]::Parse($r.TimestampUTC).ToUniversalTime() -gt [datetime]::UtcNow.AddMinutes(-1))
    Assert-WinSecWindowsUpdate (-not $e.ScoringEligible -and -not $e.EffectivePolicyVerified -and -not $e.UpdateSearchPerformed -and
        $e.PatchCurrency -ceq 'NOT_EVALUATED' -and $e.ComplianceAssessment -ceq 'NOT_EVALUATED' -and $null -eq $e.CriteriaSource -and
        (ConvertTo-Json $r -Depth 12) -notmatch 'PRIVATE-WU|PASS|FAIL|WUServerUrl|StartName|PathName|"Score"')
}
foreach($state in @('Stopped','Running','Start Pending','Stop Pending','Continue Pending','Pause Pending','Paused')) {
    Test-WinSecWindowsUpdateCase ('Service state is descriptive, never a security verdict: '+$state) {
        $script:WU.Services[0].State=$state;$r=Invoke-WinSecWindowsUpdateFixture
        Assert-WinSecWindowsUpdate ($r.Evidence.UpdateService.State -ceq $state.ToUpperInvariant().Replace(' ','_') -and
            $r.Status -ceq 'INFORMATIONAL' -and $r.Evidence.CollectionComplete)
    }
}
foreach($mode in @('Manual','Auto','Disabled','Boot','System')) {
    Test-WinSecWindowsUpdateCase ('Startup mode is inventoried without assuming automatic start is mandatory: '+$mode) {
        $script:WU.Services[0].StartMode=$mode;$r=Invoke-WinSecWindowsUpdateFixture
        Assert-WinSecWindowsUpdate ($r.Evidence.UpdateService.StartMode -ceq $mode.ToUpperInvariant() -and $r.Status -ceq 'INFORMATIONAL')
    }
}
foreach($badId in @('remote:host','local:hostname',('local:hw1-'+('A'*64)),('local:hw1-'+('a'*63)))) {
    Test-WinSecWindowsUpdateCase 'Noncanonical or remote identity aborts before any provider read' {
        Assert-WinSecWindowsUpdateThrows {Test-WinSecWindowsUpdate -DeviceId $badId -ScanId wu-1 -CheckId WSA-SYS-003}
        Assert-WinSecWindowsUpdate ($script:WU.IdentityReads -eq 0 -and $script:WU.CimReads -eq 0 -and $script:WU.KeyReads -eq 0 -and
            $script:WU.VersionReads -eq 0 -and $script:WU.RebootReads -eq 0)
    }
}
foreach($fault in @('Foreign','Missing','Multiple','NonText','Error')) {
    Test-WinSecWindowsUpdateCase ('Unverified current hardware blocks all configuration reads: '+$fault) {
        switch($fault){Foreign {$script:WU.LocalIds=@('local:hw1-'+('b'*64))};Missing {$script:WU.LocalIds=@()};
            Multiple {$script:WU.LocalIds=@($script:WU.DeviceId,$script:WU.DeviceId)};NonText {$script:WU.LocalIds=@(1)};Error {$script:WU.IdentityFails=$true}}
        Assert-WinSecWindowsUpdateThrows {Invoke-WinSecWindowsUpdateFixture}
        Assert-WinSecWindowsUpdate ($script:WU.CimReads -eq 0 -and $script:WU.KeyReads -eq 0 -and
            $script:WU.VersionReads -eq 0 -and $script:WU.RebootReads -eq 0)
    }
}
Test-WinSecWindowsUpdateCase 'A different CheckId or invalid ScanId cannot collect' {
    Assert-WinSecWindowsUpdateThrows {Test-WinSecWindowsUpdate -DeviceId $script:WU.DeviceId -ScanId wu-1 -CheckId WSA-SYS-001}
    Assert-WinSecWindowsUpdateThrows {Test-WinSecWindowsUpdate -DeviceId $script:WU.DeviceId -ScanId '../escape' -CheckId WSA-SYS-003}
    Assert-WinSecWindowsUpdate ($script:WU.IdentityReads -eq 0 -and $script:WU.CimReads -eq 0 -and $script:WU.KeyReads -eq 0 -and
        $script:WU.VersionReads -eq 0 -and $script:WU.RebootReads -eq 0)
}
foreach($fault in @('Missing','Multiple','MismatchedBuild','TextSKU','BooleanType','MissingVersion')) {
    Test-WinSecWindowsUpdateCase ('Invalid OS telemetry remains unknown and preserves other sources: '+$fault) {
        switch($fault){Missing {$script:WU.Systems=@()};Multiple {$script:WU.Systems+=,$script:WU.Systems[0]};
            MismatchedBuild {$script:WU.Systems[0].BuildNumber='22631'};TextSKU {$script:WU.Systems[0].OperatingSystemSKU='48'};
            BooleanType {$script:WU.Systems[0].ProductType=$true};MissingVersion {$script:WU.Systems[0].Version=$null}}
        $r=Invoke-WinSecWindowsUpdateFixture
        Assert-WinSecWindowsUpdate (-not $r.Evidence.CollectionComplete -and $r.Evidence.Platform.State -ceq 'UNKNOWN' -and
            $r.Evidence.UpdateService.StartMode -ceq 'MANUAL' -and $r.Evidence.CollectionIssues -ccontains 'OS_TELEMETRY_INVALID')
    }
}
foreach($fault in @('Missing','Multiple','Foreign','UnknownState','UnknownMode','NullState')) {
    Test-WinSecWindowsUpdateCase ('Invalid service data never becomes disabled or not applicable: '+$fault) {
        switch($fault){Missing {$script:WU.Services=@()};Multiple {$script:WU.Services+=,$script:WU.Services[0]};
            Foreign {$script:WU.Services[0].Name='other'};UnknownState {$script:WU.Services[0].State='PRIVATE-WU-STATE'};
            UnknownMode {$script:WU.Services[0].StartMode='PRIVATE-WU-MODE'};NullState {$script:WU.Services[0].State=$null}}
        $r=Invoke-WinSecWindowsUpdateFixture
        Assert-WinSecWindowsUpdate (-not $r.Evidence.CollectionComplete -and $r.Status -ceq 'INFORMATIONAL' -and
            $r.Evidence.UpdateService.StartMode -cne 'DISABLED' -and $null -eq $r.NotApplicableReason -and
            (ConvertTo-Json $r -Depth 12) -notmatch 'PRIVATE-WU')
    }
}
foreach($area in @('AutomaticUpdates','WindowsUpdate')) {
    Test-WinSecWindowsUpdateCase ('An absent policy key means not configured, not disabled or compliant: '+$area) {
        $script:WU.MissingKeys=@($area);$r=Invoke-WinSecWindowsUpdateFixture
        Assert-WinSecWindowsUpdate ($r.Evidence.CollectionComplete -and $r.Evidence.PolicyRegistry.$area.ReadState -ceq 'NOT_CONFIGURED' -and
            -not $r.Evidence.EffectivePolicyVerified -and $script:WU.Closed.Count -eq 1)
    }
    Test-WinSecWindowsUpdateCase ('Unreadable policy key is UNKNOWN and retains other observations: '+$area) {
        $script:WU.FailKeys=@($area);$r=Invoke-WinSecWindowsUpdateFixture
        Assert-WinSecWindowsUpdate (-not $r.Evidence.CollectionComplete -and $r.Evidence.PolicyRegistry.$area.ReadState -ceq 'UNKNOWN' -and
            $r.Evidence.CollectionIssues -ccontains ($area+'_KEY_READ_FAILED') -and $r.Evidence.Platform.State -ceq 'OBSERVED')
    }
}
foreach($field in @('NoAutoUpdate','AUOptions','UseWUServer')) {
    Test-WinSecWindowsUpdateCase ('An absent value is explicitly distinct from DWORD zero: '+$field) {
        $script:WU.Values.AutomaticUpdates.Remove($field);$r=Invoke-WinSecWindowsUpdateFixture
        $value=$r.Evidence.PolicyRegistry.AutomaticUpdates.$field
        Assert-WinSecWindowsUpdate ($value.State -ceq 'NOT_CONFIGURED' -and $null -eq $value.Value -and $r.Evidence.CollectionComplete)
    }
}
foreach($kind in @('String','ExpandString','MultiString','Binary','QWord')) {
    Test-WinSecWindowsUpdateCase ('Non-DWORD registry types remain unknown: '+$kind) {
        $script:WU.Kinds['AutomaticUpdates.NoAutoUpdate']=[Microsoft.Win32.RegistryValueKind]::$kind
        $r=Invoke-WinSecWindowsUpdateFixture;$value=$r.Evidence.PolicyRegistry.AutomaticUpdates.NoAutoUpdate
        Assert-WinSecWindowsUpdate ($value.State -ceq 'UNKNOWN' -and $null -eq $value.Value -and -not $r.Evidence.CollectionComplete)
    }
}
foreach($value in @($true,'1',[long]1,1.5,@(1))) {
    Test-WinSecWindowsUpdateCase 'A malformed DWORD payload is not coerced to enabled or disabled' {
        $script:WU.Values.AutomaticUpdates.NoAutoUpdate=$value;$r=Invoke-WinSecWindowsUpdateFixture
        Assert-WinSecWindowsUpdate ($r.Evidence.PolicyRegistry.AutomaticUpdates.NoAutoUpdate.State -ceq 'UNKNOWN' -and
            -not $r.Evidence.CollectionComplete)
    }
}
Test-WinSecWindowsUpdateCase 'Unsigned DWORDs preserve their bit pattern without interpreting unknown policy values' {
    $script:WU.Values.AutomaticUpdates.AUOptions=-1;$r=Invoke-WinSecWindowsUpdateFixture
    Assert-WinSecWindowsUpdate ($r.Evidence.PolicyRegistry.AutomaticUpdates.AUOptions.Value -eq 4294967295 -and
        $r.Evidence.CollectionComplete -and -not $r.Evidence.ScoringEligible)
}
Test-WinSecWindowsUpdateCase 'A value read failure does not discard adjacent fields and closes both handles' {
    $script:WU.FailValues=@('AutomaticUpdates.NoAutoUpdate');$r=Invoke-WinSecWindowsUpdateFixture
    Assert-WinSecWindowsUpdate ($r.Evidence.PolicyRegistry.AutomaticUpdates.NoAutoUpdate.State -ceq 'UNKNOWN' -and
        $r.Evidence.PolicyRegistry.AutomaticUpdates.AUOptions.Value -eq 4 -and $script:WU.Closed.Count -eq 2 -and
        (ConvertTo-Json $r -Depth 12) -notmatch 'PRIVATE-WU')
}
Test-WinSecWindowsUpdateCase 'Resource close errors are bounded diagnostics, not leaked exceptions' {
    $script:WU.FailClose=@('AutomaticUpdates');$r=Invoke-WinSecWindowsUpdateFixture
    Assert-WinSecWindowsUpdate ($r.Evidence.CollectionIssues -ccontains 'AutomaticUpdates_KEY_CLOSE_FAILED' -and
        -not $r.Evidence.CollectionComplete -and $script:WU.Closed.Count -eq 2)
}
foreach($class in @('Win32_OperatingSystem','Win32_Service')) {
    Test-WinSecWindowsUpdateCase ('A provider failure preserves successful sources and redacts the original error: '+$class) {
        $script:WU.FailClasses=@($class);$r=Invoke-WinSecWindowsUpdateFixture
        Assert-WinSecWindowsUpdate ($r.Evidence.CollectionSuccessful -and -not $r.Evidence.CollectionComplete -and
            $r.Status -ceq 'INFORMATIONAL' -and (ConvertTo-Json $r -Depth 12) -notmatch 'PRIVATE-WU')
    }
}
Test-WinSecWindowsUpdateCase 'Total collection failure is ERROR without a security verdict or false applicability' {
    $script:WU.FailClasses=@('Win32_OperatingSystem','Win32_Service');$script:WU.FailKeys=@('AutomaticUpdates','WindowsUpdate')
    $script:WU.VersionKeyFails=$true;$script:WU.RebootFails=$true
    $r=Invoke-WinSecWindowsUpdateFixture
    Assert-WinSecWindowsUpdate ($r.Status -ceq 'ERROR' -and -not $r.Evidence.CollectionSuccessful -and
        -not $r.Evidence.CollectionComplete -and $r.Evidence.CollectionIssues.Count -eq 6 -and $null -eq $r.NotApplicableReason)
}
foreach($fault in @('MissingKey','DeniedKey','MissingBuild','MissingRevision','BuildMismatch','BuildType','RevisionType',
    'NegativeRevision','RevisionText','RevisionArray','BuildRead','RevisionRead','Close')) {
    Test-WinSecWindowsUpdateCase ('Version source failures remain explicit and bounded: '+$fault) {
        $field='UBR'
        switch($fault) {
            MissingKey {$script:WU.VersionKeyMissing=$true};DeniedKey {$script:WU.VersionKeyFails=$true}
            MissingBuild {$script:WU.VersionValues.Remove('CurrentBuildNumber');$field='CurrentBuildNumber'}
            MissingRevision {$script:WU.VersionValues.Remove('UBR')}
            BuildMismatch {$script:WU.VersionValues.CurrentBuildNumber='26200';$field='CurrentBuildNumber'}
            BuildType {$script:WU.Kinds['Version.CurrentBuildNumber']=[Microsoft.Win32.RegistryValueKind]::DWord;$field='CurrentBuildNumber'}
            RevisionType {$script:WU.Kinds['Version.UBR']=[Microsoft.Win32.RegistryValueKind]::QWord}
            NegativeRevision {$script:WU.VersionValues.UBR=-1};RevisionText {$script:WU.VersionValues.UBR='9711'}
            RevisionArray {$script:WU.VersionValues.UBR=@(9711)}
            BuildRead {$script:WU.FailValues=@('Version.CurrentBuildNumber');$field='CurrentBuildNumber'}
            RevisionRead {$script:WU.FailValues=@('Version.UBR')};Close {$script:WU.VersionCloseFails=$true}
        }
        $r=Invoke-WinSecWindowsUpdateFixture
        Assert-WinSecWindowsUpdate ($r.Status -ceq 'INFORMATIONAL' -and -not $r.Evidence.CollectionComplete -and
            $r.Evidence.CollectionIssues.Count -eq 1 -and $r.Evidence.Platform.State -ceq 'OBSERVED' -and
            -not $r.Evidence.ScoringEligible -and $null -eq $r.NotApplicableReason -and
            (ConvertTo-Json $r -Depth 12) -notmatch 'PRIVATE-WU')
        if($fault -notin @('MissingKey','DeniedKey')){Assert-WinSecWindowsUpdate ($script:WU.VersionClosed -eq 1)}
        if($fault -notin @('BuildMismatch','Close')) {
            Assert-WinSecWindowsUpdate ($r.Evidence.VersionRegistry.$field.State -cne 'OBSERVED' -and
                $null -eq $r.Evidence.VersionRegistry.$field.Value)
        }
    }
}
Test-WinSecWindowsUpdateCase 'A DWORD revision preserves zero and the maximum unsigned value without accepting QWORD' {
    foreach($value in @([uint32]0,[uint32]::MaxValue)) {
        $script:WU.VersionValues.UBR=$value;$r=Invoke-WinSecWindowsUpdateFixture
        Assert-WinSecWindowsUpdate ($r.Evidence.VersionRegistry.UBR.State -ceq 'OBSERVED' -and
            $r.Evidence.VersionRegistry.UBR.Value -eq [long]$value -and $r.Evidence.CollectionComplete)
    }
}
foreach($value in @($true,$false)) {
    Test-WinSecWindowsUpdateCase 'Boolean reboot observations stay descriptive and never trigger a restart' {
        $script:WU.RebootValue=$value;$r=Invoke-WinSecWindowsUpdateFixture
        Assert-WinSecWindowsUpdate ($r.Evidence.RestartInformation.State -ceq 'OBSERVED' -and
            $r.Evidence.RestartInformation.Value -is [bool] -and $r.Evidence.RestartInformation.Value -eq $value -and
            $r.Evidence.CollectionComplete -and -not $r.Evidence.ScoringEligible)
    }
}
foreach($value in @($null,0,1,'False','True',@(),@($false))) {
    Test-WinSecWindowsUpdateCase 'Non-Boolean reboot responses cannot become a completed update' {
        $script:WU.RebootValue=$value;$r=Invoke-WinSecWindowsUpdateFixture
        Assert-WinSecWindowsUpdate ($r.Evidence.RestartInformation.State -ceq 'UNKNOWN' -and
            $null -eq $r.Evidence.RestartInformation.Value -and -not $r.Evidence.CollectionComplete -and
            $r.Evidence.CollectionIssues -ccontains 'UPDATE_REBOOT_TELEMETRY_INVALID')
    }
}
Test-WinSecWindowsUpdateCase 'Unavailable WUA reboot information preserves the independent revision and redacts the provider error' {
    $script:WU.RebootFails=$true;$r=Invoke-WinSecWindowsUpdateFixture
    Assert-WinSecWindowsUpdate ($r.Evidence.RestartInformation.State -ceq 'UNKNOWN' -and
        $r.Evidence.VersionRegistry.UBR.Value -eq 9711 -and $r.Evidence.CollectionIssues -ccontains 'UPDATE_REBOOT_QUERY_FAILED' -and
        (ConvertTo-Json $r -Depth 12) -notmatch 'PRIVATE-WU')
}
foreach($fault in @('False','True','Creation','Getter','Invalid','Release')) {
    Test-WinSecWindowsUpdateCase ('The native reboot boundary uses one getter and releases its private COM instance: '+$fault) {
        $script:rebootCreated=0;$script:rebootClosed=0
        function New-Object {
            [CmdletBinding()]param([string]$ComObject)
            Assert-WinSecWindowsUpdate ($ComObject -ceq 'Microsoft.Update.SystemInfo');$script:rebootCreated++
            if($fault -ceq 'Creation'){throw 'PRIVATE-WU-CREATION'}
            $object=[pscustomobject]@{}
            $object|Add-Member ScriptProperty RebootRequired {
                if($fault -ceq 'Getter'){throw 'PRIVATE-WU-GETTER'}
                if($fault -ceq 'Invalid'){return 'False'}
                return ($fault -ceq 'True')
            }
            return $object
        }
        function Close-WinSecWindowsUpdateSystemInfo {
            [CmdletBinding()]param([object]$SystemInfo)
            $script:rebootClosed++
            if($fault -ceq 'Release'){throw 'PRIVATE-WU-RELEASE'}
        }
        if($fault -in @('False','True')) {
            $values=@(& $realRebootReader)
            Assert-WinSecWindowsUpdate ($values.Count -eq 1 -and $values[0] -is [bool] -and $values[0] -eq ($fault -ceq 'True'))
        } else {Assert-WinSecWindowsUpdateThrows {& $realRebootReader}}
        $closed=if($fault -ceq 'Creation'){0}else{1}
        Assert-WinSecWindowsUpdate ($script:rebootCreated -eq 1 -and $script:rebootClosed -eq $closed)
    }
}
Test-WinSecWindowsUpdateCase 'The new version opener is fixed to read-only HKLM64; COM exposes no update search' {
    Assert-WinSecWindowsUpdate ($realVersionReader.ToString().Contains("OpenSubKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion',"+'$false)') -and
        $realVersionReader.ToString().Contains('RegistryView]::Registry64') -and $realVersionReader.ToString().Contains('$baseKey.Dispose()') -and
        $realRebootReader.ToString().Contains("-ComObject 'Microsoft.Update.SystemInfo'") -and
        $realRebootReader.ToString().Contains('$information.RebootRequired') -and
        $realRebootReader.ToString() -notmatch 'Microsoft.Update.Session|Microsoft.Update.AutoUpdate|\.Search\(|\.DetectNow\(')
}
Test-WinSecWindowsUpdateCase 'The native registry opener is restricted to read-only HKLM64 handles and fixed paths' {
    Assert-WinSecWindowsUpdate ($realKeyReader.ToString().Contains('RegistryView]::Registry64') -and
        $realKeyReader.ToString().Contains('OpenSubKey($SubKey,$false)') -and $realKeyReader.ToString().Contains('$baseKey.Dispose()'))
    Assert-WinSecWindowsUpdateThrows {& $realKeyReader -SubKey 'SOFTWARE\other'}
    $tokens=$null;$errors=$null;$ast=[System.Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
    $commands=@($ast.FindAll({param($node) $node -is [System.Management.Automation.Language.CommandAst]},$true)|ForEach-Object {$_.GetCommandName()})
    Assert-WinSecWindowsUpdate ($errors.Count -eq 0 -and @($commands|Where-Object {$_ -cmatch '^(Set-|Remove-|Start-|Stop-|Restart-|Invoke-|New-Object$|Install-|Enable-|Disable-)' -and $_ -cne 'New-Object'}).Count -eq 0 -and
        (Get-Content $path -Raw) -notmatch '\.(SetValue|CreateSubKey|DeleteValue|DeleteSubKey|Search|Download|Install)\(')
}
[Console]::WriteLine(('Windows Update unit: {0} passed, {1} failed.' -f $script:passed,$script:failed))
if($script:failed){throw 'Windows Update unit tests failed.'}
