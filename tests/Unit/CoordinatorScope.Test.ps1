# Coordinator scopes with synthetic local identity, catalog and collectors.
# No Windows queries, scans, native storage or configuration writes.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../../src/Core/ScanCoordinator.ps1')
function Get-CimInstance {[pscustomobject]@{UUID='12345678-1234-4567-89ab-123456789abc'}}
$script:passed=0;$script:failed=0
function Assert-WinSecCoordinatorScope {param([bool]$Condition);if(-not $Condition){throw 'Coordinator scope assertion failed.'}}
function Test-WinSecCoordinatorScope {
    param([string]$Name,[scriptblock]$Action)
    $script:auditCalls=0;$script:confirmCalls=0;$script:storageCalls=0
    $script:available=$true;$script:mutation='';$script:lastIds=@()
    try {$null=& $Action;$script:passed++;Write-Host "[PASS] $Name"}
    catch {$script:failed++;Write-Host "[FAIL] $Name : $($_.Exception.Message)"}
}
function Assert-WinSecCoordinatorScopeRejected {
    param([scriptblock]$Action,[int]$AuditCalls=0)
    $caught=$null;$published=New-Object 'System.Collections.Generic.List[object]'
    try {& $Action|ForEach-Object{$published.Add($_)}}catch{$caught=$_}
    Assert-WinSecCoordinatorScope ($null -ne $caught -and $published.Count -eq 0 -and
        $script:auditCalls -eq $AuditCalls -and $script:storageCalls -eq 0 -and
        $caught.Exception.Message -notlike '*SYNTHETIC-SCOPE-PRIVATE*')
}
function Assert-WinSecEvidenceProtection {$script:storageCalls++;throw 'Unexpected storage.'}
function Get-WinSecEvidenceStorageRoot {$script:storageCalls++;throw 'Unexpected storage.'}
function Save-WinSecCoordinatedEvidence {$script:storageCalls++;throw 'Unexpected storage.'}
function Get-WinSecCheckRegistry {
    param($ProjectRoot)
    $specs=@(
        @{Id='WSA-SYS-001';Section='SystemSecurity';Enabled=$script:available},
        @{Id='WSA-SYS-002';Section='SystemSecurity';Enabled=$false},
        @{Id='WSA-SYS-003';Section='SystemSecurity';Enabled=$script:available},
        @{Id='WSA-NET-001';Section='NetworkSecurity';Enabled=$true},
        @{Id='WSA-IAM-001';Section='IdentityAccess';Enabled=$true})
    [pscustomobject]@{CatalogVersion='SYNTHETIC-SCOPE';Checks=@(foreach($spec in $specs){
        [pscustomobject]@{CheckId=$spec.Id;SectionKey=$spec.Section;Name=('Synthetic '+$spec.Id);
            ExecutionEnabled=$spec.Enabled;ExecutionReady=$spec.Enabled;
            ImplementationStatus='VALIDATED';RegistryStatus='READY';
            ScriptPath=Join-Path $ProjectRoot 'src/Checks/Defender/Test-Defender.ps1'}
    })}
}
function Invoke-WinSecAudit {
    param($DeviceId,$ScanId,[string[]]$CheckIds,$Registry,[switch]$SkipScoring)
    $script:auditCalls++;$script:lastIds=@($CheckIds)
    Assert-WinSecCoordinatorScope ([bool]$SkipScoring)
    $controls=@(foreach($check in $Registry.Checks){
        [pscustomobject]@{DeviceId=$DeviceId;ScanId=$ScanId;CheckId=$check.CheckId;SectionKey=$check.SectionKey;
            Status=if($check.CheckId -cin $CheckIds){'INFORMATIONAL'}else{'NOT_SELECTED'};
            Evidence=@{Secret='SYNTHETIC-SCOPE-PRIVATE'}}
    })
    switch($script:mutation){
        'EXTRA' {$controls[3].Status='INFORMATIONAL'}
        'OMIT' {$controls[0].Status='NOT_SELECTED'}
        'SECTION' {$controls[0].SectionKey='NetworkSecurity'}
    }
    [pscustomobject]@{DeviceId=$DeviceId;ScanId=$ScanId;AuditId=$ScanId;CollectionMode='LOCAL';
        ComputerName='SYNTHETIC';StartedAtUTC='2026-10-20T00:00:00Z';CompletedAtUTC='2026-10-20T00:01:00Z';
        ExecutionStatus='COMPLETED';ScoringEnabled=$false;OverallScore=$null;ScoreResult=$null;
        CatalogVersion=$Registry.CatalogVersion;ControlResults=$controls;ScopeType='DEVICE';ScopeKey='ALL'}
}
$specs=@(@{T='DEVICE';K='ALL';Ids=@('WSA-IAM-001','WSA-NET-001','WSA-SYS-001','WSA-SYS-003')},
    @{T='SECTION';K='SystemSecurity';Ids=@('WSA-SYS-001','WSA-SYS-003')},
    @{T='CONTROL';K='WSA-SYS-001';Ids=@('WSA-SYS-001')})
foreach($spec in $specs){
    Test-WinSecCoordinatorScope ('Approved scope selects exactly executable controls: '+$spec.T) {
        $coordinator=New-WinSecScanCoordinator
        $result=Invoke-WinSecCoordinatedScan -Coordinator $coordinator -ScopeType $spec.T -ScopeKey $spec.K -ConfirmAction {
            param($request)
            $script:confirmCalls++
            Assert-WinSecCoordinatorScope ($request.ScopeType -ceq $spec.T -and $request.ScopeKey -ceq $spec.K -and
                $request.ReadOnly -ceq $true -and (@($request.Checks.CheckId) -join '|') -ceq ($spec.Ids -join '|'))
            $true
        }
        Assert-WinSecCoordinatorScope (($script:lastIds -join '|') -ceq ($spec.Ids -join '|') -and
            $script:auditCalls -eq 1 -and $script:confirmCalls -eq 1 -and $result.ScopeType -ceq $spec.T -and
            $result.ScopeKey -ceq $spec.K -and $result.OverallStatus -ceq 'NOT_SCORED' -and $null -eq $result.OverallScore -and
            (ConvertTo-Json -InputObject $result -Depth 15) -notmatch 'SYNTHETIC-SCOPE-PRIVATE|"Evidence"')
        $session=Get-WinSecCoordinatorSession -Coordinator $coordinator -DeviceId $result.DeviceId -ScanId $result.ScanId
        $history=@(Get-WinSecCoordinatorHistory -Coordinator $coordinator -DeviceId $result.DeviceId)
        Assert-WinSecCoordinatorScope ($session.ScopeType -ceq $spec.T -and $session.ScopeKey -ceq $spec.K -and
            (@($session.ExpectedCheckIds | Sort-Object) -join '|') -ceq ($spec.Ids -join '|') -and
            $history.Count -eq 1 -and $history[0].ScopeKey -ceq $spec.K -and $script:storageCalls -eq 0)
    }
    Test-WinSecCoordinatorScope ('Cancellation preserves prior sessions for scope '+$spec.T) {
        $coordinator=New-WinSecScanCoordinator
        $null=Invoke-WinSecCoordinatedScan -Coordinator $coordinator -ConfirmAction {$true}
        $script:auditCalls=0
        $before=ConvertTo-Json -InputObject $coordinator.Sessions -Depth 25 -Compress
        $result=Invoke-WinSecCoordinatedScan -Coordinator $coordinator -ScopeType $spec.T -ScopeKey $spec.K -ConfirmAction {$false}
        Assert-WinSecCoordinatorScope ($null -eq $result -and $script:auditCalls -eq 0 -and
            $before -ceq (ConvertTo-Json -InputObject $coordinator.Sessions -Depth 25 -Compress))
    }
    Test-WinSecCoordinatorScope ('Mutated scope preview cannot authorize '+$spec.T) {
        $coordinator=New-WinSecScanCoordinator
        Assert-WinSecCoordinatorScopeRejected {
            Invoke-WinSecCoordinatedScan -Coordinator $coordinator -ScopeType $spec.T -ScopeKey $spec.K -ConfirmAction {
                param($request);$request.ScopeKey='CHANGED';$true
            }
        }
        Assert-WinSecCoordinatorScope ($coordinator.Sessions.Count -eq 0)
    }
}
Test-WinSecCoordinatorScope 'No scope and no CheckIds creates an explicit DEVICE/ALL session' {
    $coordinator=New-WinSecScanCoordinator
    $result=Invoke-WinSecCoordinatedScan -Coordinator $coordinator -ConfirmAction {
        param($request);Assert-WinSecCoordinatorScope ($request.ScopeType -ceq 'DEVICE' -and $request.ScopeKey -ceq 'ALL');$true
    }
    Assert-WinSecCoordinatorScope ($result.ScopeType -ceq 'DEVICE' -and $result.ScopeKey -ceq 'ALL')
}
Test-WinSecCoordinatorScope 'Legacy explicit CheckIds retain unknown scope instead of acquiring a complete-device label' {
    $coordinator=New-WinSecScanCoordinator
    $result=Invoke-WinSecCoordinatedScan -Coordinator $coordinator -CheckIds @('WSA-SYS-001') -ConfirmAction {
        param($request);Assert-WinSecCoordinatorScope ($null -eq $request.ScopeType -and $null -eq $request.ScopeKey);$true
    }
    Assert-WinSecCoordinatorScope ($null -eq $result.ScopeType -and $null -eq $result.ScopeKey -and $script:lastIds.Count -eq 1)
}
foreach($arguments in @(
    @{ScopeType='DEVICE'},@{ScopeKey='ALL'},@{ScopeType=$null;ScopeKey=$null},
    @{ScopeType='device';ScopeKey='ALL'},@{ScopeType='DEVICE';ScopeKey='all'},
    @{ScopeType=@('SECTION');ScopeKey='SystemSecurity'},@{ScopeType='CONTROL';ScopeKey=@('WSA-SYS-001')},
    @{ScopeType='SECTION';ScopeKey='systemsecurity'},@{ScopeType='SECTION';ScopeKey='MissingSection'},
    @{ScopeType='CONTROL';ScopeKey='../SYNTHETIC-SCOPE-PRIVATE'},@{ScopeType='CONTROL';ScopeKey="WSA-SYS-001`n"},
    @{ScopeType='CONTROL';ScopeKey='WSA-MISSING-001'},@{ScopeType='CONTROL';ScopeKey='wsa-sys-001'},
    @{ScopeType='CONTROL';ScopeKey='WSA-SYS-002'},@{ScopeType='EXPLICIT_CHECKS';ScopeKey='ALL'},
    @{ScopeType='DEVICE';ScopeKey='ALL';CheckIds=@('WSA-SYS-001')},
    @{ScopeType='SECTION';ScopeKey='SystemSecurity';CheckIds=@('WSA-SYS-001')},
    @{ScopeType='CONTROL';ScopeKey='WSA-SYS-001';CheckIds=@('WSA-SYS-001')}
)){
    Test-WinSecCoordinatorScope 'Malformed, conflicting or unauthorized scope aborts before confirmation' {
        $coordinator=New-WinSecScanCoordinator
        Assert-WinSecCoordinatorScopeRejected {
            Invoke-WinSecCoordinatedScan -Coordinator $coordinator @arguments -ConfirmAction {$script:confirmCalls++;$true}
        }
        Assert-WinSecCoordinatorScope ($script:confirmCalls -eq 0 -and $coordinator.Sessions.Count -eq 0)
    }
}
Test-WinSecCoordinatorScope 'Empty section reports no executable controls without publishing a session' {
    $coordinator=New-WinSecScanCoordinator
    $script:available=$false
    $caught=$null
    try {
        $null=Invoke-WinSecCoordinatedScan -Coordinator $coordinator -ScopeType SECTION -ScopeKey SystemSecurity -ConfirmAction {
            param($request);$script:confirmCalls++;Assert-WinSecCoordinatorScope ($request.Checks.Count -eq 0);$true
        }
    }catch{$caught=$_}
    Assert-WinSecCoordinatorScope ($null -ne $caught -and $caught.Exception.Message -like 'NO_EXECUTABLE_CHECKS*' -and
        $script:confirmCalls -eq 1 -and $script:auditCalls -eq 0 -and $coordinator.Sessions.Count -eq 0)
}
Test-WinSecCoordinatorScope 'Selection changing after confirmation requires a new scoped request' {
    $coordinator=New-WinSecScanCoordinator
    Assert-WinSecCoordinatorScopeRejected {
        Invoke-WinSecCoordinatedScan -Coordinator $coordinator -ScopeType SECTION -ScopeKey SystemSecurity -ConfirmAction {
            $script:available=$false;$true
        }
    }
    Assert-WinSecCoordinatorScope ($coordinator.Sessions.Count -eq 0)
}
foreach($resultMutation in @('EXTRA','OMIT','SECTION')){
    Test-WinSecCoordinatorScope ('A collector outside the approved scope cannot publish: '+$resultMutation) {
        $coordinator=New-WinSecScanCoordinator;$script:mutation=$resultMutation
        Assert-WinSecCoordinatorScopeRejected {
            Invoke-WinSecCoordinatedScan -Coordinator $coordinator -ScopeType CONTROL -ScopeKey WSA-SYS-001 -ConfirmAction {$true}
        } -AuditCalls 1
        Assert-WinSecCoordinatorScope ($coordinator.Sessions.Count -eq 0)
    }
}
Test-WinSecCoordinatorScope 'Every scoped request requires fresh consent, including a repeat of the same scope' {
    $coordinator=New-WinSecScanCoordinator
    $confirm={param($request);$script:confirmCalls++;$script:confirmCalls -eq 1}
    $first=Invoke-WinSecCoordinatedScan -Coordinator $coordinator -ScopeType CONTROL -ScopeKey WSA-SYS-001 -ConfirmAction $confirm
    $second=Invoke-WinSecCoordinatedScan -Coordinator $coordinator -ScopeType CONTROL -ScopeKey WSA-SYS-001 -ConfirmAction $confirm
    Assert-WinSecCoordinatorScope ($null -ne $first -and $null -eq $second -and $script:confirmCalls -eq 2 -and
        $script:auditCalls -eq 1 -and $coordinator.Sessions.Count -eq 1)
}
Test-WinSecCoordinatorScope 'Partial scope appends an independent session without rewriting the previous device scan' {
    $coordinator=New-WinSecScanCoordinator
    $full=Invoke-WinSecCoordinatedScan -Coordinator $coordinator -ScopeType DEVICE -ScopeKey ALL -ConfirmAction {$true}
    $oldKey=Get-WinSecScanSessionKey -DeviceId $full.DeviceId -ScanId $full.ScanId
    $old=ConvertTo-Json -InputObject $coordinator.Sessions[$oldKey] -Depth 25 -Compress
    $partial=Invoke-WinSecCoordinatedScan -Coordinator $coordinator -ScopeType SECTION -ScopeKey SystemSecurity -ConfirmAction {$true}
    Assert-WinSecCoordinatorScope ($coordinator.Sessions.Count -eq 2 -and $full.ScanId -cne $partial.ScanId -and
        $old -ceq (ConvertTo-Json -InputObject $coordinator.Sessions[$oldKey] -Depth 25 -Compress))
    $partial.ScopeKey='changed'
    $stored=Get-WinSecCoordinatorPublicResult -Coordinator $coordinator -DeviceId $partial.DeviceId -ScanId $partial.ScanId
    Assert-WinSecCoordinatorScope ($stored.ScopeKey -ceq 'SystemSecurity')
}
Test-WinSecCoordinatorScope 'A history change from Scan to Rescan during confirmation requires new consent' {
    $coordinator=New-WinSecScanCoordinator
    Assert-WinSecCoordinatorScopeRejected {
        Invoke-WinSecCoordinatedScan -Coordinator $coordinator -ScanId outer -ScopeType DEVICE -ScopeKey ALL -ConfirmAction {
            param($request)
            Assert-WinSecCoordinatorScope ($request.ScanAction -ceq 'Scan')
            $null=Invoke-WinSecCoordinatedScan -Coordinator $coordinator -ScanId concurrent -ConfirmAction {$true}
            $true
        }
    } -AuditCalls 1
    Assert-WinSecCoordinatorScope ($coordinator.Sessions.Count -eq 1 -and
        (Get-WinSecScanAction $coordinator (New-WinSecLocalTarget).DeviceId DEVICE ALL) -ceq 'Rescan')
}
Write-Host "Passed: $script:passed"
Write-Host "Failed: $script:failed"
if($script:failed -gt 0){throw "$script:failed coordinator scope test(s) failed."}
