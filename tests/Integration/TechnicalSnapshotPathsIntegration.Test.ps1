[CmdletBinding()]param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/TechnicalSnapshotPaths.ps1')
. (Join-Path $root 'tests/Fixtures/TechnicalSnapshotMemory.ps1')
function Get-CimInstance {throw 'Native queries prohibited.'}
$temporaryBase=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$sandbox=Join-Path $temporaryBase ('wsa-'+[guid]::NewGuid().ToString('N').Substring(0,16))
$null=New-Item -ItemType Directory -Path $sandbox
$passed=0;$failed=0
function Assert-PathContract {param([bool]$Value);if(-not $Value){throw 'Path contract assertion failed.'}}
function Reject-PathContract {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-PathContract $caught}
function Check-PathContract {param($CaseLabel,[scriptblock]$Action);$f=New-WinSecSnapshotFixture;try{& $Action;$script:passed++;Write-Host ('[PASS] '+$CaseLabel)}catch{$script:failed++;Write-Host ('[FAIL] '+$CaseLabel+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}
try {
    Check-PathContract 'Pure path planning leaves installation empty and pairs technical paths' {
        $p=Get-WinSecTechnicalSnapshotPaths $sandbox $f.Identity $f.Snapshot.CollectedAtUTC
        Assert-PathContract (@(Get-ChildItem -LiteralPath $sandbox -Force).Count -eq 0 -and
            [IO.Path]::GetFileNameWithoutExtension($p.JsonPath) -ceq [IO.Path]::GetFileNameWithoutExtension($p.MarkdownPath) -and
            $p.JsonPath -match '\\scans\\[a-f0-9]{64}\\IdentityAccess\\20261028T0102040000000ZGuestAccount_[b]{32}\.json\z')
    }
    Check-PathContract 'Distinct snapshots create distinct names without changing the device key' {
        $a=Get-WinSecTechnicalSnapshotPaths $sandbox $f.Identity $f.Snapshot.CollectedAtUTC
        $f.Identity.SnapshotId='c'*32;$b=Get-WinSecTechnicalSnapshotPaths $sandbox $f.Identity $f.Snapshot.CollectedAtUTC
        Assert-PathContract ($a.DeviceKey -ceq $b.DeviceKey -and $a.JsonPath -cne $b.JsonPath)
    }
    Check-PathContract 'Each control of a section/device operation keeps its own pair and shared ScanId' {
        foreach($scope in @('SECTION','DEVICE')){
            $f.Identity.ScopeType=$scope;$f.Identity.ScopeKey=if($scope -ceq 'SECTION'){'IdentityAccess'}else{'ALL'}
            foreach($id in @('WSA-IAM-001','WSA-IAM-002','WSA-IAM-003')){
                $f.Identity.CheckId=$id;$p=Get-WinSecTechnicalSnapshotPaths $sandbox $f.Identity $f.Snapshot.CollectedAtUTC
                Assert-PathContract ($p.JsonPath.Contains((Get-WinSecSnapshotControl $id).ControlName) -and $f.Identity.ScanId -ceq 'synthetic-scan')
            }
        }
    }
    Check-PathContract 'Findings paths support only control/section and bind AnalysisId' {
        $c=Get-WinSecSnapshotFindingsPath $sandbox $f.Identity.DeviceId CONTROL WSA-IAM-002 ('d'*32) $f.Snapshot.GeneratedAtUTC
        $s=Get-WinSecSnapshotFindingsPath $sandbox $f.Identity.DeviceId SECTION IdentityAccess ('e'*32) $f.Snapshot.GeneratedAtUTC
        Assert-PathContract ($c -match '\\IdentityAccess\\findings\\.*GuestAccount_d{32}\.md\z' -and $s -match 'IdentityAccess_e{32}\.md\z')
        Reject-PathContract {Get-WinSecSnapshotFindingsPath $sandbox $f.Identity.DeviceId DEVICE ALL ('d'*32) $f.Snapshot.GeneratedAtUTC}
        Reject-PathContract {Get-WinSecSnapshotFindingsPath $sandbox $f.Identity.DeviceId SECTION '../escape' ('d'*32) $f.Snapshot.GeneratedAtUTC}
    }
    Check-PathContract 'Traversal, UNC, ADS, reserved names and ambiguous components are rejected' {
        foreach($bad in @('../outside.md','reports/../outside.md','reports/file.md:stream','reports/CON.md','reports/bad./file.md','reports//file.md','C:/outside.md','reports/bad name/file.md')){
            Reject-PathContract {Assert-WinSecSnapshotStoragePath $sandbox $bad}
        }
        foreach($bad in @('C:relative','\\server\share','Microsoft.PowerShell.Core\FileSystem::C:\repo',($sandbox+'\..'))){
            Reject-PathContract {Assert-WinSecSnapshotStoragePath $bad 'reports/file.md'}
        }
    }
    Check-PathContract 'Oversized paths and foreign identity never yield an artifact path' {
        Reject-PathContract {Assert-WinSecSnapshotStoragePath $sandbox ('reports/'+('a'*241)+'.md')}
        $f.Identity.DeviceId='../foreign';Reject-PathContract {Get-WinSecTechnicalSnapshotPaths $sandbox $f.Identity $f.Snapshot.CollectedAtUTC}
    }
    Check-PathContract 'Existing file, directory collision and file parent fail closed' {
        $null=New-Item -ItemType Directory -Path (Join-Path $sandbox 'reports')
        [IO.File]::WriteAllText((Join-Path $sandbox 'reports/collision.md'),'SYNTHETIC')
        Reject-PathContract {Assert-WinSecSnapshotStoragePath $sandbox 'reports/collision.md'}
        Reject-PathContract {Assert-WinSecSnapshotStoragePath $sandbox 'reports/collision.md/child.md'}
        $null=New-Item -ItemType Directory -Path (Join-Path $sandbox 'reports/directory.md')
        Reject-PathContract {Assert-WinSecSnapshotStoragePath $sandbox 'reports/directory.md'}
    }
    Check-PathContract 'An inspection permission failure is rejected rather than treated as an absent path' {
        function Get-Item {[CmdletBinding()]param($LiteralPath,[switch]$Force);$exception=New-Object UnauthorizedAccessException('SYNTHETIC');$record=New-Object Management.Automation.ErrorRecord($exception,'SyntheticDenied',[Management.Automation.ErrorCategory]::PermissionDenied,$null);$PSCmdlet.ThrowTerminatingError($record)}
        Reject-PathContract {Assert-WinSecSnapshotStoragePath $sandbox 'reports/unreadable.md'}
    }
    Check-PathContract 'Junctions below and above the project root are rejected' {
        $target=Join-Path $sandbox 'target';$null=New-Item -ItemType Directory -Path $target
        $link=Join-Path $sandbox 'linked';$null=New-Item -ItemType Junction -Path $link -Target $target
        Reject-PathContract {Assert-WinSecSnapshotStoragePath $sandbox 'linked/escape.md'}
        Reject-PathContract {Assert-WinSecSnapshotStoragePath $link 'reports/escape.md'}
        # Remove only this junction, with no recursion through its target.
        Remove-Item -LiteralPath $link -Force
        Assert-PathContract ([IO.Directory]::Exists($target))
    }
    Check-PathContract 'New snapshot contents are ignored by Git; placeholder stays eligible' {
        $ignored=@(& git -C $root check-ignore --no-index scans/SYNTHETIC/record.json);$code=$LASTEXITCODE
        Assert-PathContract ($code -eq 0 -and $ignored.Count -eq 1)
        $null=& git -C $root check-ignore --no-index scans/.gitkeep;Assert-PathContract ($LASTEXITCODE -eq 1)
    }
    Check-PathContract 'The backend default is opt-in and preserves the validated catalogue' {
        Assert-PathContract ((Get-Content -Raw -LiteralPath (Join-Path $root 'src/Core/ScanCoordinator.ps1')) -match 'NewTechnicalStorageEnabled\s*=\s*\$false')
        $checks=Get-Content -Raw -LiteralPath (Join-Path $root 'config/checks.json') | ConvertFrom-Json
        Assert-PathContract (@($checks.checks | Where-Object {$_.execution.enabled}).Count -eq 11)
    }
} finally {
    $resolved=[IO.Path]::GetFullPath($sandbox)
    if(-not $resolved.StartsWith($temporaryBase+'\',[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($resolved) -notmatch '\Awsa-[a-f0-9]{16}\z'){throw 'Unsafe test cleanup target.'}
    $leftover=Join-Path $resolved 'linked'
    $linkItem=Get-Item -LiteralPath $leftover -Force -ErrorAction SilentlyContinue
    if($null -ne $linkItem -and ($linkItem.Attributes -band [IO.FileAttributes]::ReparsePoint)){Remove-Item -LiteralPath $leftover -Force}
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
Write-Host ("Snapshot paths integration: $passed passed; $failed failed.")
if($failed){exit 1}
