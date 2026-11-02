[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Services/TechnicalSourceSessionStore.ps1')
foreach($command in @('Get-CimInstance','Get-CimClass','Get-MpComputerStatus','Get-MpPreference','Start-Job')){
    Set-Item ('Function:script:'+$command) {throw 'Native acquisition forbidden.'}
}
$passed=0;$failed=0;$base=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$sandbox=Join-Path $base ('wsu-'+[guid]::NewGuid().ToString('N').Substring(0,8));$null=[IO.Directory]::CreateDirectory($sandbox)
$identity=[pscustomobject]@{DeviceId='local:hw1-'+('b'*64);ScanId='unit-session';ScopeType='CONTROL';ScopeKey='WSA-SYS-001'}
function Assert-SSU {param([bool]$Value);if(-not $Value){throw 'Technical session storage unit assertion failed.'}}
function Reject-SSU {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-SSU $caught}
function Test-SSU {param([string]$Case,[scriptblock]$Action)
    $owner=$identity.PSObject.Copy()
    try{& $Action;$script:passed++;Write-Host ('[PASS] '+$Case)}catch{$script:failed++;Write-Host ('[FAIL] '+$Case+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}
try{
    Test-SSU 'Storage dispatch selects only the explicit technical session 1.0 format' {
        $format=Resolve-WinSecTechnicalSessionStorageFormat 'WinSec.TechnicalSourceSession' '1.0.0'
        Assert-SSU ($format.Directory -ceq 'technical-sessions' -and $format.MaxBytes -eq 16384)
    }
    foreach($type in @('WinSec.StoredSession','WinSec.TechnicalSnapshot','winsec.technicalSourceSession','UNKNOWN','')){
        Test-SSU ('Unknown artifact types cannot fall back to historical readers: '+$type) {Reject-SSU {Resolve-WinSecTechnicalSessionStorageFormat $type '1.0.0'}}
    }
    foreach($version in @('0.9.0','2.0.0','1.0','1.1.0','')){
        Test-SSU ('Unknown schema version is rejected: '+$version) {Reject-SSU {Resolve-WinSecTechnicalSessionStorageFormat 'WinSec.TechnicalSourceSession' $version}}
    }
    Test-SSU 'Array version or type metadata does not coerce' {
        Reject-SSU {Resolve-WinSecTechnicalSessionStorageFormat @('WinSec.TechnicalSourceSession') '1.0.0'}
        Reject-SSU {Resolve-WinSecTechnicalSessionStorageFormat 'WinSec.TechnicalSourceSession' @('1.0.0')}
    }
    foreach($scope in @('CONTROL','SECTION','DEVICE')){Test-SSU ('Stable isolated path and pending sibling for '+$scope) {
        $owner.ScopeType=$scope;$owner.ScopeKey=switch($scope){CONTROL {'WSA-SYS-001'};SECTION {'SystemSecurity'};DEVICE {'ALL'}}
        $layout=Get-WinSecTechnicalSessionStorageLayout $sandbox $owner
        $expected='scans\'+(Get-WinSecSnapshotDeviceKey $owner.DeviceId)+'\technical-sessions\'
        Assert-SSU ($layout.Path.Contains($expected) -and [IO.Path]::GetFileName($layout.Path) -cmatch '\A[a-f0-9]{64}\.json\z' -and
            $layout.Temporary -ceq ($layout.Path+'.tmp') -and -not [IO.Directory]::Exists((Join-Path $sandbox 'scans')))
    }}
    Test-SSU 'Identity property order does not change the canonical path' {
        $other=[pscustomobject]@{ScopeKey=$owner.ScopeKey;ScopeType=$owner.ScopeType;ScanId=$owner.ScanId;DeviceId=$owner.DeviceId}
        Assert-SSU ((Get-WinSecTechnicalSessionStorageLayout $sandbox $owner).Path -ceq (Get-WinSecTechnicalSessionStorageLayout $sandbox $other).Path)
    }
    foreach($damage in @('Device','Scan','Scope','Section','OtherControl','Extra','Array')){Test-SSU ('Unsafe or foreign layout identity rejects: '+$damage) {
        switch($damage){Device {$owner.DeviceId='../foreign'};Scan {$owner.ScanId='../foreign'};Scope {$owner.ScopeType='SECTION'}
            Section {$owner.ScopeType='SECTION';$owner.ScopeKey='NetworkSecurity'};OtherControl {$owner.ScopeKey='WSA-SYS-002'}
            Extra {$owner|Add-Member Path 'C:\private'};Array {$owner.ScanId=@('unit-session')}}
        Reject-SSU {Get-WinSecTechnicalSessionStorageLayout $sandbox $owner}
    }}
    Test-SSU 'Getters in expected identity never execute' {
        $script:getters=0;$owner|Add-Member -MemberType ScriptProperty -Name ScanId -Value {$script:getters++;throw 'PRIVATE-SSU-SECRET'} -Force
        Reject-SSU {Get-WinSecTechnicalSessionStorageLayout $sandbox $owner};Assert-SSU ($script:getters -eq 0)
    }
    Test-SSU 'Different device, scan or scope cannot alias the same container' {
        $paths=@((Get-WinSecTechnicalSessionStorageLayout $sandbox $owner).Path)
        $other=$owner.PSObject.Copy();$other.DeviceId='local:hw1-'+('c'*64);$paths+=(Get-WinSecTechnicalSessionStorageLayout $sandbox $other).Path
        $other=$owner.PSObject.Copy();$other.ScanId='another-session';$paths+=(Get-WinSecTechnicalSessionStorageLayout $sandbox $other).Path
        $other=$owner.PSObject.Copy();$other.ScopeType='SECTION';$other.ScopeKey='SystemSecurity';$paths+=(Get-WinSecTechnicalSessionStorageLayout $sandbox $other).Path
        Assert-SSU (@($paths|Sort-Object -Unique).Count -eq 4)
    }
    foreach($badRoot in @('\\server\share','C:relative','C:\unsafe\..\root','C:\unsafe.\root')){
        Test-SSU ('Unsafe project root cannot choose a storage location: '+$badRoot) {Reject-SSU {Get-WinSecTechnicalSessionStorageLayout $badRoot $owner}}
    }
    Test-SSU 'Unknown read or recovery dispatch rejects before any inventory or directory access' {
        $script:inventoryCalls=0;function Open-WinSecTechnicalSessionOwner {$script:inventoryCalls++;throw 'Unexpected inventory access.'}
        Reject-SSU {Read-WinSecTechnicalSourceSession $sandbox $owner -ArtifactType 'WinSec.StoredSession'}
        Reject-SSU {Repair-WinSecTechnicalSourceSession $sandbox $owner ('A'*64) -SchemaVersion '9.0.0'}
        Assert-SSU ($script:inventoryCalls -eq 0 -and -not [IO.Directory]::Exists((Join-Path $sandbox 'data')))
    }
    foreach($digest in @('','abc',('a'*64),@('A'*64))){Test-SSU 'Recovery requires an explicit uppercase scalar digest before filesystem access' {
        Reject-SSU {Repair-WinSecTechnicalSourceSession $sandbox $owner $digest}
    }}
    Test-SSU 'Cancellation before recovery creates no data or storage directories' {
        $cancelled=$false;try{$null=Repair-WinSecTechnicalSourceSession $sandbox $owner ('A'*64) -CancellationAction {$true}}catch [OperationCanceledException]{$cancelled=$true}
        Assert-SSU ($cancelled -and @(Get-ChildItem -LiteralPath $sandbox -Force).Count -eq 0)
    }
}finally{
    $full=[IO.Path]::GetFullPath($sandbox)
    if([IO.Path]::GetDirectoryName($full) -cne $base -or [IO.Path]::GetFileName($full) -cnotmatch '\Awsu-[a-f0-9]{8}\z'){throw 'Unsafe storage unit fixture cleanup.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
Write-Host ("Technical session storage unit: $passed passed; $failed failed.");if($failed){exit 1}
