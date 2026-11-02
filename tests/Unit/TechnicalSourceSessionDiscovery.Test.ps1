[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Services/TechnicalSourceSessionDiscovery.ps1')
foreach($command in @('Get-CimInstance','Get-CimClass','Get-MpComputerStatus','Get-MpPreference','Start-Job')){
    Set-Item ('Function:script:'+$command) {throw 'Native acquisition forbidden.'}
}
$passed=0;$failed=0;$base=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$sandbox=Join-Path $base ('wdu-'+[guid]::NewGuid().ToString('N').Substring(0,8));$null=[IO.Directory]::CreateDirectory($sandbox)
$id='local:hw1-'+('b'*64)
function Assert-TDU {param([bool]$Value);if(-not $Value){throw 'Technical discovery unit assertion failed.'}}
function Reject-TDU {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-TDU $caught}
function Test-TDU {param([string]$Case,[scriptblock]$Action)
    try{& $Action;$script:passed++;Write-Host ('[PASS] '+$Case)}catch{$script:failed++;Write-Host ('[FAIL] '+$Case+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}
try{
    foreach($type in @('WinSec.StoredSession','WinSec.TechnicalSnapshot','unknown')){Test-TDU 'Unknown artifact type rejects before inventory access' {
        function Open-WinSecTechnicalSessionOwner {throw 'Unexpected inventory access.'}
        Reject-TDU {Read-WinSecTechnicalSourceSessions $sandbox $id -ArtifactType $type}
        Assert-TDU (-not [IO.Directory]::Exists((Join-Path $sandbox 'data')))
    }}
    foreach($version in @('0.9.0','1.1.0','2.0.0',@('1.0.0'))){Test-TDU 'Unknown or non-scalar version never guesses a reader' {
        Reject-TDU {Read-WinSecTechnicalSourceSessions $sandbox $id -SchemaVersion $version}
        Assert-TDU (-not [IO.Directory]::Exists((Join-Path $sandbox 'data')))
    }}
    foreach($badId in @('foreign',('local:hw1-'+('B'*64)),'../device')){Test-TDU 'Invalid device cannot inspect or create a namespace' {
        Reject-TDU {Read-WinSecTechnicalSourceSessions $sandbox $badId}
        Assert-TDU (-not [IO.Directory]::Exists((Join-Path $sandbox 'scans')))
    }}
    Test-TDU 'Cancellation before I/O publishes no result and creates no inventory directory' {
        $cancelled=$false;try{$null=Read-WinSecTechnicalSourceSessions $sandbox $id -CancellationAction {$true}}catch [OperationCanceledException]{$cancelled=$true}
        Assert-TDU ($cancelled -and -not [IO.Directory]::Exists((Join-Path $sandbox 'data')))
    }
    Test-TDU 'Non-Boolean cancellation responses reject before filesystem mutation' {
        Reject-TDU {Read-WinSecTechnicalSourceSessions $sandbox $id -CancellationAction {'yes'}}
        Assert-TDU (-not [IO.Directory]::Exists((Join-Path $sandbox 'data')))
    }
    $core=Join-Path $sandbox 'src/Core';$null=[IO.Directory]::CreateDirectory($core)
    Copy-Item -LiteralPath (Join-Path $root 'src/Core/TargetRegistry.ps1') -Destination (Join-Path $core 'TargetRegistry.ps1')
    $null=[IO.Directory]::CreateDirectory((Join-Path $sandbox 'data'))
    $inventory=[pscustomobject]@{schemaVersion='1.0.0';targets=@([pscustomobject]@{DeviceId=$id;Hostname='SYNTHETIC';Mode='LOCAL';Enabled=$true})}
    [IO.File]::WriteAllText((Join-Path $sandbox 'data/devices.json'),(ConvertTo-Json $inventory -Depth 6 -Compress))
    Test-TDU 'A registered device with no technical namespace returns an explicit empty discovery without creating it' {
        $before=Get-WinSecDeviceInventoryFingerprint $sandbox;$r=Read-WinSecTechnicalSourceSessions $sandbox $id
        Assert-TDU ($r.ArtifactType -ceq 'WinSec.TechnicalSourceDiscovery' -and $r.SchemaVersion -ceq '1.0.0' -and $r.DeviceId -ceq $id -and
            $r.Sessions -is [array] -and $r.Sessions.Count -eq 0 -and -not [IO.Directory]::Exists((Join-Path $sandbox 'scans')) -and
            (Get-WinSecDeviceInventoryFingerprint $sandbox) -ceq $before)
    }
    Test-TDU 'An unknown device is not silently represented as an empty registered history' {
        Reject-TDU {Read-WinSecTechnicalSourceSessions $sandbox ('local:hw1-'+('c'*64))}
    }
    Test-TDU 'The actual inventory lease rejects concurrent discovery and is released afterwards' {
        $lease=Open-WinSecDeviceInventoryStore $sandbox
        try{Reject-TDU {Read-WinSecTechnicalSourceSessions $sandbox $id}}finally{$lease.Lock.Dispose()}
        Assert-TDU ((Read-WinSecTechnicalSourceSessions $sandbox $id).Sessions.Count -eq 0)
    }
    Test-TDU 'An empty protected metadata directory is distinct from historical sessions and is not indexed' {
        $layout=[pscustomobject]@{DeviceKey=(Get-WinSecSnapshotDeviceKey $id);Directory='technical-sessions'}
        $held=Open-WinSecTechnicalSessionDirectories $sandbox $layout -Create
        try{}finally{foreach($h in $held){$h.Dispose()}}
        Assert-TDU ((Read-WinSecTechnicalSourceSessions $sandbox $id).Sessions.Count -eq 0 -and
            -not [IO.Directory]::Exists((Join-Path $sandbox ('scans/'+$layout.DeviceKey+'/sessions'))))
    }
    Test-TDU 'An ordinary .gitkeep placeholder is retained without becoming a session' {
        $placeholder=Join-Path $sandbox ('scans/'+(Get-WinSecSnapshotDeviceKey $id)+'/technical-sessions/.gitkeep')
        [IO.File]::WriteAllText($placeholder,'PLACEHOLDER')
        Assert-TDU ((Read-WinSecTechnicalSourceSessions $sandbox $id).Sessions.Count -eq 0 -and [IO.File]::ReadAllText($placeholder) -ceq 'PLACEHOLDER')
        Remove-Item -LiteralPath $placeholder
    }
    Test-TDU 'A directory named .gitkeep cannot hide unknown nested artifacts' {
        $placeholder=Join-Path $sandbox ('scans/'+(Get-WinSecSnapshotDeviceKey $id)+'/technical-sessions/.gitkeep')
        $null=[IO.Directory]::CreateDirectory($placeholder)
        Reject-TDU {Read-WinSecTechnicalSourceSessions $sandbox $id}
        Assert-TDU ([IO.Directory]::Exists($placeholder))
    }
}finally{
    $full=[IO.Path]::GetFullPath($sandbox)
    if([IO.Path]::GetDirectoryName($full) -cne $base -or [IO.Path]::GetFileName($full) -cnotmatch '\Awdu-[a-f0-9]{8}\z'){throw 'Unsafe discovery unit fixture cleanup.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
Write-Host ("Technical session discovery unit: $passed passed; $failed failed.");if($failed){exit 1}
