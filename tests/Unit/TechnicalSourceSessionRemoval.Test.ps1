[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Services/TechnicalSourceSessionRemoval.ps1')
foreach($command in @('Get-CimInstance','Get-CimClass','Get-MpComputerStatus','Get-MpPreference','Start-Job')){
    Set-Item ('Function:script:'+$command) {throw 'Native acquisition forbidden.'}
}
$passed=0;$failed=0;$base=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$sandbox=Join-Path $base ('wru-'+[guid]::NewGuid().ToString('N').Substring(0,8));$null=[IO.Directory]::CreateDirectory($sandbox)
$id='local:hw1-'+('b'*64);$device=[pscustomobject]@{DeviceId=$id;Hostname='SYNTHETIC';Mode='LOCAL';Enabled=$true}
function Assert-TRU {param([bool]$Value);if(-not $Value){throw 'Technical removal unit assertion failed.'}}
function Reject-TRU {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-TRU $caught}
function Test-TRU {param([string]$Case,[scriptblock]$Action)
    try{& $Action;$script:passed++;Write-Host ('[PASS] '+$Case)}catch{$script:failed++;Write-Host ('[FAIL] '+$Case+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}
try{
    Test-TRU 'An absent namespace returns no files without creating directories or acquiring an inventory lease' {
        function Open-WinSecTechnicalSessionOwner {throw 'Unexpected owner lease.'}
        function Import-WinSecDeviceInventory {throw 'Unexpected inventory access.'}
        $r=Get-WinSecTechnicalSessionRemovalFiles $sandbox $id $device
        Assert-TRU ($r.Files.Count -eq 0 -and @(Get-ChildItem -LiteralPath $sandbox -Force).Count -eq 0)
    }
    foreach($invalid in @('foreign','local:hw1-'+('c'*64),'')){Test-TRU 'A foreign or malformed expected device cannot select files' {
        Reject-TRU {Get-WinSecTechnicalSessionRemovalFiles $sandbox $invalid $device}
    }}
    foreach($owner in @($null,[pscustomobject]@{},[pscustomobject]@{DeviceId=@($id)},@{DeviceId=$id})){
        Test-TRU 'Invalid caller owner metadata cannot authorize namespace recognition' {Reject-TRU {Get-WinSecTechnicalSessionRemovalFiles $sandbox $id $owner}}
    }
    Test-TRU 'Device identity getters do not execute' {
        $script:getters=0;$owner=[pscustomobject]@{DeviceId=$id}
        $owner|Add-Member -MemberType ScriptProperty -Name DeviceId -Value {$script:getters++;throw 'PRIVATE-REMOVAL-SECRET'} -Force
        Reject-TRU {Get-WinSecTechnicalSessionRemovalFiles $sandbox $id $owner};Assert-TRU ($script:getters -eq 0)
    }
    Test-TRU 'An unchanged shared source is included exactly once' {
        $files=New-Object 'Collections.Generic.List[object]';$known=@{};$path=Join-Path $sandbox 'same.json'
        Add-WinSecTechnicalSessionRemovalFile $files $known $path ('A'*64)
        Add-WinSecTechnicalSessionRemovalFile $files $known $path ('A'*64)
        Assert-TRU ($files.Count -eq 1 -and $known.Count -eq 1 -and $files[0].Hash -ceq ('A'*64))
    }
    Test-TRU 'Contradictory hashes cannot overwrite a previously verified source' {
        $files=New-Object 'Collections.Generic.List[object]';$known=@{};$path=Join-Path $sandbox 'same.json'
        Add-WinSecTechnicalSessionRemovalFile $files $known $path ('A'*64)
        Reject-TRU {Add-WinSecTechnicalSessionRemovalFile $files $known $path ('B'*64)}
        Assert-TRU ($files.Count -eq 1 -and $files[0].Hash -ceq ('A'*64))
    }
    foreach($hash in @('','bad',('a'*64))){Test-TRU 'Noncanonical removal digests reject without adding a file' {
        $files=New-Object 'Collections.Generic.List[object]';$known=@{}
        Reject-TRU {Add-WinSecTechnicalSessionRemovalFile $files $known (Join-Path $sandbox 'bad.json') $hash}
        Assert-TRU ($files.Count -eq 0 -and $known.Count -eq 0)
    }}
    Test-TRU 'A file occupying the namespace is not silently treated as an absent directory' {
        $dir=Join-Path $sandbox ('scans/'+(Get-WinSecSnapshotDeviceKey $id));$null=[IO.Directory]::CreateDirectory($dir)
        [IO.File]::WriteAllText((Join-Path $dir 'technical-sessions'),'FOREIGN')
        Reject-TRU {Get-WinSecTechnicalSessionRemovalFiles $sandbox $id $device}
    }
}finally{
    $full=[IO.Path]::GetFullPath($sandbox)
    if([IO.Path]::GetDirectoryName($full) -cne $base -or [IO.Path]::GetFileName($full) -cnotmatch '\Awru-[a-f0-9]{8}\z'){throw 'Unsafe technical removal unit cleanup.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
Write-Host ("Technical session removal unit: $passed passed; $failed failed.");if($failed){exit 1}
