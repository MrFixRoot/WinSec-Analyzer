# Exercise the real worker body and owned-job lifecycle with synthetic CIM only.
[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/OpenPortsTelemetry.ps1')
. (Join-Path $root 'src/Checks/Network/Test-OpenPorts.ps1')
$nativeStart=Get-Command Start-Job -CommandType Cmdlet
$script:owned=$null;$script:portsQueryCount=1;$script:absent='';$script:foreign=$false;$script:fail=$false;$script:lastArgs=@()
function New-WinSecOpenPortsQueryJob {
    [CmdletBinding()]param($ScriptBlock,[object[]]$ArgumentList)
    $script:lastArgs=$ArgumentList
    if(@($ArgumentList[2]|Where-Object {$_ -cin @('RemoteAddress','RemotePort','CommandLine','ExecutablePath','UserName')}).Count){throw 'Sensitive property requested.'}
    $script:owned=& $script:nativeStart -ArgumentList $ScriptBlock.ToString(),$ArgumentList,$script:portsQueryCount,$script:absent,$script:foreign,$script:fail -ScriptBlock {
        param($body,$call,$count,$missing,$badClass,$failed)
        function Get-CimClass {
            [CmdletBinding()]param($Namespace,$ClassName,$OperationTimeoutSec)
            if($failed){throw 'PRIVATE-SCHEMA'}
            if($Namespace -cne 'root/StandardCimv2' -or $OperationTimeoutSec -ne 5){throw 'Unexpected schema query.'}
            [pscustomobject]@{CimClassName=$(if($badClass){'Foreign_Class'}else{$ClassName});CimClassProperties=@(foreach($name in @($call[2])+@('RemoteAddress','CommandLine')){if($name -cne $missing){[pscustomobject]@{Name=$name}}})}
        }
        function Get-CimInstance {
            [CmdletBinding()]param($Namespace,$ClassName,$Property,$Filter,$OperationTimeoutSec)
            if(@($Property|Where-Object {$_ -cnotin $call[2] -or ($missing -and $_ -ceq $missing)}).Count -or $OperationTimeoutSec -ne 5){throw 'Query projection changed.'}
            for($i=0;$i -lt $count;$i++){$r=[ordered]@{};foreach($name in $Property){$r[$name]=[uint32]0};[pscustomobject]$r}
        }
        & ([scriptblock]::Create($body)) @call
    }
    return $script:owned
}
Set-Alias Start-Job New-WinSecOpenPortsQueryJob -Scope Script
function Assert-PortsQuery {param([bool]$Value);if(-not $Value){throw 'Endpoint query assertion failed.'}}
function Reject-PortsQuery {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true;Assert-PortsQuery ($_.Exception.Message -notmatch 'PRIVATE-')};Assert-PortsQuery $caught}
$unrelated=& $nativeStart -ScriptBlock {'Synthetic unrelated job'}
try {
    foreach($role in @('Platform','TCP','UDP')){
        $r=@(Invoke-WinSecOpenPortsQuery $role)
        Assert-PortsQuery ($r.Count -eq 1 -and $null -eq (Get-Job -Id $owned.Id -ErrorAction SilentlyContinue))
        if($role -ceq 'TCP'){Assert-PortsQuery ($lastArgs[3] -ceq 'State = 2' -and $lastArgs[0] -ceq 'root/StandardCimv2')}
        if($role -ceq 'UDP'){Assert-PortsQuery ($null -eq $lastArgs[3] -and $lastArgs[1] -ceq 'MSFT_NetUDPEndpoint')}
    }
    Write-Host '[PASS] Three local providers use exact projections and TCP LISTEN filtering'
    $script:absent='OwningProcess';$r=@(Invoke-WinSecOpenPortsQuery UDP);Assert-PortsQuery ($null -eq $r[0].PSObject.Properties['OwningProcess'])
    Write-Host '[PASS] Optional schema absence preserves required endpoint fields'
    $script:absent='LocalPort';Reject-PortsQuery {Invoke-WinSecOpenPortsQuery TCP};$script:absent=''
    Write-Host '[PASS] Missing required schema fields reject the provider'
    $script:foreign=$true;Reject-PortsQuery {Invoke-WinSecOpenPortsQuery UDP};$script:foreign=$false
    Write-Host '[PASS] Foreign CIM class metadata is rejected'
    $script:fail=$true;Reject-PortsQuery {Invoke-WinSecOpenPortsQuery UDP};$script:fail=$false
    Write-Host '[PASS] Provider exceptions never expose private messages'
    $script:portsQueryCount=513;Reject-PortsQuery {Invoke-WinSecOpenPortsQuery UDP};$script:portsQueryCount=0
    $empty=@(Invoke-WinSecOpenPortsQuery UDP);Assert-PortsQuery ($empty.Count -eq 0)
    Write-Host '[PASS] Overflow is rejected and a genuinely empty provider remains valid'
    $cancelled=$false;try{$null=Invoke-WinSecOpenPortsQuery TCP -CancellationAction {$true}}catch [OperationCanceledException]{$cancelled=$true}
    Assert-PortsQuery ($cancelled -and $null -eq (Get-Job -Id $owned.Id -ErrorAction SilentlyContinue) -and $null -ne (Get-Job -Id $unrelated.Id -ErrorAction Stop))
    Write-Host '[PASS] Esc cleans only the owned job'
    Reject-PortsQuery {Invoke-WinSecOpenPortsQuery TCP -CancellationAction {'invalid'}}
    Reject-PortsQuery {Invoke-WinSecOpenPortsQuery 'TCP -CimSession other'}
    Write-Host '[PASS] Malformed cancellation and role injection are rejected'
}finally{foreach($job in @($owned,$unrelated)){if($job -and $null -ne (Get-Job -Id $job.Id -ErrorAction SilentlyContinue)){Stop-Job $job -ErrorAction SilentlyContinue;Remove-Job $job -Force -ErrorAction SilentlyContinue}}}
Write-Host 'Open Ports query: 8 passed; 0 failed.'
