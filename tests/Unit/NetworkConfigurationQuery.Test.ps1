# Run the real worker against synthetic CIM implementations, never Windows providers.
[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/NetworkConfigurationTelemetry.ps1')
. (Join-Path $root 'src/Checks/Network/Test-NetworkConfiguration.ps1')
$nativeStart=Get-Command Start-Job -CommandType Cmdlet
$script:owned=$null;$script:queryCount=1;$script:absent='';$script:foreign=$false;$script:fail=$false;$script:lastArgs=@()
function New-WinSecNetworkConfigurationQueryJob {
    [CmdletBinding()]param($ScriptBlock,[object[]]$ArgumentList)
    $script:lastArgs=$ArgumentList
    if($ArgumentList[0] -ceq 'Registry'){throw 'Native registry access prohibited in worker tests.'}
    if(@($ArgumentList[3]|Where-Object {$_ -cin @('Name','InterfaceAlias','MACAddress','DNSDomain','SSID','UserName','Description')}).Count){throw 'Sensitive property requested.'}
    $script:owned=& $script:nativeStart -ArgumentList $ScriptBlock.ToString(),$ArgumentList,$script:queryCount,$script:absent,$script:foreign,$script:fail -ScriptBlock {
        param($body,$call,$count,$missing,$badClass,$failed)
        function Get-CimClass {
            [CmdletBinding()]param($Namespace,$ClassName,$OperationTimeoutSec)
            if($failed){throw 'PRIVATE-SCHEMA'}
            if($Namespace -cne $call[1] -or $ClassName -cne $call[2] -or $OperationTimeoutSec -ne 5){throw 'Unexpected schema query.'}
            [pscustomobject]@{CimClassName=$(if($badClass){'Foreign_Class'}else{$ClassName});CimClassProperties=@(foreach($name in @($call[3])+@('SSID','DNSDomain')){if($name -cne $missing){[pscustomobject]@{Name=$name}}})}
        }
        function Get-CimInstance {
            [CmdletBinding()]param($Namespace,$ClassName,$Property,$OperationTimeoutSec)
            if($Namespace -cne $call[1] -or $ClassName -cne $call[2] -or @($Property|Where-Object {$_ -cnotin $call[3] -or ($missing -and $_ -ceq $missing)}).Count -or $OperationTimeoutSec -ne 5){throw 'Query projection changed.'}
            for($i=0;$i -lt $count;$i++){$r=[ordered]@{};foreach($name in $Property){$r[$name]=[uint32]0};[pscustomobject]$r}
        }
        & ([scriptblock]::Create($body)) @call
    };return $script:owned
}
Set-Alias Start-Job New-WinSecNetworkConfigurationQueryJob -Scope Script
function Assert-NetworkQuery {param([bool]$Value);if(-not $Value){throw 'Network query assertion failed.'}}
function Reject-NetworkQuery {param([scriptblock]$Action,[string]$Expected='');$caught=$false;try{$null=& $Action}catch{$caught=$true;Assert-NetworkQuery ($_.Exception.Message -notmatch 'PRIVATE-');if($Expected){Assert-NetworkQuery ($_.Exception.Message -ceq $Expected)}};Assert-NetworkQuery $caught}
$unrelated=& $nativeStart -ScriptBlock {'Synthetic unrelated job'}
try {
    foreach($role in @('Platform')+@(Get-WinSecNetworkConfigurationProviders|ForEach-Object Role)){
        $r=@(Invoke-WinSecNetworkConfigurationQuery $role)
        Assert-NetworkQuery ($r.Count -eq 1 -and $null -eq (Get-Job -Id $owned.Id -ErrorAction SilentlyContinue))
    }
    Write-Host '[PASS] All ten local CIM roles use exact closed projections and clean their owned jobs'
    $script:absent='IPv4Connectivity';$r=@(Invoke-WinSecNetworkConfigurationQuery Profile);Assert-NetworkQuery ($null -eq $r[0].PSObject.Properties['IPv4Connectivity'])
    Write-Host '[PASS] Optional schema absence never broadens the query'
    $script:absent='InterfaceIndex';Reject-NetworkQuery {Invoke-WinSecNetworkConfigurationQuery Adapter} 'NETWORK_SCHEMA_INVALID';$script:absent=''
    $script:foreign=$true;Reject-NetworkQuery {Invoke-WinSecNetworkConfigurationQuery IPAddress} 'NETWORK_SCHEMA_INVALID';$script:foreign=$false
    Write-Host '[PASS] Missing required metadata and foreign classes are rejected'
    $script:fail=$true;Reject-NetworkQuery {Invoke-WinSecNetworkConfigurationQuery DNSServer} 'NETWORK_QUERY_FAILED';$script:fail=$false
    Write-Host '[PASS] Provider error text cannot escape'
    $script:queryCount=65;Reject-NetworkQuery {Invoke-WinSecNetworkConfigurationQuery Route} 'NETWORK_RECORD_LIMIT';$script:queryCount=0
    Assert-NetworkQuery (@(Invoke-WinSecNetworkConfigurationQuery Route).Count -eq 0)
    Write-Host '[PASS] Overflow rejects the full inventory and empty inventory is preserved'
    $cancelled=$false;try{$null=Invoke-WinSecNetworkConfigurationQuery Adapter -CancellationAction {$true}}catch [OperationCanceledException]{$cancelled=$true}
    Assert-NetworkQuery ($cancelled -and $null -eq (Get-Job -Id $owned.Id -ErrorAction SilentlyContinue) -and $null -ne (Get-Job -Id $unrelated.Id -ErrorAction Stop))
    Write-Host '[PASS] Esc cleans only this query job, never an unrelated job'
    Reject-NetworkQuery {Invoke-WinSecNetworkConfigurationQuery Adapter -CancellationAction {'invalid'}}
    Reject-NetworkQuery {Invoke-WinSecNetworkConfigurationQuery 'Adapter -CimSession other'}
    Write-Host '[PASS] Invalid cancellation and unreviewed roles are rejected'
}finally{foreach($job in @($owned,$unrelated)){if($job -and $null -ne (Get-Job -Id $job.Id -ErrorAction SilentlyContinue)){Stop-Job $job -ErrorAction SilentlyContinue;Remove-Job $job -Force -ErrorAction SilentlyContinue}}}
Write-Host 'Network Configuration query: 7 passed; 0 failed.'
