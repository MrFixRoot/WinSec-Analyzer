# Real owned job lifecycle, synthetic output. The native CIM script never executes.
[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/RdpTelemetry.ps1')
. (Join-Path $root 'src/Checks/Network/Test-RDP.ps1')
$script:nativeStart=Get-Command Start-Job -CommandType Cmdlet
$script:queryCount=0;$script:outputCount=1;$script:lastArgs=@();$script:owned=$null
$script:absentField='';$script:badSchema=$false;$script:metadataFailure=$false
function New-WinSecRdpQueryJob {
    [CmdletBinding()]param($ScriptBlock,[object[]]$ArgumentList)
    $script:queryCount++;$script:lastArgs=$ArgumentList
    if(-not $ScriptBlock.ToString().Contains('Get-CimInstance @queryParameters')){throw 'Unexpected native query script.'}
    if($ArgumentList[2] -contains 'Password' -or $ArgumentList[2] -contains 'UserName' -or $ArgumentList[2] -contains 'Certificates' -or
        $ArgumentList[2] -contains 'StringSecurityDescriptor'){throw 'Sensitive native property requested.'}
    $script:owned=& $script:nativeStart -ArgumentList $script:outputCount,$ScriptBlock.ToString(),$ArgumentList,$script:absentField,$script:badSchema,$script:metadataFailure -ScriptBlock {
        param($n,$body,$call,$absent,$wrongSchema,$failMetadata)
        function Get-CimClass {
            [CmdletBinding()]param($Namespace,$ClassName,$OperationTimeoutSec)
            if($failMetadata){throw 'PRIVATE-SCHEMA-ERROR'}
            if($Namespace -cne 'root/cimv2/TerminalServices' -or $OperationTimeoutSec -ne 5){throw 'Unexpected synthetic schema query.'}
            [pscustomobject]@{CimClassName=if($wrongSchema){'Win32_LogonSession'}else{$ClassName};CimClassProperties=@(
                foreach($name in @($call[2])+@('Password','Certificates','UnreviewedField')){if($name -cne $absent){[pscustomobject]@{Name=$name}}}
            )}
        }
        function Get-CimInstance {
            [CmdletBinding()]param($Namespace,$ClassName,$Property,$Filter,$OperationTimeoutSec)
            if($Property -contains $absent -and $absent){throw 'A missing property invalidated the whole provider query.'}
            if(@($Property|Where-Object {$_ -cnotin $call[2]}).Count){throw 'Query broadened beyond the reviewed projection.'}
            for($i=0;$i -lt $n;$i++){
                $r=[ordered]@{}
                foreach($name in $Property){$r[$name]=if($name -ceq 'TerminalName'){'Synthetic-'+$i}else{[uint32]0}}
                [pscustomobject]$r
            }
        }
        & ([scriptblock]::Create($body)) @call
    }
    return $script:owned
}
Set-Alias Start-Job New-WinSecRdpQueryJob -Scope Script
function Assert-RdpQuery {param([bool]$Value);if(-not $Value){throw 'RDP query assertion failed.'}}
$unrelated=& $script:nativeStart -ScriptBlock {'Unrelated synthetic job'}
try {
    foreach($c in Get-WinSecRdpClasses){
        $r=@(Invoke-WinSecRdpQuery $c.Id -CancellationAction {$false})
        $expected=if($c.Singleton){$c.Fields}else{@('TerminalName')+$c.Fields}
        Assert-RdpQuery ($r.Count -eq 1 -and $lastArgs[0] -ceq 'root/cimv2/TerminalServices' -and $lastArgs[1] -ceq $c.Class -and
            ($lastArgs[2] -join '|') -ceq ($expected -join '|') -and $null -eq $lastArgs[3] -and $null -eq (Get-Job -Id $owned.Id -ErrorAction SilentlyContinue))
    }
    Write-Host '[PASS] Seven host providers query only explicit reviewed configuration fields and clean up owned jobs'
    foreach($role in @('Platform','Services')){
        $null=Invoke-WinSecRdpQuery $role
        Assert-RdpQuery ($lastArgs[0] -ceq 'root/cimv2' -and ($role -ne 'Services' -or $lastArgs[3] -ceq "Name = 'TermService' OR Name = 'UmRdpService' OR Name = 'SessionEnv'"))
    }
    Write-Host '[PASS] Platform and service sources are local with a fixed service filter'
    $caught=$false;try{$null=Invoke-WinSecRdpQuery General -CancellationAction {$true}}catch [OperationCanceledException]{$caught=$true}
    Assert-RdpQuery ($caught -and $null -eq (Get-Job -Id $owned.Id -ErrorAction SilentlyContinue) -and $null -ne (Get-Job -Id $unrelated.Id -ErrorAction Stop))
    Write-Host '[PASS] Esc stops and removes only the query-owned job'
    $script:outputCount=65;$caught=$false;try{$null=Invoke-WinSecRdpQuery General}catch{$caught=$true}
    Assert-RdpQuery ($caught -and $null -eq (Get-Job -Id $owned.Id -ErrorAction SilentlyContinue))
    Write-Host '[PASS] Oversized inventory fails closed without silently truncating records'
    $script:outputCount=1;$caught=$false;try{$null=Invoke-WinSecRdpQuery General -CancellationAction {'invalid'}}catch{$caught=$true}
    Assert-RdpQuery ($caught -and $null -eq (Get-Job -Id $owned.Id -ErrorAction SilentlyContinue))
    Write-Host '[PASS] Malformed cancellation responses reject the query and release its job'
    $before=$queryCount
    foreach($role in @('Win32_LogonSession','General -CimSession remote','Other')){
        $caught=$false;try{$null=Invoke-WinSecRdpQuery $role}catch{$caught=$true};Assert-RdpQuery $caught
    }
    Assert-RdpQuery ($queryCount -eq $before)
    Write-Host '[PASS] Remote or unreviewed selectors are rejected before job creation'
    $script:absentField='AllowDwm';$metadata=@();$r=@(Invoke-WinSecRdpQuery Redirection -Metadata ([ref]$metadata))
    Assert-RdpQuery ($r.Count -eq 1 -and $metadata.Count -eq 1 -and $metadata[0] -ceq 'AllowDwm' -and
        $null -eq $r[0].PSObject.Properties['AllowDwm'] -and $null -ne $r[0].PSObject.Properties['ClipboardMapping'] -and
        $null -eq $r[0].PSObject.Properties['Password'])
    Write-Host '[PASS] Missing schema properties no longer discard the remaining redirection readings'
    $script:absentField='';$script:badSchema=$true;$caught=$false
    try{$null=Invoke-WinSecRdpQuery General}catch{$caught=($_.Exception.Data['WinSecRdpQueryStatus'] -ceq 'SCHEMA_INVALID')}
    Assert-RdpQuery ($caught -and $null -eq (Get-Job -Id $owned.Id -ErrorAction SilentlyContinue))
    Write-Host '[PASS] Foreign class metadata fails closed without reading its instances'
    $script:badSchema=$false;$script:metadataFailure=$true;$caught=$false
    try{$null=Invoke-WinSecRdpQuery General}catch{$caught=($_.Exception.Data['WinSecRdpQueryStatus'] -ceq 'QUERY_FAILED' -and $_.Exception.Message -notmatch 'PRIVATE-')}
    Assert-RdpQuery $caught
    Write-Host '[PASS] Schema read failures remain failures and expose only a closed diagnostic'
} finally {
    foreach($job in @($owned,$unrelated)){if($job -and $null -ne (Get-Job -Id $job.Id -ErrorAction SilentlyContinue)){Stop-Job $job -ErrorAction SilentlyContinue;Remove-Job $job -Force -ErrorAction SilentlyContinue}}
}
Write-Host 'RDP query: 9 passed; 0 failed.'
