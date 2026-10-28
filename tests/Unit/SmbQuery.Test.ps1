# Owned synthetic PowerShell jobs only. No SMB, CIM or registry reads.
[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Checks/Network/Test-SMBv1.ps1')
function Get-SmbServerConfiguration {
    [CmdletBinding()]param([switch]$AsJob)
    if(-not $AsJob){throw 'Unexpected synthetic query.'}
    $script:owned=Start-Job -ArgumentList $script:resultCount -ScriptBlock {param($n);for($i=0;$i -lt $n;$i++){[pscustomobject]@{EnableSMB1Protocol=$false}}}
    return $script:owned
}
function Assert-SmbQuery {param([bool]$Value);if(-not $Value){throw 'SMB query assertion failed.'}}
$unrelated=Start-Job -ScriptBlock {'Unrelated synthetic result'}
try {
    $script:resultCount=1;$r=Invoke-WinSecSmbQuery Server -CancellationAction {$false}
    Assert-SmbQuery ($r.EnableSMB1Protocol -ceq $false -and $null -eq (Get-Job -Id $owned.Id -ErrorAction SilentlyContinue))
    Write-Host '[PASS] Successful query receives exactly one result and removes only its owned job'
    $caught=$false;try{$null=Invoke-WinSecSmbQuery Server -CancellationAction {$true}}catch [OperationCanceledException]{$caught=$true}
    Assert-SmbQuery ($caught -and $null -eq (Get-Job -Id $owned.Id -ErrorAction SilentlyContinue) -and $null -ne (Get-Job -Id $unrelated.Id -ErrorAction Stop))
    Write-Host '[PASS] Cancellation preserves unrelated jobs'
    foreach($count in @(0,2)){
        $script:resultCount=$count;$caught=$false;try{$null=Invoke-WinSecSmbQuery Server}catch{$caught=$true}
        Assert-SmbQuery ($caught -and $null -eq (Get-Job -Id $owned.Id -ErrorAction SilentlyContinue))
    }
    Write-Host '[PASS] Missing and duplicate provider records fail closed'
    foreach($bad in @('Set-SmbServerConfiguration','Server -CimSession remote','Other')){
        $caught=$false;try{$null=Invoke-WinSecSmbQuery $bad}catch{$caught=$true};Assert-SmbQuery $caught
    }
    Write-Host '[PASS] Remote selectors and unreviewed commands are rejected before execution'
} finally {
    foreach($job in @($owned,$unrelated)){if($job -and $null -ne (Get-Job -Id $job.Id -ErrorAction SilentlyContinue)){Stop-Job $job -ErrorAction SilentlyContinue;Remove-Job $job -Force -ErrorAction SilentlyContinue}}
}
Write-Host 'SMB query: 4 passed; 0 failed.'
