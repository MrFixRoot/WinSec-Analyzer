# Owned synthetic PowerShell jobs only; no Windows security providers.
[CmdletBinding()]param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Checks/Firewall/Test-Firewall.ps1')
function Get-NetFirewallProfile {
    [CmdletBinding()]param([switch]$AsJob,[string]$PolicyStore,[switch]$All)
    if(-not $AsJob -or $PolicyStore -cne 'ActiveStore'){throw 'Unexpected synthetic query.'}
    $script:ownedJob=Start-Job -ScriptBlock {[pscustomobject]@{Name='Synthetic';Enabled=$true}}
    return $script:ownedJob
}
function Assert-Query {param([bool]$Value);if(-not $Value){throw 'Firewall query assertion failed.'}}
$unrelated=Start-Job -ScriptBlock {'Unrelated synthetic result'}
try {
    $result=Invoke-WinSecFirewallQuery Get-NetFirewallProfile @{PolicyStore='ActiveStore';All=$true} -CancellationAction {$false}
    Assert-Query ($result.Count -eq 1 -and $result[0].Name -ceq 'Synthetic' -and $null -eq (Get-Job -Id $ownedJob.Id -ErrorAction SilentlyContinue))
    Write-Host '[PASS] Owned job is received and removed without modifying unrelated jobs'
    $caught=$false;try{$null=Invoke-WinSecFirewallQuery Get-NetFirewallProfile @{PolicyStore='ActiveStore'} -CancellationAction {$true}}catch [OperationCanceledException]{$caught=$true}
    Assert-Query ($caught -and $null -eq (Get-Job -Id $ownedJob.Id -ErrorAction SilentlyContinue) -and $null -ne (Get-Job -Id $unrelated.Id -ErrorAction Stop))
    Write-Host '[PASS] Cancellation stops and removes only the job owned by this query'
    foreach($arguments in @(@{PolicyStore='remote:server'},@{CimSession='remote'},@{PolicyStore='ActiveStore';ComputerName='remote'})) {
        $caught=$false;try{$null=Invoke-WinSecFirewallQuery Get-NetFirewallProfile $arguments}catch{$caught=$true};Assert-Query $caught
    }
    $caught=$false;try{$null=Invoke-WinSecFirewallQuery Set-NetFirewallProfile @{}}catch{$caught=$true};Assert-Query $caught
    Write-Host '[PASS] Remote and mutation arguments are rejected before command execution'
} finally {
    foreach($job in @($ownedJob,$unrelated)) {
        if($null -ne $job -and $null -ne (Get-Job -Id $job.Id -ErrorAction SilentlyContinue)){Stop-Job -Job $job -ErrorAction SilentlyContinue;Remove-Job -Job $job -Force -ErrorAction SilentlyContinue}
    }
}
Write-Host 'Firewall query: 3 passed; 0 failed.'
