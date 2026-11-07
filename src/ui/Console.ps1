function Show-WinSecBanner {
    [CmdletBinding()]
    param(
        [string]$Nickname='mrRoot',
        [string]$Description='Windows Security Auditor',
        [string]$GitHub='https://github.com/MrFixRoot/WinSec-Analyzer',
        [string]$LinkedIn='https://www.linkedin.com/in/normanlp/',
        [int]$Width=0
    )
    $logo=@(
        '██╗    ██╗██╗███╗   ██╗███████╗███████╗ ██████╗'
        '██║    ██║██║████╗  ██║██╔════╝██╔════╝██╔════╝'
        '██║ █╗ ██║██║██╔██╗ ██║███████╗█████╗  ██║     '
        '██║███╗██║██║██║╚██╗██║╚════██║██╔══╝  ██║     '
        '╚███╔███╔╝██║██║ ╚████║███████║███████╗╚██████╗'
        ' ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝ ╚═════╝'
    )
    if ($Width -le 0) { try { $Width=$Host.UI.RawUI.WindowSize.Width } catch { $Width=80 } }
    Write-Host ''
    foreach ($line in $logo) {
        $pad=[math]::Max(0,[int][math]::Floor(($Width-$line.Length)/2))
        Write-Host ((' '*$pad)+$line) -ForegroundColor Cyan
    }
    Write-Host ''
    Write-Host ('  '+$Description+'  |  by '+$Nickname) -ForegroundColor White
    Write-Host ('  GitHub   : '+$GitHub) -ForegroundColor DarkGray
    Write-Host ('  LinkedIn : '+$LinkedIn) -ForegroundColor DarkGray
    Write-Host '  Platform : Windows 11 desktop ONLY  |  Mode: READ-ONLY' -ForegroundColor Green
    Write-Host ''
}

function Invoke-WinSecMenu {
    param([string]$OutputRoot)
    $domains=@('SystemSecurity','NetworkSecurity','IdentityAccess','ServicesHardening','LoggingAuditing','PatchManagement')
    while ($true) {
        Clear-Host
        Show-WinSecBanner
        Write-Host '  SYSTEM AUDIT' -ForegroundColor Cyan
        for ($i=0;$i -lt $domains.Count;$i++) { Write-Host ('  [{0}] {1}' -f ($i+1),$domains[$i]) }
        Write-Host '  [7] Cross-Domain Correlation'
        Write-Host '  [8] Full System Collection'
        Write-Host '  [9] Analyze Saved Evidence'
        Write-Host '  [0] Exit'
        $choice=Read-Host '  Select an option'
        if ($choice -eq '0') { return }
        if ($choice -match '^[1-6]$') {
            $domain=$domains[[int]$choice-1]
            $agents=@(Get-WinSecCatalog | Where-Object { $_.domain -eq $domain })
            while ($true) {
                Clear-Host
                Show-WinSecBanner
                Write-Host ('  '+$domain) -ForegroundColor Cyan
                for ($i=0;$i -lt $agents.Count;$i++) { Write-Host ('  [{0}] {1}' -f ($i+1),$agents[$i].id) }
                Write-Host '  [S] Scan all collectors in this domain'
                Write-Host '  [A] Analyze latest snapshot (CIS / NIST)'
                Write-Host '  [0] Back'
                $sel=Read-Host '  Select'
                if ($sel -eq '0') { break }
                try {
                    if ($sel -match '^[sS]$') { [void](Invoke-WinSecCollection -Domain $domain -OutputRoot $OutputRoot) }
                    elseif ($sel -match '^[aA]$') {
                        $f=Read-Host '  Framework: cis, nist or cis,nist'
                        Clear-Host; Show-WinSecBanner
                        Invoke-WinSecNamedAnalysis -Framework @($f -split ',') -OutputRoot $OutputRoot -DomainFilter $domain
                    } elseif ($sel -match '^\d+$' -and [int]$sel -ge 1 -and [int]$sel -le $agents.Count) {
                        $agent=$agents[[int]$sel-1]
                        $act=Read-Host ('  '+$agent.id+' [S]can or [A]nalyze')
                        if ($act -match '^[sS]$') { [void](Invoke-WinSecCollection -Collector $agent.id -Domain $domain -OutputRoot $OutputRoot) }
                        elseif ($act -match '^[aA]$') {
                            $f=Read-Host '  Framework: cis, nist or cis,nist'
                            Clear-Host; Show-WinSecBanner
                            Invoke-WinSecNamedAnalysis -Framework @($f -split ',') -OutputRoot $OutputRoot -CollectorFilter $agent.id
                        }
                    }
                } catch { Write-Warning $_.Exception.Message }
                [void](Read-Host '  Press Enter to continue')
            }
        }
        elseif ($choice -eq '7') {
            try {
                Clear-Host; Show-WinSecBanner
                Write-Host '  [1] Network Security + Services & Hardening'
                Write-Host '  [2] Identity & Access + Logging & Auditing'
                Write-Host '  [3] Network Security + Identity & Access'
                Write-Host '  [4] System Security + Logging & Auditing'
                Write-Host '  [5] All Available Correlations'
                $n=Read-Host '  Select correlation'
                if ($n -match '^[1-5]$') { Clear-Host; Show-WinSecBanner; Invoke-WinSecNamedAnalysis -Correlation ([int]$n) -OutputRoot $OutputRoot }
            } catch { Write-Warning $_.Exception.Message }
            [void](Read-Host '  Press Enter to continue')
        }
        elseif ($choice -eq '8') {
            try { [void](Invoke-WinSecCollection -Domain all -OutputRoot $OutputRoot) } catch { Write-Warning $_.Exception.Message }
            [void](Read-Host '  Press Enter to continue')
        }
        elseif ($choice -eq '9') {
            try {
                $f=Read-Host '  Framework: cis, nist or cis,nist'
                Clear-Host; Show-WinSecBanner
                Invoke-WinSecNamedAnalysis -Framework @($f -split ',') -OutputRoot $OutputRoot
            } catch { Write-Warning $_.Exception.Message }
            [void](Read-Host '  Press Enter to continue')
        }
    }
}
