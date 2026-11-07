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

function Show-WinSecMenuPage {
    param([string]$View,$Session,[string]$Domain,$Agent,$Catalog)
    Clear-Host
    Show-WinSecBanner
    $sections=@(Get-WinSecSections)
    $section=@($sections | Where-Object { $_.Domain -eq $Domain })
    switch ($View) {
        'main' {
            Write-Host '  SYSTEM AUDIT' -ForegroundColor Cyan
            foreach ($item in $sections) {
                $agents=@($Catalog | Where-Object { $_.domain -eq $item.Domain })
                $states=@($agents | ForEach-Object { Get-WinSecCollectorState $Session $_.id })
                $complete=@($states | Where-Object { $_.Text -eq 'Scanned' }).Count
                $attempted=@($states | Where-Object { $_.Text -ne 'Not yet' }).Count
                $label=if ($complete -eq $agents.Count) {'Scanned'} elseif ($attempted -eq 0) {'Not yet'} else {'{0}/{1} scanned' -f $attempted,$agents.Count}
                $color=if ($complete -eq $agents.Count) {'Green'} elseif ($attempted -gt 0) {'Yellow'} else {'Gray'}
                Write-Host ('  [{0}] {1,-24} {2}' -f $item.Number,$item.Name,$label) -ForegroundColor $color
            }
            Write-Host ''
            Write-Host '  PLUS' -ForegroundColor Cyan
            Write-Host '  [7] Cross-Domain Correlation   |   help = Help' -ForegroundColor DarkCyan
        }
        'section' {
            Write-Host ('  '+$section[0].Name) -ForegroundColor Cyan
            $agents=@($Catalog | Where-Object { $_.domain -eq $Domain })
            for ($i=0; $i -lt $agents.Count; $i++) {
                $state=Get-WinSecCollectorState $Session $agents[$i].id
                Write-Host ('  [{0}] {1,-26} {2}' -f ($i+1),$agents[$i].id,$state.Text) -ForegroundColor $state.Color
            }
        }
        'control' {
            $state=Get-WinSecCollectorState $Session $Agent.id
            Write-Host ('  '+$Agent.id+' | '+$state.Text) -ForegroundColor $state.Color
            Write-Host ('  '+$Agent.description) -ForegroundColor DarkGray
            Write-Host ''
            Write-Host '  [A] Analyze'
        }
        'framework' {
            Write-Host ('  Analyze / '+$Agent.id) -ForegroundColor Cyan
            Write-Host '  [C] CIS Benchmarks'
            Write-Host '  [N] NIST CSF 2.0'
        }
        'help' { Show-WinSecHelp -Domain $Domain }
        'correlations' {
            Write-Host '  PLUS / Cross-Domain Correlation' -ForegroundColor Cyan
            Write-Host '  [1] Network Security + Services & Hardening'
            Write-Host '  [2] Identity & Access + Logging & Auditing'
            Write-Host '  [3] Network Security + Identity & Access'
            Write-Host '  [4] System Security + Logging & Auditing'
            Write-Host '  [5] All Available Correlations'
        }
    }
    Write-Host ''
    Write-Host '  Esc = back / cancel   |   Q = quit   |   help = commands' -ForegroundColor DarkGray
    if ($Session.Snapshot) { Write-Host ('  Snapshot: '+$Session.Snapshot) -ForegroundColor DarkGray }
}

function Wait-WinSecResult {
    $answer=Read-WinSecInput -Hints @('Esc / Enter = back   |   Q = quit') -Shortcuts 'q'
    return (-not $answer.Cancelled -and $answer.Text -eq 'q')
}

function Invoke-WinSecMenu {
    param([string]$OutputRoot,[string]$Snapshot)
    $session=New-WinSecSession -OutputRoot $OutputRoot -Snapshot $Snapshot
    if ($Snapshot) { $session.Context=Get-WinSecSnapshotManifest -Snapshot $Snapshot }
    $catalog=@(Get-WinSecCatalog)
    $sections=@(Get-WinSecSections)
    $view='main'; $domain='all'; $agent=$null; $helpReturnView='main'; $quit=$false
    try {
        while (-not $quit) {
            Show-WinSecMenuPage -View $view -Session $session -Domain $domain -Agent $agent -Catalog $catalog
            $shortcuts=switch ($view) {
                'main' {'1234567q'}
                'section' { ((1..(@($catalog | Where-Object { $_.domain -eq $domain }).Count)) -join '')+'q' }
                'control' {'aq'}
                'framework' {'cnq'}
                'correlations' {'12345q'}
                default {'q'}
            }
            $collectorId=if ($null -ne $agent) {$agent.id} else {''}
            $answer=Read-WinSecInput -Hints @(Get-WinSecHint -Session $session -Domain $domain -Collector $collectorId) -Shortcuts $shortcuts
            if ($answer.Cancelled) {
                switch ($view) {
                    'section' { $view='main'; $domain='all'; $agent=$null }
                    'control' { $view='section'; $agent=$null }
                    'framework' { $view='control' }
                    'help' { $view=$helpReturnView }
                    'correlations' { $view='main'; $domain='all' }
                }
                continue
            }
            $text=$answer.Text
            if (-not $text) { continue }
            if ($text -eq 'q') { $quit=$true; continue }
            if ($text -in @('help','?')) {
                if ($view -ne 'help') { $helpReturnView=$view }
                $view='help'; continue
            }
            if ($view -eq 'main' -and $text -match '^[1-6]$') {
                $domain=$sections[[int]$text-1].Domain; $view='section'; continue
            }
            if ($view -eq 'main' -and $text -eq '7') { $view='correlations'; continue }
            $number=0
            if ($view -eq 'section' -and [int]::TryParse($text,[ref]$number)) {
                $agents=@($catalog | Where-Object { $_.domain -eq $domain })
                if ($number -ge 1 -and $number -le $agents.Count) { $agent=$agents[$number-1]; $view='control' }
                continue
            }
            if ($view -eq 'control' -and $text -eq 'a') { $view='framework'; continue }
            try {
                if ($view -eq 'framework' -and $text -in @('c','n')) {
                    $parameters=@{ Analyze=$agent.id; NoBanner=$true; Session=$session }
                    if ($text -eq 'c') { $parameters.Cis=$true } else { $parameters.Nist=$true }
                } elseif ($view -eq 'correlations' -and $text -match '^[1-5]$') {
                    $parameters=@{ Correlation=[int]$text; NoBanner=$true; Session=$session }
                } else {
                    $parameters=ConvertFrom-WinSecInputCommand -Text $text
                    if ($parameters.ContainsKey('Help')) {
                        if ($view -ne 'help') { $helpReturnView=$view }
                        $view='help'; continue
                    }
                    if ($parameters.Count -eq 0) { throw 'Escribe help para consultar los comandos disponibles.' }
                    $parameters.Session=$session
                    $parameters.NoBanner=$true
                }
                winsec @parameters | Out-Host
            } catch { Write-Warning $_.Exception.Message }
            $quit=Wait-WinSecResult
            if ($view -eq 'framework') { $view='control' }
        }
    } finally {
        Close-WinSecSession $session
    }
}
