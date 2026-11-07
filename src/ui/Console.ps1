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
    if ($Session.DeviceName) { Write-Host ('  Device: '+$Session.DeviceName) -ForegroundColor Cyan }
    $sections=@(Get-WinSecSections)
    $section=@($sections | Where-Object { $_.Domain -eq $Domain })
    switch ($View) {
        'main' {
            Write-Host '  SYSTEM AUDIT' -ForegroundColor Cyan
            foreach ($item in $sections) {
                $agents=@($Catalog | Where-Object { $_.domain -eq $item.Domain })
                $states=@($agents | ForEach-Object { Get-WinSecCollectorState $Session $_.id })
                $complete=@($states | Where-Object { $_.Status -eq 'COMPLETED' }).Count
                $attempted=@($states | Where-Object { $_.Text -ne 'Not yet' }).Count
                $label=if ($complete -eq $agents.Count) {'Scanned'} elseif ($attempted -eq 0) {'Not yet'} else {'{0}/{1} scanned' -f $attempted,$agents.Count}
                $color=if ($complete -eq $agents.Count) {'Green'} elseif ($attempted -gt 0) {'Yellow'} else {'Gray'}
                Write-Host ('  [{0}] {1,-24} {2}' -f $item.Number,$item.Name,$label) -ForegroundColor $color
            }
            Write-Host ''
            Write-Host '  PLUS' -ForegroundColor Cyan
            Write-Host '  [+] Cross-Domain Correlation' -ForegroundColor DarkCyan
        }
        'section' {
            Write-Host ('  '+$section[0].Name) -ForegroundColor Cyan
            $agents=@($Catalog | Where-Object { $_.domain -eq $Domain })
            for ($i=0; $i -lt $agents.Count; $i++) {
                $state=Get-WinSecCollectorState $Session $agents[$i].id
                $name=ConvertTo-WinSecControlName $agents[$i].id
                Write-Host ('  [{0}] {1,-26} {2}' -f ($i+1),$name,$state.Text) -ForegroundColor $state.Color
            }
        }
        'control' {
            $state=Get-WinSecCollectorState $Session $Agent.id
            Write-Host ('  '+(ConvertTo-WinSecControlName $Agent.id)+' | '+$state.Text) -ForegroundColor $state.Color
            Write-Host ('  '+$Agent.description) -ForegroundColor DarkGray
            Write-Host ''
            Write-Host '  [A] Analyze'
        }
        'framework' {
            Write-Host ('  Analyze / '+(ConvertTo-WinSecControlName $Agent.id)) -ForegroundColor Cyan
            Write-Host '  [C] CIS Benchmarks'
            Write-Host '  [N] NIST CSF 2.0'
        }
        'help' {
            $collectorId=if ($null -ne $Agent) {$Agent.id} else {''}
            Show-WinSecHelp -Domain $Domain -Collector $collectorId
        }
        'correlations' {
            Write-Host '  PLUS / Cross-Domain Correlation' -ForegroundColor Cyan
            Write-Host '  [1] Network Security + Services & Hardening'
            Write-Host '  [2] Identity & Access + Logging & Auditing'
            Write-Host '  [3] Network Security + Identity & Access'
            Write-Host '  [4] System Security + Logging & Auditing'
            Write-Host '  [5] All Available Correlations (1, 2, 3, 4)'
        }
    }
    if ($Session.Snapshot) {
        $displaySnapshot=if ($null -ne $Agent) {
            Get-WinSecSessionSnapshot -Session $Session -Collector $Agent.id
        } elseif ($Domain -ne 'all') {
            Get-WinSecSessionSnapshot -Session $Session -Domain $Domain
        } else { $Session.Snapshot }
        $label=if ($Session.RunId -and $displaySnapshot -eq $Session.Snapshot) {'Snapshot saved: '} else {'Snapshot: '}
        Write-Host ('  '+$label+(Format-WinSecSnapshotPath $displaySnapshot)) -ForegroundColor DarkGray
    }
    if ($Session.Notice) { Write-Host ('  '+$Session.Notice) -ForegroundColor Yellow }
}

function Wait-WinSecResult {
    param([string]$Domain='all',[string]$Collector)
    while ($true) {
        $answer=Read-WinSecInput -Hints @('Press Enter to return.') -Shortcuts 'q'
        if ($answer.HelpRequested) {
            Clear-Host
            Show-WinSecBanner
            Show-WinSecHelp -Domain $Domain -Collector $Collector
            continue
        }
        return (-not $answer.Cancelled -and $answer.Text -eq 'q')
    }
}

function Show-WinSecDevicePage {
    param($Devices,[int]$Index,$LocalDevice,[string]$OutputRoot,[string]$Notice)
    Clear-Host
    Show-WinSecBanner
    Write-Host '  DEVICE INVENTORY' -ForegroundColor Cyan
    for ($i=0; $i -lt $Devices.Count; $i++) {
        $device=$Devices[$i]
        $marker=if ($i -eq $Index) {'>'} else {' '}
        $kind=if ($device.id -eq $LocalDevice.id) {'Local'} else {'Saved'}
        $count=@(Get-WinSecDeviceSnapshots -OutputRoot $OutputRoot -DeviceId $device.id).Count
        Write-Host ('  {0} [{1}] {2} | {3} | {4} | {5} snapshots' -f $marker,($i+1),$device.name,$device.host,$kind,$count) -ForegroundColor $(if ($i -eq $Index) {'Cyan'} else {'Gray'})
    }
    if ($Devices.Count -eq 0) { Write-Host '  No saved devices.' -ForegroundColor DarkGray }
    if (@($Devices | Where-Object {$_.id -eq $LocalDevice.id}).Count -eq 0) {
        Write-Host ('  [+] Add current device: '+$LocalDevice.host)
    }
    if ($Devices.Count -gt 0 -and $null -ne $Devices[$Index].hardware) {
        $hardware=$Devices[$Index].hardware
        $memory=if ($null -eq $hardware.memoryBytes) {'RAM unavailable'} else {'{0:N1} GB RAM' -f ([double]$hardware.memoryBytes/1GB)}
        Write-Host ''
        Write-Host ('  {0} {1} | {2}' -f $hardware.manufacturer,$hardware.model,$memory) -ForegroundColor DarkGray
        Write-Host ('  CPU: '+(@($hardware.processors) -join ', ')) -ForegroundColor DarkGray
    }
    if ($Devices.Count -gt 0) {
        foreach ($warning in @($Devices[$Index].warnings)) { Write-Host ('  '+$warning) -ForegroundColor Yellow }
    }
    if ($Notice) { Write-Host ('  '+$Notice) -ForegroundColor Yellow }
}

function Get-WinSecMenuScanSelection {
    param($Parameters)
    $target=Resolve-WinSecTarget $(if ($Parameters.ContainsKey('Domain')) {$Parameters.Domain} else {'all'})
    return $target
}

function Invoke-WinSecMenu {
    param([string]$OutputRoot,[string]$Snapshot)
    $session=New-WinSecSession -OutputRoot $OutputRoot -Snapshot $Snapshot
    if ($Snapshot) { $session.Context=Get-WinSecSnapshotManifest -Snapshot $Snapshot }
    $localDevice=Get-WinSecLocalDevice
    $inventory=Register-WinSecDevice -OutputRoot $session.OutputRoot -LocalDevice $localDevice
    $catalog=@(Get-WinSecCatalog)
    $sections=@(Get-WinSecSections)
    $view='devices'; $domain='all'; $agent=$null; $helpReturnView='main'; $quit=$false
    $deviceIndex=0; $deviceNotice=''; $session.DeviceId=$localDevice.id; $session.DeviceName=$localDevice.host
    try {
        while (-not $quit) {
            if ($view -eq 'devices') {
                $devices=@($inventory.devices | Sort-Object @{Expression={$_.id -ne $localDevice.id}},name)
                if ($deviceIndex -ge $devices.Count) { $deviceIndex=0 }
                Show-WinSecDevicePage -Devices $devices -Index $deviceIndex -LocalDevice $localDevice -OutputRoot $session.OutputRoot -Notice $deviceNotice
                $answer=Read-WinSecInput -Hints @('Enter: open selected device. Type its number to select.','[Up/Down] Select | [F2] Rename | [Supr] Delete device + snapshots') -Shortcuts '+q' -Actions @('Rename','Delete','Up','Down')
                $deviceNotice=''
                if ($answer.Text -eq 'q') { $quit=$true; continue }
                if ($answer.Cancelled) { continue }
                if ($answer.HelpRequested) {
                    $deviceNotice='Enter opens saved scans. F2 edits the display name. Supr deletes the device AND all its snapshots after confirmation.'
                    continue
                }
                $action=if ($answer.PSObject.Properties['Action']) {$answer.Action} else {''}
                if ($action -in @('Up','Down')) {
                    if ($devices.Count -gt 0) { $deviceIndex=($deviceIndex+$(if ($action -eq 'Up') {$devices.Count-1} else {1})) % $devices.Count }
                    continue
                }
                try {
                    if ($answer.Text -eq '+') {
                        $inventory=Register-WinSecDevice -OutputRoot $session.OutputRoot -LocalDevice $localDevice
                        $deviceIndex=0; continue
                    }
                    if ($devices.Count -eq 0) { continue }
                    $selected=$devices[$deviceIndex]
                    if ($action -in @('Rename','Delete')) {
                        Clear-Host
                        Show-WinSecBanner
                        Write-Host ('  '+$selected.name+' | Host: '+$selected.host) -ForegroundColor Cyan
                        if ($action -eq 'Rename') {
                            $edit=Read-WinSecInput -Hints @('New display name (1-80 characters):') -Footer '[Esc] Cancel | [Enter] Save'
                            if (-not $edit.Cancelled -and -not $edit.HelpRequested) {
                                $inventory=Rename-WinSecDevice -OutputRoot $session.OutputRoot -DeviceId $selected.id -Name $edit.Text
                                if ($session.DeviceId -eq $selected.id) { $session.DeviceName=$edit.Text.Trim() }
                            }
                        } else {
                            $paths=@(Get-WinSecDeviceRemovalPlan -OutputRoot $session.OutputRoot -DeviceId $selected.id)
                            Write-Host '  Delete this device AND ALL its snapshots, correlations and exports.' -ForegroundColor Yellow
                            foreach ($path in $paths) { Write-Host ('  '+$path) -ForegroundColor DarkGray }
                            $confirmation=Read-WinSecInput -Hints @('Type the exact hostname to confirm:', $selected.host) -Footer '[Esc] Cancel | [Enter] Confirm deletion'
                            if (-not $confirmation.Cancelled -and -not $confirmation.HelpRequested) {
                                if ($confirmation.Text -cne $selected.host) { throw 'Hostname does not match. Nothing deleted.' }
                                if ($session.DeviceId -eq $selected.id) { Close-WinSecSession $session }
                                $inventory=Remove-WinSecDeviceData -OutputRoot $session.OutputRoot -DeviceId $selected.id -Confirmation $confirmation.Text
                                $deviceNotice='Device and snapshots deleted.'
                            }
                        }
                        continue
                    }
                    $number=0
                    if ([int]::TryParse($answer.Text,[ref]$number)) {
                        if ($number -ge 1 -and $number -le $devices.Count) { $deviceIndex=$number-1 }
                        continue
                    }
                    if ($answer.Text) { $deviceNotice='Use Enter, a device number, F2 or Supr.'; continue }
                    if ($session.Closed -or $session.DeviceId -ne $selected.id) {
                        Close-WinSecSession $session
                        $root=$session.OutputRoot
                        $session=New-WinSecSession -OutputRoot $root
                    }
                    Open-WinSecDeviceHistory -Session $session -DeviceId $selected.id
                    $session.DeviceId=$selected.id; $session.DeviceName=$selected.name
                    $view='main'; $domain='all'; $agent=$null
                } catch { $deviceNotice=$_.Exception.Message }
                continue
            }
            Show-WinSecMenuPage -View $view -Session $session -Domain $domain -Agent $agent -Catalog $catalog
            $shortcuts=switch ($view) {
                'main' {'123456+q'}
                'section' { ((1..(@($catalog | Where-Object { $_.domain -eq $domain }).Count)) -join '')+'q' }
                'control' {'aq'}
                'framework' {'cnq'}
                'correlations' {'12345q'}
                default {'q'}
            }
            $collectorId=if ($null -ne $agent) {$agent.id} else {''}
            $hintView=if ($view -eq 'help') {$helpReturnView} else {$view}
            $answer=Read-WinSecInput -Hints @(Get-WinSecHint -Session $session -Domain $domain -Collector $collectorId -View $hintView) -Shortcuts $shortcuts
            if ($answer.Cancelled) {
                switch ($view) {
                    'main' { $view='devices' }
                    'section' { $view='main'; $domain='all'; $agent=$null }
                    'control' { $view='section'; $agent=$null }
                    'framework' { $view='control' }
                    'help' { $view=$helpReturnView }
                    'correlations' { $view='main'; $domain='all' }
                }
                continue
            }
            if ($answer.HelpRequested) {
                if ($view -ne 'help') { $helpReturnView=$view }
                $view='help'; continue
            }
            $text=$answer.Text
            if (-not $text) { continue }
            if ($text -eq 'q') { $quit=$true; continue }
            if ($view -eq 'main' -and $text -match '^[1-6]$') {
                $domain=$sections[[int]$text-1].Domain; $view='section'; continue
            }
            if ($view -eq 'main' -and $text -eq '+') { $view='correlations'; continue }
            $number=0
            if ($view -eq 'section' -and [int]::TryParse($text,[ref]$number)) {
                $agents=@($catalog | Where-Object { $_.domain -eq $domain })
                if ($number -ge 1 -and $number -le $agents.Count) { $agent=$agents[$number-1]; $view='control' }
                continue
            }
            if ($view -eq 'control' -and $text -eq 'a') { $view='framework'; continue }
            $isScan=$false; $scanSelection=$null
            $session.Notice=$null
            try {
                if ($view -eq 'framework' -and $text -in @('c','n')) {
                    $parameters=@{ Analyze=$agent.id; NoBanner=$true; Session=$session }
                    if ($text -eq 'c') { $parameters.Cis=$true } else { $parameters.Nist=$true }
                } elseif ($view -eq 'correlations' -and $text -match '^[1-5]$') {
                    $parameters=@{ Correlation=[int]$text; NoBanner=$true; Session=$session }
                } else {
                    $parameters=ConvertFrom-WinSecInputCommand -Text $text
                    if ($parameters.Count -eq 0) { throw 'Pulsa F1 para consultar los comandos disponibles.' }
                    $parameters.Session=$session
                    $parameters.NoBanner=$true
                }
                $isScan=($parameters.ContainsKey('Scan') -and $parameters.Scan)
                if ($isScan) {
                    if ($session.DeviceId -ne $localDevice.id) { throw 'Only the local device can be scanned. Select it in the inventory.' }
                    $scanSelection=Get-WinSecMenuScanSelection -Parameters $parameters
                    Clear-Host
                    Show-WinSecBanner
                }
                winsec @parameters | Out-Host
            } catch {
                $session.Notice=$_.Exception.Message
                Write-Warning $_.Exception.Message
            }
            if ($isScan) {
                if ($null -ne $scanSelection) {
                    $domain=$scanSelection.Domain; $agent=$null
                    $view=if ($domain -eq 'all') {'main'} else {'section'}
                }
                continue
            }
            $quit=Wait-WinSecResult -Domain $domain -Collector $collectorId
            if ($view -eq 'framework') { $view='control' }
        }
    } finally {
        Close-WinSecSession $session
    }
    Clear-Host
    Write-Host 'Exiting Winsec-Analyzer.'
}
