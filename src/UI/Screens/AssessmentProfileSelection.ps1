# Per-operation profile selection. UI data and keyboard only; no collection.
. (Join-Path $PSScriptRoot '../../Services/WindowsUpdateProfileRegistry.ps1')
function Show-WinSecAssessmentProfileSelection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Request,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Profiles,
        [ValidateLength(0,256)][ValidatePattern('\A[^\p{C}]*\z')][string]$CurrentSystemLabel = ''
    )
    $requestCopy = Copy-WinSecResultData $Request
    if ($requestCopy.Operation -isnot [string] -or $requestCopy.Operation -cne 'SCAN' -or
        $requestCopy.ReadOnly -isnot [bool] -or -not $requestCopy.ReadOnly -or
        -not (Test-WinSecTargetIdentifier $requestCopy.DeviceId) -or $requestCopy.Hostname -isnot [string] -or
        [string]::IsNullOrWhiteSpace($requestCopy.Hostname) -or $requestCopy.Hostname.Length -gt 253 -or
        $requestCopy.Hostname -match '[\p{C}]' -or $requestCopy.Checks -isnot [array] -or $requestCopy.Checks.Count -eq 0) {
        throw 'Invalid profile selection request.'
    }
    Assert-WinSecResultScope -ScopeType $requestCopy.ScopeType -ScopeKey $requestCopy.ScopeKey
    $checkIds = @{}
    foreach ($check in $requestCopy.Checks) {
        if (-not (Test-WinSecTargetIdentifier $check.CheckId) -or $checkIds.ContainsKey($check.CheckId)) {
            throw 'Invalid profile selection control identity.'
        }
        if (($requestCopy.ScopeType -ceq 'CONTROL' -and
             ($requestCopy.Checks.Count -ne 1 -or $check.CheckId -cne $requestCopy.ScopeKey)) -or
            ($requestCopy.ScopeType -ceq 'SECTION' -and
             ($check.SectionKey -isnot [string] -or $check.SectionKey -cne $requestCopy.ScopeKey))) {
            throw 'Profile selection controls contradict the requested scope.'
        }
        $checkIds[$check.CheckId] = $true
    }
    $options = New-Object 'System.Collections.Generic.List[object]'
    $seen = @{}
    if ($Profiles.Count -gt 128) { throw 'Too many assessment profiles.' }
    foreach ($item in $Profiles) {
        $profile = Assert-WinSecAssessmentProfilePreview $item
        if ($seen.ContainsKey($profile.Profile)) { throw 'Duplicate assessment profile.' }
        $seen[$profile.Profile] = $true
        foreach ($policy in $profile.Policies) {
            if (@($requestCopy.Checks|Where-Object {$_.CheckId -ceq $policy.CheckId}).Count -ne 1) {
                throw 'Profile lies outside the requested control selection.'
            }
        }
        $options.Add($profile)
    }
    # Labels are presentation metadata only. The chosen, validated preview is
    # returned unchanged; labels never determine applicability or permission.
    $matrix = $null
    if (@($options | Where-Object {$_.Profile -cmatch '^WSA-W11-'}).Count) {
        $matrix = (Get-WinSecDefenderProfileMatrix -ProjectRoot ([IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..')))).Matrix
    }
    $variants=@{}
    if(@($options|Where-Object {$_.Policies.CheckId -ccontains 'WSA-SYS-003'}).Count) {
        $variantCatalog=(Get-WinSecWindowsUpdateVariantCatalog -ProjectRoot ([IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..')))).Catalog
        foreach($profile in $options) {
            $update=@($profile.Policies|Where-Object CheckId -CEQ 'WSA-SYS-003')
            if($update.Count) {$variants[$profile.Profile]=Get-WinSecWindowsUpdateProfileVariant -Catalog $variantCatalog -Matrix $matrix -Policy $update[0]}
        }
    }
    $groups = New-Object 'System.Collections.Generic.List[object]'
    $groupMap = @{}
    foreach ($profile in $options) {
        $policy = $profile.Policies[0]
        $system = $policy.OSFamily
        $releaseLabel = $policy.OSRelease
        $build = 0
        if ($policy.OSFamily -ceq 'Windows' -and $policy.OSRelease -cmatch '^Windows 11 10\.0\.([0-9]+)$') {
            $system = 'Windows 11'
            $build = [int]$Matches[1]
            $release = @($matrix.Releases | Where-Object {$_.Build -eq $build})
            if ($release.Count -eq 1) { $releaseLabel = '{0} | build {1}' -f $release[0].Name,$build }
        }
        $edition = $policy.Edition
        $editionName = @($matrix.Editions | Where-Object {('SKU:' + $_.Sku) -ceq $edition})
        if ($editionName.Count -eq 1) { $edition = $editionName[0].Name }
        $groupKey = $system + '|' + $policy.Edition
        if (-not $groupMap.ContainsKey($groupKey)) {
            $group = [pscustomobject]@{Label=($system + ' / ' + $edition);Profiles=New-Object 'System.Collections.Generic.List[object]'}
            $groupMap[$groupKey] = $group
            $groups.Add($group)
        }
        $groupMap[$groupKey].Profiles.Add([pscustomobject]@{Label=$releaseLabel;Build=$build;Preview=$profile})
    }
    foreach ($group in $groups) {
        $group.Profiles = @($group.Profiles | Sort-Object Label,Build)
    }
    $groups = @($groups | Sort-Object Label)
    $display = [pscustomobject]@{Stage='OS';Index=0;SystemIndex=0;CanChoose=$false}
    $wrap = {
        param([object[]]$Lines,[int]$Width)
        foreach ($line in $Lines) {
            for ($offset=0;$offset -lt $line.Length;$offset+=$Width) {
                $line.Substring($offset,[Math]::Min($Width,$line.Length-$offset))
            }
        }
    }
    $render = {
        param($UnusedState)
        $display.CanChoose = $false
        $terminal = Get-WinSecTerminalSize
        Clear-WinSecScreen
        $width = [Math]::Max(1,[int]$terminal.ContentWidth)
        $lines = @('WINSEC ANALYZER - ASSESSMENT PROFILE',
            ('Device: ' + $requestCopy.Hostname),('DeviceId: ' + $requestCopy.DeviceId),
            ('Scope: {0} / {1}' -f $requestCopy.ScopeType,$requestCopy.ScopeKey),
            'Mode: READ ONLY | Saved readings for framework review')
        if ($CurrentSystemLabel) { $lines += 'Current OS: ' + $CurrentSystemLabel }
        $details = @()
        if ($display.Stage -ceq 'OS') {
            $lines += 'OPERATING SYSTEM / EDITION'
            $labels = @('Collection only - no configuration evaluation') + @($groups | ForEach-Object {$_.Label})
            if ($options.Count -eq 0) { $details += 'No approved profile is available for this selection.' }
            $details += 'Selected: ' + $labels[$display.Index]
        }
        else {
            $group = $groups[$display.SystemIndex-1]
            $lines += 'VERSION / BUILD - ' + $group.Label
            $labels = @($group.Profiles | ForEach-Object {$_.Label})
            $selected = $group.Profiles[$display.Index].Preview
            $details += 'Selected: ' + $labels[$display.Index]
            $details += 'Profile: ' + $selected.Profile
            foreach ($policy in $selected.Policies) {
                $label=if($policy.CatalogId -cin @('WSA-FIREWALL-COLLECTION','WSA-SMB-COLLECTION','WSA-RDP-COLLECTION','WSA-PORTS-COLLECTION')){'Collection schema'}else{'Criteria'}
                $details += ($label+': {0} | {1} / {2}' -f $policy.CheckId,$policy.CatalogId,$policy.CatalogVersion)
                $details += $label+' SHA256: ' + $policy.CatalogSha256
                $details += 'Applies to: {0} / {1} / {2}' -f $policy.OSFamily,$policy.OSRelease,$policy.Edition
            }
            if($variants.ContainsKey($selected.Profile)) {
                $variant=$variants[$selected.Profile]
                $details += 'Windows Update variant: '+$variant.Label+' / '+$variant.Channel
                $details += 'Policy model: '+$variant.DeadlineModel
                $details += 'Support dates follow edition, release and channel. Findings explain maintenance and support warnings.'
                $details += 'Policy support depends on installed revision. Unknown data is not a failure.'
            }
            $details += 'Applicability and prerequisites are checked during the scan.'
        }
        $lines += 'Choice {0} / {1}' -f ($display.Index+1),$labels.Count
        $details += 'A scan confirmation follows. No scan has started.'
        $details += '[Up / Down] Choice | [Enter] Select'
        $details += if ($display.Stage -ceq 'OS') {'[Esc] Cancel scan'} else {'[Esc] Back to operating systems'}
        $header = @(& $wrap $lines $width)
        $footer = @(& $wrap $details $width)
        $rows = [Math]::Min(8,[Math]::Min($labels.Count,$terminal.Height-1-$header.Count-$footer.Count))
        if ($terminal.Width -lt 40 -or $rows -lt 1) {
            $hints = @('Resize to view the complete profile.','[Esc] Back')
            for ($i=0;$i -lt [Math]::Min($hints.Count,[Math]::Max(0,$terminal.Height-1));$i++) {
                Write-WinSecText -Text $hints[$i].Substring(0,[Math]::Min($width,$hints[$i].Length)) -Color Yellow
            }
            return
        }
        foreach ($line in $header) { Write-WinSecText -Text $line -Color Cyan }
        $start = [Math]::Max(0,[Math]::Min($display.Index-[int][Math]::Floor($rows/2),$labels.Count-$rows))
        for ($i=$start;$i -lt ($start+$rows);$i++) {
            $prefix = if ($i -eq $display.Index) {'> '} else {'  '}
            $line = $prefix + $labels[$i]
            if ($line.Length -gt $width) { $line = $line.Substring(0,$width-3) + '...' }
            $color = if ($i -eq $display.Index) {'Cyan'} else {'Gray'}
            Write-WinSecText -Text $line -Color $color
        }
        foreach ($line in $footer) { Write-WinSecText -Text $line -Color Gray }
        $display.CanChoose = $true
    }
    $resizeState = New-WinSecResizeState
    $null = & $render $null
    while ($true) {
        $key = Read-WinSecResizeAwareKey -ResizeState $resizeState -RenderAction $render
        $null = Invoke-WinSecResizeHandler -ResizeState $resizeState -RenderAction $render
        if ($null -eq $key -or $key.KeyDown -ceq $false -or ([int]$key.ControlKeyState -band 0x0F) -ne 0) { continue }
        if ($key.VirtualKeyCode -eq 27 -and $display.Stage -ceq 'BUILD') {
            $display.Stage='OS';$display.Index=$display.SystemIndex
            $null = & $render $null
            continue
        }
        if ($key.VirtualKeyCode -eq 27) {
            return [pscustomobject]@{Confirmed=$false;Selection=$null}
        }
        if ($key.VirtualKeyCode -in @(38,40)) {
            $delta = if ($key.VirtualKeyCode -eq 38) {-1} else {1}
            $count = if ($display.Stage -ceq 'OS') {$groups.Count+1} else {$groups[$display.SystemIndex-1].Profiles.Count}
            $display.Index = ($display.Index+$delta+$count) % $count
            $null = & $render $null
        }
        elseif ($display.CanChoose -and $key.VirtualKeyCode -eq 13) {
            if ($display.Stage -ceq 'OS' -and $display.Index -gt 0) {
                $display.SystemIndex=$display.Index;$display.Index=0;$display.Stage='BUILD'
                $null = & $render $null
                continue
            }
            $choice = if ($display.Stage -ceq 'OS') {$null} else {Copy-WinSecResultData $groups[$display.SystemIndex-1].Profiles[$display.Index].Preview}
            return [pscustomobject]@{Confirmed=$true;Selection=$choice}
        }
    }
}
