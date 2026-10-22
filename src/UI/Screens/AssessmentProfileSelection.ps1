# Per-operation profile selection. UI data and keyboard only; no collection.
function Show-WinSecAssessmentProfileSelection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Request,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Profiles
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
    $display = [pscustomobject]@{Index=0;CanChoose=$false}
    $render = {
        param($UnusedState)
        $display.CanChoose = $false
        $terminal = Get-WinSecTerminalSize
        Clear-WinSecScreen
        $width = [Math]::Max(1,[int]$terminal.ContentWidth)
        $lines = @('WINSEC ANALYZER - ASSESSMENT PROFILE',
            ('Device: ' + $requestCopy.Hostname),('DeviceId: ' + $requestCopy.DeviceId),
            ('Scope: {0} / {1}' -f $requestCopy.ScopeType,$requestCopy.ScopeKey),
            'Mode: READ ONLY | Overall score: NOT_SCORED',
            ('Approved profiles available: ' + $options.Count),
            ('Choice {0} / {1}' -f ($display.Index+1),($options.Count+1)))
        if ($display.Index -eq 0) {
            $lines += 'Collection only - no configuration evaluation'
            if ($options.Count -eq 0) { $lines += 'No approved profile is available for this selection.' }
        }
        else {
            $selected = $options[$display.Index-1]
            $lines += 'Profile: ' + $selected.Profile
            foreach ($policy in $selected.Policies) {
                $lines += 'Criteria: {0} | {1} / {2}' -f $policy.CheckId,$policy.CatalogId,$policy.CatalogVersion
                $lines += 'Criteria SHA256: ' + $policy.CatalogSha256
                $lines += 'Applies to: {0} / {1} / {2}' -f $policy.OSFamily,$policy.OSRelease,$policy.Edition
            }
            $lines += 'Applicability and prerequisites are checked during the scan.'
        }
        $lines += 'A scan confirmation follows. No scan has started.'
        $lines += '[Up / Down] Choice | [Y / Enter] Select | [N / Esc] Cancel scan'
        $wrapped = @(foreach ($line in $lines) {
            for ($offset=0;$offset -lt $line.Length;$offset+=$width) {
                $line.Substring($offset,[Math]::Min($width,$line.Length-$offset))
            }
        })
        if ($terminal.Width -lt 40 -or $terminal.Height -lt ($wrapped.Count+1)) {
            $hints = @('Resize to view the complete profile.',('[N / Esc] Cancel scan'))
            for ($i=0;$i -lt [Math]::Min($hints.Count,[Math]::Max(0,$terminal.Height-1));$i++) {
                Write-WinSecText -Text $hints[$i].Substring(0,[Math]::Min($width,$hints[$i].Length)) -Color Yellow
            }
            return
        }
        foreach ($line in $wrapped) { Write-WinSecText -Text $line }
        $display.CanChoose = $true
    }
    $resizeState = New-WinSecResizeState
    $null = & $render $null
    while ($true) {
        $key = Read-WinSecResizeAwareKey -ResizeState $resizeState -RenderAction $render
        $null = Invoke-WinSecResizeHandler -ResizeState $resizeState -RenderAction $render
        if ($null -eq $key -or $key.KeyDown -ceq $false -or ([int]$key.ControlKeyState -band 0x0F) -ne 0) { continue }
        if ($key.VirtualKeyCode -eq 27 -or [string]$key.Character -ieq 'N') {
            return [pscustomobject]@{Confirmed=$false;Selection=$null}
        }
        if ($key.VirtualKeyCode -in @(38,40)) {
            $delta = if ($key.VirtualKeyCode -eq 38) {-1} else {1}
            $display.Index = ($display.Index+$delta+$options.Count+1) % ($options.Count+1)
            $null = & $render $null
        }
        elseif ($display.CanChoose -and ($key.VirtualKeyCode -eq 13 -or [string]$key.Character -ieq 'Y')) {
            $choice = if ($display.Index -eq 0) {$null} else {Copy-WinSecResultData $options[$display.Index-1]}
            return [pscustomobject]@{Confirmed=$true;Selection=$choice}
        }
    }
}
