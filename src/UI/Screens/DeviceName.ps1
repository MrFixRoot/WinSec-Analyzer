# Editor de nombre de presentación. No cambia el hostname de Windows ni persiste datos.
function Show-WinSecDeviceNameEditor {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Request)
    $requestCopy=Copy-WinSecResultData -Value $Request
    if (-not (Test-WinSecTargetIdentifier $requestCopy.DeviceId) -or
        -not (Test-WinSecDeviceDisplayName $requestCopy.DisplayName)) { throw 'Invalid device name editor request.' }
    $text=$requestCopy.DisplayName;$replace=$true;$review=$false
    $render={
        param($State)
        $terminal=Get-WinSecTerminalSize
        Clear-WinSecScreen
        $width=[Math]::Max(1,[int]$terminal.ContentWidth)
        $lines=@('DEVICE NAME',('Device ID: '+$requestCopy.DeviceId),('Current: '+$requestCopy.DisplayName),('New name: '+$text),
            'This changes the application label only.')
        if($review){$lines+='[Y / Enter] Save | [N / Esc] Cancel'}
        else{$lines+='Type to replace; Backspace deletes. Enter reviews; Esc cancels.'}
        $wrapped=@(foreach($line in $lines){for($i=0;$i -lt $line.Length;$i+=$width){$line.Substring($i,[Math]::Min($width,$line.Length-$i))}})
        $script:WinSecDeviceNameVisible=($terminal.Width -ge 40 -and $terminal.Height -ge ($wrapped.Count+1))
        if(-not $script:WinSecDeviceNameVisible){Write-WinSecText -Text 'Resize to view the complete name request.' -Color Yellow;return}
        foreach($line in $wrapped){Write-WinSecText -Text $line -Color Gray}
    }
    $resize=New-WinSecResizeState
    while($true){
        $null=& $render $null
        $key=Read-WinSecResizeAwareKey -ResizeState $resize -RenderAction $render
        if($null -eq $key -or $key.KeyDown -ceq $false -or ([int]$key.ControlKeyState -band 0x0F) -ne 0){continue}
        if($key.VirtualKeyCode -eq 27){return $null}
        if($review){
            if([string]$key.Character -match '^[nN]$'){return $null}
            if(($key.VirtualKeyCode -eq 13 -or [string]$key.Character -match '^[yY]$') -and $script:WinSecDeviceNameVisible){
                return [pscustomobject]@{DeviceId=$requestCopy.DeviceId;DisplayName=$text}
            }
            continue
        }
        if($key.VirtualKeyCode -eq 13){if(Test-WinSecDeviceDisplayName $text.Trim()){$text=$text.Trim();$review=$true};continue}
        if($key.VirtualKeyCode -in @(8,46)){
            if($replace){$text='';$replace=$false}elseif($text.Length -gt 0){$text=$text.Substring(0,$text.Length-1)}
            continue
        }
        $character=[string]$key.Character
        if($character.Length -eq 1 -and $character -notmatch '[\p{C}\p{Zl}\p{Zp}]'){
            if($replace){$text='';$replace=$false}
            if($text.Length -lt 253){$text+=$character}
        }
    }
}
