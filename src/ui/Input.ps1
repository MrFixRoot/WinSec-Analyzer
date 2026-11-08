function Read-WinSecKey {
    try { return $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown') }
    catch { throw 'El menu requiere una consola interactiva. Usa run.ps1 -Help para consultar los comandos CLI.' }
}

function Get-WinSecCursor {
    try { return $Host.UI.RawUI.CursorPosition } catch { return $null }
}

function Move-WinSecCursor {
    param($Position)
    if ($null -ne $Position) {
        try { $Host.UI.RawUI.CursorPosition=$Position } catch { }
    }
}

function Show-WinSecInputArea {
    param([string]$Text,[string[]]$Guidance,$Completion,$Area)
    $width=80
    try { $width=[math]::Max(8,$Host.UI.RawUI.BufferSize.Width) } catch { }
    $lines=New-Object 'System.Collections.Generic.List[string]'
    $matches=@(Get-WinSecCompletionLines -Completion $Completion -Width $width)
    $content=$matches
    if ($matches.Count -gt 0) { $content+=@('') }
    $content+=@($Guidance)
    foreach ($item in $content) {
        $line=[string]$item
        while ($line.Length -gt $width-3) {
            $lines.Add($line.Substring(0,$width-3))
            $line=$line.Substring($width-3)
        }
        $lines.Add($line)
    }
    # Keep the caret on one visible row; retain the complete command in memory.
    $visible=$Text
    $capacity=$width-5
    if ($visible.Length -gt $capacity) {
        $visible=if ($capacity -gt 3) {'...'+$visible.Substring($visible.Length-$capacity+3)} else {$visible.Substring($visible.Length-$capacity)}
    }
    if ($null -ne $Area.Origin -and $Area.Width -eq $width -and $Area.Lines.Count -eq $lines.Count) {
        Move-WinSecCursor $Area.Origin
        Write-Host (('  > '+$visible).PadRight($width-1)) -NoNewline
        for ($i=0; $i -lt $lines.Count; $i++) {
            if ($Area.Lines[$i] -cne $lines[$i]) {
                Move-WinSecCursor ([System.Management.Automation.Host.Coordinates]::new(0,$Area.Origin.Y+$i+1))
                Write-Host (('  '+$lines[$i]).PadRight($width-1)) -NoNewline -ForegroundColor DarkGray
            }
        }
        $Area.Lines=$lines.ToArray()
        Move-WinSecCursor ([System.Management.Automation.Host.Coordinates]::new(4+$visible.Length,$Area.Origin.Y))
        return
    }
    if ($null -ne $Area.Origin) {
        for ($i=0; $i -lt $Area.Rows; $i++) {
            Move-WinSecCursor ([System.Management.Automation.Host.Coordinates]::new(0,$Area.Origin.Y+$i))
            Write-Host (' '*($width-1)) -NoNewline
        }
        Move-WinSecCursor $Area.Origin
    }
    Write-Host ('  > '+$visible)
    foreach ($line in $lines) { Write-Host ('  '+$line) -ForegroundColor DarkGray }
    $Area.Rows=1+$lines.Count
    $Area.Width=$width; $Area.Lines=$lines.ToArray()
    $Area.End=Get-WinSecCursor
    if ($null -ne $Area.End) {
        $row=[math]::Max(0,$Area.End.Y-$Area.Rows)
        $Area.Origin=[System.Management.Automation.Host.Coordinates]::new(0,$row)
        Move-WinSecCursor ([System.Management.Automation.Host.Coordinates]::new(4+$visible.Length,$row))
    }
    else { $Area.Origin=$null; Write-Host ('  > '+$visible) -NoNewline }
}

function Clear-WinSecMessageArea {
    param($Area)
    if ($null -eq $Area -or -not $Area.Active) { return }
    $Area.Active=$false
    if ($null -eq $Area.Origin -or $Area.Rows -le 0) { return }
    try {
        $ui=$Host.UI.RawUI
        $bottom=[math]::Min($ui.BufferSize.Height-1,$Area.Origin.Y+$Area.Rows-1)
        $rectangle=[System.Management.Automation.Host.Rectangle]::new(0,$Area.Origin.Y,$ui.BufferSize.Width-1,$bottom)
        $blank=[System.Management.Automation.Host.BufferCell]::new([char]' ',$ui.ForegroundColor,$ui.BackgroundColor,[System.Management.Automation.Host.BufferCellType]::Complete)
        $ui.SetBufferContents($rectangle,$blank)
    } catch { }
}

function Read-WinSecInput {
    param([string[]]$Hints=@(),[string]$Shortcuts='',[string[]]$Actions=@(),[string]$Footer='[Esc] Back/Cancel | [F1] Help | [Q] Exit',[switch]$NoLeadingSpace,[switch]$CompleteCommands,[string]$CompletionDomain='all',[string]$CompletionCollector,$MessageArea)
    $guidance=@($Hints)
    if ($CompleteCommands) { $guidance+=@('[Tab] Complete | [Shift+Tab] Previous match') }
    $guidance+=@('',$Footer)
    if (-not $NoLeadingSpace) { Write-Host '' }
    $buffer=New-Object System.Text.StringBuilder
    $area=[pscustomobject]@{Origin=$null;End=$null;Rows=0;Width=0;Lines=@()}
    $completion=$null
    Show-WinSecInputArea -Text '' -Guidance $guidance -Area $area
    if ($null -ne $MessageArea -and $null -ne $area.Origin) {
        $row=[math]::Max(0,$area.Origin.Y-$MessageArea.Rows-$(if ($NoLeadingSpace) {0} else {1}))
        $MessageArea.Origin=[System.Management.Automation.Host.Coordinates]::new(0,$row)
    }
    while ($true) {
        $key=Read-WinSecKey
        if ($key.VirtualKeyCode -in @(8,9,13) -or -not [char]::IsControl([char]$key.Character)) {
            Clear-WinSecMessageArea -Area $MessageArea
        }
        if ($key.VirtualKeyCode -eq 27) {
            Move-WinSecCursor $area.End
            Write-Host ''
            return [pscustomobject]@{ Cancelled=$true; HelpRequested=$false; Action=''; Text='' }
        }
        if ($key.VirtualKeyCode -eq 112) {
            Move-WinSecCursor $area.End
            Write-Host ''
            return [pscustomobject]@{ Cancelled=$false; HelpRequested=$true; Action=''; Text='' }
        }
        if ($key.VirtualKeyCode -eq 9) {
            if (-not $CompleteCommands) { continue }
            $text=$buffer.ToString()
            $reverse=($null -ne $key.PSObject.Properties['ControlKeyState'] -and ([int]$key.ControlKeyState -band 16) -ne 0)
            if ($null -ne $completion -and $completion.Cycle -and $completion.LastText -ceq $text) {
                $step=if ($reverse) {$completion.Matches.Count-1} else {1}
                $completion.Index=if ($completion.Index -lt 0) {if ($reverse) {$completion.Matches.Count-1} else {0}} else {($completion.Index+$step) % $completion.Matches.Count}
                $text=$completion.Prefix+$completion.Matches[$completion.Index]+' '
            } else {
                $completion=New-WinSecCompletionState -Text $text -Domain $CompletionDomain -Collector $CompletionCollector
                if ($null -eq $completion) { continue }
                if ($completion.Matches.Count -eq 1) { $text=$completion.Prefix+$completion.Matches[0]+' '; $completion=$null }
                elseif ($reverse) {
                    $completion.Index=$completion.Matches.Count-1
                    $text=$completion.Prefix+$completion.Matches[$completion.Index]+' '
                } else {
                    $common=$completion.Matches[0]
                    foreach ($match in $completion.Matches) {
                        while (-not $match.StartsWith($common,[StringComparison]::OrdinalIgnoreCase)) { $common=$common.Substring(0,$common.Length-1) }
                    }
                    $text=$completion.Prefix+$common
                }
            }
            if ($text.Length -gt 4096) { $completion=$null; continue }
            [void]$buffer.Clear(); [void]$buffer.Append($text)
            if ($null -ne $completion) { $completion.Cycle=$true; $completion.LastText=$text }
            Show-WinSecInputArea -Text $text -Guidance $guidance -Completion $completion -Area $area
            continue
        }
        $keys=@{113='Rename';46='Delete';38='Up';40='Down'}
        if ($buffer.Length -eq 0 -and $keys.ContainsKey([int]$key.VirtualKeyCode) -and $keys[[int]$key.VirtualKeyCode] -in $Actions) {
            Move-WinSecCursor $area.End
            Write-Host ''
            return [pscustomobject]@{ Cancelled=$false; HelpRequested=$false; Action=$keys[[int]$key.VirtualKeyCode]; Text='' }
        }
        if ($key.VirtualKeyCode -eq 13) { break }
        if ($key.VirtualKeyCode -eq 8) {
            if ($buffer.Length -gt 0) {
                [void]$buffer.Remove($buffer.Length-1,1)
                if ($null -ne $completion) { $completion=New-WinSecCompletionState -Text $buffer.ToString() -Domain $CompletionDomain -Collector $CompletionCollector }
                Show-WinSecInputArea -Text $buffer.ToString() -Guidance $guidance -Completion $completion -Area $area
            }
            continue
        }
        $character=[char]$key.Character
        if ([char]::IsControl($character)) { continue }
        if ($buffer.Length -ge 4096) { continue }
        if ($buffer.Length -eq 0 -and $Shortcuts.IndexOf([string]$character,[StringComparison]::OrdinalIgnoreCase) -ge 0) {
            [void]$buffer.Append($character)
            break
        }
        [void]$buffer.Append($character)
        if ($null -ne $completion) { $completion=New-WinSecCompletionState -Text $buffer.ToString() -Domain $CompletionDomain -Collector $CompletionCollector }
        Show-WinSecInputArea -Text $buffer.ToString() -Guidance $guidance -Completion $completion -Area $area
    }
    if ($null -ne $completion) { Show-WinSecInputArea -Text $buffer.ToString() -Guidance $guidance -Area $area }
    Move-WinSecCursor $area.End
    Write-Host ''
    return [pscustomobject]@{ Cancelled=$false; HelpRequested=$false; Action=''; Text=$buffer.ToString().Trim() }
}

function ConvertFrom-WinSecInputCommand {
    param([Parameter(Mandatory)][string]$Text)
    $tokens=$null; $parseErrors=$null
    $ast=[System.Management.Automation.Language.Parser]::ParseInput($Text,[ref]$tokens,[ref]$parseErrors)
    if (@($parseErrors).Count -gt 0 -or $ast.EndBlock.Statements.Count -ne 1) {
        throw 'Escribe un solo comando winsec. No se admiten expresiones ni varios comandos.'
    }
    $pipeline=$ast.EndBlock.Statements[0]
    if ($pipeline -isnot [System.Management.Automation.Language.PipelineAst] -or $pipeline.PipelineElements.Count -ne 1) {
        throw 'Solo se admiten comandos winsec sin pipelines.'
    }
    $command=$pipeline.PipelineElements[0]
    if ($command -isnot [System.Management.Automation.Language.CommandAst] -or
        $command.InvocationOperator -ne [System.Management.Automation.Language.TokenKind]::Unknown -or
        $command.Redirections.Count -gt 0 -or $command.GetCommandName() -ne 'winsec') {
        throw 'Escribe winsec seguido de sus opciones, o pulsa F1 para consultar la ayuda.'
    }
    $metadata=Get-WinSecInputParameters
    $switches=$metadata.Switches; $values=$metadata.Values
    $parameters=@{}
    $elements=$command.CommandElements
    for ($i=1; $i -lt $elements.Count; $i++) {
        $element=$elements[$i]
        if ($element -is [System.Management.Automation.Language.CommandParameterAst]) {
            $name=$element.ParameterName.ToLowerInvariant()
            if ($null -ne $element.Argument) { throw 'Usa las opciones separadas por espacios, sin expresiones.' }
            if ($switches.ContainsKey($name)) {
                $parameter=$switches[$name]; $value=$true
            } elseif ($values.ContainsKey($name)) {
                $parameter=$values[$name]; $i++
                if ($i -ge $elements.Count -or
                    ($elements[$i] -isnot [System.Management.Automation.Language.StringConstantExpressionAst] -and
                    -not ($elements[$i] -is [System.Management.Automation.Language.ConstantExpressionAst] -and $elements[$i].Value -is [int]))) {
                    throw ('Falta un valor literal para -'+$name+'.')
                }
                $value=$elements[$i].Value
            } else { throw ('Opcion desconocida: -'+$name+'. Pulsa F1 para consultar la ayuda.') }
        } elseif ($element -is [System.Management.Automation.Language.StringConstantExpressionAst] -or
            ($element -is [System.Management.Automation.Language.ConstantExpressionAst] -and $element.Value -is [int])) {
            $parameter='Domain'; $value=$element.Value
        } else { throw 'No se admiten variables, expresiones ni ejecucion de PowerShell en este menu.' }
        if ($parameters.ContainsKey($parameter)) { throw ('Opcion repetida: '+$parameter+'.') }
        $parameters[$parameter]=$value
    }
    return $parameters
}
