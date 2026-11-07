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

function Read-WinSecInput {
    param([string[]]$Hints=@(),[string]$Shortcuts='',[string[]]$Actions=@(),[string]$Footer='[Esc] Back/Cancel | [F1] Help | [Q] Exit')
    $guidance=@($Hints)+@('',$Footer)
    Write-Host ''
    Write-Host '  > ' -NoNewline
    Write-Host ''
    $width=80
    try { $width=[math]::Max(1,$Host.UI.RawUI.BufferSize.Width) } catch { }
    $hintRows=0
    foreach ($hint in $guidance) { $hintRows+=[math]::Max(1,[math]::Ceiling((2+$hint.Length)/$width)) }
    foreach ($hint in $guidance) { Write-Host ('  '+$hint) -ForegroundColor DarkGray }
    $endPosition=Get-WinSecCursor
    if ($null -ne $endPosition) {
        # Calculate from the final position: printing hints may have scrolled the buffer.
        $row=[math]::Max(0,$endPosition.Y-$hintRows-1)
        Move-WinSecCursor ([System.Management.Automation.Host.Coordinates]::new(4,$row))
    }
    else { Write-Host '  > ' -NoNewline }
    $buffer=New-Object System.Text.StringBuilder
    while ($true) {
        $key=Read-WinSecKey
        if ($key.VirtualKeyCode -eq 27) {
            Move-WinSecCursor $endPosition
            Write-Host ''
            return [pscustomobject]@{ Cancelled=$true; HelpRequested=$false; Action=''; Text='' }
        }
        if ($key.VirtualKeyCode -eq 112) {
            Move-WinSecCursor $endPosition
            Write-Host ''
            return [pscustomobject]@{ Cancelled=$false; HelpRequested=$true; Action=''; Text='' }
        }
        $keys=@{113='Rename';46='Delete';38='Up';40='Down'}
        if ($buffer.Length -eq 0 -and $keys.ContainsKey([int]$key.VirtualKeyCode) -and $keys[[int]$key.VirtualKeyCode] -in $Actions) {
            Move-WinSecCursor $endPosition
            Write-Host ''
            return [pscustomobject]@{ Cancelled=$false; HelpRequested=$false; Action=$keys[[int]$key.VirtualKeyCode]; Text='' }
        }
        if ($key.VirtualKeyCode -eq 13) { break }
        if ($key.VirtualKeyCode -eq 8) {
            if ($buffer.Length -gt 0) {
                [void]$buffer.Remove($buffer.Length-1,1)
                Write-Host (([string][char]8)+' '+[char]8) -NoNewline
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
        Write-Host ([string]$character) -NoNewline
    }
    Move-WinSecCursor $endPosition
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
    $switches=@{s='Scan';scan='Scan';n='Nist';nist='Nist';c='Cis';cis='Cis';r='Correlate';correlate='Correlate';deep='Deep';list='List';report='Report';nobanner='NoBanner'}
    $values=@{a='Analyze';analyze='Analyze';domain='Domain';collector='Collector';snapshot='Snapshot';outputroot='OutputRoot';correlation='Correlation'}
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
