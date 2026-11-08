function Get-WinSecInputParameters {
    # Shared with the literal command parser; completion never invokes PowerShell.
    return @{
        Switches=@{s='Scan';scan='Scan';n='Nist';nist='Nist';w='WinSecBaseline';winsecbaseline='WinSecBaseline';r='Correlate';correlate='Correlate';deep='Deep';list='List';report='Report';nobanner='NoBanner'}
        Values=@{a='Analyze';analyze='Analyze';domain='Domain';collector='Collector';snapshot='Snapshot';outputroot='OutputRoot';correlation='Correlation'}
        Names=@{
            Scan=@('-s','-Scan');Analyze=@('-a','-Analyze');Nist=@('-n','-Nist');WinSecBaseline=@('-w','-WinSecBaseline')
            Correlate=@('-r','-Correlate');Deep=@('-Deep');List=@('-List');Report=@('-Report')
            NoBanner=@('-NoBanner');Domain=@('-Domain');Collector=@('-Collector')
            Snapshot=@('-Snapshot');OutputRoot=@('-OutputRoot');Correlation=@('-Correlation')
        }
    }
}

function Get-WinSecCommandCompletion {
    param([string]$Text,[string]$Domain='all',[string]$Collector)
    $result=[pscustomobject]@{Start=$Text.Length;Matches=@()}
    $root=[regex]::Match($Text,'^\s*(?<word>[a-zA-Z]*)$')
    if ($root.Success) {
        $result.Start=$root.Groups['word'].Index
        if ('winsec'.StartsWith($root.Groups['word'].Value,[StringComparison]::OrdinalIgnoreCase)) { $result.Matches=@('winsec') }
        return $result
    }
    $tokens=$null; $errors=$null
    $ast=[System.Management.Automation.Language.Parser]::ParseInput($Text,[ref]$tokens,[ref]$errors)
    if (@($errors).Count -gt 0 -or $null -eq $ast.EndBlock -or $ast.EndBlock.Statements.Count -ne 1) { return $result }
    $pipeline=$ast.EndBlock.Statements[0]
    if ($pipeline -isnot [System.Management.Automation.Language.PipelineAst] -or $pipeline.PipelineElements.Count -ne 1) { return $result }
    $command=$pipeline.PipelineElements[0]
    if ($command -isnot [System.Management.Automation.Language.CommandAst] -or $command.GetCommandName() -ne 'winsec' -or
        $command.InvocationOperator -ne [System.Management.Automation.Language.TokenKind]::Unknown -or $command.Redirections.Count -gt 0) { return $result }
    $elements=@($command.CommandElements | Select-Object -Skip 1)
    $fragment=''
    if ($Text -notmatch '\s$' -and $elements.Count -gt 0) {
        $last=$elements[-1]
        if ($last -is [System.Management.Automation.Language.CommandParameterAst] -and $null -eq $last.Argument) { $fragment='-'+$last.ParameterName }
        elseif ($last -is [System.Management.Automation.Language.StringConstantExpressionAst] -or
            ($last -is [System.Management.Automation.Language.ConstantExpressionAst] -and $last.Value -is [int])) { $fragment=[string]$last.Value }
        else { return $result }
        $result.Start=$last.Extent.StartOffset
        $elements=@($elements | Select-Object -SkipLast 1)
    }
    $metadata=Get-WinSecInputParameters
    $parsed=@{}; $pending=$null
    foreach ($element in $elements) {
        if ($element -is [System.Management.Automation.Language.CommandParameterAst]) {
            if ($pending -or $null -ne $element.Argument) { return $result }
            $name=$element.ParameterName.ToLowerInvariant()
            if ($metadata.Switches.ContainsKey($name)) {
                $key=$metadata.Switches[$name]
                if ($parsed.ContainsKey($key)) { return $result }
                $parsed[$key]=$true
            } elseif ($metadata.Values.ContainsKey($name)) { $pending=$metadata.Values[$name] }
            else { return $result }
        } elseif ($element -is [System.Management.Automation.Language.StringConstantExpressionAst] -or
            ($element -is [System.Management.Automation.Language.ConstantExpressionAst] -and $element.Value -is [int])) {
            $key=if ($pending) {$pending} else {'Domain'}
            if ($parsed.ContainsKey($key)) { return $result }
            $parsed[$key]=$element.Value; $pending=$null
        } else { return $result }
    }
    $catalog=@(Get-WinSecCatalog)
    $sections=@(Get-WinSecSections)
    $controls=@($catalog | Where-Object {$_.id -eq $Collector})+
        @($catalog | Where-Object {$_.domain -eq $Domain -and $_.id -ne $Collector})+
        @($catalog | Where-Object {$_.domain -ne $Domain -and $_.id -ne $Collector})
    $sectionNames=@($sections | ForEach-Object {$_.Command;ConvertTo-WinSecControlName $_.Domain})+@('logging')
    $targets=$sectionNames+@($controls | ForEach-Object {ConvertTo-WinSecControlName $_.id})
    if ($Domain -ne 'all' -or $Collector) {
        $targets=@($controls | Where-Object {$_.domain -eq $Domain -or $_.id -eq $Collector} | ForEach-Object {ConvertTo-WinSecControlName $_.id})+$targets
    }
    $mode=if ($parsed.ContainsKey('Analyze')) {'Analyze'} elseif ($parsed.ContainsKey('Scan')) {'Scan'}
        elseif ($parsed.ContainsKey('Correlate') -or $parsed.ContainsKey('Correlation')) {'Correlation'}
        elseif ($parsed.ContainsKey('Report')) {'Report'} elseif ($parsed.ContainsKey('List')) {'List'} else {''}
    $choices=@()
    if ($pending) {
        switch ($pending) {
            'Analyze' { $choices=$targets }
            'Domain' { $choices=$sectionNames+@('all') }
            'Collector' { $choices=@($controls | ForEach-Object {ConvertTo-WinSecControlName $_.id}) }
            'Correlation' { $choices=@('1','2','3','4','5') }
        }
    } elseif (-not $fragment.StartsWith('-') -and -not $parsed.ContainsKey('Domain') -and -not $parsed.ContainsKey('Collector') -and $mode -in @('Scan','Correlation')) {
        $choices=if ($mode -eq 'Scan') {$targets+@('all')} else {@('1','2','3','4')}
    } else {
        $allowed=switch ($mode) {
            'Analyze' {@('Nist','WinSecBaseline','Snapshot','NoBanner')}
            'Scan' {@('Deep','Collector','NoBanner')}
            'Correlation' {@('Snapshot','NoBanner')}
            'Report' {@('Snapshot','NoBanner')}
            'List' {@('NoBanner')}
            default {@('Scan','Analyze','Correlate','List','Report','Snapshot','OutputRoot','NoBanner','Domain','Collector','Correlation')}
        }
        foreach ($key in $allowed) {
            if ($parsed.ContainsKey($key)) { continue }
            if (($key -eq 'WinSecBaseline' -and $parsed.ContainsKey('Nist')) -or ($key -eq 'Nist' -and $parsed.ContainsKey('WinSecBaseline'))) { continue }
            if ($key -eq 'Collector' -and $parsed.ContainsKey('Domain')) { continue }
            $names=@($metadata.Names[$key])
            $choices+=$names[0]
            if ($fragment.Length -gt 2 -and $names.Count -gt 1) { $choices+=$names[1] }
        }
    }
    $seen=@{}
    $result.Matches=@(foreach ($choice in $choices) {
        if ($choice.StartsWith($fragment,[StringComparison]::OrdinalIgnoreCase) -and -not $seen.ContainsKey($choice)) {
            $seen[$choice]=$true
            $choice
        }
    })
    return $result
}

function New-WinSecCompletionState {
    param([string]$Text,[string]$Domain='all',[string]$Collector)
    $model=Get-WinSecCommandCompletion -Text $Text -Domain $Domain -Collector $Collector
    if ($model.Matches.Count -eq 0) { return $null }
    return [pscustomobject]@{
        Prefix=$Text.Substring(0,$model.Start);Matches=$model.Matches
        Index=-1;LastText=$Text;Cycle=$false
    }
}

function Get-WinSecCompletionLines {
    param($Completion,[int]$Width=80)
    if ($null -eq $Completion -or $Completion.Matches.Count -eq 0) { return }
    # Page the visible alternatives so hints and the footer remain below them.
    $index=[math]::Max(0,$Completion.Index)
    $first=[int][math]::Floor($index/8)*8
    $last=[math]::Min($first+7,$Completion.Matches.Count-1)
    'Matches {0}-{1}/{2}:' -f ($first+1),($last+1),$Completion.Matches.Count
    $line=''
    for ($i=$first; $i -le $last; $i++) {
        $name=$Completion.Matches[$i]
        if ($i -eq $Completion.Index) { $name='['+$name+']' }
        $part=if ($line) {' | '+$name} else {$name}
        if ($line -and $line.Length+$part.Length -gt $Width-3) { $line; $line=$name }
        else { $line+=$part }
    }
    if ($line) { $line }
}
