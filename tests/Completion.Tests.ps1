# Completion uses catalog metadata only; no scans, hardware queries or files.
$ErrorActionPreference='Stop'
Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'WinSecAnalyzer.psm1') -Force -DisableNameChecking
try {
    & (Get-Module WinSecAnalyzer) {
        $script:assertions=0; $script:executions=0
        function Assert-Test {
            param([bool]$Condition,[string]$Message)
            if (-not $Condition) {throw ('FAIL: '+$Message)}
            $script:assertions++
        }
        function winsec {$script:executions++;throw 'Completion must not execute commands.'}
        function Assert-WinSecWindows11 {$script:executions++;throw 'Completion must not query Windows.'}
        Assert-Test ((Get-WinSecCommandCompletion 'wins').Matches[0] -eq 'winsec') 'The command name must complete from a prefix.'
        Assert-Test ((Get-WinSecCommandCompletion '').Matches[0] -eq 'winsec') 'Tab on an empty command must offer winsec.'
        foreach ($section in @(Get-WinSecSections)) {
            $matches=(Get-WinSecCommandCompletion -Text 'winsec -s ' -Domain $section.Domain).Matches
            Assert-Test ($matches -contains $section.Command) 'Every documented section must be available for completion.'
        }
        foreach ($agent in @(Get-WinSecCatalog)) {
            $name=ConvertTo-WinSecControlName $agent.id
            $matches=(Get-WinSecCommandCompletion -Text 'winsec -a ' -Domain $agent.domain).Matches
            Assert-Test ($matches -ccontains $name) 'Every registered control must complete with its camelCase name.'
            $parsed=ConvertFrom-WinSecInputCommand ('winsec -a '+$name+' -n')
            Assert-Test ($parsed.Analyze -ceq $name -and $parsed.Nist) 'Completed controls must be accepted by the literal command parser.'
        }
        Assert-Test ((Get-WinSecCommandCompletion 'WINSEC -a WINDOWSDE').Matches -ccontains 'windowsDefender') 'Matching must be case insensitive while preserving canonical spelling.'
        Assert-Test ((Get-WinSecCommandCompletion 'winsec -a ').Matches -notcontains 'all') 'Analysis completion must not suggest a global target.'
        Assert-Test (((Get-WinSecCommandCompletion 'winsec -r ').Matches -join ',') -eq '1,2,3,4') 'Correlation shortcuts must complete only numbers 1 through 4.'
        Assert-Test ((Get-WinSecCommandCompletion 'winsec -Correlation ').Matches -contains '5') 'The long correlation parameter must retain its supported selector 5.'
        foreach ($flag in @('-n','-Nist')) {
            $matches=(Get-WinSecCommandCompletion ('winsec -a windowsDefender '+$flag+' -')).Matches
            Assert-Test ($matches -notcontains '-c' -and $matches -notcontains '-n' -and $matches -contains '-Snapshot') 'Completion must exclude duplicate and conflicting framework flags, including their aliases.'
        }
        Assert-Test ((Get-WinSecCommandCompletion 'winsec -s system -d').Matches -contains '-Deep') 'Scan options must complete after their target.'
        Assert-Test ((Get-WinSecCommandCompletion 'winsec -an').Matches -contains '-Analyze') 'Long parameter aliases must complete when typed.'
        foreach ($text in @('Get-Service -','winsec -s; Get-Service','winsec -s | Get-Service','winsec -s > output.txt','& winsec -s','winsec -a $(Get-Service)','winsec -a $env:USERNAME','winsec -Snapshot ''C:\example path','winsec -s zzzzz')) {
            Assert-Test ((Get-WinSecCommandCompletion $text).Matches.Count -eq 0) 'Unsafe, unsupported or unmatched text must not produce completions.'
        }

        $script:keys=New-Object System.Collections.Queue
        function Get-WinSecCursor {return $null}
        function Move-WinSecCursor {param($Position)}
        function Read-WinSecKey {
            if ($script:keys.Count -eq 0) {throw 'Unexpected extra completion input read.'}
            return $script:keys.Dequeue()
        }
        function Push-Text {
            param([string]$Text)
            foreach ($ch in $Text.ToCharArray()) {$script:keys.Enqueue([pscustomobject]@{VirtualKeyCode=0;Character=$ch;ControlKeyState=0})}
        }
        function Push-Key {
            param([int]$Code,[switch]$Shift)
            $script:keys.Enqueue([pscustomobject]@{VirtualKeyCode=$Code;Character=[char]0;ControlKeyState=$(if ($Shift) {16} else {0})})
        }
        Push-Text 'w';Push-Key 9
        Push-Text '-a';Push-Key 9
        Push-Text 'windowsD';Push-Key 9
        Push-Text '-';Push-Key 9;Push-Key 9;Push-Key 13
        $answer=Read-WinSecInput -CompleteCommands -CompletionDomain SystemSecurity 6>$null
        Assert-Test ($answer.Text -ceq 'winsec -a windowsDefender -n' -and $script:keys.Count -eq 0) 'Tab must complete a command, target and framework without submitting it before Enter.'

        Push-Text 'winsec -a windows';Push-Key 9;Push-Key 9;Push-Key 9;Push-Key 9 -Shift;Push-Key 13
        $rendered=@(Read-WinSecInput -CompleteCommands -CompletionDomain SystemSecurity 6>&1)
        $answer=$rendered[-1]
        $display=($rendered | ForEach-Object {$_.ToString()}) -join [Environment]::NewLine
        Assert-Test ($answer.Text -eq 'winsec -a windowsDefender') 'Repeated Tab and Shift+Tab must move forward and backward through the same matches.'
        Assert-Test ($display -match 'Matches' -and $display -match 'windowsDefender' -and $display -match 'windowsFirewall') 'Ambiguous completion must show the alternatives below the input.'

        Push-Text 'winsec -a windows';Push-Key 9;Push-Text 'Def';Push-Key 9;Push-Key 13
        $answer=Read-WinSecInput -CompleteCommands -CompletionDomain SystemSecurity 6>$null
        Assert-Test ($answer.Text -ceq 'winsec -a windowsDefender') 'Typing after ambiguous completion must narrow the alternatives.'
        Push-Text 'winsec -s syx';Push-Key 8;Push-Key 9;Push-Key 9;Push-Key 13
        $answer=Read-WinSecInput -CompleteCommands 6>$null
        Assert-Test ($answer.Text -eq 'winsec -s system') 'Backspace must update the prefix used for completion.'
        $matches=(Get-WinSecCommandCompletion 'winsec -a windows' -Domain SystemSecurity).Matches
        Push-Text 'winsec -a windows';Push-Key 9;Push-Key 9 -Shift;Push-Key 13
        $answer=Read-WinSecInput -CompleteCommands -CompletionDomain SystemSecurity 6>$null
        Assert-Test ($answer.Text -eq ('winsec -a '+$matches[-1])) 'Shift+Tab from an unselected list must start at its last match.'
        foreach ($code in @(27,112)) {
            Push-Text 'winsec -a windows';Push-Key 9;Push-Key $code
            $answer=Read-WinSecInput -CompleteCommands 6>$null
            Assert-Test ($answer.Text -eq '' -and ($answer.Cancelled -or $answer.HelpRequested)) 'Esc and F1 must remain responsive while matches are displayed.'
        }
        Push-Text 'ws';Push-Key 9;Push-Key 13
        $answer=Read-WinSecInput 6>$null
        Assert-Test ($answer.Text -eq 'ws') 'Tab must leave device names and deletion confirmation fields unchanged.'
        $long='winsec -a windowsDefender -n -Snapshot ''C:\'+('synthetic-directory\'*10)+'manifest.json'''
        Push-Text $long;Push-Key 9;Push-Key 13
        $answer=Read-WinSecInput -CompleteCommands 6>$null
        Assert-Test ($answer.Text -ceq $long) 'Horizontal clipping must preserve the full command and quoted path.'
        $page=New-WinSecCompletionState 'winsec -a '
        $page.Index=9
        $lines=@(Get-WinSecCompletionLines -Completion $page -Width 40)
        Assert-Test ($lines[0] -match '^Matches 9-16/' -and ($lines -join ' ') -match ([regex]::Escape($page.Matches[9]))) 'Long lists must show the page containing the selected match.'
        Assert-Test ($script:executions -eq 0) 'Completing and displaying commands must have no Windows or command-execution side effects.'
        Write-Output ('PASS: '+$script:assertions+' completion assertions')
    }
} finally {Remove-Module WinSecAnalyzer -ErrorAction SilentlyContinue}
