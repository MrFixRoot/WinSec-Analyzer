# Validate public help without local Markdown maps or Windows queries.
$ErrorActionPreference='Stop'
Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'WinSecAnalyzer.psm1') -Force -DisableNameChecking
try {
    & (Get-Module WinSecAnalyzer) {
        $script:assertions=0
        function Assert-Test {
            param([bool]$Condition,[string]$Message)
            if (-not $Condition) {throw ('FAIL: '+$Message)}
            $script:assertions++
        }
        function Assert-WinSecWindows11 {throw 'Help must not query Windows.'}
        function Test-Path {param($LiteralPath,$PathType) return $false}
        foreach ($section in @(Get-WinSecSections)) {
            $rendered=@(Show-WinSecHelp -Domain $section.Domain 6>&1)
            $text=($rendered | ForEach-Object {$_.ToString()}) -join [Environment]::NewLine
            Assert-Test ($text.Contains('winsec -s '+$section.Command)) 'Section help must work without a local Markdown file.'
            $examples=$text.Substring($text.IndexOf('Ejemplos de analisis por control'))
            foreach ($control in @(Get-WinSecCatalog | Where-Object {$_.domain -eq $section.Domain})) {
                foreach ($flag in @('n','c')) {
                    $pattern='winsec -a '+[regex]::Escape($control.id)+' -'+$flag+'(?=\s|$)'
                    Assert-Test ([regex]::Matches($examples,$pattern,[Text.RegularExpressions.RegexOptions]::IgnoreCase).Count -eq 1) 'Every control must have one example for each framework.'
                }
            }
            foreach ($flag in @('n','c')) {
                Assert-Test ($text.Contains('winsec -a '+$section.Command+' -'+$flag)) 'Section analysis examples must retain separate frameworks.'
            }
            Assert-Test ($text -notmatch 'Esc:|Q / q|-a \[A\]nalizar|winsec -a all') 'Help must retain compact contextual examples.'
            Assert-Test ($text.Contains('-c [c]is benchmarks') -and $text.Contains('-n [n]ist csf 2.0')) 'Framework descriptions must remain available.'
        }
        $rendered=@(Show-WinSecHelp 6>&1)
        $text=($rendered | ForEach-Object {$_.ToString()}) -join [Environment]::NewLine
        foreach ($id in 1..4) {Assert-Test ($text.Contains('winsec -r '+$id)) 'General help must describe each correlation.'}
        Assert-Test ($text.Contains('Ejecuta las correlaciones 1, 2, 3 y 4')) 'Option 5 must explain its four correlations.'
        Write-Output ('PASS: '+$script:assertions+' help assertions')
    }
} finally {Remove-Module WinSecAnalyzer -ErrorAction SilentlyContinue}
