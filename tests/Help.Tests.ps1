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
            $names=@($rendered | ForEach-Object {$_.ToString().Trim()})
            Assert-Test ($text.Contains('winsec -a [section|control] -n|w') -and $text.Contains($section.Command+' ('+$section.Name+')')) 'Help must show compact analysis syntax and the section name.'
            Assert-Test ($text -notmatch 'winsec -a [a-zA-Z]') 'Section help must omit concrete analysis examples.'
            foreach ($control in @(Get-WinSecCatalog | Where-Object {$_.domain -eq $section.Domain})) {
                $name=ConvertTo-WinSecControlName $control.id
                Assert-Test (@($names | Where-Object {$_ -ceq $name}).Count -eq 1) 'Every control must be listed once by its canonical name.'
                $renderedControl=@(Show-WinSecHelp -Domain $section.Domain -Collector $control.id 6>&1)
                $controlText=($renderedControl | ForEach-Object {$_.ToString()}) -join [Environment]::NewLine
                Assert-Test ($controlText.Contains('winsec -s '+$name) -and $controlText.Contains('winsec -a [section|control] -n|w') -and $controlText -notmatch 'winsec -a [a-zA-Z]') 'Every selected control must keep compact help without analysis examples.'
            }
            Assert-Test ($text -notmatch 'Esc:|Q / q|-a \[A\]nalizar|winsec -a all') 'Help must retain compact contextual examples.'
            Assert-Test ($text.Contains('-w [w]insec baseline') -and $text.Contains('-n [n]ist csf 2.0')) 'Framework descriptions must remain available.'
            Assert-Test ($text.IndexOf('-n [n]ist csf 2.0') -lt $text.IndexOf('-w [w]insec baseline')) 'NIST must precede WinSec Baseline in every section help page.'
        }
        $rendered=@(Show-WinSecHelp 6>&1)
        $text=($rendered | ForEach-Object {$_.ToString()}) -join [Environment]::NewLine
        Assert-Test ($text.Contains('winsec -a [section|control] -n|w') -and $text -notmatch 'winsec -a [a-zA-Z]') 'General help must also show syntax instead of concrete analysis examples.'
        foreach ($section in @(Get-WinSecSections)) {Assert-Test ($text.Contains($section.Command+' ('+$section.Name+')')) 'General help must list every section name.'}
        foreach ($id in 1..4) {Assert-Test ($text.Contains('winsec -r '+$id)) 'General help must describe each correlation.'}
        Assert-Test ($text.Contains('Ejecuta las correlaciones 1, 2, 3 y 4')) 'Option 5 must explain its four correlations.'
        Write-Output ('PASS: '+$script:assertions+' help assertions')
    }
} finally {Remove-Module WinSecAnalyzer -ErrorAction SilentlyContinue}
