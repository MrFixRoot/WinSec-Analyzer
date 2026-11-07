# Pruebas adicionales para ejecutar en Windows 11 con Pester instalado.
Describe 'WinSec-Analyzer module' {
    BeforeAll {
        Import-Module (Join-Path $PSScriptRoot '../../WinSecAnalyzer.psm1') -Force
    }
    It 'Exports primary CLI and aliases' {
        (Get-Command winsec -ErrorAction Stop).CommandType | Should -Be 'Function'
        (Get-Command win-defender -ErrorAction Stop).CommandType | Should -Be 'Function'
    }
    It 'Registers 32 collector functions' {
        $root = Join-Path $PSScriptRoot '../..'
        $catalog = Get-Content (Join-Path $root 'catalog/collectors.json') -Raw | ConvertFrom-Json
        @($catalog.collectors).Count | Should -Be 32
        foreach ($agent in $catalog.collectors) {
            (Get-Command $agent.function -All -ErrorAction Stop).Count | Should -BeGreaterThan 0
        }
    }
}
