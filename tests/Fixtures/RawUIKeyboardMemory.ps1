# Windows RawUI semantics in memory: KeyAvailable includes key-up records.
# A filtered ReadKey with no matching record would block; the fixture throws
# instead so a regression fails deterministically without hanging the test.
function New-WinSecRawUIKeyboardFixture {
    param([Parameter(Mandatory)][System.Collections.Generic.Queue[object]]$Keys)
    $inputUI=[pscustomobject]@{Keys=$Keys;ReadCalls=0;BlockedReads=0;Options=New-Object 'System.Collections.Generic.List[object]'}
    $inputUI|Add-Member -MemberType ScriptProperty -Name KeyAvailable -Value {$this.Keys.Count -gt 0}
    $inputUI|Add-Member -MemberType ScriptMethod -Name ReadKey -Value {
        param([System.Management.Automation.Host.ReadKeyOptions]$Options)
        $this.ReadCalls++;$this.Options.Add($Options)
        while($this.Keys.Count -gt 0) {
            $key=$this.Keys.Dequeue()
            $wanted=if($key.KeyDown){[System.Management.Automation.Host.ReadKeyOptions]::IncludeKeyDown}
                else{[System.Management.Automation.Host.ReadKeyOptions]::IncludeKeyUp}
            if(($Options -band $wanted) -ne 0){return $key}
        }
        $this.BlockedReads++
        throw 'ReadKey would wait for a future key after filtering buffered input.'
    }
    return $inputUI
}
