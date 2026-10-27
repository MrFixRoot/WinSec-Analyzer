# Technical TXT artifacts. No collection, scoring or changes to public history.
. (Join-Path $PSScriptRoot '../Core/TechnicalReportModel.ps1')

function Get-WinSecTechnicalReportPolicy {
    param([string]$ProjectRoot,[string]$DeviceId,[string[]]$CheckIds)
    if(@($CheckIds|Where-Object {$_ -cnotin @('WSA-SYS-001','WSA-SYS-002','WSA-SYS-003')}).Count){throw 'Technical report adapter is not validated.'}
    $parts=@(foreach($file in @('src/Core/TechnicalReportModel.ps1','src/Services/TechnicalReportService.ps1','src/Services/ExportService.ps1')) {
        (Get-FileHash -LiteralPath (Join-Path $ProjectRoot $file) -Algorithm SHA256 -ErrorAction Stop).Hash
    })
    [pscustomobject]@{SchemaVersion='1.0.0';CatalogVersion='1.0.0';Mode='PER_EXECUTED_CONTROL';Count=$CheckIds.Count;
        Directory=('reports/exports/'+(Get-WinSecEvidenceHash $DeviceId));PolicySha256=(Get-WinSecReportTextHash ($parts -join '|'))}
}

function ConvertTo-WinSecTechnicalBody {
    param([object]$Report)
    $r=ConvertTo-WinSecTechnicalReport $Report
    $defs=@(Get-WinSecTechnicalDefinitions $r.CheckId)
    $name=switch($r.CheckId){WSA-SYS-001 {'Windows Defender'};WSA-SYS-002 {'BitLocker'};WSA-SYS-003 {'Windows Update'}}
    $lines=New-Object 'Collections.Generic.List[string]'
    foreach($line in @('WINSEC ANALYZER - INFORME TECNICO DETALLADO',
        ('Dispositivo: '+$r.DeviceName),('Hostname observado: '+$r.Hostname),('DeviceId: '+$r.DeviceId),
        ('Seccion: '+$r.SectionKey),('Control: '+$name+' / '+$r.CheckId),('ScanId: '+$r.ScanId),
        ('Alcance original: '+$r.ScopeType+' / '+$r.ScopeKey),('Windows observado: '+$r.ObservedOSRelease+' / '+$r.ObservedEdition),
        ('Perfil elegido (no sustituye al SO observado): '+$r.Profile),('Recopilado UTC: '+$r.CollectedAtUTC),
        ('Generado UTC: '+$r.GeneratedAtUTC),('Estado del recolector: '+$r.CollectorStatus),
        'Formato/catalogo tecnico: 1.0.0 / 1.0.0','',
        '# Este archivo incluye lecturas informativas; OBSERVED no significa PASS.',
        '# false y 0 son valores observados. UNKNOWN/ERROR no equivalen a fallo de seguridad.',
        '# NOT_COLLECTED indica un campo sin lectura. No se consultan otros controles para rellenarlo.',
        '# Claves, rutas personales, URLs de servidores y mensajes libres quedan fuera del catalogo.',
        '# Defender: preferencias Disable=true desactivan la funcion correspondiente.',
        '# PUA: 0 desactivado, 1 bloqueo, 2 auditoria. MAPS: 0 sin nube, 1 basico, 2 avanzado.',
        '# ASR: BLOCK bloquea, AUDIT registra, WARN advierte; no demuestra bloqueo efectivo.',
        '# BitLocker: EncryptionPercentage es el porcentaje cifrado; ProtectionStatus indica proteccion activa.',
        '# Windows Update: UBR es la revision instalada. NOT_CONFIGURED no significa desactivado.',
        '# Estas notas describen lecturas; los criterios y notas originales se consultan en Findings/Markdown.',
        '# Los valores tecnicos siguen sus nombres originales para facilitar el analisis manual.','')){$lines.Add($line)}
    $group=''
    foreach($row in $r.Rows) {
        $d=Get-WinSecTechnicalRowDefinition $row.SettingId $defs
        if($d.Group -cne $group){$group=$d.Group;$lines.Add('');$lines.Add('=== '+$group+' ===')}
        $value=if($null -eq $row.Value){'(sin valor)'}else{ConvertTo-Json -InputObject $row.Value -Compress}
        $source=$d.Source
        if($r.CheckId -ceq 'WSA-SYS-001' -and $source -cin @('Get-MpComputerStatus','Get-MpPreference')) {
            $sourceField=if($source -ceq 'Get-MpComputerStatus'){'StatusSource'}else{'PreferenceSource'}
            $origin=@($r.Rows|Where-Object SettingId -CEQ $sourceField)[0]
            $source=if($origin.State -ceq 'OBSERVED'){$origin.Value}else{'Defender provider (unresolved)'}
        }
        $lines.Add($row.SettingId+' = '+$value)
        $lines.Add('  Estado: '+$row.State+' | Motivo: '+$row.Reason+' | Tipo: '+$d.Kind+' | Fuente: '+$source)
    }
    $lines.Add('');$lines.Add('=== DATOS ESTRUCTURADOS JSON / 1.0.0 ===')
    $lines.Add((Get-WinSecPublicHistoryJson $r))
    return ($lines -join "`n")+"`n"
}

function ConvertFrom-WinSecTechnicalArtifact {
    param([Parameter(Mandatory)][string]$Text,[Parameter(Mandatory)][string]$DeviceId)
    if([Text.Encoding]::UTF8.GetByteCount($Text) -gt 1048576 -or $Text -match '[\x00-\x09\x0b-\x1f\x7f]' -or
        $Text -cnotmatch '\AWinSec technical scan report\n([^\r\n]+)\n\n([\s\S]*)\z'){throw 'Unrecognized technical report.'}
    $metadata=$Matches[1];$body=$Matches[2]
    $m=ConvertFrom-WinSecStoredJson $metadata
    Assert-WinSecConfigurationFields $m @('SchemaVersion','DeviceId','ScanId','CheckId','ScopeType','ScopeKey','ContentSha256')
    if($m.SchemaVersion -cne '1.0.0' -or $m.DeviceId -isnot [string] -or $m.DeviceId -cne $DeviceId -or
        $m.ContentSha256 -isnot [string] -or $m.ContentSha256 -cne (Get-WinSecReportTextHash $body)){throw 'Invalid technical report ownership or digest.'}
    $marker="`n=== DATOS ESTRUCTURADOS JSON / 1.0.0 ===`n"
    $at=$body.LastIndexOf($marker,[StringComparison]::Ordinal)
    if($at -lt 0){throw 'Missing technical data record.'}
    $r=ConvertTo-WinSecTechnicalReport (ConvertFrom-WinSecStoredJson ($body.Substring($at+$marker.Length).TrimEnd("`n")))
    foreach($field in @('DeviceId','ScanId','CheckId','ScopeType','ScopeKey')) {
        if($m.$field -isnot [string] -or $m.$field -cne $r.$field){throw 'Mixed technical report identity.'}
    }
    if((ConvertTo-WinSecTechnicalBody $r) -cne $body){throw 'Technical report text contradicts its data.'}
    return $m
}

function Write-WinSecTechnicalArtifact {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectRoot,[Parameter(Mandatory)][object]$Report)
    $ProjectRoot=Get-WinSecReportInstallation $ProjectRoot
    $r=ConvertTo-WinSecTechnicalReport $Report;$body=ConvertTo-WinSecTechnicalBody $r
    $m=[ordered]@{SchemaVersion='1.0.0';DeviceId=$r.DeviceId;ScanId=$r.ScanId;CheckId=$r.CheckId;
        ScopeType=$r.ScopeType;ScopeKey=$r.ScopeKey;ContentSha256=(Get-WinSecReportTextHash $body)}
    $text="WinSec technical scan report`n"+(ConvertTo-Json $m -Compress)+"`n`n"+$body
    $null=ConvertFrom-WinSecTechnicalArtifact $text $r.DeviceId
    $hash=Get-WinSecEvidenceHash $r.DeviceId
    $stamp=(ConvertTo-WinSecResultUtc $r.GeneratedAtUTC GeneratedAtUTC).UtcDateTime.ToString('yyyyMMdd_HHmmssfffZ')
    $token=(Get-WinSecReportTextHash $r.ScanId).Substring(0,12).ToLowerInvariant()
    $name=$hash.Substring(0,12)+'_'+$r.SectionKey+'_'+$r.CheckId+'_'+$stamp+'_'+$token+'.txt'
    $directory=Join-Path $ProjectRoot ('reports/exports/'+$hash);$path=Join-Path $directory $name
    $temporary=Join-Path $directory ('.'+[guid]::NewGuid().ToString('N')+'.tmp')
    if($path.Length -gt 240){throw 'Technical report path exceeds compatibility limit.'}
    Assert-WinSecDeviceRemovalPath $ProjectRoot $path
    $null=[IO.Directory]::CreateDirectory($directory)
    Assert-WinSecDeviceRemovalPath $ProjectRoot $path
    Assert-WinSecDeviceRemovalPath $ProjectRoot $temporary
    $owned=$false;$moved=$false
    try {
        $bytes=[Text.Encoding]::UTF8.GetBytes($text)
        $stream=[IO.File]::Open($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);$owned=$true
        try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
        Assert-WinSecDeviceRemovalPath $ProjectRoot $temporary
        if((Get-FileHash -LiteralPath $temporary -Algorithm SHA256).Hash -cne (Get-WinSecReportTextHash $text)){throw 'Technical write verification failed.'}
        Assert-WinSecDeviceRemovalPath $ProjectRoot $path
        [IO.File]::Move($temporary,$path);$moved=$true
        Assert-WinSecDeviceRemovalPath $ProjectRoot $path
        if((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne (Get-WinSecReportTextHash $text)){throw 'Technical publication verification failed.'}
        [pscustomobject]@{DeviceId=$r.DeviceId;ScanId=$r.ScanId;CheckId=$r.CheckId;Path=$path;RelativePath=('reports/exports/'+$hash+'/'+$name)}
    } finally {
        if($owned -and -not $moved){Assert-WinSecDeviceRemovalPath $ProjectRoot $temporary;if([IO.File]::Exists($temporary)){[IO.File]::Delete($temporary)}}
    }
}

function Save-WinSecTechnicalReports {
    param([object]$Coordinator,[object]$Session,[object]$Target,[AllowNull()][object]$Context)
    $files=@();$failures=@();$name=$Target.Hostname;$lease=$null
    try {
    try {
        $managed=(Get-WinSecTargetField $Coordinator RequireDeviceInventory) -ceq $true
        # Serialize managed-device writes with Delete Device. Re-read ownership
        # under the same inventory lease, so a removed device gains no orphan TXT.
        if($managed){$lease=Open-WinSecDeviceInventoryStore $Coordinator.ProjectRoot}
        $inventory=Import-WinSecDeviceInventory $Coordinator.ProjectRoot
        $devices=@($inventory.targets|Where-Object DeviceId -CEQ $Session.DeviceId)
        if($devices.Count -gt 1 -or ($managed -and $devices.Count -ne 1)){throw 'Missing or duplicate technical device metadata.'}
        if($devices.Count -eq 1) {
            $label=(Get-WinSecTechnicalField $devices[0] DisplayName).Value
            if($label){$name=$label}
        }
        if(-not (Test-WinSecDeviceDisplayName $name)){throw 'Invalid technical device label.'}
    } catch {return [pscustomobject]@{DeviceId=$Session.DeviceId;ScanId=$Session.ScanId;Status='FAILED';Files=@();FailedCheckIds=@($Session.ControlResults|Where-Object Status -CNE NOT_SELECTED|ForEach-Object CheckId)}}
    foreach($check in @($Session.ControlResults|Where-Object Status -CNE NOT_SELECTED)) {
        try {
            $report=New-WinSecTechnicalReport -Session $Session -CheckId $check.CheckId -DeviceName $name -Hostname $Target.Hostname -Context $Context
            $files+=Write-WinSecTechnicalArtifact -ProjectRoot $Coordinator.ProjectRoot -Report $report
        } catch {$failures+=$check.CheckId}
    }
    [pscustomobject]@{DeviceId=$Session.DeviceId;ScanId=$Session.ScanId;Status=if($failures.Count){if($files.Count){'PARTIAL'}else{'FAILED'}}else{'SAVED'};
        Files=$files;FailedCheckIds=$failures}
    } finally {if($null -ne $lease){$lease.Lock.Dispose()}}
}
