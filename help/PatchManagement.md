# Ayuda: Patch Management

Escanear esta seccion:
    winsec -s patch

Escanear un solo control:
    winsec -s -Collector WindowsUpdate

Analizar la seccion:
    winsec -a patch -c
    winsec -a patch -n

Analizar un control sin abrir su menu:
    winsec -a WindowsUpdate -c
    winsec -a WindowsUpdate -n

Controles disponibles:
    WindowsUpdate
    InstalledHotfixes
    PendingReboot

Selecciona el numero del control para entrar a Analyze [A].
Despues elige CIS [C] o NIST CSF [N]; siempre por separado.
Scanned (verde): recoleccion completa; no significa cumplimiento.
Scanned (partial): hay advertencias. Scan error: la consulta fallo.
Not yet: no existe una recoleccion del control en esta captura.

Esc: cancelar / volver atras. Q / q: salir. help: abrir esta ayuda.
Un solo utc_runId por sesion interactiva; los JSON se agregan por control.
Repetir un escaneo reutiliza la evidencia guardada, sin sobrescribirla.
Una captura historica abierta con -Snapshot solo se usa para consultar.
CIS sin pack verificado: NOT_CONFIGURED. NIST no certifica cumplimiento.
