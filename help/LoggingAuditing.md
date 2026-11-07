# Ayuda: Logging & Auditing

Escanear esta seccion:
    winsec -s logging

Escanear un solo control:
    winsec -s -Collector AuditPolicy

Analizar la seccion:
    winsec -a logging -c
    winsec -a logging -n

Analizar un control sin abrir su menu:
    winsec -a AuditPolicy -c
    winsec -a AuditPolicy -n

Controles disponibles:
    AuditPolicy
    PowerShellLogging
    EventLogConfiguration

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
