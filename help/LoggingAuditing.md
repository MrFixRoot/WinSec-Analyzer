# Ayuda de controles: Logging & Auditing

Escanear esta seccion:
    winsec -s login

Escanear un solo control:
    winsec -s auditPolicy

Analizar una seccion o un control:
    winsec -a [section|control] -n|w
    Elige un nombre y una opcion; no escribas los corchetes ni |.

Marcos de referencia:
    -n [n]ist csf 2.0
    -w [w]insec baseline

Seccion disponible:
    login (Logging & Auditing)

Controles disponibles:
    auditPolicy
    powerShellLogging
    eventLogConfiguration
