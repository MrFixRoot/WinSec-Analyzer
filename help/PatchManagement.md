# Ayuda de controles: Patch Management

Escanear esta seccion:
    winsec -s patch

Escanear un solo control:
    winsec -s windowsUpdate

Analizar una seccion o un control:
    winsec -a [section|control] -n|w
    Elige un nombre y una opcion; no escribas los corchetes ni |.

Marcos de referencia:
    -n [n]ist csf 2.0
    -w [w]insec baseline

Seccion disponible:
    patch (Patch Management)

Controles disponibles:
    windowsUpdate
    installedHotfixes
    pendingReboot
