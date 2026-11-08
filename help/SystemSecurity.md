# Ayuda de controles: System Security

Escanear esta seccion:
    winsec -s system

Escanear un solo control:
    winsec -s windowsDefender

Analizar una seccion o un control:
    winsec -a [section|control] -n|w
    Elige un nombre y una opcion; no escribas los corchetes ni |.

Marcos de referencia:
    -n [n]ist csf 2.0
    -w [w]insec baseline

Seccion disponible:
    system (System Security)

Controles disponibles:
    windowsDefender
    windowsFirewall
    bitLocker
    secureBoot
    tpm
    uac
    credentialGuard
    smartScreen
