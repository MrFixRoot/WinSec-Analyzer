# Ayuda de controles: Network Security

Escanear esta seccion:
    winsec -s network

Escanear un solo control:
    winsec -s smb

Analizar una seccion o un control:
    winsec -a [section|control] -n|w
    Elige un nombre y una opcion; no escribas los corchetes ni |.

Marcos de referencia:
    -n [n]ist csf 2.0
    -w [w]insec baseline

Seccion disponible:
    network (Network Security)

Controles disponibles:
    smb
    rdp
    winRM
    tcpListeners
    networkAdapters
    dnsAndProxy
