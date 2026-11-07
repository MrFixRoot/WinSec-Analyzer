# Ayuda de controles: Network Security

Escanear esta seccion:
    winsec -s network

Escanear un solo control:
    winsec -s smb

Marcos de referencia:
    -a [A]nalizar
    -c [C]IS Benchmarks
    -n [N]IST CSF 2.0

Ejemplos de analisis por control (un framework por comando):
    winsec -a smb -n
    winsec -a smb -c
    winsec -a rdp -n
    winsec -a rdp -c
    winsec -a winRM -n
    winsec -a winRM -c
    winsec -a tcpListeners -n
    winsec -a tcpListeners -c
    winsec -a networkAdapters -n
    winsec -a networkAdapters -c
    winsec -a dnsAndProxy -n
    winsec -a dnsAndProxy -c
