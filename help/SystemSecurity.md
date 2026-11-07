# Ayuda de controles: System Security

Escanear esta seccion:
    winsec -s system

Escanear un solo control:
    winsec -s windowsDefender

Marcos de referencia:
    -a [A]nalizar
    -c [C]IS Benchmarks
    -n [N]IST CSF 2.0

Ejemplos de analisis por control (un framework por comando):
    winsec -a windowsDefender -n
    winsec -a windowsDefender -c
    winsec -a windowsFirewall -n
    winsec -a windowsFirewall -c
    winsec -a bitLocker -n
    winsec -a bitLocker -c
    winsec -a secureBoot -n
    winsec -a secureBoot -c
    winsec -a tpm -n
    winsec -a tpm -c
    winsec -a uac -n
    winsec -a uac -c
    winsec -a credentialGuard -n
    winsec -a credentialGuard -c
    winsec -a smartScreen -n
    winsec -a smartScreen -c
