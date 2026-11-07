# Ayuda de controles: Logging & Auditing

Escanear esta seccion:
    winsec -s login

Escanear un solo control:
    winsec -s auditPolicy

Marcos de referencia:
    -a [A]nalizar
    -c [C]IS Benchmarks
    -n [N]IST CSF 2.0

Ejemplos de analisis por control (un framework por comando):
    winsec -a auditPolicy -n
    winsec -a auditPolicy -c
    winsec -a powerShellLogging -n
    winsec -a powerShellLogging -c
    winsec -a eventLogConfiguration -n
    winsec -a eventLogConfiguration -c
