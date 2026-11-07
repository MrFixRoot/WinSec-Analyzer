# Ayuda de controles: Services & Hardening

Escanear esta seccion:
    winsec -s servicesHardening

Escanear un solo control:
    winsec -s services

Marcos de referencia:
    -a [A]nalizar
    -c [C]IS Benchmarks
    -n [N]IST CSF 2.0

Ejemplos de analisis por control (un framework por comando):
    winsec -a services -n
    winsec -a services -c
    winsec -a windowsFeatures -n
    winsec -a windowsFeatures -c
    winsec -a startupEntries -n
    winsec -a startupEntries -c
    winsec -a systemHardening -n
    winsec -a systemHardening -c
    winsec -a powerShellPolicy -n
    winsec -a powerShellPolicy -c
    winsec -a installedSoftware -n
    winsec -a installedSoftware -c
