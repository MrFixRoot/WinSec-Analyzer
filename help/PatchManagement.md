# Ayuda de controles: Patch Management

Escanear esta seccion:
    winsec -s patch

Escanear un solo control:
    winsec -s windowsUpdate

Marcos de referencia:
    -a [A]nalizar
    -c [C]IS Benchmarks
    -n [N]IST CSF 2.0

Ejemplos de analisis por control (un framework por comando):
    winsec -a windowsUpdate -n
    winsec -a windowsUpdate -c
    winsec -a installedHotfixes -n
    winsec -a installedHotfixes -c
    winsec -a pendingReboot -n
    winsec -a pendingReboot -c
