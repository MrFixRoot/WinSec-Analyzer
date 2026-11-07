# Ayuda de controles: Identity & Access

Escanear esta seccion:
    winsec -s identity

Escanear un solo control:
    winsec -s localUsers

Marcos de referencia:
    -a [A]nalizar
    -c [C]IS Benchmarks
    -n [N]IST CSF 2.0

Ejemplos de analisis por control (un framework por comando):
    winsec -a localUsers -n
    winsec -a localUsers -c
    winsec -a localGroups -n
    winsec -a localGroups -c
    winsec -a localAdministrators -n
    winsec -a localAdministrators -c
    winsec -a guestAccount -n
    winsec -a guestAccount -c
    winsec -a passwordPolicy -n
    winsec -a passwordPolicy -c
    winsec -a privilegeRights -n
    winsec -a privilegeRights -c
