# Ayuda de controles: Identity & Access

Escanear esta seccion:
    winsec -s identity

Escanear un solo control:
    winsec -s localUsers

Analizar una seccion o un control:
    winsec -a [section|control] -n|w
    Elige un nombre y una opcion; no escribas los corchetes ni |.

Marcos de referencia:
    -n [n]ist csf 2.0
    -w [w]insec baseline

Seccion disponible:
    identity (Identity & Access)

Controles disponibles:
    localUsers
    localGroups
    localAdministrators
    guestAccount
    passwordPolicy
    privilegeRights
