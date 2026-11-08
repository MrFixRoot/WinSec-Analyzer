# Ayuda de secciones

Escanear todas las secciones:
    winsec -s

Escanear secciones individuales (elige una):
    winsec -s [system|network|identity|servicesHardening|login|patch]

Analizar una seccion o un control:
    winsec -a [section|control] -n|w
    Elige un nombre y una opcion; no escribas los corchetes ni |.

Marcos de referencia:
    -n [n]ist csf 2.0
    -w [w]insec baseline

Secciones disponibles:
    system (System Security)
    network (Network Security)
    identity (Identity & Access)
    servicesHardening (Services & Hardening)
    login (Logging & Auditing)
    patch (Patch Management)

Correlacion PLUS [+]:
    -r co[r]relation

Correlacion 1: Network Security + Services & Hardening
    winsec -r 1
Correlacion 2: Identity & Access + Logging & Auditing
    winsec -r 2
Correlacion 3: Network Security + Identity & Access
    winsec -r 3
Correlacion 4: System Security + Logging & Auditing
    winsec -r 4
Correlacion 5: Ejecuta las correlaciones 1, 2, 3 y 4
    winsec -r
