# Ayuda de secciones

Escanear todas las secciones:
    winsec -s

Escanear secciones individuales (elige una):
    winsec -s [system|network|identity|servicesHardening|login|patch]

Marcos de referencia:
    -a [A]nalizar
    -c [C]IS Benchmarks
    -n [N]IST CSF 2.0

Seccion:
    winsec -a network -n
    winsec -a network -c

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
