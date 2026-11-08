# WinSec-Analyzer

**Windows Security Auditor — Windows 11 Endpoint Configuration Evidence & Assessment**

> **Estado: EN DESARROLLO.** Este repositorio es un prototipo funcional a nivel
> de codigo, con **validacion parcial en Windows 11 y PowerShell 5.1**. No
> constituye un producto certificado, un escaner de vulnerabilidades ni una
> auditoria oficial de cumplimiento CIS o NIST.

WinSec-Analyzer es una herramienta en desarrollo, preparada para GitHub y desarrollada principalmente
en **PowerShell** para recolectar configuraciones de seguridad de estaciones de
trabajo **Windows 11**, almacenarlas en snapshots JSON trazables y analizarlas
posteriormente utilizando **CIS Benchmarks** y **NIST CSF 2.0**. Los resultados
pueden correlacionarse entre dominios sin volver a ejecutar consultas al equipo.

**Autor/alias:** mrRoot  
**GitHub:** https://github.com/MrFixRoot/WinSec-Analyzer  
**LinkedIn:** https://www.linkedin.com/in/normanlp/

No se muestra ningun numero de version de la aplicacion en el banner.

## Alcance y compatibilidad

- **Unicamente Windows 11 de tipo cliente:** Home, Pro, Enterprise, Education
  (algunas APIs solo estan presentes en determinadas ediciones).
- **Excluye expresamente Windows Server y Windows 10.** Se valida ProductType=1
  y build >= 22000 antes de permitir un escaneo.
- **Solo el equipo local:** no hay sondeo de redes, ejecucion remota ni cambios de
  configuracion.
- **Windows PowerShell 5.1 (64 bits)** como referencia inicial; PowerShell 7
  requiere pruebas adicionales de compatibilidad de modulos.
- Algunas fuentes requieren una consola elevada; un fallo debe registrarse, no
  interpretarse como PASS ni como configuracion deshabilitada.
- Modo de recoleccion `STANDARD`; `-Deep` esta expuesto, pero la diferenciacion
  completa por volumen/tipo de fuente sigue en desarrollo.

## Por que separar Scan y Analyze

1. **Scan (`-s`)**: consulta Windows 11, recoge propiedades seguras de cada
   fuente y guarda un JSON por collector mas un `manifest.json` con hashes.
2. **Analyze (`-a <control|seccion|all> -c` o `-n`)**: lee y analiza el snapshot;
   **no vuelve a consultar Windows**.
3. **Correlate (`-Correlation 1..5`)**: une configuraciones de distintas areas del MISMO
   snapshot, registra evidencia faltante y produce observaciones para revision.
4. **Report (`-Report`)**: crea un indice JSON de lo recolectado y analizado.

Un collector **no asigna PASS/FAIL**. Ese estado es exclusivo de reglas de
benchmark explicitas, verificadas y compatibles con la edicion/perfil.

## Seis dominios / 32 agentes de recoleccion

| Dominio | Agentes incluidos | Fuentes y ejemplos |
|---|---|---|
| **System Security** (8) | WindowsDefender, WindowsFirewall, BitLocker, SecureBoot, TPM, UAC, CredentialGuard, SmartScreen | Antivirus y politicas; firmas; firewall perfiles/reglas/filtros; cifrado; UEFI, TPM, LSA, VBS, SmartScreen |
| **Network Security** (6) | SMB, RDP, WinRM, TCPListeners, NetworkAdapters, DNSAndProxy | SMB cliente/servidor, NLA, WinRM, TCP/UDP, interfaces, IP, rutas, DNS, proxy flags |
| **Identity & Access** (6) | LocalUsers, LocalGroups, LocalAdministrators, GuestAccount, PasswordPolicy, PrivilegeRights | Usuarios, membresia, Guest por SID, politicas de contrasena/bloqueo, derechos locales |
| **Services & Hardening** (6) | Services, WindowsFeatures, StartupEntries, SystemHardening, PowerShellPolicy, InstalledSoftware | Servicios, caracteristicas Windows, inicio automatico, UAC/LSA, PowerShell, apps |
| **Logging & Auditing** (3) | AuditPolicy, PowerShellLogging, EventLogConfiguration | `auditpol`, Script Block/Module Logging, transcripcion, canales y retencion |
| **Patch Management** (3) | WindowsUpdate, InstalledHotfixes, PendingReboot | Politicas de WU, servicios, hotfixes visibles, reinicio pendiente |

**Total: 32 agentes con archivos individuales `.ps1` y ~99 familias de
items de evidencia** en `catalog/evidence-inventory.json`. El inventario recoge
**evidencias a recolectar**, no un total de recomendaciones oficiales CIS. La
cobertura exhaustiva de todos los controles de todos los Benchmarks CIS todavia
no esta implementada. Las propiedades disponibles varian segun permisos y
edicion de Windows 11. Algunos collectors son deliberadamente parciales para
proteger secretos o evitar costes excesivos.

## Estado del desarrollo

| Componente | Estado | Situacion real |
|---|---|---|
| Logo, banner, menu interactivo | **Implementado** | Q/Esc, seis secciones y ayuda contextual; validacion parcial PS5.1 |
| 32 agentes por dominios | **Implementacion inicial** | Consultas y normalizacion creadas; por probar en Home/Pro/Enterprise |
| Validacion solo Windows 11 | **Implementado en codigo** | Comprobacion de build y tipo de producto; requiere prueba en SO real |
| JSON por agente + manifest + SHA-256 | **Implementado en codigo** | Persistencia y comprobacion de hashes; pendiente prueba integral |
| CLI `winsec -s / -a objetivo -c o -n` | **Implementado** | Un framework por comando; regresiones sinteticas PS5.1 |
| Sesion interactiva incremental | **Implementado** | Un runId, manifest compartido y reutilizacion sin sobrescribir collectors |
| Correlaciones 1–4 entre dominios | **Base preparada** | Hechos y disponibilidad; interpretacion avanzada en desarrollo |
| Mapeo NIST CSF 2.0 | **Inicial** | Categorias asociadas a evidencia; subcategorias y validacion pendientes |
| Motor CIS Benchmarks | **Adaptador preparado** | **Sin rulepacks oficiales ni cumplimiento evaluable por defecto** |
| Calificacion CIS | **Condicionada** | Solo si se cargan reglas verificadas y evaluables; no score global por defecto |
| Reportes | **Indice JSON inicial** | HTML/CSV, graficas y comparaciones historicas en desarrollo |
| Pruebas | **Estructurales y sinteticas** | UI/CLI/sesion en PS5.1; matriz completa por edicion pendiente |
| Coleccion Deep | **En desarrollo** | Bandera existe; catalogos profundos adicionales pendientes |
| Firma de evidencias / atestacion | **Pendiente** | Hashes no constituyen una firma digital confiable |

## Requisitos

Windows 11 cliente, PowerShell 5.1, acceso a cmdlets locales de Windows;
permisos de administrador recomendados para auditar mas fuentes. No se
requiere acceso a Internet para escanear ni analizar JSON ya guardado. Las
reglas CIS deben obtenerse legitimamente por el operador cuando se habilite
la funcion.

## Instalacion

Descargar/clonar el repositorio y abrir una terminal **Windows PowerShell
x64** desde su directorio. No modificar ExecutionPolicy del equipo como paso
automatico. Utilizar las politicas de ejecucion aprobadas en la organizacion.

```powershell
Import-Module .\WinSecAnalyzer.psm1 -Force
.\run.ps1
```

## Uso

### Menu y sesion interactiva

```powershell
.\run.ps1
```

El listado principal contiene solamente:

1. System Security
2. Network Security
3. Identity & Access
4. Services & Hardening
5. Logging & Auditing
6. Patch Management

La correlacion queda aparte, como **PLUS [7]**. Escribe `help` para abrir la
ayuda del contexto actual. No hay opciones principales 8, 9 ni 0.

- **Q / q** sale desde cualquier vista, sin confirmacion.
- **Esc** cancela la entrada sin ejecutarla o vuelve al nivel anterior.
- Numeros y atajos de menu funcionan sin Enter; los comandos usan Enter.
- El prompt es `>`, con una sugerencia variable debajo.
- Cada seccion muestra sus controles y el estado registrado en la captura:
  **Scanned** en verde para `COMPLETED`, **Scanned (partial)** en amarillo,
  **Scan error** en rojo, y **Not yet** si no se ha recolectado.
  Estos estados no significan cumplimiento.
- Dentro de un control solo aparece **[A] Analyze**, seguido de
  **[C] CIS Benchmarks** o **[N] NIST CSF 2.0**, siempre por separado.
- Los escaneos se escriben como comandos; el menu del control no ofrece Scan.

El primer escaneo crea
`device/Windows11_<Edition>_<Build>/<Host>/<UTC>_<runId>/`.
Las demas secciones agregan evidencia al **mismo runId y manifest**.
Cada collector conserva su JSON individual. Repetir un collector verifica
su hash y reutiliza lo guardado, sin consultarlo otra vez ni sobrescribirlo.
Esto incluye intentos parciales o fallidos que quedaron guardados.

Al salir se registra `sessionState=CLOSED` y `finishedAtUtc`. Para obtener
una captura nueva, salir con Q y abrir otra sesion. Nunca se agrega evidencia
a una captura historica; `collectedAtUtc` distingue el momento de cada control.

### Comandos del prompt y del entrypoint

Dentro del menu escribe `winsec`. Desde PowerShell, importa el modulo o usa
`.\run.ps1` con los mismos parametros.

```powershell
winsec -s                     # Todas las secciones
winsec -s system
winsec -s network
winsec -s identity
winsec -s services
winsec -s logging
winsec -s patch
winsec -s -Collector WindowsDefender

winsec -a WindowsDefender -c   # CIS para este control
winsec -a WindowsDefender -n   # NIST para este control
winsec -a network -n          # Una seccion
winsec -a all -c              # Toda la evidencia

winsec -Correlation 1         # Network + Services
winsec -Correlation 2         # Identity + Logging
winsec -Correlation 3         # Network + Identity
winsec -Correlation 4         # System + Logging
winsec -Correlation 5         # Las cuatro correlaciones
```

`-a` significa Analyze y recibe **un control, seccion o all**. `-n` elige
NIST CSF; `-c` elige CIS. No se admiten ambos switches ni nombres/listas
de frameworks combinados. `-c` ya no identifica correlaciones.

```powershell
.\run.ps1 -s system -OutputRoot 'D:\WinSec-Private-Evidence'
.\run.ps1 -a WindowsDefender -n -Snapshot 'D:\WinSec-Private-Evidence\captura\manifest.json'
.\run.ps1 -List
.\run.ps1 -Report
.\run.ps1 -Help
.\run.ps1 network -Help
```

En el menu, analizar sin `-Snapshot` usa exclusivamente su captura actual;
si aun no existe, solicita escanear. Fuera del menu, sin `-Snapshot` se busca
la ultima captura del host actual. Analizar JSON no consulta el host.
Al abrir el menu con una captura historica, esta puede analizarse; el primer
escaneo crea una captura nueva.

La reutilizacion de runId corresponde a **una apertura del menu**.
Cada escaneo ejecutado fuera del menu crea una captura independiente.
El prompt acepta opciones literales de `winsec`; no ejecuta expresiones
PowerShell, pipelines, redirecciones ni otros comandos.

### Comandos cortos del modulo

Disponibles desde PowerShell despues de importar el modulo:

```powershell
Import-Module .\WinSecAnalyzer.psm1 -Force
win-defender -s
win-defender -a -c
win-defender -a -n
win-firewall -s
win-bitlocker -s
win-update -s
win-network -s
win-network -a -n
win-identity -s
win-logging -s
win-services -s
```

En los comandos cortos, `-a` es un switch porque el objetivo ya esta definido.

### Ayuda por seccion

La UI lee estos archivos; contienen comandos, controles y navegacion propios:

| Contexto | Archivo |
|---|---|
| General | [help/README.md](help/README.md) |
| System Security | [SystemSecurity.md](help/SystemSecurity.md) |
| Network Security | [NetworkSecurity.md](help/NetworkSecurity.md) |
| Identity & Access | [IdentityAccess.md](help/IdentityAccess.md) |
| Services & Hardening | [ServicesHardening.md](help/ServicesHardening.md) |
| Logging & Auditing | [LoggingAuditing.md](help/LoggingAuditing.md) |
| Patch Management | [PatchManagement.md](help/PatchManagement.md) |

## CIS Benchmarks y NIST

**Solo se utilizaran CIS Benchmarks y NIST CSF 2.0.**

- **CIS Benchmarks:** criterios tecnicos verificables por producto, benchmark,
  version, edicion y perfil. Sin packs oficiales incluidos. El motor devuelve
  `NOT_CONFIGURED` hasta que exista un paquete local legitimo y verificado.
  El porcentaje opcional PASS/(PASS+FAIL) es una metrica propia, no puntuacion
  o certificacion CIS. Defender dispone de un benchmark independiente del de
  Windows 11 en las versiones actuales de CIS.
- **NIST CSF 2.0:** categorias y evidencias observables. `EVIDENCE_AVAILABLE`
  NO significa cumplimiento del resultado organizacional. No se inventa
  `NIST Score` ni `PASS` para CSF.

Referencias oficiales:
[CIS Windows Desktop](https://www.cisecurity.org/benchmark/microsoft_windows_desktop),
[NIST CSF 2.0](https://www.nist.gov/cyberframework).

## Correlaciones entre dominios

| ID | Dominios | Hechos relacionados |
|---|---|---|
| 1 | Network Security + Services & Hardening | WinRM, servicios, puertos, SMB, hardening |
| 2 | Identity & Access + Logging & Auditing | Administradores y disponibilidad de audit policy / logging |
| 3 | Network Security + Identity & Access | RDP/NLA, miembros y reglas de firewall |
| 4 | System Security + Logging & Auditing | Defender, firewall y registros habilitados |
| 5 | Todas | Ejecuta los cuatro conjuntos anteriores |

Las correlaciones unen datos del **mismo snapshot**, no cruzan datos de
momentos diferentes. Si falta evidencia, aparece `INSUFFICIENT_EVIDENCE`.
La presencia de un puerto local no demuestra exposicion desde Internet.

## Estructura de proyecto

```text
WinSec-Analyzer/
├── run.ps1                         # CLI / menu
├── WinSecAnalyzer.psm1              # Modulo PowerShell
├── catalog/
│   ├── collectors.json             # Registry de 32 collectors
│   └── evidence-inventory.json     # Familias de evidencia a recolectar
├── src/
│   ├── core/                        # Validacion, almacenamiento, CLI, analisis
│   ├── collectors/                  # Seis dominios, 32 archivos de agentes .ps1
│   └── ui/                          # Banner/menu/estado
├── help/                            # Ayuda general y seis mapas por seccion
├── config/
│   ├── benchmarks/CIS/             # Ejemplo inactivo
│   ├── benchmarks/local/           # Packs propios no versionados en Git
│   ├── mappings/                   # NIST CSF 2.0
│   └── correlation-rules/          # Cuatro correlaciones
├── tests/                           # Pruebas estructurales y Pester
└── device/                          # Snapshots LOCALES ignorados por Git
```

### Estructura de una ejecucion

```text
device/
└── Windows11_Pro_26100/
    └── DESKTOP-001/
        └── 20261107T165500Z_<runId>/
            ├── manifest.json
            ├── SystemSecurity/WindowsDefender.json
            ├── SystemSecurity/WindowsFirewall.json
            ├── NetworkSecurity/SMB.json
            ├── IdentityAccess/LocalUsers.json
            ├── ServicesHardening/Services.json
            ├── LoggingAuditing/AuditPolicy.json
            ├── PatchManagement/WindowsUpdate.json
            └── analysis/cis|nist|correlations/*.json
```

La ubicacion, ejemplos y nombres son ilustrativos. Nunca subir JSON reales
ni el directorio `device/` a repositorios publicos.

## Privacidad y seguridad

Recopilar configuraciones no implica capturar secretos. Los agents utilizan
listas de propiedades permitidas. Nunca se guardan contrasenas, keys de
recuperacion BitLocker, hashes, tokens o registros de actividad del usuario.
Algunos metadatos (SID, usuarios, direcciones IP, nombres de programas) son
sensibles y requieren ACLs NTFS adecuadas. El `.gitignore` excluye `device/`,
`scans/`, `snapshots/`, `evidence/`, `reports/`, `logs/` y ficheros sensibles,
pero `git add -f` podria evadirlo. Revisar siempre staging.

En Windows, el programa **no cambia configuraciones de seguridad**. Hay una
excepcion operativa de escritura local temporal: `PrivilegeRights` crea un
INF con `secedit /export` y lo elimina; esto **no aplica ni modifica**
politicas del equipo. Ninguna remediacion automatica esta incluida.

## Desarrollo, extensibilidad y pruebas

- Catalogo: [`catalog/collectors.json`](catalog/collectors.json)

Pruebas estructurales independientes de Windows:

```bash
python -m unittest discover -s tests -v
```

La suite incluye regresiones sinteticas de UI, comandos, navegacion Q/Esc,
sesion compartida y analisis sin consultas al host. En Windows ejecuta
`tests/UiSession.Tests.ps1` con Windows PowerShell 5.1 y elimina sus
temporales fuera del repositorio. En otros entornos esa prueba se omite.
La matriz completa por edicion, elevacion y packs licenciados queda pendiente.

## Licencias y responsabilidad

No se incluyen rulepacks de CIS ni material protegido con licencia. El uso y
redistribucion de cualquier benchmark debera respetar sus terminos. NIST se
utiliza como mapa de resultados y no como certificacion. La auditoria tiene
alcance local y no garantiza que un endpoint sea seguro.

**Proyecto en desarrollo; licencia del codigo pendiente de definir.** Se agradecen contribuciones que mejoren la
calidad de la evidencia, validacion de fuentes, tests, documentacion y
trazabilidad sin comprometer la privacidad de los equipos.
