# WinSec-Analyzer

**Windows Security Auditor — Windows 11 Endpoint Configuration Evidence & Assessment**

> **Estado: EN DESARROLLO.** Este repositorio es un prototipo funcional a nivel
> de codigo, **todavia no probado en un Windows 11 real en este entorno**. No
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
2. **Analyze (`-a cis|nist`)**: lee el snapshot y analiza las evidencias;
   **no vuelve a consultar Windows**.
3. **Correlate (`-c 1..5`)**: une configuraciones de distintas areas del MISMO
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
| Logo, banner, menu interactivo | **Codigo preparado** | Pendiente validacion visual en Windows 11 |
| 32 agentes por dominios | **Implementacion inicial** | Consultas y normalizacion creadas; por probar en Home/Pro/Enterprise |
| Validacion solo Windows 11 | **Implementado en codigo** | Comprobacion de build y tipo de producto; requiere prueba en SO real |
| JSON por agente + manifest + SHA-256 | **Implementado en codigo** | Persistencia y comprobacion de hashes; pendiente prueba integral |
| CLI `winsec -s / -a / -c` y alias `win-*` | **Codigo preparado** | Pendiente pruebas completas en PS5.1 |
| Correlaciones 1–4 entre dominios | **Base preparada** | Hechos y disponibilidad; interpretacion avanzada en desarrollo |
| Mapeo NIST CSF 2.0 | **Inicial** | Categorias asociadas a evidencia; subcategorias y validacion pendientes |
| Motor CIS Benchmarks | **Adaptador preparado** | **Sin rulepacks oficiales ni cumplimiento evaluable por defecto** |
| Calificacion CIS | **Condicionada** | Solo si se cargan reglas verificadas y evaluables; no score global por defecto |
| Reportes | **Indice JSON inicial** | HTML/CSV, graficas y comparaciones historicas en desarrollo |
| Pruebas | **Estructurales** | Sin ejecucion del proyecto en Windows 11 dentro de este entorno |
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

### Menu numerico

```powershell
.\run.ps1
```

Opciones 1–6 dominios; 7 correlacion cruzada; 8 recoleccion completa; 9
analisis de snapshots; 0 salir. El menu limpia pantalla solo entre vistas.

### Comandos del entrypoint

```powershell
.\run.ps1 -s                     # Todos los agentes
.\run.ps1 -s system              # System Security
.\run.ps1 -s network             # Network Security
.\run.ps1 -s identity            # Identity & Access
.\run.ps1 -s services            # Services & Hardening
.\run.ps1 -s logging             # Logging & Auditing
.\run.ps1 -s patch               # Patch Management
.\run.ps1 -s -Collector WindowsDefender
.\run.ps1 -s -OutputRoot 'D:\WinSec-Private-Evidence'

.\run.ps1 -a cis                  # Requiere reglas CIS locales verificadas
.\run.ps1 -a nist                 # Mapping NIST por evidencia, no compliance
.\run.ps1 -a cis,nist
.\run.ps1 -c 1                    # Network + Services
.\run.ps1 -c 2                    # Identity + Logging
.\run.ps1 -c 3                    # Network + Identity
.\run.ps1 -c 4                    # System + Logging
.\run.ps1 -c 5                    # Todas
.\run.ps1 -List                  # Snapshots disponibles
.\run.ps1 -Report                # Indice JSON de evidencia
```

### Comandos cortos del modulo

```powershell
winsec -s
winsec -s system
win-defender -s
win-defender -a cis
win-defender -a nist
win-firewall -s
win-bitlocker -s
win-update -s
win-network -s
win-identity -s
win-logging -s
win-services -s
```

El comando `win-defender` debe existir en una sesion en la que se haya
importado `WinSecAnalyzer.psm1`. Los alias `-s` y `-a` corresponden a `Scan`
y `Analyze`. Sin `-Snapshot`, se busca el ultimo snapshot del equipo actual.
Para analizar un equipo diferente o una captura antigua, especificar
`-Snapshot` directamente.

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

Documentacion: [Marco CIS/NIST](docs/FRAMEWORKS.md),
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
├── AGENTS.md                        # Instrucciones para agentes de desarrollo
├── catalog/
│   ├── collectors.json             # Registry de 32 collectors
│   └── evidence-inventory.json     # Familias de evidencia a recolectar
├── src/
│   ├── core/                        # Validacion, almacenamiento, CLI, analisis
│   ├── collectors/                  # Seis dominios, 32 archivos de agentes .ps1
│   │   └── <Domain>/AGENTS.md       # Reglas especificas por dominio
│   └── ui/                          # Banner/menu/estado
├── config/
│   ├── benchmarks/CIS/             # Ejemplo inactivo
│   ├── benchmarks/local/           # Packs propios no versionados en Git
│   ├── mappings/                   # NIST CSF 2.0
│   └── correlation-rules/          # Cuatro correlaciones
├── docs/                            # Especificaciones y riesgos
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
- Instrucciones de agentes: [`AGENTS.md`](AGENTS.md) y `AGENTS.md` en cada dominio
- Arquitectura: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- JSON: [`docs/DATA-FORMAT.md`](docs/DATA-FORMAT.md)
- CLI: [`docs/CLI.md`](docs/CLI.md)
- Seguridad: [`docs/SECURITY-AND-PRIVACY.md`](docs/SECURITY-AND-PRIVACY.md)
- Hoja de ruta: [`docs/ROADMAP.md`](docs/ROADMAP.md)
- Contribuciones: [`CONTRIBUTING.md`](CONTRIBUTING.md)

Pruebas estructurales independientes de Windows:

```bash
python -m unittest discover -s tests -v
```

Pruebas reales de PowerShell 5.1 sobre Windows 11, benchmark packs licenciados,
tests de datos sintéticos y pruebas por edicion quedan pendientes.

## Licencias y responsabilidad

No se incluyen rulepacks de CIS ni material protegido con licencia. El uso y
redistribucion de cualquier benchmark debera respetar sus terminos. NIST se
utiliza como mapa de resultados y no como certificacion. La auditoria tiene
alcance local y no garantiza que un endpoint sea seguro.

**Proyecto en desarrollo; licencia del codigo pendiente de definir.** Se agradecen contribuciones que mejoren la
calidad de la evidencia, validacion de fuentes, tests, documentacion y
trazabilidad sin comprometer la privacidad de los equipos.
