# WinSec-Analyzer

**Windows Security Auditor — Windows 11 Endpoint Configuration Evidence & Assessment**

> **Estado: EN DESARROLLO.** Este repositorio es un prototipo funcional a nivel
> de codigo, con **validacion parcial en Windows 11 y PowerShell 5.1**. No
> constituye un producto certificado, un escaner de vulnerabilidades ni una
> auditoria oficial NIST.

WinSec-Analyzer es una herramienta en desarrollo, preparada para GitHub y desarrollada principalmente
en **PowerShell** para recolectar configuraciones de seguridad de estaciones de
trabajo **Windows 11**, almacenarlas en snapshots JSON trazables y analizarlas
posteriormente utilizando **NIST CSF 2.0** y una linea base propia,
**WinSec Baseline**. Los resultados pueden correlacionarse entre dominios sin
volver a ejecutar consultas al equipo.

**Autor/alias:** mrRoot  
**GitHub:** https://github.com/MrFixRoot/WinSec-Analyzer  
**LinkedIn:** https://www.linkedin.com/in/normanlp/

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
2. **Analyze (`-a <control|seccion> -n` o `-w`)**: lee y analiza el snapshot;
   **no vuelve a consultar Windows**.
3. **Correlate (`-r 1..4` o `-r` para todas)**: une configuraciones del MISMO
   snapshot, registra evidencia faltante y produce observaciones para revision.
4. **Report (`-Report`)**: crea un indice JSON de lo recolectado y analizado.

Un collector **no asigna PASS/FAIL**. Ese estado es exclusivo de reglas de
WinSec Baseline explicitas, verificadas y compatibles con la edicion/perfil.

## Seis dominios / 32 collectors

| Dominio | Collectors incluidos (IDs del catalogo) | Fuentes y ejemplos |
|---|---|---|
| **System Security** (8) | WindowsDefender, WindowsFirewall, BitLocker, SecureBoot, TPM, UAC, CredentialGuard, SmartScreen | Antivirus y politicas; firmas; firewall perfiles/reglas/filtros; cifrado; UEFI, TPM, LSA, VBS, SmartScreen |
| **Network Security** (6) | SMB, RDP, WinRM, TCPListeners, NetworkAdapters, DNSAndProxy | SMB cliente/servidor, NLA, WinRM, TCP/UDP, interfaces, IP, rutas, DNS, proxy flags |
| **Identity & Access** (6) | LocalUsers, LocalGroups, LocalAdministrators, GuestAccount, PasswordPolicy, PrivilegeRights | Usuarios, membresia, Guest por SID, politicas de contrasena/bloqueo, derechos locales |
| **Services & Hardening** (6) | Services, WindowsFeatures, StartupEntries, SystemHardening, PowerShellPolicy, InstalledSoftware | Servicios, caracteristicas Windows, inicio automatico, UAC/LSA, PowerShell, apps |
| **Logging & Auditing** (3) | AuditPolicy, PowerShellLogging, EventLogConfiguration | `auditpol`, Script Block/Module Logging, transcripcion, canales y retencion |
| **Patch Management** (3) | WindowsUpdate, InstalledHotfixes, PendingReboot | Politicas de WU, servicios, hotfixes visibles, reinicio pendiente |

**Total: 32 collectors con archivos individuales `.ps1` y ~99 familias de
items de evidencia** en `catalog/evidence-inventory.json`. El inventario recoge
**evidencias a recolectar**, no un total de reglas evaluativas ni una garantia
de cobertura completa. Las propiedades disponibles varian segun permisos y
edicion de Windows 11. Algunos collectors son deliberadamente parciales para
proteger secretos o evitar costes excesivos.

## Requisitos

Windows 11 cliente, PowerShell 5.1, acceso a cmdlets locales de Windows;
permisos de administrador recomendados para auditar mas fuentes. No se
requiere acceso a Internet para escanear ni analizar JSON ya guardado.
La prioridad actual es el mapeo NIST CSF 2.0; WinSec Baseline aun no incluye
reglas activas.

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

Al iniciar el menu se valida Windows 11 y se registra el equipo local en
`device/inventory.json`: hostname, fabricante, modelo, CPU y RAM. Si una
fuente falla, se conserva lo disponible y se muestra su advertencia.
El contexto del SO conserva tambien `displayVersion`, `ubr` e
`installationType`, tanto en el inventario como en el `manifest.json` de
cada captura. `ubr` es numerico; los datos opcionales ausentes quedan en
`null` con su advertencia. El contexto y el dispositivo se marcan `PARTIAL`
cuando sus consultas generan advertencias.
No se guardan numeros de serie ni identificadores de CPU. El inventario tambien
descubre equipos con capturas anteriores, sin crear un scan vacio.

Usa las flechas para seleccionar un equipo y **Enter** para abrirlo.
Tambien puedes escribir su numero y pulsar **Enter una sola vez** para abrirlo
directamente. Se admiten numeros de varias cifras; un numero fuera del listado
mantiene el inventario abierto.
**F2** cambia su nombre visible, inicialmente el hostname; conserva el hostname
de Windows y las rutas de las capturas. **Supr** elimina el dispositivo del
inventario y todos sus datos, incluidas capturas, correlaciones y exportaciones de todas las
ediciones/builds presentes en ese OutputRoot. Para confirmar debes escribir el
hostname exacto; Esc cancela. Tras eliminar el equipo local, `+` permite
registrarlo de nuevo. Al iniciar de nuevo el programa, la deteccion local
tambien puede registrarlo otra vez, con cero capturas anteriores.

Al abrir un equipo, incluido el local, se carga su captura mas reciente.
Los controles conservan tambien el ultimo estado registrado en capturas
anteriores: aparecen como `Scanned (saved)` en lugar de `Not yet`.
Esto se mantiene al cerrar/reabrir el programa o escanear otra seccion.
Solo se permite escanear el equipo local. Cambiar de equipo cierra la sesion
anterior. Esc desde el listado principal vuelve al inventario.

El listado principal contiene solamente:

1. System Security
2. Network Security
3. Identity & Access
4. Services & Hardening
5. Logging & Auditing
6. Patch Management

La correlacion queda aparte, como **PLUS [+]**: pulsa `+` para abrirla.
Pulsa **F1** para la ayuda del contexto. No hay opciones principales 7, 8, 9 ni 0.

- **Q / q** cierra la sesion desde las vistas de navegacion, limpia la consola y muestra
  `Exiting Winsec-Analyzer.`, sin confirmacion.
- **Esc** cancela la entrada sin ejecutarla o vuelve al nivel anterior.
- Los numeros de secciones/controles y sus atajos funcionan sin Enter; los
  comandos y numeros de dispositivos escritos usan Enter.
- El prompt es `>`, con una sugerencia variable debajo. Tras una linea en
  blanco aparece un unico pie: `[Esc] Back/Cancel | [F1] Help | [Q] Exit`.
  PLUS muestra solamente la correlacion.
- **Tab** autocompleta `winsec`, opciones, secciones, controles y numeros
  de correlacion. Con varias coincidencias amplia el prefijo comun y muestra
  alternativas debajo de la entrada. Sigue escribiendo para filtrarlas o pulsa
  Tab para recorrerlas; **Shift+Tab** retrocede. Enter ejecuta el comando.
  Por ejemplo: `w<Tab>-a<Tab>windowsD<Tab>` completa
  `winsec -a windowsDefender `; despues puedes elegir `-n` o `-w`.
  Las listas largas muestran ocho alternativas por pagina; Tab recorre todas.
  El autocompletado del menu no consulta Windows ni ejecuta el texto escrito.
  Los campos de nombre de dispositivo y confirmacion de borrado no lo activan.
- Cada seccion muestra sus controles y el ultimo estado guardado del equipo:
  **Scanned** en verde para `COMPLETED`, **Scanned (partial)** en amarillo,
  **Scan error** en rojo, y **Not yet** si no existe ningun intento guardado.
  Los registros de sesiones anteriores llevan **(saved)** y conservan su color.
  Estos estados no significan cumplimiento.
- Dentro de un control solo aparece **[A] Analyze**, seguido de
  **[N] NIST CSF 2.0** o **[W] WinSec Baseline**, siempre por separado.
- Los nombres de controles se muestran en camelCase, por ejemplo
  `windowsDefender`, `bitLocker`, `tpm` y `uac`.
- En el menu principal, los ejemplos son de secciones. En el listado de
  controles recorren los controles de esa seccion; dentro de un control
  usan solo ese control. La ayuda no repite parrafos de navegacion ni de sesion.
- Los escaneos se escriben como comandos; el menu del control no ofrece Scan.
- Al escanear desde el menu se limpia la consola y se conserva el logo/banner
  mientras se muestra el progreso. Al terminar se limpia de nuevo y se abre
  el listado de controles de esa seccion sin pedir Enter. Un scan global
  vuelve al listado principal.
- Los escaneos vuelven automaticamente, tambien al reutilizar collectors
  de la misma sesion; nunca muestran `Press Enter to return`.
  Al crear un snapshot, la confirmacion temporal muestra
  `Snapshot created: ../<Host>\<UTC_runId>\manifest.json`.
- La franja entre el listado (debajo de PLUS en la vista principal) y el
  prompt muestra las advertencias y los mensajes recientes una sola vez,
  con una linea vacia arriba y abajo. La franja reserva espacio incluso vacia,
  igual en secciones y controles. Si un mensaje necesita mas lineas, conserva
  esa altura durante la sesion para que el prompt no suba al borrarlo.
  Los mensajes desaparecen al empezar a escribir,
  usar Tab/Backspace, pulsar Enter o navegar; la primera tecla se conserva
  como parte del nuevo comando. Un comando invalido vuelve directamente
  al prompt, sin pedir `Press Enter to return`.
  Las notificaciones de archivos o dispositivos solo se generan al crearlos
  o eliminarlos. Abrir una captura
  guardada, reutilizar collectors o actualizar archivos existentes deja la
  franja vacia; no se muestra permanentemente la ruta del snapshot.
  Los errores regresan a esa misma franja, sin repetirse en la cabecera.
  La CLI conserva su salida y usa la ruta abreviada, sin limpiar pantalla.

El primer escaneo crea
`device/Windows11_<Edition>_<Build>/<Host>/<UTC>_<runId>/`.
Las demas secciones agregan evidencia al **mismo runId y manifest**.
Cada collector conserva su JSON individual. Repetir un collector verifica
su hash y reutiliza lo guardado, sin consultarlo otra vez ni sobrescribirlo.
Esto incluye intentos parciales o fallidos que quedaron guardados.
Las advertencias de contexto marcan la captura `PARTIAL`; las advertencias
de un collector marcan su evidencia `PARTIAL`, conservando los estados
`ERROR` y `NOT_APPLICABLE` cuando corresponda. Si cambia un dato conocido
de version, revision o tipo de instalacion, se requiere otra captura para
evitar mezclar contextos de Windows distintos.

Al cerrar el run se registra `sessionState=CLOSED` y `finishedAtUtc`.
Una apertura nueva del menu, cambiar de dispositivo o confirmar un reescaneo
permite crear otra captura. Nunca se agrega evidencia a una captura historica;
`collectedAtUtc` distingue el momento de cada control. Si el manifest fue
eliminado, cerrar la sesion conserva su eliminacion.

### Comandos del prompt y del entrypoint

Dentro del menu escribe `winsec`. Desde PowerShell, importa el modulo o usa
`.\run.ps1` con los mismos parametros.

```powershell
winsec -s                     # Todas las secciones
winsec -s system
winsec -s network
winsec -s identity
winsec -s servicesHardening
winsec -s login               # Logging & Auditing; logging sigue disponible
winsec -s patch
winsec -s windowsDefender     # Un solo control

winsec -a windowsDefender -n   # NIST para este control
winsec -a windowsDefender -w   # WinSec Baseline para este control
winsec -a network -n          # Una seccion
winsec -a network -w

winsec -r 1                   # Network + Services
winsec -r 2                   # Identity + Logging
winsec -r 3                   # Network + Identity
winsec -r 4                   # System + Logging
winsec -r                     # Las cuatro correlaciones
```

`-a` significa Analyze y recibe **un control o seccion**. `-n` elige
NIST CSF 2.0; `-w` elige WinSec Baseline. No se admiten ambos switches ni nombres/listas
de frameworks combinados. `-r` significa co[r]relation: admite un numero
del 1 al 4, o ninguno para ejecutar todas. `-w` queda reservado para WinSec Baseline.
En la ayuda compacta, los corchetes y `|` indican alternativas: se elige
una, sin escribir esos signos en el comando.

```powershell
.\run.ps1 -s system -OutputRoot 'D:\WinSec-Private-Evidence'
.\run.ps1 -a windowsDefender -n -Snapshot 'D:\WinSec-Private-Evidence\captura\manifest.json'
.\run.ps1 -List
.\run.ps1 -Report
.\run.ps1 -Help
.\run.ps1 network -Help
```

En el menu, la ayuda se abre con la tecla F1, sin escribir `help` ni pulsar
Enter. F1 tambien funciona al consultar resultados. Fuera del menu,
`-Help` sigue disponible para consultar la ayuda desde PowerShell.

Los mapas de ayuda general y por seccion se incluyen en `help/` como parte
del proyecto. WinSec los lee para mostrar la ayuda; si falta un mapa, genera
su contenido desde el catalogo.

Analizar sin `-Snapshot` selecciona la captura mas reciente del control/seccion
solicitado, segun su UTC de recoleccion. Las capturas anteriores quedan como
historial; no se sustituyen los ultimos datos por otros mas antiguos para
ocultar archivos faltantes. Cada analisis usa una sola captura y guarda alli
su exportacion. `-Snapshot` permite elegir expresamente una captura historica.

Si faltan la captura o sus JSON registrados, el menu pregunta si deseas
reescanear. **Y/S** confirma; **N**, Enter o Esc cancela el analisis.
Confirmar inicia un run nuevo, aun cuando haya otras capturas; conserva el
historial y escanea solo el control o la seccion solicitada. Despues ejecuta
el analisis sobre los nuevos JSON. El reescaneo es una accion separada;
analizar JSON no consulta Windows. La CLI fuera del menu no abre esta pregunta
ni reescanea automaticamente.

Las correlaciones usan la captura actual, sin mezclar sesiones.
Al abrir el menu con una captura historica, esta puede analizarse; el primer
escaneo crea una captura nueva.

La ayuda muestra `winsec -a [section|control] -n|w` y los nombres disponibles:
secciones en la ayuda general y controles del dominio en la ayuda de seccion
o control. Los ejemplos concretos de analisis aparecen solo como sugerencias
del prompt. La leyenda mantiene `-n [n]ist csf 2.0` y `-w [w]insec baseline`.

Los escaneos normales comparten **un run activo** hasta cerrar o cambiar de
dispositivo. Un reescaneo confirmado inicia otro run dentro del mismo menu.
Cada escaneo ejecutado fuera del menu crea una captura independiente.
El prompt acepta opciones literales de `winsec`; no ejecuta expresiones
PowerShell, pipelines, redirecciones ni otros comandos.

### Comandos cortos del modulo

Disponibles desde PowerShell despues de importar el modulo:

```powershell
Import-Module .\WinSecAnalyzer.psm1 -Force
win-defender -s
win-defender -a -n
win-defender -a -w
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

## NIST CSF 2.0 y WinSec Baseline

Las opciones se presentan en orden alfabetico y se ejecutan por separado:

- **NIST CSF 2.0 (`-n`):** prioridad actual del proyecto. Relaciona las
  evidencias con categorias del marco y explica sus limites de cobertura.
  `EVIDENCE_AVAILABLE` indica disponibilidad de evidencia; no acredita
  cumplimiento, certificacion ni puntuacion NIST.
- **WinSec Baseline (`-w`):** linea base propia para seleccionar configuraciones
  importantes de Windows 11 a partir de documentacion tecnica y buenas practicas
  de seguridad de distintas fuentes. Sus criterios se redactaran y verificaran
  dentro del proyecto, con referencias documentadas y sin reproducir reglas de
  terceros. Todavia no incluye reglas activas: devuelve `NOT_CONFIGURED` hasta
  disponer de un conjunto propio verificado y aplicable a la edicion/perfil.

Referencia del marco: [NIST CSF 2.0](https://www.nist.gov/cyberframework).

## Correlaciones entre dominios

| ID / comando | Dominios | Hechos relacionados |
|---|---|---|
| 1 | Network Security + Services & Hardening | WinRM, servicios, puertos, SMB, hardening |
| 2 | Identity & Access + Logging & Auditing | Administradores y disponibilidad de audit policy / logging |
| 3 | Network Security + Identity & Access | RDP/NLA, miembros y reglas de firewall |
| 4 | System Security + Logging & Auditing | Defender, firewall y registros habilitados |
| `winsec -r` | Todas | Ejecuta los cuatro conjuntos anteriores |

Las correlaciones unen datos del **mismo snapshot**, no cruzan datos de
momentos diferentes. Si falta evidencia, aparece `INSUFFICIENT_EVIDENCE`.
La presencia de un puerto local no demuestra exposicion desde Internet.
La ayuda de las opciones 1-4 muestra el numero y los dominios relacionados,
por ejemplo `Correlacion 3: Network Security + Identity & Access`.
La opcion **5 — All Available Correlations** ejecuta las correlaciones
**1, 2, 3 y 4** sobre el mismo snapshot; no es una quinta regla independiente.
Su comando equivalente es `winsec -r` sin numero.

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
│   ├── collectors/                  # Seis dominios, 32 collectors .ps1
│   └── ui/                          # Banner/menu/estado
├── config/
│   ├── baselines/WinSec/             # Ejemplo inactivo
│   ├── baselines/local/           # Reglas locales propias ignoradas por Git
│   ├── mappings/                   # NIST CSF 2.0
│   └── correlation-rules/          # Cuatro correlaciones
└── device/                          # Snapshots LOCALES ignorados por Git
    └── inventory.json               # Equipos, nombres visibles y hardware permitido
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
            ├── correlations/
            │   ├── networkSecurity+servicesHardening.json
            │   ├── identityAccess+loggingAuditing.json
            │   ├── networkSecurity+identityAccess.json
            │   └── systemSecurity+loggingAuditing.json
            └── export/
                ├── nistcsf/
                │   ├── windowsDefender.json
                │   └── networkSecurity.json
                └── winsecbaseline/
                    ├── windowsDefender.json
                    └── networkSecurity.json
```

La ubicacion, ejemplos y nombres son ilustrativos. Nunca subir JSON reales
ni el directorio `device/` a repositorios publicos.

Cada correlacion se guarda en `correlations/<seccion>+<seccion>.json` dentro
del mismo run. La opcion 5 genera los cuatro archivos, sin otra copia conjunta.
Los frameworks se guardan en `export/nistcsf/<control|seccion>.json` o
`export/winsecbaseline/<control|seccion>.json`. Los nombres usan camelCase y la seccion
canonica: `winsec -a network -n` genera `export/nistcsf/networkSecurity.json`.
Repetir un analisis actualiza su archivo derivado; conserva los JSON fuente y
su manifest. No se crea la carpeta `analysis/`. El reporte incluye las nuevas
rutas y sus hashes.

## Licencia y responsabilidad

El codigo de WinSec-Analyzer se distribuye bajo **Apache License 2.0
(Apache-2.0)**. El texto completo y sus condiciones estan en [LICENSE](LICENSE).

**Copyright 2026 Norman López P. (mrRoot / MrFixRoot)**, autor y creador original.
[NOTICE](NOTICE) identifica la autoria, el proyecto y su repositorio oficial,
y recoge los avisos de atribucion aplicables. Es informativo y no modifica
los terminos de la licencia.

Al redistribuir el proyecto o una obra derivada, deben cumplirse las condiciones
de la seccion 4 de LICENSE: proporcionar la licencia, identificar los archivos
modificados y conservar los avisos de copyright y atribucion aplicables,
incluidos los de NOTICE. Las aportaciones de terceros conservan los derechos
que les correspondan.

El software se proporciona **tal cual, sin garantias**, con las exclusiones y
limitaciones de responsabilidad establecidas en LICENSE. El usuario debe evaluar
su idoneidad y revisar los resultados; una captura no garantiza la seguridad
del equipo ni acredita cumplimiento oficial.

Los collectors son implementaciones propias. Los futuros criterios de WinSec
Baseline se desarrollaran dentro del proyecto; las referencias tecnicas y
materiales de terceros conservan sus propios terminos. El uso de NIST CSF 2.0
sirve para relacionar evidencia y no implica aval, puntuacion ni certificacion
oficial.
