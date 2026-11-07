# Arquitectura

## Contrato

`run.ps1` importa `WinSecAnalyzer.psm1`. El modulo carga Common, Storage,
Devices, Session, Collection, Analysis, Input, Help, Console y los 32 collectors.
`winsec` enruta CLI y menu; `win-*` ofrece objetivos predefinidos.

- **Collect:** verifica Windows 11 cliente antes de consultar fuentes.
  Un JSON por collector con runId, modo, UTC, datos permitidos y warnings.
- **Devices:** inventario por hostname en `<OutputRoot>/inventory.json`.
  Valida Windows 11 antes de consultar Win32_ComputerSystem y Win32_Processor.
  Guarda fabricante, modelo, RAM y CPU con propiedades permitidas; conserva
  errores por fuente. Descubre capturas antiguas sin alterar sus JSON.
  F2 edita el nombre visible; Supr elimina registro y carpetas de ese host,
  con confirmacion exacta y validacion previa de rutas y enlaces.
- **Session:** una apertura del menu crea una sesion en memoria. La carpeta
  UTC se crea solo al primer escaneo. Los siguientes agregan collectors
  al mismo manifest y runId. Nunca se reescribe evidencia guardada.
- **Store:** el manifest se actualiza incrementalmente; cada evidencia
  registra SHA-256. El temporal se valida antes del reemplazo del manifest.
  Una ejecucion nueva utiliza GUID completo y creacion exclusiva.
- **Analyze:** `-a <objetivo> -c` o `-n` lee JSON de una captura de Windows 11.
  Un framework por llamada. No se consulta Windows para analizar.
  Guarda `export/cisf/<control|seccion>.json` o
  `export/nistcsf/<control|seccion>.json` dentro de la captura.
- **Correlate:** PLUS [+] o `-r` reutiliza el mismo snapshot; `-r 1..4`
  selecciona una correlacion y `-r` sin numero ejecuta las cuatro.
  Propiedades requeridas ausentes producen INSUFFICIENT_EVIDENCE.
  Cada pareja se guarda en `correlations/<seccion>+<seccion>.json`; la opcion
  5 guarda los cuatro archivos sin una copia agregada.
- **Report:** indice JSON de evidencias y resultados de `export/` y
  `correlations/`, con ruta relativa y SHA-256. Conserva lectura de resultados
  historicos en `analysis/`, sin crear esa carpeta. HTML/CSV pendientes.

## UI

La pantalla inicial muestra el inventario: flechas o numero+Enter seleccionan,
Enter abre las secciones. F2 renombra y Supr solicita confirmacion por hostname.
Esc desde el listado principal vuelve al inventario. El equipo local permite
escanear; otro equipo abre su ultimo manifest para analisis sin consultas remotas.
Cambiar de equipo cierra la sesion anterior; volver al mismo conserva la abierta.

Abrir un equipo local o guardado carga los manifests existentes en orden de
actualizacion. La captura mas reciente es el contexto inicial. Si falta un
control en ese contexto, la UI muestra su ultimo estado historico con `(saved)`.
`Not yet` indica ausencia de registros del control en todo ese historial.
Los estados de la sesion activa tienen prioridad sobre los historicos.
La vista no fusiona JSON ni modifica los manifests guardados.

Un analisis dirigido usa la captura actual si contiene el objetivo y, si no,
la ultima captura anterior que lo contiene. La exportacion se guarda en ese
run. Analisis de seccion y correlaciones no combinan evidencias de distintos
runs. Un scan crea su propio run y la UI conserva visibles los otros controles.
Supr elimina tanto el registro de inventario como todas las capturas del host.

Listado principal: System Security, Network Security, Identity & Access,
Services & Hardening, Logging & Auditing y Patch Management.
Solo correlacion queda en PLUS. Q/q sale; Esc cancela o vuelve.
El pie `[Esc] Back/Cancel | [F1] Help | [Q] Exit` aparece una sola vez, al final,
separada por una linea en blanco de la sugerencia y sus comandos de ejemplo.
El lector de teclado admite comandos y atajos; nunca evalua codigo recibido.
La tecla F1 devuelve una solicitud de ayuda separada de la entrada de comandos.
Abre la ayuda del contexto actual sin Enter, tambien desde resultados.
El texto help y ? no abren ayuda interactiva; -Help se conserva para la CLI.
Clear-Host solo se usa al dibujar paginas o al salir del menu interactivo.
Al salir con Q/q, primero se cierra la sesion; despues se limpia la consola
y se muestra `Exiting Winsec-Analyzer.`.

Un comando de escaneo limpia y redibuja el banner antes de la recoleccion.
Al finalizar vuelve automaticamente a los controles del dominio resuelto;
un scan global vuelve al listado principal. Ningun scan espera Enter, tampoco
si reutiliza JSON de esta sesion. La confirmacion del snapshot y su referencia
en el menu usan `../<Host>\<UTC_runId>\manifest.json`. El almacenamiento
conserva la ruta real; solo se abrevia su presentacion.
Los fallos nuevos dejan un aviso en la vista de retorno. Analisis y correlacion
conservan su pantalla de resultados. La CLI no limpia consola.

Dentro de una seccion se muestran los controles. Scanned verde corresponde
a COMPLETED; parcial amarillo, error rojo y Not yet sin recoleccion.
Dentro de un control se presenta Analyze [A], seguido de CIS [C] o NIST [N].
Los mapas de ayuda son archivos publicos en `help/`.
Cada mapa contiene ejemplos separados de analisis NIST y CIS para todos los
collectors de su dominio. Las sugerencias del listado cubren los mismos
collectors; seleccionar uno resalta sus ejemplos sin eliminar los restantes.
Estos mapas no repiten parrafos de navegacion o sesion. La ayuda y las
sugerencias muestran ejemplos del contexto actual: secciones, controles
en camelCase o correlaciones. Los IDs tecnicos del catalogo y JSON se
conservan; `winsec -s <control>` resuelve el ID antes de consultar fuentes.

## Ciclo de vida del snapshot

`device/Windows11_<Edition>_<Build>/<Host>/<UTC>_<runId>/` contiene un
manifest compartido, JSON por dominio/collector y analisis posteriores.

Los resultados derivados usan nombres canonicos en camelCase y conservan
schemaVersion, sourceRunId, generatedAtUtc y scope. Repetir un analisis
reemplaza atomicamente su archivo; nunca cambia los JSON fuente o el manifest.
Los directorios y archivos derivados se crean solo cuando se solicitan.

`sessionState=OPEN` permite agregar collectors solo desde la instancia
propietaria. Los ya guardados se reutilizan despues de verificar integridad;
para recolocarlos hace falta una sesion nueva. `sessionState=CLOSED` y
`finishedAtUtc` se guardan al salir, incluso si se utilizo Q en una subvista.
Un error de consulta no significa una configuracion deshabilitada.

Abrir una captura historica permite consultarla. El primer escaneo de esa
apertura crea otra captura; nunca agrega evidencia al historial.
Los escaneos CLI fuera del menu mantienen una captura por invocacion.

## Estados y limites

Collector: COMPLETED, PARTIAL, ERROR o NOT_APPLICABLE.
CIS: PASS, FAIL, NOT_ASSESSED con reglas aplicables; sin pack NOT_CONFIGURED.
NIST: EVIDENCE_MAPPING_ONLY y estados de disponibilidad, nunca score.
Correlacion: REVIEW_REQUIRED o INSUFFICIENT_EVIDENCE; no inferir compromiso.

Las secciones pueden recolectarse en momentos diferentes dentro de la misma
sesion. Cada JSON conserva collectedAtUtc: no se afirma captura simultanea.
Los hashes no autentican el origen y la normalizacion exhaustiva por fuente
sigue pendiente. Deep conserva su estado de desarrollo; no garantiza mas datos.

## Validacion

`python -B -m unittest discover -s tests -v` ejecuta pruebas estructurales.
En Windows incluye `tests/UiSession.Tests.ps1` bajo Windows PowerShell 5.1:
teclado Q/Esc, parser seguro, estados, sesion compartida, hashes y analisis.
Solo usa datos sinteticos y temporales externos que se eliminan al finalizar.
La cobertura completa por edicion/permisos y mediciones de recursos sigue pendiente.
