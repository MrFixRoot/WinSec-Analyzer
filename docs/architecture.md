# Arquitectura

## Contrato

`run.ps1` importa `WinSecAnalyzer.psm1`. El modulo carga Common, Storage,
Session, Collection, Analysis, Input, Help, Console y los 32 collectors.
`winsec` enruta CLI y menu; `win-*` ofrece objetivos predefinidos.

- **Collect:** verifica Windows 11 cliente antes de consultar fuentes.
  Un JSON por collector con runId, modo, UTC, datos permitidos y warnings.
- **Session:** una apertura del menu crea una sesion en memoria. La carpeta
  UTC se crea solo al primer escaneo. Los siguientes agregan collectors
  al mismo manifest y runId. Nunca se reescribe evidencia guardada.
- **Store:** el manifest se actualiza incrementalmente; cada evidencia
  registra SHA-256. El temporal se valida antes del reemplazo del manifest.
  Una ejecucion nueva utiliza GUID completo y creacion exclusiva.
- **Analyze:** `-a <objetivo> -c` o `-n` lee JSON de una captura de Windows 11.
  Un framework por llamada. No se consulta Windows para analizar.
- **Correlate:** PLUS [7] o `-Correlation` reutiliza el mismo snapshot.
  Propiedades requeridas ausentes producen INSUFFICIENT_EVIDENCE.
- **Report:** indice JSON de evidencias y analisis; HTML/CSV pendientes.

## UI

Listado principal: System Security, Network Security, Identity & Access,
Services & Hardening, Logging & Auditing y Patch Management.
Correlacion y ayuda quedan en PLUS. Q/q sale; Esc cancela o vuelve.
El lector de teclado admite comandos y atajos; nunca evalua codigo recibido.
Clear-Host solo se usa al dibujar paginas del menu.

Dentro de una seccion se muestran los controles. Scanned verde corresponde
a COMPLETED; parcial amarillo, error rojo y Not yet sin recoleccion.
Dentro de un control se presenta Analyze [A], seguido de CIS [C] o NIST [N].
Los mapas de ayuda son archivos publicos en `help/`.

## Ciclo de vida del snapshot

`device/Windows11_<Edition>_<Build>/<Host>/<UTC>_<runId>/` contiene un
manifest compartido, JSON por dominio/collector y analisis posteriores.

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
