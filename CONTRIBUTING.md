# Contribuir

1. Lea `AGENTS.md` y las instrucciones del dominio correspondiente.
2. Cree un collector sin acciones de escritura sobre Windows; evite secretos.
3. Actualice `catalog/collectors.json` y `catalog/evidence-inventory.json`.
4. Añada tests y una nota sobre limitaciones (Windows 11 Home/Pro/Enterprise).
5. Ejecute `python -m unittest discover -s tests -v`.
6. Verifique `git status --short` antes de enviar PR. No adjunte ningun scan.
7. Los criterios CIS deben ser validados desde fuente licita y no se publican
   extractos o rulepacks licenciados sin revisar autorizacion.

## Estilo

Funciones verbales `Get-WinSec<Id>Evidence`, no escribir sobre configuraciones
Windows, errores por subconsulta, datos normalizados, evitar stdout inesperado,
PowerShell 5.1 compatible. Se prefieren cambios pequeños y revisables.

## UI, ayuda y sesiones

- Conservar el banner y sus datos de autor, sin version de aplicacion.
- Menu principal: seis secciones; PLUS [+] contiene solo la correlacion.
- Antes de las secciones aparece el inventario. Validar Windows 11 antes de
  consultar hardware y guardar solo propiedades permitidas en `inventory.json`
  bajo OutputRoot. La deteccion no crea un snapshot.
- F2 edita solo el nombre visible. Supr requiere el hostname exacto y elimina
  el registro y todos los datos del equipo seleccionado bajo OutputRoot, en todas sus
  ediciones/builds. Validar previamente rutas y descendientes; rechazar
  reparse points. Probar solo con carpetas sinteticas externas.
- Abrir cualquier device recupera la ultima captura y los estados anteriores
  de cada control. Mostrar `(saved)` para otros runs; `Not yet` solo si no
  hay un registro guardado. Un nuevo scan no debe ocultar los demas controles.
  El analisis dirigido puede elegir una captura anterior del objetivo, pero
  cada exportacion y correlacion debe usar exclusivamente un mismo snapshot.
- Al escanear desde el menu, limpiar y redibujar banner antes del progreso;
  al terminar abrir los controles actualizados sin pausa, incluso al reutilizar
  collectors. No mostrar `Press Enter to return` tras un scan. La confirmacion
  muestra `../<Host>\<UTC_runId>\manifest.json`, sin ruta absoluta, tambien
  en CLI. La CLI no limpia.
- `[Esc] Back/Cancel | [F1] Help | [Q] Exit` aparece en un unico pie, despues de la sugerencia/comandos
  y una linea en blanco. No repetir atajos en PLUS ni sobre el prompt.
- F1 abre la ayuda contextual directamente, tambien desde resultados.
  No usar el texto help ni ? como atajos interactivos; -Help queda para la CLI.
- Q/q cierra la sesion, limpia la consola y muestra `Exiting Winsec-Analyzer.`
  sin confirmacion. Esc cancela la entrada o vuelve atras.
- Un control ofrece Analyze [A], seguido de CIS [C] o NIST CSF [N].
- `winsec -a <control|seccion> -c` y `-n` son excluyentes.
- Las correlaciones usan `-r 1..4` o `-r` para todas; `-c` es CIS.
- Mostrar controles y ejemplos en camelCase; conservar IDs tecnicos del catalogo.
- `winsec -s windowsDefender` debe resolver solo ese collector.
- Ayudas compactas: sin parrafos de navegacion/sesion ni ejemplos de analisis
  global. Los ejemplos del prompt deben corresponder a la vista actual.
- Mantener `help/README.md` y el mapa `help/<Dominio>.md` correspondiente.
- Cada control del catalogo debe tener ejemplos completos `-a <control> -n`
  y `-a <control> -c` en la ayuda de su dominio y en las sugerencias del listado.
  Seleccionar un control no debe reemplazar los ejemplos de otros controles.
- Una apertura del menu comparte runId/manifest. No sobrescribir evidencia
  existente ni agregar datos a sesiones historicas o cerradas.
- Guardar correlaciones en `<UTC_runId>/correlations/<seccion>+<seccion>.json`
  y frameworks en `<UTC_runId>/export/nistcsf|cisf/<control|seccion>.json`.
  Usar nombres canonicos en camelCase. La opcion 5 genera los cuatro archivos
  de parejas; no guardar copias agregadas ni escribir en `analysis/`.
- Repetir un analisis reemplaza solo su resultado derivado mediante escritura
  atomica; mantener evidencia fuente y manifest intactos. Incluir schemaVersion,
  sourceRunId, generatedAtUtc y scope; el reporte indexa las rutas y hashes.
- Probar navegacion, parsing y persistencia con datos sinteticos:
  `powershell.exe -NoProfile -NonInteractive -File tests/UiSession.Tests.ps1`.
  El inventario y borrado se prueban con `tests/Devices.Tests.ps1`, tambien
  incluido en unittest. No utilizar snapshots reales como fixtures.
