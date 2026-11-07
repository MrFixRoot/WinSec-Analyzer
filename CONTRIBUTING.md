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
- Menu principal: seis secciones; correlacion PLUS [7] y ayuda fuera del listado.
- Q/q sale sin confirmacion. Esc cancela la entrada o vuelve atras.
- Un control ofrece Analyze [A], seguido de CIS [C] o NIST CSF [N].
- `winsec -a <control|seccion|all> -c` y `-n` son excluyentes.
- Las correlaciones usan `-Correlation`, nunca el atajo `-c`.
- Mantener `help/README.md` y el mapa `help/<Dominio>.md` correspondiente.
- Una apertura del menu comparte runId/manifest. No sobrescribir evidencia
  existente ni agregar datos a sesiones historicas o cerradas.
- Probar navegacion, parsing y persistencia con datos sinteticos:
  `powershell.exe -NoProfile -NonInteractive -File tests/UiSession.Tests.ps1`.
  No utilizar snapshots reales como fixtures.
