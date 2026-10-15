# Arquitectura

Flujo: UI/CLI -> Core -> Checks -> Core (resultados y score) -> UI/Services.

La UI consulta datos y gestiona navegacion; los Checks solo recopilan evidencias.
La TUI debe adaptarse al ancho y alto disponibles sin cambiar el tamano de la terminal del usuario.

Pantallas previstas:
- Menu principal
- Auditoria
- Tabla de calificaciones por seccion
- Tabla de hallazgos de la seccion seleccionada
- Configuracion

Un estado ERROR o N/A no debe calificarse automaticamente como FAIL.