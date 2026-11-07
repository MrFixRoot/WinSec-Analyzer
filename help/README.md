# Ayuda de WinSec-Analyzer

Escribe el numero de una seccion o un comando winsec.
Q / q: salir de la sesion. Esc: cancelar la entrada o volver atras.
Las teclas de menu se activan sin Enter; los comandos requieren Enter.

Escanear todas las secciones:
    winsec -s

Escanear una seccion:
    winsec -s system
    winsec -s network
    winsec -s identity
    winsec -s services
    winsec -s logging
    winsec -s patch

Analizar un control o una seccion, un framework por comando:
    winsec -a WindowsDefender -c
    winsec -a WindowsDefender -n
    winsec -a network -n
    winsec -a all -c

Correlacion es una opcion PLUS [7]; no es una septima seccion:
    winsec -Correlation 1
    winsec -Correlation 5

Ayuda: escribe help dentro de cualquier seccion.
CIS requiere un pack local verificado; NIST solo mapea evidencia.

La sesion interactiva usa una carpeta UTC y un manifest compartido.
Cada collector conserva su JSON; repetir el escaneo reutiliza lo guardado.
Para volver a consultar collectors ya guardados, sal con Q y abre otra sesion.
Los comandos ejecutados fuera del menu crean una captura por invocacion.
