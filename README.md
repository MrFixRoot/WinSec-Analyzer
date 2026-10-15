# WinSec Analyzer

Herramienta de auditoria de configuraciones de seguridad de Windows desarrollada principalmente en PowerShell.

## Estado

Estructura inicial del proyecto. **Las auditorias y la TUI aun no estan implementadas.**

## Inicio de prueba

```powershell
.\Start-WinSec.ps1
```

## Arquitectura

- `src/Core`: motor de auditoria, resultados y puntuacion.
- `src/Checks`: controles independientes de seguridad.
- `src/Services`: exportacion TXT, reportes y registros.
- `src/UI`: interfaz adaptable a la terminal; banner, tablas y teclado.
- `src/CLI`: futuro modo sin interfaz.
- `config`: informacion del proyecto y reglas configurables.
- `tests`: pruebas Pester unitarias y de integracion.
- `reports`: exportaciones generadas (no versionadas).

Los controles no deben depender de la UI. Los resultados deben ser estructurados y reutilizables.