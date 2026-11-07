# Arquitectura

## Contrato

`run.ps1` importa `WinSecAnalyzer.psm1`. El modulo carga Common, Storage,
Collection, Analysis, UI y los 32 collectors registrados. `winsec` es la puerta
unica de CLI y menu; `win-*` son alias/funciones de conveniencia.

- **Collect:** verifica que el equipo sea Windows 11 cliente, invoca cada collector
  una vez, serializa datos permitidos y escribe `manifest.json` incremental.
- **Store:** un snapshot por ejecucion, con UUID, fecha UTC, OS, host, estado por
  collector y SHA-256 de todos los archivos. Escritura a fichero temporal y renombre.
- **Analyze:** lee UN snapshot; verifica integridad y que sea Windows 11; aplica
  rules packs CIS en `config/benchmarks/local` o mappings NIST. Nunca vuelve a
  consultar el equipo durante el analisis.
- **Correlate:** une datos por IDs de collector dentro del mismo snapshot, marca
  evidencia faltante y emite observaciones para revision tecnica.
- **Report:** produce indice JSON de hallazgos y evidencias. HTML/CSV pendientes.

## Dominios

1. SystemSecurity
2. NetworkSecurity
3. IdentityAccess
4. ServicesHardening
5. LoggingAuditing
6. PatchManagement

## Estados

- Collector: `COMPLETED`, `PARTIAL`, `ERROR`, `NOT_APPLICABLE`.
- CIS: `PASS`, `FAIL`, `NOT_ASSESSED` (solo si hay pack valido), o `NOT_CONFIGURED`.
- NIST: `EVIDENCE_MAPPING_ONLY`, `EVIDENCE_AVAILABLE`, `PARTIAL_EVIDENCE`,
  `NO_EVIDENCE` (nunca score de compliance).
- Correlacion: `REVIEW_REQUIRED`, `INSUFFICIENT_EVIDENCE`.

## Limitaciones reales

El snapshot registra las fuentes consultadas, no es una imagen forense completa.
Un `COMPLETED` significa que ese collector obtuvo su dato, no que cubra todas
las configuraciones CIS. `PARTIAL` puede significar ausencia de permisos,
componentes no instalados o errores de API. Los objetos se normalizan con
allowlists para impedir guardar secretos. Recolecciones enormes se manejaran
con streaming en una etapa futura.

## Restricciones de rendimiento

Ejecucion secuencial inicial para seguridad y reproducibilidad. Un JSON por
modulo. Consola muestra solo estado y progreso por collector. Los modulos
Firewall/Services/Features pueden producir muchos objetos. Hay que medir coste
en Windows 11 real antes de agregar paralelismo y limites de profundidad.
