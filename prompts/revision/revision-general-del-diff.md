---
id: revision-general-del-diff
title: Revisión de código de los cambios locales
category: revision
tools_used: [git_status, git_diff, read_file]
requires_approval: false
risk: read-only
---

## Prompt

```text
Usa Vör Commander en el dispositivo <DEVICE_ID> y el workspace <WORKSPACE_ID>; pasa device_id y workspace_id en cada llamada.

Revisa como lo haría un revisor exigente los cambios sin commitear de <RUTA_DEL_REPO>.

1. Llama a git_status para ver el alcance completo, y a git_diff para leer los cambios.
2. Cuando un hunk no se entienda sin contexto, lee el archivo con read_file (base64), preferiblemente solo el tramo con line_start y line_count.
3. Busca, por orden de importancia: errores de lógica, casos límite sin tratar, manejo de errores, concurrencia, regresiones de rendimiento, y después legibilidad y nombres.
4. Entrégame los hallazgos como lista: severidad (bloqueante, importante, menor), archivo:línea, el problema, por qué importa y una propuesta concreta. Termina con un veredicto: listo, listo con cambios menores o necesita otra vuelta.

Solo lectura. No apliques ninguna corrección. Si hay archivos en git_status que no aparecen en el diff (preparados o sin seguimiento), dilo: la revisión no los cubre salvo que los leas.
```

## Qué hace

Hace una revisión de código de los cambios pendientes con hallazgos priorizados, referencias de línea y un veredicto final.

## Límites

- Solo lectura.
- `git_diff` solo muestra cambios no preparados. Lo que ya está en el índice (tras `git add`) y los archivos nuevos sin seguimiento no salen en el diff; para revisarlos hay que leerlos con `read_file`.
- La salida del diff está acotada (4 MiB en Git y el límite de salida del agente); en cambios muy grandes la revisión sale parcial.
- Los rangos de `read_file` llegan con el PR #5.
