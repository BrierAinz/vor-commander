---
id: diagnosticar-build-roto
title: Diagnosticar un build o un test roto
category: tests
tools_used: [prepare_terminal, commit_terminal, poll_terminal, read_file, search_content, git_diff]
requires_approval: true
risk: exec
---

## Prompt

```text
Usa Vör Commander en el dispositivo <DEVICE_ID> y el workspace <WORKSPACE_ID>; pasa device_id y workspace_id en cada llamada.

El comando <COMANDO_QUE_FALLA> falla en <RUTA_DEL_PROYECTO>. Encuentra la causa.

1. Ejecútalo una vez para ver el error real: llama a prepare_terminal con cwd = <RUTA_DEL_PROYECTO>, el comando como argv, timeout_ms 120000 y max_output_bytes 262144. Devuelve un desafío de aprobación: enséñame el argv y espera a que firme en el aprobador de Vör y te pase el approval_base64. Después commit_terminal con el request_base64 exacto y mi approval_base64, y poll_terminal hasta el final.
2. Toma el primer error de la salida y ve al código: read_file con line_start y line_count sobre el archivo y la línea que cita, y search_content para encontrar definiciones o usos relacionados.
3. Llama a git_diff para ver si el fallo lo introduce algún cambio local.
4. Explícame la causa con la evidencia (salida del comando, línea de código, hunk del diff) y propón la corrección. No la apliques: si la quiero, usaremos el flujo de escritura con aprobación.

Nunca generes ni reutilices aprobaciones, y no vuelvas a ejecutar el comando sin pedírmelo: cada ejecución necesita su propia aprobación.
```

## Qué hace

Ejecuta una vez el comando que falla, sigue el primer error hasta el código y lo cruza con los cambios locales para dar una causa respaldada por evidencia.

## Límites

- La ejecución requiere aprobación firmada; la investigación posterior es de solo lectura.
- Cada nueva ejecución necesita otra aprobación: el asistente no puede iterar compilando por su cuenta.
- 120 s y 512 KiB de salida como máximo por ejecución.
- `git_diff` no ve cambios ya preparados ni archivos sin seguimiento.
- `search_content` y los rangos de `read_file` llegan con el PR #5.
