---
id: espacio-libre-en-disco
title: Espacio libre en una unidad
category: windows
tools_used: [prepare_terminal, commit_terminal, poll_terminal]
requires_approval: true
risk: exec
---

## Prompt

```text
Usa Vör Commander en el dispositivo <DEVICE_ID> y el workspace <WORKSPACE_ID>; pasa device_id y workspace_id en cada llamada.

Dime cuánto espacio libre queda en la unidad <LETRA_DE_UNIDAD> (solo la letra, por ejemplo D).

1. Prepara con prepare_terminal el comando de consulta argv ["fsutil", "volume", "diskfree", "<LETRA_DE_UNIDAD>:"], con cwd = <CARPETA_PERMITIDA>, timeout_ms 15000 y max_output_bytes 16384.
2. Devuelve un desafío de aprobación: enséñame el argv y espera a que firme en el aprobador de Vör y te pase el approval_base64.
3. Llama a commit_terminal con el request_base64 exacto y mi approval_base64, y a poll_terminal con el session_id hasta que termine.
4. Dame el total, lo libre y el porcentaje libre en GB legibles. Si queda menos de un 10 %, avísame y propón usar el prompt de carpetas que más ocupan para buscar qué liberar.

Nunca generes ni reutilices aprobaciones. Si fsutil falla por permisos, dímelo tal cual: el terminal no eleva privilegios y no quiero que lo intentes por otra vía.
```

## Qué hace

Consulta el espacio total y libre de una unidad con un único comando de solo consulta, aprobado por el operador.

## Límites

- Requiere aprobación firmada aunque el comando solo lea: cualquier proceso lanzado en el equipo la necesita.
- El `cwd` debe ser una carpeta permitida del workspace; la unidad consultada la ves exacta en el argv que apruebas.
- En algunas configuraciones `fsutil` pide privilegios de administrador; el terminal nunca los concede.
