---
id: estado-de-un-servicio
title: Estado y configuración de un servicio de Windows
category: windows
tools_used: [process_list, prepare_terminal, commit_terminal, poll_terminal]
requires_approval: true
risk: exec
---

## Prompt

```text
Usa Vör Commander en el dispositivo <DEVICE_ID> y el workspace <WORKSPACE_ID>; pasa device_id y workspace_id en cada llamada.

Quiero saber si el servicio <NOMBRE_DEL_SERVICIO> está funcionando y cómo está configurado.

1. Primero en solo lectura: llama a process_list y dime si ves el ejecutable que normalmente usa ese servicio (<EJECUTABLE_DEL_SERVICIO>, si lo conozco) y cuántas instancias tiene.
2. Después prepara dos consultas con prepare_terminal, con cwd = <CARPETA_PERMITIDA>, timeout_ms 15000 y max_output_bytes 32768:
   - estado: argv ["sc.exe", "queryex", "<NOMBRE_DEL_SERVICIO>"]
   - configuración: argv ["sc.exe", "qc", "<NOMBRE_DEL_SERVICIO>"]
   Cada una devuelve un desafío de aprobación. Enséñame los argv y espera a que firme cada aprobación en el aprobador de Vör y te pase su approval_base64.
3. Ejecuta cada una con commit_terminal (request_base64 exacto y su approval_base64) y recoge el resultado con poll_terminal.
4. Explícame: estado (en ejecución, detenido, pendiente), PID y si coincide con lo que viste en process_list, tipo de inicio, cuenta con la que se ejecuta, dependencias, y el código de salida si está detenido con error.

Solo consultas: no prepares comandos que arranquen, paren, reconfiguren o eliminen el servicio. Si hace falta, te diré yo qué hacer. Nunca generes ni reutilices aprobaciones.
```

## Qué hace

Combina la lista de procesos con dos consultas de `sc.exe` para explicar si un servicio está vivo, con qué configuración y, si falló, con qué código.

## Límites

- Las consultas `sc.exe` requieren aprobación firmada; `process_list` no.
- El prompt se limita a `queryex` y `qc`. Arrancar, parar o reconfigurar servicios suele exigir privilegios de administrador, y el terminal nunca eleva privilegios.
- `process_list` no relaciona procesos con servicios; el PID de `sc.exe queryex` es el que establece esa relación.
