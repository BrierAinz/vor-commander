---
id: compilar-el-proyecto
title: Compilar el proyecto
category: tests
tools_used: [prepare_terminal, commit_terminal, poll_terminal, cancel_terminal]
requires_approval: true
risk: exec
---

## Prompt

```text
Usa Vör Commander en el dispositivo <DEVICE_ID> y el workspace <WORKSPACE_ID>; pasa device_id y workspace_id en cada llamada.

Compila <RUTA_DEL_PROYECTO> con este comando: <COMANDO_DE_BUILD> (por ejemplo cargo build --locked, npm run build o dotnet build).

1. Convierte el comando en argv, un argumento por elemento, y llama a prepare_terminal con cwd = <RUTA_DEL_PROYECTO>, timeout_ms 120000 y max_output_bytes 262144. No uses shell ni powershell -Command.
2. prepare_terminal no arranca nada: devuelve un desafío de aprobación. Enséñame cwd y argv y espera a que firme la aprobación en el aprobador de Vör y te pase el approval_base64.
3. Llama a commit_terminal con el request_base64 exacto y mi approval_base64. Consulta con poll_terminal hasta que termine; si te pido pararlo, usa cancel_terminal con el mismo session_id.
4. Dime si compiló. Si hubo errores, agrúpalos por archivo, empieza por el primero (los siguientes suelen ser consecuencia) y explica la causa probable de cada grupo. Resume también los avisos importantes.

Nunca generes ni reutilices aprobaciones. Si la compilación se corta por tiempo o por tamaño de salida, dilo: no es un éxito ni un fallo del código.
```

## Qué hace

Lanza la compilación con el terminal acotado, tras aprobación, y ordena los errores por causa en lugar de volcar la salida completa.

## Límites

- Requiere aprobación firmada para arrancar el proceso.
- 120 s como máximo: una compilación en frío de un proyecto grande puede no caber. En ese caso compila un paquete o un objetivo concreto.
- La salida está limitada a 512 KiB; al superarla el proceso se termina.
- Si el build necesita privilegios de administrador o variables de entorno que el agente no tiene, fallará: el terminal nunca eleva privilegios.
