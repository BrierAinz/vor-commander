---
id: estado-git-inesperado
title: Qué ha pasado en este repositorio
category: depuracion
tools_used: [git_status, git_diff, read_file]
requires_approval: false
risk: read-only
---

## Prompt

```text
Usa Vör Commander en el dispositivo <DEVICE_ID> y el workspace <WORKSPACE_ID>; pasa device_id y workspace_id en cada llamada.

El repositorio <RUTA_DEL_REPO> se comporta de forma rara (compila distinto, faltan cambios, o Git dice cosas que no espero). Diagnostica su estado.

1. Llama a git_status. La salida es porcelain v2 con --branch: interpreta la rama, el upstream, el adelanto/retraso (ab), y clasifica cada entrada en modificada, preparada (staged), sin seguimiento, renombrada o en conflicto (líneas "u").
2. Llama a git_diff para ver los cambios del árbol de trabajo que aún no están en el índice.
3. Si hay conflictos o archivos sin seguimiento que parezcan relevantes, léelos con read_file (base64) para ver los marcadores de conflicto o su contenido.
4. Explícame en lenguaje llano en qué estado está el repositorio, qué parece haber pasado y qué pasos concretos de Git me recomiendas, advirtiendo cuáles serían destructivos.

Solo lectura: no ejecutes ningún comando de Git que cambie el estado. Los pasos que recomiendes los ejecutaré yo.
```

## Qué hace

Interpreta la salida exacta de `git status` y `git diff` para explicar el estado del repositorio (rama, cambios, conflictos, archivos perdidos) y propone pasos de recuperación marcando los peligrosos.

## Límites

- Solo lectura.
- `git_diff` ejecuta `git diff` sin argumentos: muestra árbol de trabajo frente a índice. Los cambios ya preparados (staged) y el contenido de archivos sin seguimiento no aparecen; solo se ven en `git_status`.
- No hay acceso al historial (`git log`, reflog) ni a otras ramas; lo que el asistente deduzca de ellos es inferencia.
- La salida de Git está limitada a 4 MiB y al límite de salida del agente.
