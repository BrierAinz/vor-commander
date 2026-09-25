---
id: rastrear-mensaje-de-error
title: De un mensaje de error al código que lo emite
category: depuracion
tools_used: [search_content, read_file]
requires_approval: false
risk: read-only
---

## Prompt

```text
Usa Vör Commander en el dispositivo <DEVICE_ID> y el workspace <WORKSPACE_ID>; pasa device_id y workspace_id en cada llamada.

Me aparece este error: "<MENSAJE_DE_ERROR>". Encuentra en <RUTA_DEL_PROYECTO> qué código lo produce.

1. Quita del mensaje las partes variables (rutas, números, identificadores) y busca el texto fijo que quede con search_content, regex false. Si no aparece, prueba con fragmentos más cortos o con regex true.
2. Por cada coincidencia, lee unas 60 líneas de contexto con read_file (line_start y line_count; la salida viene en base64).
3. Explica qué condición dispara el error, qué valores tienen que darse para llegar ahí y qué comprobarías primero para confirmarlo. Si hay varios sitios que emiten el mismo mensaje, dime cómo distinguir cuál ha sido.

Solo lectura. No propongas el arreglo hasta que la causa esté identificada.
```

## Qué hace

Convierte un mensaje de error visto en pantalla o en un log en la línea de código que lo genera y en la condición exacta que lo dispara.

## Límites

- Solo lectura.
- Si el mensaje se construye en tiempo de ejecución (plantillas, traducciones, códigos de error) la búsqueda literal puede no encontrarlo; el asistente debe decirlo.
- Los errores que vienen de dependencias externas no están en el repositorio y no se encontrarán.
- `search_content` y los rangos de `read_file` llegan con el PR #5.
