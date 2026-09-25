---
id: mapa-del-proyecto
title: Mapa de un proyecto en cinco minutos
category: exploracion
tools_used: [list_directory, file_info, read_file]
requires_approval: false
risk: read-only
---

## Prompt

```text
Usa Vör Commander en el dispositivo <DEVICE_ID> y el workspace <WORKSPACE_ID>; pasa device_id y workspace_id en cada llamada.

Quiero un mapa del proyecto que está en <RUTA_DEL_PROYECTO>.

1. Llama a list_directory sobre esa ruta con depth 2 y max_entries 500. Si el resultado llega al tope, dilo y vuelve a pedir solo las carpetas que parezcan relevantes.
2. Identifica los archivos que definen el proyecto (manifiestos de paquetes, archivos de build, README, configuración de CI). Usa file_info para ver su tamaño antes de leerlos y lee con read_file solo los que pesen menos de 200 KB. read_file devuelve base64: decodifícalo antes de citarlo.
3. Entrégame:
   - una tabla con las carpetas principales y para qué sirve cada una;
   - el lenguaje, el sistema de build y los puntos de entrada;
   - tres archivos que debería leer primero y por qué.

No modifiques nada. Si una ruta está fuera de las carpetas permitidas o la llamada falla por autorización, detente y dímelo; no pruebes rutas alternativas para esquivarlo.
```

## Qué hace

Recorre dos niveles del árbol, lee los archivos que definen el proyecto y devuelve un mapa de carpetas, tecnología y puntos de entrada. Es el primer prompt que conviene usar en un repositorio desconocido.

## Límites

- Solo lectura. `list_directory` no sigue enlaces simbólicos ni junctions, así que las carpetas enlazadas aparecen sin contenido.
- `depth` admite como máximo 16 y `max_entries` como máximo 10 000; en monorepos grandes el mapa sale parcial y el asistente debe decirlo.
- `read_file` sin rango rechaza archivos mayores que el límite de salida del agente (1 MiB por defecto).
- `list_directory` y `file_info` llegan con el PR #5 (`pilot/read-tools`); sin ellas el asistente solo puede leer rutas que tú le des.
