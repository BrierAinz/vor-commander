---
id: borrador-de-readme
title: Borrador de README a partir del código
category: documentacion
tools_used: [list_directory, search_files, read_file]
requires_approval: false
risk: read-only
---

## Prompt

```text
Usa Vör Commander en el dispositivo <DEVICE_ID> y el workspace <WORKSPACE_ID>; pasa device_id y workspace_id en cada llamada.

Escribe un borrador de README para <RUTA_DEL_PROYECTO> basado solo en lo que hay en disco.

1. Recorre la estructura con list_directory (depth 2) y localiza con search_files los manifiestos, scripts de build, archivos de CI y ejemplos de configuración.
2. Lee con read_file (base64) lo imprescindible para saber: qué hace el proyecto, cómo se instala, cómo se ejecuta, cómo se prueban los tests y qué configuración necesita.
3. Redacta el README en Markdown con las secciones: descripción, requisitos, instalación, uso, configuración, tests y estructura del proyecto.
4. Marca con [VERIFICAR] cada afirmación que no hayas podido confirmar leyendo un archivo, e indica al final qué archivo respalda cada sección.

Entrégame el README como texto en la respuesta; no lo escribas en disco. Si existe un README, compáralo con el tuyo y señala lo que está desactualizado.
```

## Qué hace

Genera un README fiel al código: cada sección está respaldada por un archivo concreto y lo que no se pudo comprobar queda marcado para revisión.

## Límites

- Solo lectura: el resultado se entrega en la conversación. Para guardarlo usa el prompt de escribir documentación con aprobación.
- No ejecuta nada, así que los comandos de instalación y uso salen de los scripts y manifiestos, no de una ejecución comprobada.
- `list_directory` y `search_files` llegan con el PR #5.
