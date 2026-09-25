---
id: docs-desactualizadas
title: Detectar documentación desactualizada
category: documentacion
tools_used: [search_files, search_content, read_file]
requires_approval: false
risk: read-only
---

## Prompt

```text
Usa Vör Commander en el dispositivo <DEVICE_ID> y el workspace <WORKSPACE_ID>; pasa device_id y workspace_id en cada llamada.

Comprueba si la documentación de <RUTA_DEL_PROYECTO> sigue siendo cierta.

1. Localiza la documentación con search_files (**/*.md, docs/**) y léela con read_file (base64). Empieza por README y guías de instalación.
2. Extrae las afirmaciones comprobables: nombres de comandos, flags, rutas de archivos, variables de entorno, nombres de funciones y valores por defecto.
3. Comprueba cada una con search_content (regex false) contra el código y los scripts.
4. Dame una tabla: afirmación, archivo de documentación y línea, estado (confirmada, contradicha, no encontrada) y la evidencia en el código.

Solo lectura. No corrijas nada todavía; quiero la lista para decidir.
```

## Qué hace

Cruza lo que dice la documentación con lo que hay en el código y devuelve una tabla de afirmaciones confirmadas, contradichas o sin respaldo.

## Límites

- Solo lectura.
- "No encontrada" no significa "falsa": el valor puede construirse dinámicamente o vivir fuera de las carpetas permitidas.
- Cada búsqueda está acotada a 5 segundos y 10 000 coincidencias; con mucha documentación conviene ir por archivos.
- `search_files`, `search_content` y los rangos de `read_file` llegan con el PR #5.
