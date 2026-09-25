---
id: documentar-api-publica
title: Referencia de la API pública de un módulo
category: documentacion
tools_used: [search_content, read_file]
requires_approval: false
risk: read-only
---

## Prompt

```text
Usa Vör Commander en el dispositivo <DEVICE_ID> y el workspace <WORKSPACE_ID>; pasa device_id y workspace_id en cada llamada.

Genera la referencia de la API pública del módulo <RUTA_DEL_MODULO>.

1. Con search_content (regex true) localiza las declaraciones públicas según el lenguaje: por ejemplo "^\s*pub (fn|struct|enum|trait)" en Rust, "^export " en TypeScript o "^def [a-z]" en Python. Ajusta el patrón a lo que veas.
2. Lee cada declaración con su comentario de documentación usando read_file con line_start y line_count (base64).
3. Para cada elemento escribe: firma, descripción de una o dos frases, parámetros, valor de retorno, errores o excepciones y un ejemplo mínimo de uso si el código lo deja claro.
4. Señala aparte los elementos públicos sin documentación y los que parecen públicos por accidente.

Entrégalo como Markdown en la respuesta. Solo lectura. No inventes comportamiento: si algo no se deduce del código, escríbelo como pregunta abierta.
```

## Qué hace

Extrae las declaraciones públicas de un módulo y produce una referencia en Markdown, además de una lista de lo que falta documentar.

## Límites

- Solo lectura; el resultado se entrega en la conversación.
- La detección de "público" se hace con expresiones regulares, no con el compilador: las macros, reexportaciones y visibilidades por configuración pueden escaparse.
- `search_content` limita cada línea a 4 KiB y la búsqueda a 5 segundos.
- `search_content` y los rangos de `read_file` llegan con el PR #5.
