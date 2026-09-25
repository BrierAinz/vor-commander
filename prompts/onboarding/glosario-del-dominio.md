---
id: glosario-del-dominio
title: Glosario del dominio del proyecto
category: onboarding
tools_used: [search_files, search_content, read_file]
requires_approval: false
risk: read-only
---

## Prompt

```text
Usa Vör Commander en el dispositivo <DEVICE_ID> y el workspace <WORKSPACE_ID>; pasa device_id y workspace_id en cada llamada.

Construye un glosario de los términos propios del dominio de <RUTA_DEL_REPO>.

1. Localiza con search_files los modelos de datos, esquemas y tipos centrales (por ejemplo **/models/**, **/domain/**, **/*schema*, **/*.proto, **/migrations/**).
2. Léelos con read_file (base64) y extrae los nombres de entidades, estados y conceptos que no sean vocabulario técnico genérico.
3. Para cada término, usa search_content para ver cómo se usa en código y documentación, y detecta sinónimos (dos nombres para lo mismo) y homónimos (un nombre para dos cosas).
4. Entrégame una tabla: término, definición en una frase, dónde se define (archivo:línea), términos relacionados y notas sobre ambigüedades.

Solo lectura. Si una definición es deducción tuya y no está escrita en ningún sitio, márcala como tal.
```

## Qué hace

Extrae el vocabulario de negocio del código y lo organiza en un glosario con definiciones, referencias y ambigüedades, para entender las conversaciones del equipo.

## Límites

- Solo lectura.
- Las definiciones salen del código y los comentarios; el significado de negocio real puede requerir confirmación con el equipo.
- `search_files` y `search_content` llegan con el PR #5.
