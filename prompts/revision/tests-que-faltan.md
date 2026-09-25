---
id: tests-que-faltan
title: ¿Tienen tests los cambios?
category: revision
tools_used: [git_status, git_diff, search_files, search_content]
requires_approval: false
risk: read-only
---

## Prompt

```text
Usa Vör Commander en el dispositivo <DEVICE_ID> y el workspace <WORKSPACE_ID>; pasa device_id y workspace_id en cada llamada.

Comprueba si los cambios pendientes de <RUTA_DEL_REPO> están cubiertos por tests.

1. Con git_status y git_diff identifica las funciones y ramas de código nuevas o modificadas.
2. Con search_files localiza los archivos de test del proyecto (por ejemplo **/*test*, **/tests/**, **/*.spec.*) y con search_content busca en ellos los nombres de las funciones cambiadas.
3. Para cada cambio relevante dime si hay test que lo ejerza, si el test existente sigue siendo válido tras el cambio y qué casos faltan (caso normal, límites, errores).
4. Propón los tests que faltan como lista de nombres y descripción de una línea; no escribas su código salvo que te lo pida.

Solo lectura: no ejecutes los tests ni escribas archivos.
```

## Qué hace

Relaciona cada cambio con los tests que lo cubren y enumera los casos sin probar, para decidir qué añadir antes de integrar.

## Límites

- Solo lectura; no mide cobertura real, la estima por búsqueda de nombres. Un test puede ejercer código sin nombrarlo.
- Para ejecutar los tests usa los prompts de la categoría de tests, que requieren aprobación.
- `search_files` y `search_content` llegan con el PR #5.
