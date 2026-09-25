---
id: changelog-desde-cambios
title: Entrada de CHANGELOG a partir de los cambios locales
category: documentacion
tools_used: [git_status, git_diff]
requires_approval: false
risk: read-only
---

## Prompt

```text
Usa Vör Commander en el dispositivo <DEVICE_ID> y el workspace <WORKSPACE_ID>; pasa device_id y workspace_id en cada llamada.

Redacta la entrada de CHANGELOG para los cambios pendientes en <RUTA_DEL_REPO>.

1. Llama a git_status para ver qué archivos cambian, incluidos los nuevos sin seguimiento y los ya preparados (staged).
2. Llama a git_diff para leer los cambios no preparados.
3. Redacta la entrada con el formato Keep a Changelog (Añadido, Cambiado, Corregido, Eliminado, Seguridad), escrita para usuarios del proyecto y no para quien lo programa.
4. Si hay archivos en git_status cuyo diff no puedes ver (staged o sin seguimiento), enuméralos y dime que la entrada puede estar incompleta por ellos.

Solo lectura: entrégame el texto en la respuesta, no lo escribas en disco.
```

## Qué hace

Convierte el diff local en una entrada de CHANGELOG orientada a usuarios y avisa de los cambios que no pudo ver.

## Límites

- Solo lectura.
- `git_diff` solo muestra cambios no preparados. Si ya hiciste `git add`, esos cambios no aparecen en el diff; el asistente solo verá sus nombres en `git_status`.
- No hay acceso a commits anteriores: para una versión que abarca varios commits este prompt no basta.
