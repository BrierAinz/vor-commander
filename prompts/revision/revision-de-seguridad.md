---
id: revision-de-seguridad
title: Revisión de seguridad del diff
category: revision
tools_used: [git_diff, read_file, search_content]
requires_approval: false
risk: read-only
---

## Prompt

```text
Usa Vör Commander en el dispositivo <DEVICE_ID> y el workspace <WORKSPACE_ID>; pasa device_id y workspace_id en cada llamada.

Haz una revisión de seguridad de los cambios no commiteados de <RUTA_DEL_REPO>.

1. Lee el diff con git_diff.
2. Para cada cambio que toque entrada externa, autenticación, autorización, rutas de archivos, ejecución de procesos, serialización, SQL, criptografía o registro de logs, lee el contexto con read_file (base64) y sigue de dónde viene el dato con search_content.
3. Busca en concreto: inyección (comandos, SQL, rutas), recorrido de directorios, comprobaciones de permisos ausentes o invertidas, secretos en código o en logs, errores que filtran detalles internos, criptografía casera y condiciones de carrera entre comprobar y usar.
4. Por cada hallazgo: severidad, archivo:línea, escenario de ataque concreto en dos o tres frases y corrección propuesta. Si no encuentras nada, di qué revisaste para llegar a esa conclusión.

Solo lectura. Si encuentras un secreto real, no lo repitas en la respuesta: indica solo dónde está.
```

## Qué hace

Revisa los cambios locales con foco en seguridad, siguiendo el origen de los datos que llegan a operaciones sensibles, y describe cada hallazgo con un escenario de ataque concreto.

## Límites

- Solo lectura; no sustituye a herramientas de análisis estático ni a una auditoría completa.
- `git_diff` no incluye cambios ya preparados ni archivos sin seguimiento.
- El rastreo del origen de los datos se hace por búsqueda de texto y puede cortarse en llamadas dinámicas.
- `search_content` y los rangos de `read_file` llegan con el PR #5.
