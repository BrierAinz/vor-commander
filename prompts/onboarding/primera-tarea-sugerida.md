---
id: primera-tarea-sugerida
title: Proponer una primera tarea asequible
category: onboarding
tools_used: [search_content, read_file, git_status]
requires_approval: false
risk: read-only
---

## Prompt

```text
Usa Vör Commander en el dispositivo <DEVICE_ID> y el workspace <WORKSPACE_ID>; pasa device_id y workspace_id en cada llamada.

Soy nuevo en <RUTA_DEL_REPO>. Propón tres tareas pequeñas y útiles para empezar a contribuir.

1. Llama a git_status para confirmar en qué rama estoy y que no hay trabajo a medias.
2. Busca candidatos con search_content (regex true), por ejemplo "TODO|FIXME|HACK|XXX", además de funciones sin tests y documentación marcada como pendiente.
3. Lee con read_file (base64, con line_start y line_count) el contexto de los candidatos más prometedores.
4. Elige tres tareas que se puedan terminar en un día, que no toquen partes críticas y que me obliguen a recorrer una zona distinta del código cada una. Para cada una: qué hay que hacer, archivos implicados, cómo comprobar que está bien y a quién o qué documento consultar antes.

Solo lectura. No empieces ninguna tarea.
```

## Qué hace

Busca en el código tareas pequeñas y seguras (TODO, pruebas que faltan, documentación pendiente) y propone tres que sirvan también para conocer el proyecto.

## Límites

- Solo lectura.
- Los TODO pueden estar obsoletos o ya resueltos en otra rama; no hay acceso a issues ni al historial.
- `search_content` llega con el PR #5 y limita cada búsqueda a 5 segundos y 10 000 coincidencias.
