---
id: mensaje-de-commit
title: Proponer el mensaje de commit
category: revision
tools_used: [git_status, git_diff]
requires_approval: false
risk: read-only
---

## Prompt

```text
Usa Vör Commander en el dispositivo <DEVICE_ID> y el workspace <WORKSPACE_ID>; pasa device_id y workspace_id en cada llamada.

Propón el mensaje de commit para los cambios de <RUTA_DEL_REPO>.

1. Llama a git_status y a git_diff.
2. Si los cambios mezclan temas distintos, propón cómo dividirlos en varios commits y qué archivos van en cada uno.
3. Para cada commit escribe un asunto de menos de 72 caracteres en imperativo y un cuerpo que explique el porqué, no el qué. Respeta la convención del repositorio si la ves en los archivos (por ejemplo Conventional Commits); si no puedes verla, pregúntame.

Solo lectura: no ejecutes git add ni git commit, solo dame el texto.
```

## Qué hace

Lee los cambios pendientes y propone uno o varios mensajes de commit bien formados, sugiriendo cómo dividir cambios que mezclan temas.

## Límites

- Solo lectura; el commit lo haces tú.
- `git_diff` no ve lo ya preparado con `git add`: esos archivos solo aparecen por nombre en `git_status`.
- No hay acceso a `git log`, así que el asistente no puede imitar el estilo de commits anteriores salvo que se lo describas.
