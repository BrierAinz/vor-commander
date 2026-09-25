---
id: primer-dia-en-el-repo
title: Primer día en un repositorio nuevo
category: onboarding
tools_used: [commander_status, list_directory, read_file, git_status]
requires_approval: false
risk: read-only
---

## Prompt

```text
Usa Vör Commander. Llama primero a commander_status para confirmar que el dispositivo <DEVICE_ID> está conectado (si no te doy uno, usa recommended_device_id). En todas las llamadas siguientes pasa device_id y el workspace_id <WORKSPACE_ID>.

Acabo de llegar al repositorio <RUTA_DEL_REPO> y no sé nada de él. Oriéntame.

1. Llama a git_status para saber la rama actual, si está al día con su upstream y si hay trabajo local sin commitear que no sea mío.
2. Recorre la estructura con list_directory (depth 2).
3. Lee con read_file (base64) el README, la guía de contribución (CONTRIBUTING, AGENTS, docs/) y el manifiesto principal.
4. Entrégame una guía de una página:
   - qué hace el proyecto y para quién;
   - cómo está organizado (carpetas clave);
   - cómo se compila, se prueba y se ejecuta, según lo documentado;
   - las reglas del equipo que deba conocer (ramas, estilo, revisiones);
   - las preguntas que debería hacer a alguien del equipo porque no están escritas.

Solo lectura. No ejecutes nada ni modifiques archivos.
```

## Qué hace

Primera sesión en un repositorio: comprueba la conexión, el estado de Git y la estructura, lee la documentación clave y lo resume en una guía de una página con las preguntas pendientes.

## Límites

- Solo lectura; los comandos de build y test se toman de la documentación, no se ejecutan.
- `git_status` muestra la rama y el estado frente al upstream, pero no el historial.
- `list_directory` llega con el PR #5; sin ella hay que darle al asistente las rutas de los archivos a leer.
