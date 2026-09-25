---
id: como-se-compila-y-se-prueba
title: Cómo se compila y se prueba este proyecto
category: onboarding
tools_used: [search_files, read_file]
requires_approval: false
risk: read-only
---

## Prompt

```text
Usa Vör Commander en el dispositivo <DEVICE_ID> y el workspace <WORKSPACE_ID>; pasa device_id y workspace_id en cada llamada.

Averigua cómo se compila, se prueba y se ejecuta <RUTA_DEL_REPO>, sin ejecutar nada.

1. Con search_files localiza: manifiestos (package.json, Cargo.toml, pyproject.toml, *.csproj, go.mod), scripts (Makefile, justfile, *.ps1, *.sh, scripts/**), configuración de CI (.github/workflows/**, .gitlab-ci.yml, azure-pipelines.yml) y archivos de versión de herramientas (rust-toolchain*, .nvmrc, .python-version, global.json).
2. Lee con read_file (base64) los relevantes. La configuración de CI es la fuente más fiable: muestra lo que de verdad se ejecuta.
3. Entrégame:
   - los requisitos con versiones (toolchain, runtime, herramientas);
   - los comandos exactos de build, test, lint y ejecución, como listas argv listas para usar con el terminal aprobado de Vör;
   - las variables de entorno o servicios que necesitan los tests;
   - las diferencias entre lo que dice el README y lo que hace el CI.

Solo lectura. No ejecutes ningún comando: cuando quiera ejecutarlos, usaré los prompts de tests, que piden aprobación.
```

## Qué hace

Deduce de manifiestos, scripts y CI los comandos reales de build y test y los entrega como argv listos para el terminal aprobado, señalando dónde la documentación y el CI discrepan.

## Límites

- Solo lectura; los comandos no se validan ejecutándolos.
- Los secretos del CI no son visibles ni deben pedirse; los tests que dependan de ellos se marcan como tales.
- `search_files` llega con el PR #5.
