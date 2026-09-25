---
id: dependencias-del-proyecto
title: Inventario de dependencias
category: exploracion
tools_used: [search_files, file_info, read_file]
requires_approval: false
risk: read-only
---

## Prompt

```text
Usa Vör Commander en el dispositivo <DEVICE_ID> y el workspace <WORKSPACE_ID>; pasa device_id y workspace_id en cada llamada.

Haz un inventario de las dependencias de <RUTA_DEL_PROYECTO>.

1. Con search_files localiza los manifiestos: package.json, Cargo.toml, pyproject.toml, requirements*.txt, go.mod, *.csproj, pom.xml, build.gradle*. Descarta las rutas dentro de node_modules, target, .venv y carpetas similares.
2. Lee cada manifiesto con read_file (base64). De los archivos de bloqueo (package-lock.json, Cargo.lock, poetry.lock...) mira solo si existen y su tamaño con file_info; no los leas enteros.
3. Dame una tabla por manifiesto con: dependencia, versión declarada, si es de desarrollo o de producción, y una nota cuando la versión esté sin fijar, esté repetida entre manifiestos con versiones distintas o falte el archivo de bloqueo.

Solo lectura. No consultes registros de paquetes ni internet: trabaja con lo que hay en disco y marca como "a verificar" cualquier opinión que dependa de información externa.
```

## Qué hace

Encuentra todos los manifiestos de dependencias del proyecto y resume qué se usa, con qué versión y dónde hay riesgos evidentes, como versiones sin fijar o incoherentes entre módulos.

## Límites

- Solo lectura y sin red: no comprueba vulnerabilidades publicadas ni versiones más recientes; lo que el asistente diga de ello sale de su conocimiento y hay que verificarlo.
- `search_files` devuelve como máximo 10 000 rutas; en monorepos grandes conviene acotar la raíz.
- `search_files` y `file_info` llegan con el PR #5.
