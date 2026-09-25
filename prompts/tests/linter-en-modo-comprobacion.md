---
id: linter-en-modo-comprobacion
title: Linter y formato en modo comprobación
category: tests
tools_used: [prepare_terminal, commit_terminal, poll_terminal]
requires_approval: true
risk: exec
---

## Prompt

```text
Usa Vör Commander en el dispositivo <DEVICE_ID> y el workspace <WORKSPACE_ID>; pasa device_id y workspace_id en cada llamada.

Pasa el linter y el comprobador de formato de <RUTA_DEL_PROYECTO> sin modificar archivos.

1. Elige la variante de solo comprobación de cada herramienta, nunca la que corrige: por ejemplo ["cargo", "fmt", "--check"], ["cargo", "clippy", "--locked", "--", "-D", "warnings"], ["npx", "eslint", "."], ["npx", "prettier", "--check", "."], ["ruff", "check", "."]. No uses --fix ni --write.
2. Prepara cada comando por separado con prepare_terminal (cwd = <RUTA_DEL_PROYECTO>, timeout_ms 120000, max_output_bytes 262144). Cada uno devuelve un desafío de aprobación: enséñame los argv y espera a que firme cada aprobación en el aprobador de Vör y te pase el approval_base64 de cada una.
3. Ejecuta cada uno con commit_terminal (request_base64 exacto y su approval_base64) y recoge el resultado con poll_terminal.
4. Agrupa los problemas por regla y por archivo, di cuántos hay de cada tipo y cuáles son errores y cuáles avisos.

Nunca generes ni reutilices aprobaciones. Si quiero aplicar las correcciones automáticas, lo pediré aparte: eso modifica archivos.
```

## Qué hace

Ejecuta linters y comprobadores de formato en su modo de solo comprobación, con una aprobación por comando, y resume los problemas agrupados por regla.

## Límites

- Requiere una aprobación firmada por cada comando.
- Aunque el modo sea de comprobación, un proceso aprobado puede escribir en disco (cachés, artefactos); el aprobador muestra el argv exacto para que lo revises.
- 120 s y 512 KiB de salida por ejecución; en repositorios grandes conviene pasar rutas concretas.
