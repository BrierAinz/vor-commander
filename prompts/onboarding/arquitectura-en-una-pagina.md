---
id: arquitectura-en-una-pagina
title: La arquitectura en una página
category: onboarding
tools_used: [list_directory, search_files, search_content, read_file]
requires_approval: false
risk: read-only
---

## Prompt

```text
Usa Vör Commander en el dispositivo <DEVICE_ID> y el workspace <WORKSPACE_ID>; pasa device_id y workspace_id en cada llamada.

Describe la arquitectura de <RUTA_DEL_REPO> en una página.

1. Identifica los componentes (aplicaciones, paquetes, crates, servicios) con list_directory (depth 2) y search_files sobre los manifiestos.
2. Para cada componente, lee su manifiesto y su punto de entrada con read_file (base64) y averigua de qué otros componentes depende.
3. Con search_content localiza las fronteras: servidores HTTP o gRPC, colas, acceso a base de datos, llamadas a APIs externas, lectura de configuración.
4. Entrégame:
   - un diagrama en texto (Mermaid o ASCII) con los componentes y sus dependencias;
   - una frase por componente con su responsabilidad;
   - cómo fluye una petición típica entre ellos;
   - las decisiones de diseño que se deducen del código y dónde está documentada cada una, si lo está.

Solo lectura. Distingue lo que has leído en el código de lo que deduces.
```

## Qué hace

Produce una vista de arquitectura de una página (componentes, dependencias, fronteras y flujo típico) construida a partir de manifiestos y código, no de suposiciones.

## Límites

- Solo lectura.
- Las dependencias en tiempo de ejecución que no aparecen en el código (configuración de despliegue en otro repositorio, servicios gestionados) no se ven.
- En monorepos grandes la exploración se acota por los límites de `list_directory` y `search_files` (10 000 entradas) y de `search_content` (5 s por búsqueda).
- `list_directory`, `search_files` y `search_content` llegan con el PR #5.
