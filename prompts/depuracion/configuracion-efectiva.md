---
id: configuracion-efectiva
title: Qué configuración está usando realmente
category: depuracion
tools_used: [search_files, search_content, read_file]
requires_approval: false
risk: read-only
---

## Prompt

```text
Usa Vör Commander en el dispositivo <DEVICE_ID> y el workspace <WORKSPACE_ID>; pasa device_id y workspace_id en cada llamada.

Sospecho que <RUTA_DEL_PROYECTO> no está usando el valor que creo para la opción "<NOMBRE_DE_LA_OPCION>".

1. Con search_files localiza todos los archivos de configuración candidatos (**/*.env*, **/*.toml, **/*.json, **/*.yaml, **/*.yml, **/*.ini, **/*.config).
2. Con search_content (regex false) busca la opción en esos archivos y en el código, para ver dónde se lee y qué valor por defecto tiene.
3. Lee con read_file los tramos relevantes (base64) y reconstruye el orden de precedencia: valor por defecto en código, archivos, variables de entorno, argumentos.
4. Dime qué valor gana según lo que hay en disco, qué no puedes saber sin ver el entorno del proceso, y dónde está la discrepancia más probable.

Solo lectura. Si encuentras secretos (claves, contraseñas, cadenas de conexión), no los copies: indica solo el archivo y la clave.
```

## Qué hace

Reconstruye de dónde sale el valor de una opción de configuración y en qué orden se aplican las fuentes, para explicar por qué el programa no se comporta como se esperaba.

## Límites

- Solo lectura.
- Las variables de entorno y los argumentos del proceso en ejecución no son visibles: `process_inspect` no devuelve la línea de comandos ni el entorno.
- Los archivos fuera de las carpetas permitidas (por ejemplo, configuración de usuario en otra unidad) no se pueden leer.
- `search_files`, `search_content` y los rangos de `read_file` llegan con el PR #5.
