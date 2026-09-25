---
id: crear-archivo-nuevo
title: Crear un archivo nuevo sin pisar nada
category: edicion
tools_used: [file_info, prepare_write, commit_write]
requires_approval: true
risk: write
---

## Prompt

```text
Usa Vör Commander en el dispositivo <DEVICE_ID> y el workspace <WORKSPACE_ID>; pasa device_id y workspace_id en cada llamada.

Crea el archivo <RUTA_DEL_ARCHIVO_NUEVO> con este propósito: <PROPOSITO_DEL_ARCHIVO>.

1. Comprueba con file_info que la ruta no existe todavía. Si existe, detente y avísame: no la sobrescribas.
2. Redacta el contenido y enséñamelo completo para que lo revise.
3. Cuando lo apruebe en la conversación, codifícalo en UTF-8 y luego en base64 y llama a prepare_write con path, content_base64 y expected_target_sha256 = "absent". Así el dispositivo rechazará la escritura si entretanto alguien crea el archivo.
4. prepare_write no escribe: devuelve un desafío de aprobación, request_base64 y content_sha256. Muéstrame el content_sha256 y espera a que firme la aprobación en el aprobador de Vör y te pase el approval_base64.
5. Llama a commit_write con el request_base64 exacto y mi approval_base64.

Nunca generes, adivines ni reutilices una aprobación. Si se rechaza o caduca, no reintentes por otra vía; dime qué ha pasado.
```

## Qué hace

Crea un archivo nuevo con la garantía de no sobrescribir uno existente: el valor `absent` hace que el dispositivo rechace la escritura si la ruta ya está ocupada.

## Límites

- Requiere aprobación firmada del operador.
- Máximo 1 MiB por archivo. La ruta debe estar dentro de las carpetas permitidas del workspace; si la carpeta padre no existe, la escritura puede fallar y no hay herramienta para crear directorios.
- La solicitud preparada caduca a los 180 segundos.
- `file_info` llega con el PR #5; sin ella, confía en `expected_target_sha256 = "absent"`, que por sí solo ya impide pisar un archivo existente.
