---
id: secretos-antes-de-commitear
title: Comprobar que no se cuelan secretos antes del commit
category: revision
tools_used: [git_status, git_diff, read_file]
requires_approval: false
risk: read-only
---

## Prompt

```text
Usa Vör Commander en el dispositivo <DEVICE_ID> y el workspace <WORKSPACE_ID>; pasa device_id y workspace_id en cada llamada.

Antes de commitear en <RUTA_DEL_REPO>, comprueba que no se cuela ningún secreto.

1. Llama a git_status. Fíjate especialmente en archivos nuevos sin seguimiento con nombres como .env, *.pem, *.key, *.pfx, id_rsa, credentials, secrets o config local.
2. Revisa git_diff buscando claves de API, tokens, contraseñas, cadenas de conexión, claves privadas, cookies y direcciones internas.
3. Lee con read_file los archivos nuevos sospechosos que no aparezcan en el diff.
4. Dame una lista con archivo:línea y el tipo de secreto, sin reproducir nunca el valor; como mucho sus cuatro primeros caracteres. Indica también qué patrones convendría añadir a .gitignore.

Solo lectura. No modifiques ni borres nada, y no me pidas que pegue ningún secreto en la conversación.
```

## Qué hace

Actúa como última barrera antes de un commit: revisa archivos nuevos y cambios en busca de credenciales, sin repetir su valor en la respuesta.

## Límites

- Solo lectura.
- `git_diff` no muestra cambios ya preparados; si ya hiciste `git add`, el asistente solo verá esos archivos por nombre en `git_status` y tendrá que leerlos enteros.
- La detección la hace el modelo leyendo, no un escáner con reglas: es una ayuda, no una garantía. Un escáner dedicado en CI sigue siendo recomendable.
