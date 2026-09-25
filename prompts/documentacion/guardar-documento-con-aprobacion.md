---
id: guardar-documento-con-aprobacion
title: Guardar un documento con aprobación
category: documentacion
tools_used: [file_info, read_file, prepare_write, commit_write]
requires_approval: true
risk: write
---

## Prompt

```text
Usa Vör Commander en el dispositivo <DEVICE_ID> y el workspace <WORKSPACE_ID>; pasa device_id y workspace_id en cada llamada.

Quiero guardar en <RUTA_DEL_DOCUMENTO> el documento que hemos redactado en esta conversación.

1. Comprueba con file_info si el archivo existe.
   - Si no existe, usarás expected_target_sha256 = "absent".
   - Si existe, léelo entero con read_file y usa como expected_target_sha256 el valor hexadecimal (64 caracteres, minúsculas) de decodificar digest_base64 de esa respuesta. Enséñame qué partes vas a sustituir.
2. Codifica el texto final completo en UTF-8 y luego en base64, y llama a prepare_write con path, content_base64 y expected_target_sha256. prepare_write no escribe nada: devuelve un desafío de aprobación, un request_base64 y el content_sha256.
3. Muéstrame el content_sha256, el tamaño y un resumen del contenido, y espera. Yo reviso y firmo la aprobación en el aprobador de Vör y te paso el approval_base64.
4. Solo entonces llama a commit_write con el request_base64 exacto que devolvió prepare_write y mi approval_base64.

Reglas: nunca generes, adivines ni reutilices una aprobación; cada una sirve una sola vez. Si la aprobación se rechaza, caduca (la solicitud vive 3 minutos) o commit_write falla, no reintentes por otra vía: dime qué ha pasado y, si quiero, preparamos una solicitud nueva.
```

## Qué hace

Escribe en disco un documento redactado en la conversación siguiendo el flujo de dos pasos de Vör Commander: preparar la escritura, que el operador la apruebe con su firma y confirmarla con esa aprobación exacta.

## Límites

- Requiere aprobación firmada del operador para cada escritura; sin ella no se escribe nada.
- Escribe el archivo completo (no hay parches parciales) y como máximo 1 MiB.
- Si el archivo cambia entre la lectura y la confirmación, el hash esperado no coincide y el dispositivo rechaza la escritura: hay que volver a leer y preparar.
- La solicitud preparada caduca a los 180 segundos.
- `file_info` llega con el PR #5; sin ella, un `read_file` fallido por inexistencia indica que el archivo no existe.
