---
id: verificar-una-escritura
title: Verificar que una escritura quedó como se aprobó
category: edicion
tools_used: [read_file, file_info, git_diff]
requires_approval: false
risk: read-only
---

## Prompt

```text
Usa Vör Commander en el dispositivo <DEVICE_ID> y el workspace <WORKSPACE_ID>; pasa device_id y workspace_id en cada llamada.

Acabo de aprobar una escritura en <RUTA_DEL_ARCHIVO> cuyo content_sha256 era <SHA256_APROBADO>. Comprueba que el disco contiene exactamente eso.

1. Llama a file_info para ver tamaño y fecha de modificación.
2. Lee el archivo entero con read_file y compara el SHA-256 en hexadecimal que sale de decodificar digest_base64 con <SHA256_APROBADO>.
3. Si el archivo está en un repositorio (<RUTA_DEL_REPO>), llama a git_diff y enséñame los cambios de ese archivo.
4. Dime claramente: coincide o no coincide. Si no coincide, explica qué diferencias ves, sin intentar corregirlas.

Solo lectura: esta comprobación no escribe nada.
```

## Qué hace

Comprueba, después de una escritura aprobada, que el contenido en disco es bit a bit el que se firmó, comparando hashes, y muestra el diff resultante.

## Límites

- Solo lectura.
- El archivo debe caber en el límite de salida del agente (1 MiB por defecto) para leerse entero y obtener su hash.
- Si otro proceso modificó el archivo después de la escritura, el hash no coincidirá aunque la escritura fuera correcta; la fecha de `file_info` ayuda a distinguirlo.
- `file_info` llega con el PR #5.
