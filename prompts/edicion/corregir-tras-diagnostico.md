---
id: corregir-tras-diagnostico
title: Aplicar la corrección de un fallo ya diagnosticado
category: edicion
tools_used: [search_content, read_file, prepare_write, commit_write, git_diff]
requires_approval: true
risk: write
---

## Prompt

```text
Usa Vör Commander en el dispositivo <DEVICE_ID> y el workspace <WORKSPACE_ID>; pasa device_id y workspace_id en cada llamada.

Ya sabemos la causa del fallo: <CAUSA_DEL_FALLO>. Aplica la corrección mínima en <RUTA_DEL_REPO>.

1. Usa search_content para encontrar todos los sitios afectados por la misma causa, no solo el primero. Enséñame la lista.
2. Por cada archivo a tocar, léelo entero con read_file y anota el SHA-256 en hexadecimal que resulta de decodificar digest_base64; será su expected_target_sha256.
3. Enséñame un diff unificado por archivo con el cambio más pequeño que corrige la causa. Nada de refactors ni cambios de estilo añadidos.
4. Cuando confirme, prepara una escritura por archivo con prepare_write (archivo completo en content_base64). Cada una devuelve un desafío de aprobación: dime el path y el content_sha256 de cada solicitud y espera a que firme cada aprobación en el aprobador de Vör y te pase su approval_base64.
5. Llama a commit_write por cada archivo con su request_base64 exacto y su approval_base64 correspondiente.
6. Al terminar, llama a git_diff y comprueba que el diff real coincide con el que te aprobé.

Nunca generes ni reutilices aprobaciones, y no mezcles la aprobación de un archivo con la solicitud de otro. Si alguna escritura falla, detente y dime en qué estado quedó cada archivo.
```

## Qué hace

Lleva una corrección desde el diagnóstico hasta el disco: encuentra todos los puntos afectados, propone el cambio mínimo, lo escribe con aprobación por archivo y verifica el resultado con `git_diff`.

## Límites

- Requiere una aprobación firmada por cada archivo escrito; no hay escritura por lotes.
- Cada archivo se reescribe entero (máximo 1 MiB) y debe poder leerse entero para obtener su hash.
- Las escrituras no son atómicas entre archivos: si falla la tercera de cinco, las dos primeras ya están hechas. El paso final con `git_diff` sirve para verlo.
- `git_diff` no incluye archivos sin seguimiento; si la corrección crea uno nuevo, compruébalo con `read_file`.
- `search_content` llega con el PR #5.
