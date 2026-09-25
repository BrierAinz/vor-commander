---
id: edicion-puntual-aprobada
title: Cambio puntual en un archivo con aprobación
category: edicion
tools_used: [prepare_edit, commit_write]
requires_approval: true
risk: write
---

## Prompt

```text
Usa Vör Commander en el dispositivo <DEVICE_ID> y el workspace <WORKSPACE_ID>; pasa device_id y workspace_id en cada llamada.

Quiero este cambio en <RUTA_DEL_ARCHIVO>: <DESCRIPCION_DEL_CAMBIO>.

1. Formula el cambio como uno o varios bloques exactos `{old_text, new_text, expected_occurrences}`. Usa 1 como expected_occurrences salvo que yo pida reemplazar varias apariciones conocidas.
2. Llama a prepare_edit con path y edits. El dispositivo lee el archivo y aplica los bloques en orden; no envíes ni reconstruyas el archivo completo.
3. Enséñame el diff_summary devuelto. Si el conteo no coincide, detente y usa el conteo real y la línea más cercana para corregir el bloque, sin relajar expected_occurrences.
4. Dime el content_sha256 y espera. Yo reviso el desafío en el aprobador de Vör, lo firmo si estoy de acuerdo y te paso el approval_base64.
5. Llama a commit_write con el request_base64 exacto y mi approval_base64, y enséñame el resultado.

Nunca generes, adivines ni reutilices una aprobación. Si la aprobación se rechaza o caduca, o el dispositivo rechaza la escritura porque el archivo cambió, no busques otra forma de escribir: vuelve a leer, enséñame el diff nuevo y preparamos otra solicitud.
```

## Qué hace

Aplica un cambio pequeño y bien delimitado a un archivo existente con el flujo seguro de Vör Commander: diff revisado por el operador, escritura preparada, aprobación firmada y confirmación con protección contra cambios concurrentes.

## Límites

- Requiere aprobación firmada del operador; `prepare_edit` por sí solo nunca escribe y admite como máximo 20 bloques.
- El resultado máximo es 1 MiB. El dispositivo conserva BOM/codificación compatible y finales de línea del original.
- El hash capturado por el dispositivo durante `prepare_edit` protege contra escrituras sobre una versión que cambió: si alguien lo editó entretanto, `commit_write` falla.
- La solicitud preparada caduca a los 180 segundos y cada aprobación sirve una sola vez.
- El `request_base64` ya contiene el resultado completo y opaco; no lo decodifiques ni modifiques antes de `commit_write`.
