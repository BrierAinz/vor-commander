---
id: errores-recientes-del-sistema
title: Errores recientes en el registro de eventos
category: windows
tools_used: [prepare_terminal, commit_terminal, poll_terminal, cancel_terminal]
requires_approval: true
risk: exec
---

## Prompt

```text
Usa Vör Commander en el dispositivo <DEVICE_ID> y el workspace <WORKSPACE_ID>; pasa device_id y workspace_id en cada llamada.

Quiero ver los errores recientes del registro de eventos <REGISTRO> (System o Application).

1. Prepara con prepare_terminal la consulta argv ["wevtutil", "qe", "<REGISTRO>", "/c:40", "/rd:true", "/f:text", "/q:*[System[(Level=1 or Level=2)]]"], con cwd = <CARPETA_PERMITIDA>, timeout_ms 30000 y max_output_bytes 262144. Pide los 40 eventos críticos y de error más recientes.
2. Devuelve un desafío de aprobación: enséñame el argv y espera a que firme en el aprobador de Vör y te pase el approval_base64.
3. Llama a commit_terminal con el request_base64 exacto y mi approval_base64, y a poll_terminal hasta que termine. Si tarda más de lo esperado y te lo pido, usa cancel_terminal.
4. Agrupa los eventos por origen (Provider) e Id, con recuento, primera y última aparición. Explica los tres grupos más relevantes: qué significan y qué revisaría a continuación.

Nunca generes ni reutilices aprobaciones. No prepares comandos que borren o exporten registros.
```

## Qué hace

Obtiene los eventos críticos y de error más recientes de un registro de Windows con una consulta aprobada y los agrupa por origen para encontrar patrones.

## Límites

- Requiere aprobación firmada.
- El registro Security y algunos canales exigen privilegios de administrador; el terminal nunca los concede y la consulta fallará.
- La salida está limitada a 512 KiB: con mensajes largos conviene bajar `/c:` en lugar de subir el presupuesto.
- Los mensajes de algunos proveedores dependen de DLL de recursos; si faltan, `wevtutil` muestra el evento sin texto descriptivo.
