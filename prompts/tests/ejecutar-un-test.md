---
id: ejecutar-un-test
title: Ejecutar solo el test que falla
category: tests
tools_used: [search_content, prepare_terminal, commit_terminal, poll_terminal]
requires_approval: true
risk: exec
---

## Prompt

```text
Usa Vör Commander en el dispositivo <DEVICE_ID> y el workspace <WORKSPACE_ID>; pasa device_id y workspace_id en cada llamada.

Quiero ejecutar solo el test <NOMBRE_DEL_TEST> de <RUTA_DEL_PROYECTO>.

1. Localiza el test con search_content (regex false) para saber en qué archivo, módulo o paquete está.
2. Construye el argv más estrecho que ejecute solo ese test con el runner del proyecto (por ejemplo ["cargo", "test", "-p", "mi_paquete", "modulo::nombre_del_test", "--", "--exact"], ["npx", "vitest", "run", "ruta", "-t", "nombre"] o ["pytest", "ruta::nombre", "-q"]).
3. Llama a prepare_terminal con cwd = <RUTA_DEL_PROYECTO>, ese argv, timeout_ms 60000 y max_output_bytes 131072. Devuelve un desafío de aprobación: enséñame el argv exacto y espera a que firme en el aprobador de Vör y te pase el approval_base64.
4. Llama a commit_terminal con el request_base64 exacto y mi approval_base64, y después a poll_terminal con el session_id hasta que termine.
5. Dime si pasó o falló. Si falló, cita la aserción, el valor esperado y el obtenido, y la línea del test.

Nunca generes ni reutilices aprobaciones. Si el runner dice que ejecutó 0 tests, el filtro no ha funcionado: dilo, no lo cuentes como aprobado.
```

## Qué hace

Ejecuta un único test en lugar de toda la suite, con un argv mínimo que el operador aprueba, y devuelve el detalle del fallo si lo hay.

## Límites

- Requiere aprobación firmada para ejecutar.
- Tiempo máximo 120 s y salida máxima 512 KiB; sin shell, así que no se pueden encadenar comandos ni filtrar la salida con tuberías.
- Si el filtro del runner no coincide con ningún test, muchos runners terminan con código 0: por eso el prompt exige comprobar el recuento.
- `search_content` llega con el PR #5.
