---
id: ejecutar-la-suite
title: Ejecutar la suite de tests
category: tests
tools_used: [read_file, prepare_terminal, commit_terminal, poll_terminal, cancel_terminal]
requires_approval: true
risk: exec
---

## Prompt

```text
Usa Vör Commander en el dispositivo <DEVICE_ID> y el workspace <WORKSPACE_ID>; pasa device_id y workspace_id en cada llamada.

Ejecuta los tests de <RUTA_DEL_PROYECTO>.

1. Averigua el comando de tests leyendo con read_file el manifiesto o la documentación (package.json, Cargo.toml, pyproject.toml, Makefile, README). Dime qué comando vas a usar y por qué.
2. Llama a prepare_terminal con cwd = <RUTA_DEL_PROYECTO>, argv como lista de argumentos separados (por ejemplo ["cargo", "test", "--locked"] o ["npm", "test"]), timeout_ms 120000 y max_output_bytes 262144. No hay shell: nada de tuberías, redirecciones ni "&&", y no envuelvas el comando en powershell -Command ni cmd /c.
3. prepare_terminal no ejecuta nada: devuelve un desafío de aprobación y un request_base64. Enséñame cwd, argv, timeout y presupuesto de salida, y espera a que firme la aprobación en el aprobador de Vör y te pase el approval_base64.
4. Llama a commit_terminal con el request_base64 exacto y mi approval_base64. Guarda el session_id.
5. Llama a poll_terminal con ese session_id hasta que la sesión termine; el resultado final se entrega una sola vez, así que consérvalo. Si algo se queda colgado y te lo pido, usa cancel_terminal.
6. Resume: código de salida, tests pasados, fallidos e ignorados, y para cada fallo el nombre del test y el mensaje esencial.

Nunca generes ni reutilices aprobaciones. Una salida vacía o sin línea de resumen no es un aprobado: si no ves el recuento de tests, dilo.
```

## Qué hace

Detecta el comando de tests del proyecto, lo ejecuta en el terminal acotado de Vör Commander tras la aprobación del operador y resume el resultado sin dar por buena una salida vacía.

## Límites

- Requiere aprobación firmada para arrancar el proceso. `poll_terminal` y `cancel_terminal` solo actúan sobre sesiones propias ya aprobadas y nunca inician un proceso nuevo.
- Tiempo máximo 120 s y salida máxima 512 KiB por ejecución: si se superan, el proceso se termina. Las suites largas hay que partirlas (ver el prompt de un test concreto).
- `argv` es estructurado y no pasa por shell. Las formas de evaluación en línea (`powershell -Command`, `cmd /c`, `python -c`, `node -e`) se clasifican aparte y exigen una aprobación de nivel elevado.
- El `cwd` debe estar dentro de una raíz permitida. El proceso no se ejecuta con privilegios elevados.
- Un dispositivo guarda como máximo 4 sesiones de terminal.
