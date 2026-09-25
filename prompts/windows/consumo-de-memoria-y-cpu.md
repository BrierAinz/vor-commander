---
id: consumo-de-memoria-y-cpu
title: Qué está consumiendo memoria y CPU
category: windows
tools_used: [process_list, prepare_terminal, commit_terminal, poll_terminal]
requires_approval: true
risk: exec
---

## Prompt

```text
Usa Vör Commander en el dispositivo <DEVICE_ID> y el workspace <WORKSPACE_ID>; pasa device_id y workspace_id en cada llamada.

El equipo va lento. Averigua qué consume memoria y CPU.

1. Empieza en solo lectura: llama a process_list y dime cuántos procesos hay y cuáles tienen más instancias. process_list no da consumo, así que para eso necesitamos comandos de Windows.
2. Prepara dos comandos de solo consulta con prepare_terminal, con cwd = <CARPETA_PERMITIDA>, timeout_ms 30000 y max_output_bytes 262144:
   - memoria por proceso: argv ["tasklist", "/fo", "csv", "/nh"]
   - CPU total durante 5 segundos: argv ["typeperf", "\Processor(_Total)\% Processor Time", "-sc", "5"]
   Cada uno devuelve un desafío de aprobación. Enséñame los argv y espera a que firme cada aprobación en el aprobador de Vör y te pase su approval_base64.
3. Ejecuta cada uno con commit_terminal (request_base64 exacto y su approval_base64) y recoge el resultado con poll_terminal.
4. Suma la memoria por nombre de ejecutable, dame los diez que más consumen y la media de CPU. Relaciónalo con lo que viste en process_list y dime qué parece estar causando la lentitud.

Nunca generes ni reutilices aprobaciones. No propongas terminar procesos desde aquí; si hay que cerrar algo, lo decidiré yo.
```

## Qué hace

Combina la lista de procesos de solo lectura con dos comandos de consulta de Windows, aprobados por el operador, para identificar qué programas consumen más memoria y cuánta CPU se está usando.

## Límites

- Los dos comandos requieren aprobación firmada; `process_list` no.
- `tasklist` muestra memoria (working set) pero no CPU por proceso; `typeperf` da la CPU total, no el reparto. Un reparto de CPU por proceso exigiría `powershell -Command`, que se clasifica como evaluación en línea y requiere aprobación elevada; este prompt lo evita.
- El `cwd` debe ser una carpeta permitida del workspace aunque el comando no use archivos.
- Sin privilegios elevados, `tasklist` puede no ver todos los detalles de procesos de otros usuarios o del sistema.
