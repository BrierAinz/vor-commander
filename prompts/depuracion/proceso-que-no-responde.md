---
id: proceso-que-no-responde
title: ¿Está vivo mi proceso y quién lo lanzó?
category: depuracion
tools_used: [process_list, process_inspect]
requires_approval: false
risk: read-only
---

## Prompt

```text
Usa Vör Commander en el dispositivo <DEVICE_ID> y el workspace <WORKSPACE_ID>; pasa device_id y workspace_id en cada llamada.

Creo que <NOMBRE_DEL_EJECUTABLE> (por ejemplo node.exe o python.exe) se ha quedado colgado o duplicado.

1. Llama a process_list y filtra las entradas cuyo executable_name coincida, sin distinguir mayúsculas.
2. Para cada PID encontrado, sube por la cadena de padres con process_inspect (parent_pid) hasta llegar a un proceso del sistema o a uno que ya no exista.
3. Dime cuántas instancias hay, el árbol padre → hijo de cada una y si alguna parece huérfana (su padre ya no existe) o duplicada respecto a lo que cabría esperar.

Solo lectura: no intentes terminar ningún proceso ni sugieras hacerlo por otra vía. Si quiero pararlo, lo decidiré yo.
```

## Qué hace

Comprueba si un programa sigue ejecutándose, cuántas copias hay y qué proceso lanzó cada una, para distinguir un bloqueo real de instancias duplicadas o huérfanas.

## Límites

- Solo lectura. Vör Commander no expone ninguna herramienta MCP para terminar procesos.
- `process_list` y `process_inspect` devuelven solo `pid`, `parent_pid` y `executable_name`: no hay CPU, memoria, línea de comandos ni usuario. Para ver consumo usa el prompt de consumo de CPU y memoria, que requiere aprobación.
- Windows reutiliza PIDs: un `parent_pid` puede apuntar a un proceso distinto del que realmente lo lanzó.
