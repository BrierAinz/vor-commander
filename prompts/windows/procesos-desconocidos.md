---
id: procesos-desconocidos
title: Procesos desconocidos o sospechosos
category: windows
tools_used: [process_list, process_inspect]
requires_approval: false
risk: read-only
---

## Prompt

```text
Usa Vör Commander en el dispositivo <DEVICE_ID> y el workspace <WORKSPACE_ID>; pasa device_id y workspace_id en cada llamada.

Quiero saber si hay procesos que no deberían estar en este equipo.

1. Llama a process_list.
2. Clasifica cada executable_name en: componente de Windows, software conocido, o desconocido para ti.
3. Para los desconocidos y para los que imitan nombres del sistema (por ejemplo svch0st.exe, scvhost.exe, lsass con mayúsculas raras, o un explorer.exe hijo de algo que no sea userinit o el propio explorer), usa process_inspect con su pid y el de su padre para reconstruir quién los lanzó.
4. Dame una tabla: pid, nombre, padre, por qué te llama la atención y qué comprobaría yo a continuación (por ejemplo, ver la ruta del ejecutable o su firma con otra herramienta).

Solo lectura. No afirmes que algo es malware: indica el grado de sospecha y la razón. No propongas terminar procesos desde aquí.
```

## Qué hace

Repasa la lista de procesos buscando nombres desconocidos, imitaciones de procesos del sistema y cadenas padre-hijo inusuales, y propone qué comprobar de cada uno.

## Límites

- Solo lectura; no es un antivirus.
- Sin ruta del ejecutable, firma digital ni línea de comandos (no las devuelve `process_inspect`), la sospecha se basa solo en nombres y parentesco.
- Los PIDs se reutilizan: un padre ya terminado puede aparecer como otro proceso distinto.
