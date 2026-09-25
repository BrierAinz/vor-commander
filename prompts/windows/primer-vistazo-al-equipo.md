---
id: primer-vistazo-al-equipo
title: Primer vistazo al equipo, sin tocar nada
category: windows
tools_used: [commander_status, process_list]
requires_approval: false
risk: read-only
---

## Prompt

```text
Usa Vör Commander. Antes de nada llama a commander_status y dime qué dispositivos conectados ves, cuál es el recommended_device_id y qué dice operator_hint. Si no hay ninguno conectado, detente y dime cómo reconectarlo según ese mensaje.

Después, en el dispositivo <DEVICE_ID> (o el recomendado si no te doy otro) y el workspace <WORKSPACE_ID>, pasando device_id y workspace_id en cada llamada:

1. Llama a process_list.
2. Resume el estado del equipo: número total de procesos, los ejecutables con más instancias, y qué familias de software se están ejecutando (navegadores, IDE, bases de datos, antivirus, herramientas de sincronización, agentes de Vör).
3. Señala lo que te parezca anómalo, por ejemplo decenas de instancias del mismo ejecutable o nombres que imitan procesos del sistema.

Solo lectura. No propongas terminar procesos; esto es solo una fotografía para decidir por dónde seguir.
```

## Qué hace

Confirma que la conexión con el equipo funciona y saca una fotografía rápida de lo que se está ejecutando, sin ningún efecto sobre el sistema. Es el punto de partida de los demás prompts de esta categoría.

## Límites

- Solo lectura.
- `commander_status` solo muestra los dispositivos que tu credencial está autorizada a ver.
- `process_list` devuelve `pid`, `parent_pid` y `executable_name`: sin CPU, memoria, usuario ni línea de comandos, así que "anómalo" se juzga por nombres y recuentos.
