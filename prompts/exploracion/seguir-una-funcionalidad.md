---
id: seguir-una-funcionalidad
title: Seguir una funcionalidad de punta a punta
category: exploracion
tools_used: [search_files, search_content, read_file]
requires_approval: false
risk: read-only
---

## Prompt

```text
Usa Vör Commander en el dispositivo <DEVICE_ID> y el workspace <WORKSPACE_ID>; pasa device_id y workspace_id en cada llamada.

Quiero entender cómo funciona "<FUNCIONALIDAD>" en <RUTA_DEL_PROYECTO>, desde la entrada (ruta HTTP, comando, evento o botón) hasta donde se guarda o se responde.

1. Localiza el punto de entrada con search_content (regex false primero; usa regex true solo si hace falta). Si no sabes dónde buscar, usa search_files con patrones como **/*route* o **/*handler*.
2. Sigue la cadena de llamadas leyendo con read_file solo los tramos necesarios (line_start y line_count). Decodifica el base64.
3. Entrégame la secuencia numerada de pasos con archivo:línea en cada uno, los datos que viajan entre pasos y los puntos donde puede fallar (validaciones, errores, llamadas externas).

Solo lectura. Si pierdes el hilo en algún paso (por ejemplo, una llamada dinámica que no puedes resolver leyendo), dilo en lugar de suponer.
```

## Qué hace

Reconstruye el recorrido de una funcionalidad a través del código y lo presenta como una secuencia de pasos verificables con referencias a archivo y línea.

## Límites

- Solo lectura; no ejecuta el código, así que el despacho dinámico, la inyección de dependencias o la reflexión pueden cortar el rastro.
- Cada búsqueda está acotada (5 s, hasta 10 000 resultados); en repositorios grandes conviene restringir `file_glob`.
- `search_files`, `search_content` y los rangos de `read_file` llegan con el PR #5.
