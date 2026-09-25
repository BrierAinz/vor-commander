---
id: analizar-log
title: Leer el final de un log y encontrar el primer error
category: depuracion
tools_used: [file_info, read_file, search_content]
requires_approval: false
risk: read-only
---

## Prompt

```text
Usa Vör Commander en el dispositivo <DEVICE_ID> y el workspace <WORKSPACE_ID>; pasa device_id y workspace_id en cada llamada.

Analiza el log <RUTA_DEL_LOG>.

1. Llama a file_info para saber su tamaño y su fecha de modificación.
2. Lee los últimos 200 KB con read_file usando offset = tamaño − 204800 (o 0 si es menor) y length 204800. Decodifica el base64; la primera línea puede salir cortada.
3. Busca en ese tramo errores, excepciones, timeouts y reinicios. Si necesitas ver cuándo empezó el problema, usa search_content con regex true, query <PATRON_DE_ERROR> (por ejemplo "ERROR|panic|Exception") y file_glob con el nombre del log, y lee con line_start y line_count el contexto de la primera aparición.
4. Devuélveme: el primer error relevante con su marca de tiempo, la secuencia de eventos que lleva a él, cuántas veces se repite y una hipótesis de causa con la evidencia que la apoya.

Solo lectura. Si el log contiene lo que parezcan contraseñas, tokens o datos personales, no los copies en tu respuesta: descríbelos.
```

## Qué hace

Localiza el final de un log sin leerlo entero, encuentra el primer error significativo y reconstruye qué pasó antes, con una hipótesis de causa respaldada por líneas concretas.

## Límites

- Solo lectura.
- Cada lectura por rango está limitada por el límite de salida del agente (1 MiB por defecto); los logs enormes se exploran a trozos.
- `search_content` omite archivos de más de 8 MiB aunque subas `max_file_bytes`: para logs mayores solo queda leer por rangos de bytes.
- `file_info`, `search_content` y los rangos de `read_file` llegan con el PR #5.
