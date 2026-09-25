---
id: explicar-archivo
title: Explícame este archivo
category: exploracion
tools_used: [file_info, read_file]
requires_approval: false
risk: read-only
---

## Prompt

```text
Usa Vör Commander en el dispositivo <DEVICE_ID> y el workspace <WORKSPACE_ID>; pasa device_id y workspace_id en cada llamada.

Explícame el archivo <RUTA_DEL_ARCHIVO>.

1. Llama primero a file_info para conocer su tamaño.
2. Si ocupa menos de 300 KB, léelo entero con read_file. Si es mayor, léelo por tramos de 400 líneas con line_start y line_count y ve resumiendo tramo a tramo. read_file devuelve base64.
3. Explícame:
   - su responsabilidad en una frase;
   - los tipos y funciones públicos y qué hace cada uno;
   - de qué depende y quién parece depender de él (por los imports);
   - las partes difíciles o frágiles, citando número de línea.

No propongas cambios todavía, solo quiero entenderlo. No modifiques nada.
```

## Qué hace

Lee un archivo concreto, por tramos si es grande, y lo explica: propósito, API, dependencias y zonas delicadas con referencias de línea.

## Límites

- Solo lectura.
- Sin el PR #5 no hay `file_info` ni lectura por rangos: los archivos que superen el límite de salida del agente (1 MiB por defecto) no se pueden leer.
- El asistente solo ve este archivo; lo que diga de quién lo usa es una inferencia hasta que lo compruebes con una búsqueda.
