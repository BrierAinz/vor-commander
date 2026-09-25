---
id: localizar-simbolo
title: Dónde se define y dónde se usa un símbolo
category: exploracion
tools_used: [search_content, read_file]
requires_approval: false
risk: read-only
---

## Prompt

```text
Usa Vör Commander en el dispositivo <DEVICE_ID> y el workspace <WORKSPACE_ID>; pasa device_id y workspace_id en cada llamada.

Busca el símbolo <NOMBRE_DEL_SIMBOLO> en <RUTA_DEL_PROYECTO>.

1. Llama a search_content con regex false, query igual al símbolo y file_glob <GLOB_DE_ARCHIVOS> (por ejemplo **/*.rs). Pon max_matches 300 y usa el campo matches del objeto devuelto; revisa también sus contadores skipped_binary_files y skipped_size_limit_files.
2. Separa la definición de los usos. Si hay varias definiciones candidatas, dilo.
3. Para la definición y para los tres usos más representativos, lee el contexto con read_file usando line_start y line_count (unas 40 líneas alrededor de la coincidencia). La salida viene en base64.
4. Devuélveme: dónde se define (archivo:línea), su firma, quién lo usa agrupado por módulo, y cualquier uso que te parezca sospechoso.

Solo lectura. Si la búsqueda se corta por el límite de coincidencias o de tiempo, dilo y no presentes el resultado como completo.
```

## Qué hace

Encuentra la definición de una función, tipo o constante y la lista de sus usos, con el contexto justo para entender cada uno sin leer archivos enteros.

## Límites

- Solo lectura. `search_content` omite binarios, se detiene a los 5 segundos y trunca cada línea a 4 KiB; `max_matches` admite hasta 10 000.
- Por defecto ignora archivos de más de 1 MiB (`max_file_bytes`, máximo 8 MiB): el código generado grande puede quedar fuera.
- Es una búsqueda de texto, no un análisis semántico: encuentra también comentarios y nombres homónimos.
- `search_content` y los rangos de línea de `read_file` llegan con el PR #5.
