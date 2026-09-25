---
id: carpetas-que-mas-ocupan
title: Qué carpetas ocupan más espacio
category: windows
tools_used: [list_directory, file_info]
requires_approval: false
risk: read-only
---

## Prompt

```text
Usa Vör Commander en el dispositivo <DEVICE_ID> y el workspace <WORKSPACE_ID>; pasa device_id y workspace_id en cada llamada.

Me estoy quedando sin espacio. Averigua qué ocupa más dentro de <CARPETA_PERMITIDA>.

1. Llama a list_directory sobre esa carpeta con depth 3 y max_entries 10000. Cada entrada trae path, entry_type y size.
2. Suma los tamaños de los archivos por carpeta de primer y segundo nivel y ordénalas de mayor a menor. Si el listado llegó al tope de entradas, dilo: las sumas serán un mínimo.
3. Baja un nivel más, con otra llamada a list_directory, en las tres carpetas más grandes.
4. Para los diez archivos más grandes, usa file_info para ver sus fechas de modificación y acceso.
5. Dame: las carpetas que más ocupan, los archivos grandes que llevan meses sin tocarse, y qué tipo de contenido parece (cachés de build como target o node_modules, descargas, copias de seguridad, vídeos). Marca lo que suele poder regenerarse.

Solo lectura. No borres ni muevas nada; la decisión de limpiar es mía.
```

## Qué hace

Recorre una carpeta permitida, agrega tamaños por subcarpeta y señala los archivos grandes y antiguos, distinguiendo lo que suele poder regenerarse de lo que no.

## Límites

- Solo lectura; Vör Commander no expone herramientas para borrar.
- Solo ve carpetas permitidas del workspace, no la unidad entera. Para el espacio libre del volumen usa el prompt de espacio libre en disco.
- `list_directory` no sigue enlaces ni junctions, así que no cuenta dos veces, pero tampoco ve lo que haya detrás de ellos. Máximo 10 000 entradas por llamada.
- `list_directory` y `file_info` llegan con el PR #5.
