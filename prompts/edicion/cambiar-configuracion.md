---
id: cambiar-configuracion
title: Cambiar un valor de configuración
category: edicion
tools_used: [read_file, prepare_write, commit_write]
requires_approval: true
risk: write
---

## Prompt

```text
Usa Vör Commander en el dispositivo <DEVICE_ID> y el workspace <WORKSPACE_ID>; pasa device_id y workspace_id en cada llamada.

En el archivo de configuración <RUTA_DEL_ARCHIVO_DE_CONFIGURACION>, cambia <CLAVE> de su valor actual a <VALOR_NUEVO>.

1. Lee el archivo entero con read_file. Decodifica data y guarda el SHA-256 en hexadecimal que sale de decodificar digest_base64 como expected_target_sha256.
2. Dime el valor actual de la clave, en qué línea está y si aparece más de una vez (secciones, perfiles, entornos). Si hay ambigüedad, pregúntame antes de seguir.
3. Enséñame el antes y el después de esa línea. No reordenes claves, no cambies comentarios, indentación ni finales de línea, y comprueba que el resultado sigue siendo sintácticamente válido para su formato (JSON, TOML, YAML, INI).
4. Con mi visto bueno, llama a prepare_write con el archivo completo en base64 y el expected_target_sha256. Devuelve un desafío de aprobación: muéstrame el content_sha256 y espera a que firme en el aprobador de Vör y te pase el approval_base64.
5. Llama a commit_write con el request_base64 exacto y mi approval_base64.

Nunca generes ni reutilices aprobaciones. Si el archivo contiene secretos, no los repitas en la conversación. Recuérdame al final si el cambio necesita reiniciar algún servicio para aplicarse; no lo reinicies tú.
```

## Qué hace

Cambia una sola clave de un archivo de configuración respetando el formato original y confirmando la sintaxis, con el flujo de escritura aprobada.

## Límites

- Requiere aprobación firmada del operador.
- El archivo completo se reescribe (máximo 1 MiB); si otro proceso lo modifica entre la lectura y la confirmación, el dispositivo rechaza la escritura.
- La validación de sintaxis la hace el modelo leyendo, no un parser: en formatos complejos conviene ejecutar después el validador del propio programa.
- Aplicar el cambio (reiniciar el servicio) queda fuera de este prompt.
