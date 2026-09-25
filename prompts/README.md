# Biblioteca de prompts de Vör Commander

Prompts listos para pegar en un asistente que tenga conectado el servidor MCP de
Vör Commander. Están en español, agrupados por flujo de trabajo, y cada uno usa
solo herramientas que existen en el código de la pasarela
(`apps/vor-gateway/src/lib.rs`).

## Estructura

```
prompts/
  catalog.json        categorías y registro de herramientas reales
  index.json          generado; lo consume la web
  validate.mjs        validador y generador del índice (Node, sin dependencias)
  <categoria>/<id>.md un prompt por archivo
```

Categorías: `exploracion`, `depuracion`, `documentacion`, `revision`, `edicion`,
`tests`, `windows`, `onboarding`. Sus títulos y descripciones están en
`catalog.json`.

## Formato de un prompt

Cada archivo empieza con un front-matter de exactamente estos seis campos:

```yaml
---
id: localizar-simbolo            # kebab-case, igual al nombre del archivo
title: Dónde se define y dónde se usa un símbolo
category: exploracion            # igual al nombre de la carpeta
tools_used: [search_content, read_file]
requires_approval: false         # true si usa prepare/commit de escritura o terminal
risk: read-only                  # read-only | write | exec
---
```

El cuerpo tiene tres secciones, en este orden:

- `## Prompt`: el texto que pega el usuario, dentro de un bloque ` ```text `.
- `## Qué hace`: un párrafo; el primero se usa como resumen en la web.
- `## Límites`: lo que el prompt no puede hacer y los topes reales de las
  herramientas.

## Convenciones

- **Marcadores.** Lo que el usuario debe rellenar va en `<MAYUSCULAS_CON_GUIONES_BAJOS>`,
  por ejemplo `<RUTA_DEL_REPO>`. El índice los lista en `placeholders` para que
  la web pueda pedirlos en un formulario.
- **Alcance.** Todas las llamadas llevan `device_id` y `workspace_id`, y solo
  alcanzan las carpetas permitidas del workspace. Si no sabes tu `device_id`,
  `commander_status` devuelve los dispositivos que puedes usar y un
  `recommended_device_id`.
- **Solo lectura primero.** Los prompts de diagnóstico empiezan por
  herramientas de lectura y solo después proponen comandos.
- **Aprobaciones.** `prepare_write` y `prepare_terminal` nunca escriben ni
  ejecutan: devuelven un desafío que el operador firma en el aprobador de Vör.
  `commit_write` y `commit_terminal` solo actúan con esa aprobación firmada, de
  un solo uso y con caducidad de 180 segundos. Todo prompt que las use lo dice
  explícitamente y prohíbe al asistente generar, adivinar o reutilizar
  aprobaciones, o buscar otra vía si una se rechaza. Ningún prompt sugiere
  esquivar una aprobación.
- **Escrituras.** Se escribe el archivo completo (máximo 1 MiB) con
  `expected_target_sha256`: `absent` para archivos nuevos o el SHA-256 del
  contenido actual. Ese hash sale de `digest_base64` de un `read_file` completo
  (sin rango), decodificado a hexadecimal.
- **Terminal.** `argv` es una lista estructurada sin shell: sin tuberías,
  redirecciones ni `&&`. Las formas `powershell -Command`, `cmd /c`,
  `python -c` o `node -e` se clasifican como evaluación en línea y exigen
  aprobación elevada, así que los prompts las evitan. Máximo 120 s y 512 KiB de
  salida por ejecución; el proceso nunca se ejecuta con privilegios elevados.
- **Git.** `git_diff` ejecuta `git diff` sin argumentos: cambios del árbol de
  trabajo frente al índice. Lo ya preparado con `git add` y los archivos sin
  seguimiento no aparecen en el diff; los prompts de revisión lo advierten.
- **Procesos.** `process_list` y `process_inspect` devuelven `pid`,
  `parent_pid` y `executable_name`, nada más. No hay herramienta MCP para
  terminar procesos y ningún prompt lo sugiere.
- **Sin datos sensibles.** Ni secretos, ni tokens, ni nombres de host, ni
  direcciones IP, ni URL. El validador lo comprueba.

## Herramientas y disponibilidad

`catalog.json` registra las 16 herramientas con su riesgo, si requieren
aprobación y dónde están disponibles:

- En `main`: `commander_status`, `read_file` (sin rangos), `git_status`,
  `git_diff`, `process_list`, `process_inspect`, `prepare_write`,
  `commit_write`, `prepare_terminal`, `commit_terminal`, `poll_terminal`,
  `cancel_terminal`.
- En `pilot/read-tools` (PR #5): `list_directory`, `search_files`,
  `search_content`, `file_info`, y los rangos de `read_file`
  (`offset`/`length` o `line_start`/`line_count`).

Los prompts que dependen del PR #5 lo indican en su sección de límites, y el
índice los marca en `requires_unmerged_tools`. Cuando el PR se integre, cambia
`available_on` a `main` en `catalog.json` y regenera el índice.

## Validar y regenerar el índice

Desde la raíz del repositorio:

```
node prompts/validate.mjs            # valida y comprueba que index.json está al día
node prompts/validate.mjs --write    # valida y regenera index.json
node prompts/validate.mjs --lib <ruta/a/lib.rs>   # contrasta con otro lib.rs
```

El validador comprueba, por cada prompt:

- que el front-matter tenga exactamente los seis campos, con tipos y valores
  válidos, y que `id` y `category` coincidan con el archivo y la carpeta;
- que cada nombre de `tools_used` exista en `catalog.json`, que el texto del
  prompt nombre todas las herramientas declaradas y ninguna más, y que no
  aparezcan nombres de herramientas que Vör Commander no tiene;
- que `risk` y `requires_approval` sean coherentes con las herramientas usadas,
  que `prepare_*` vaya con su `commit_*` (y `commit_terminal` con
  `poll_terminal`), y que los prompts con aprobación lo mencionen;
- que estén las tres secciones en orden y que no haya IP, URL, nombres de host
  ni patrones de secretos.

Además extrae los `#[tool(...)]` del `lib.rs` y falla si el código tiene una
herramienta que el catálogo no conoce, o si el catálogo da por disponible en
`main` una herramienta que el código no tiene. Sale con código 1 ante cualquier
error.

## Añadir un prompt

1. Crea `prompts/<categoria>/<id>.md` con el front-matter y las tres secciones.
2. Ejecuta `node prompts/validate.mjs --write`.
3. Incluye en el commit el prompt y el `index.json` regenerado.
