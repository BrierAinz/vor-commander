# Sitio de Vör Commander

Sitio de lanzamiento de la beta pública (modo local, código abierto). HTML, CSS y
un JavaScript mínimo, sin paso de compilación ni dependencias, más una Pages
Function para la lista de espera del acceso remoto.

```text
site/
  index.html          página principal (español)
  lista-espera.html   resultado del formulario cuando se envía sin JavaScript
  404.html            página de error
  en/                 versión en inglés: index.html, lista-espera.html, 404.html
  _headers            cabeceras de Cloudflare Pages (CSP, caché)
  robots.txt          apunta a sitemap.xml
  sitemap.xml         las dos portadas, con sus alternativas hreflang
  wrangler.toml       configuración de Pages: salida ".", binding D1 WAITLIST_DB
  functions/
    api/waitlist.js   POST /api/waitlist (Turnstile + D1)
  migrations/
    0001_waitlist.sql esquema D1 (tablas waitlist y waitlist_attempts)
  assets/
    styles.css        estilos, tokens de color claro/oscuro
    theme-init.js     aplica el tema guardado antes del primer pintado
    main.js           interruptor de tema
    waitlist.js       envío del formulario con fetch (mejora progresiva)
    lang-switch.js    conserva el #fragmento al cambiar de idioma
    favicon.svg
```

## Importante: ejecuta Wrangler con `--cwd site`

Wrangler busca `wrangler.toml` y la carpeta `functions/` en el **directorio de
trabajo**, no en la carpeta que se publica. Desde la raíz del repositorio,
`wrangler pages deploy site` publicaría los ficheros estáticos **sin** la función
y sin el binding D1. Usa siempre `--cwd site` (o ejecuta desde `site/`):

```powershell
npx wrangler pages dev    --cwd site
npx wrangler pages deploy --cwd site
```

Al publicar, Wrangler excluye `functions/`, `_headers`, `.wrangler/` y
`node_modules`, pero **sí** sube como estáticos `wrangler.toml`, `migrations/` y
este `README.md`. No contienen secretos (el id de la base D1 no lo es), pero no
pongas nunca un `.dev.vars` ni otro fichero con secretos dentro de `site/`.

## Lista de espera

`POST /api/waitlist` recibe `email` (obligatorio), `name`, `use_case` (máx. 1000
caracteres), `cf-turnstile-response` y `lang` (opcional: `es` por defecto o `en`;
cualquier otro valor cuenta como `es`).

- Verifica Turnstile en el servidor (`TURNSTILE_SECRET`, secreto de Pages) con la
  IP remota.
- Guarda en D1 (`WAITLIST_DB`, base `vor-waitlist`) una fila por correo en
  minúsculas: un duplicado actualiza la fila, no crea otra, y recibe la misma
  respuesta que un correo nuevo.
- Nunca guarda la IP en claro: guarda un HMAC-SHA256 con la clave
  `IP_HASH_SALT` si existe, o derivada de `TURNSTILE_SECRET` si no.
- Límite: más de 5 envíos por hora desde la misma IP (hash) devuelve 429.
- Responde JSON `{ ok, code, message }` sin repetir nada de lo enviado. Si el
  cliente no pide JSON (formulario enviado sin JavaScript), redirige con 303 a
  `/lista-espera#<code>`, o a `/en/lista-espera#<code>` con `lang=en`. El
  mensaje sale en el idioma de `lang`; los errores anteriores a leer el cuerpo
  (405, 413, 415) responden en español.

### Primera puesta en marcha (una vez)

```powershell
npx wrangler d1 migrations apply vor-waitlist --remote --cwd site
```

### Consultar la lista

```powershell
npx wrangler d1 execute vor-waitlist --remote --cwd site --command "SELECT email, name, use_case, created_at FROM waitlist ORDER BY created_at"
```

Para borrar a alguien que lo pida:
`DELETE FROM waitlist WHERE email = 'correo@ejemplo.com'`.

## Vista previa local

```powershell
npx wrangler d1 migrations apply vor-waitlist --local --cwd site
npx wrangler pages dev --cwd site --binding TURNSTILE_SECRET=1x0000000000000000000000000000000AA
```

`1x0000000000000000000000000000000AA` es el secreto de prueba de Turnstile que
siempre aprueba (`2x0000000000000000000000000000000AA` siempre rechaza). La site
key de producción no funciona en `localhost`: para probar el widget en local,
cambia temporalmente `data-sitekey` en `index.html` y `en/index.html` por
`1x00000000000000000000AA` y no lo subas así.

El estado local (D1 incluido) queda en `site/.wrangler/`, ignorado por git y por
el despliegue.

## Antes de publicar

- **Enlaces de descarga.** El botón «Descargar» apunta a GitHub Releases de
  `BrierAinz/vor-commander`. Mientras no haya una versión publicada, la página
  dice que el ZIP llega pronto y enlaza al README para compilar. Actualiza esos
  textos cuando salga la primera versión.
- **Contacto.** `contact@brierstudios.com` (Brier Studios) es el contacto
  secundario; las preguntas van a GitHub Discussions.
- **Datos del competidor.** La tabla comparativa cita cifras públicas de
  Desktop Commander. Revísalas contra su web antes de cada publicación.
- **Estado de las funciones.** Las etiquetas «Hoy», «En el piloto» y «Próximamente»
  reflejan `docs/CAPABILITY_MATRIX.md` y los PR abiertos. Actualízalas cuando cambien.

## Idiomas

El español vive en la raíz y el inglés en `/en/`, con los mismos `id` de sección.
Cada página enlaza a su equivalente con el selector de la cabecera
(«English» / «Español») y declara `<link rel="alternate" hreflang>` para `es`,
`en` y `x-default` (español); las 404 no, porque no tienen URL propia. No hay
redirección automática por idioma del navegador. Las páginas de `/en/` usan rutas
absolutas (`/assets/...`). Los textos que genera el JavaScript salen de atributos
`data-*` de la página (`data-msg-*` en el formulario, `data-label-to-*` en el
botón de tema), y el formulario inglés envía `lang=en`. Al cambiar un texto,
cámbialo en las dos versiones.

## Rendimiento y accesibilidad

- Sin fuentes web ni imágenes de mapa de bits: no hay desplazamiento de diseño por
  carga de recursos.
- El tema sigue `prefers-color-scheme`; el botón lo fija y lo recuerda en
  `localStorage` (si el almacenamiento falla, el sitio sigue funcionando).
- Diseño adaptable desde 360 px, sin desplazamiento horizontal de página (la tabla
  comparativa se desplaza dentro de su propio contenedor). A 360 px la tarjeta del
  formulario deja 302 px al widget de Turnstile, que necesita 300.
- Enlace para saltar al contenido, foco visible, FAQ con `<details>` nativo, y
  respeto de `prefers-reduced-motion`.
- La CSP de `_headers` solo permite scripts y estilos del propio sitio, más
  `https://challenges.cloudflare.com` para el script y el iframe de Turnstile: no
  añadas `<script>` ni atributos `style` en línea.
