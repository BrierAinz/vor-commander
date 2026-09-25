# Sitio del piloto de Vör Commander

Sitio estático de lanzamiento del piloto privado. HTML, CSS y un JavaScript mínimo
(solo el interruptor de tema). No hay paso de compilación, dependencias, backend ni
secretos: lo que hay en esta carpeta es exactamente lo que se publica.

```text
site/
  index.html          página principal (español)
  404.html            página de error
  _headers            cabeceras de Cloudflare Pages (CSP, caché)
  robots.txt
  assets/
    styles.css        estilos, tokens de color claro/oscuro
    theme-init.js     aplica el tema guardado antes del primer pintado
    main.js           interruptor de tema
    favicon.svg
```

## Vista previa local

Cualquier servidor estático sirve. Desde la raíz del repositorio:

```powershell
# Con Python
python -m http.server 8080 --directory site

# O con Node
npx --yes serve site -l 8080
```

Abre `http://localhost:8080`. También puedes abrir `site/index.html` directamente en
el navegador; en ese caso `404.html` y las cabeceras de `_headers` no se aplican.

Para simular Cloudflare Pages en local, incluidas las cabeceras:

```powershell
npx --yes wrangler pages dev site
```

## Despliegue en Cloudflare Pages

No hace falta ninguna variable de entorno ni secreto.

### Opción A: conectado al repositorio (recomendada)

1. En el panel de Cloudflare: **Workers & Pages** > **Create** > **Pages** >
   **Connect to Git** y elige `BrierAinz/vor-commander`.
2. Configuración de compilación:
   - Framework preset: **None**
   - Build command: *(vacío)*
   - Build output directory: `site`
   - Root directory: *(vacío, la raíz del repo)*
3. Rama de producción: `main`. Las demás ramas generan despliegues de vista previa.
4. Opcional: en **Custom domains** añade el dominio del sitio.

### Opción B: subida directa con Wrangler

```powershell
npx --yes wrangler pages deploy site --project-name vor-commander-site
```

La primera vez, Wrangler pide iniciar sesión en Cloudflare en el navegador.

## Antes de publicar

- **Contacto.** El botón de la sección «Precio» abre un correo a
  `contact@brierstudios.com` (Brier Studios), confirmado por el propietario el 2026-09-25.
  Si cambia, está en un único sitio de `index.html`.
- **Datos del competidor.** La tabla comparativa cita cifras públicas de
  Desktop Commander. Revísalas contra su web antes de cada publicación.
- **Estado de las funciones.** Las etiquetas «Hoy», «En el piloto» y «Próximamente»
  reflejan `docs/CAPABILITY_MATRIX.md` y los PR del piloto. Actualízalas cuando cambien.

## Rendimiento y accesibilidad

- Sin fuentes web ni imágenes de mapa de bits: no hay desplazamiento de diseño por
  carga de recursos.
- El tema sigue `prefers-color-scheme`; el botón lo fija y lo recuerda en
  `localStorage` (si el almacenamiento falla, el sitio sigue funcionando).
- Diseño adaptable desde 360 px, sin desplazamiento horizontal de página (la tabla
  comparativa se desplaza dentro de su propio contenedor).
- Enlace para saltar al contenido, foco visible, FAQ con `<details>` nativo, y
  respeto de `prefers-reduced-motion`.
- La CSP de `_headers` solo permite scripts y estilos del propio sitio: no añadas
  `<script>` ni atributos `style` en línea.
