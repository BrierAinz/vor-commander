const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "../..");
const read = (relativePath) => fs.readFileSync(path.join(root, relativePath), "utf8");

test("hallazgo 4: README ofrece instalación rápida del paquete publicado", () => {
  const readme = read("README.md");
  assert.match(readme, /^## Quick Start \/ Instalación rápida$/m);
  assert.match(readme, /vor-pilot\.zip/);
  assert.match(readme, /docs\/PILOT_INSTALLER_README\.md/);
  assert.match(readme, /Windows 10\/11/);
});

test("hallazgo 7: las portadas enlazan el ZIP publicado sin mensajes obsoletos", () => {
  for (const page of ["site/index.html", "site/en/index.html"]) {
    const html = read(page);
    assert.doesNotMatch(html, /ZIP (?:de la primera versión llega pronto|release is coming soon)/);
    assert.match(html, /releases\/download\/v0\.1\.0-beta\.2\/VorCommanderPilot-0\.1\.0-beta\.2-win-x64\.zip/);
  }
});

test("hallazgo 8: las rutas y fragmentos ingleses están localizados", () => {
  const english = read("site/en/index.html");
  for (const fragment of ["how-it-works", "security", "comparison", "installation", "waitlist"]) {
    assert.match(english, new RegExp(`id="${fragment}"`));
    assert.match(english, new RegExp(`href="#${fragment}"`));
  }
  assert.doesNotMatch(english, /#(?:como-funciona|seguridad|comparativa|instalacion|lista-espera)/);
  assert.ok(fs.existsSync(path.join(root, "site/en/waitlist.html")));
  assert.ok(!fs.existsSync(path.join(root, "site/en/lista-espera.html")));
  assert.match(read("site/functions/api/waitlist.js"), /resultPath: "\/en\/waitlist"/);
});

test("hallazgo 9: los errores del formulario anuncian campo y estado", () => {
  for (const page of ["site/index.html", "site/en/index.html"]) {
    const html = read(page);
    assert.match(html, /id="wl-email"[^>]*aria-describedby="waitlist-status"/);
    assert.match(html, /id="waitlist-status"[^>]*tabindex="-1"/);
  }
  const script = read("site/assets/waitlist.js");
  assert.match(script, /email\.setAttribute\("aria-invalid", "true"\)/);
  assert.match(script, /status\.focus\(\)/);
});

test("hallazgo 10: el conmutador usa nombre estable con aria-pressed", () => {
  const labels = { "site/index.html": "Tema visual", "site/en/index.html": "Visual theme" };
  for (const [page, label] of Object.entries(labels)) {
    const html = read(page);
    assert.match(html, new RegExp(`id="theme-toggle"[^>]*aria-label="${label}"[^>]*aria-pressed="false"`));
    assert.doesNotMatch(html, /data-label-to-(?:light|dark)/);
  }
  assert.doesNotMatch(read("site/assets/main.js"), /setAttribute\("aria-label"/);
});

test("hallazgo 13: la comparativa destaca integridad y no el recuento de prompts", () => {
  for (const page of ["site/index.html", "site/en/index.html"]) {
    const html = read(page);
    assert.doesNotMatch(html, /(?:Prompts incluidos|Included prompts|42, (?:en español|in Spanish))/);
    assert.match(html, /(?:Integridad de la auditoría|Audit integrity)/);
    assert.match(html, /(?:Cadena de hashes|Hash chain)/);
  }
});

test("hallazgo 14: el destino del enlace de salto puede recibir foco", () => {
  for (const page of ["site/index.html", "site/en/index.html"]) {
    assert.match(read(page), /<main id="main" tabindex="-1">/);
  }
});

test("hallazgo 15: Turnstile bloqueado termina con ayuda y contacto directo", () => {
  const script = read("site/assets/waitlist.js");
  assert.match(script, /setTimeout\([^]*TURNSTILE_LOAD_TIMEOUT_MS/);
  assert.match(script, /window\.turnstile/);
  assert.match(script, /mailto:contact@brierstudios\.com/);
  for (const page of ["site/index.html", "site/en/index.html"]) {
    assert.match(read(page), /data-msg-turnstile-unavailable=/);
  }
});
