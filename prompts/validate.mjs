#!/usr/bin/env node
// Validador de la biblioteca de prompts de Vör Commander.
// Sin dependencias: solo Node >= 18.
//
// Uso:
//   node prompts/validate.mjs                 comprueba todo y que index.json esté al día
//   node prompts/validate.mjs --write         comprueba todo y regenera index.json
//   node prompts/validate.mjs --lib <ruta>    contrasta el catálogo con otro lib.rs
//                                             (por defecto apps/vor-gateway/src/lib.rs)
//
// Sale con código 1 si hay algún error. Los avisos no cambian el código de salida.

import { readFileSync, writeFileSync, readdirSync, existsSync, statSync } from "node:fs";
import { join, dirname, relative, basename, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const PROMPTS_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(PROMPTS_DIR, "..");
const CATALOG_PATH = join(PROMPTS_DIR, "catalog.json");
const INDEX_PATH = join(PROMPTS_DIR, "index.json");

const REQUIRED_FIELDS = ["id", "title", "category", "tools_used", "requires_approval", "risk"];
const RISKS = ["read-only", "write", "exec"];
const RISK_ORDER = { "read-only": 0, write: 1, exec: 2 };
const SECTIONS = ["## Prompt", "## Qué hace", "## Límites"];
const ID_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

const args = process.argv.slice(2);
const writeMode = args.includes("--write");
const libIndex = args.indexOf("--lib");
const libPath = libIndex >= 0 ? resolve(args[libIndex + 1] ?? "") : join(REPO_ROOT, "apps", "vor-gateway", "src", "lib.rs");

const errors = [];
const warnings = [];
const err = (file, msg) => errors.push(`${file}: ${msg}`);
const warn = (file, msg) => warnings.push(`${file}: ${msg}`);

const readText = (path) => readFileSync(path, "utf8").replace(/^﻿/, "").replace(/\r\n/g, "\n");

// ---------------------------------------------------------------- catálogo
const catalog = JSON.parse(readText(CATALOG_PATH));
const tools = new Map(catalog.tools.map((t) => [t.name, t]));
const categories = new Map(catalog.categories.map((c) => [c.id, c]));
const forbidden = new Set(catalog.forbidden_tool_names);

// ---------------------------------------------------- contraste con lib.rs
// Extrae los nombres reales de las herramientas MCP de los bloques #[tool(...)].
// Si el bloque no declara name = "...", rmcp usa el nombre de la función.
function toolsFromLibRs(source) {
  const names = [];
  const re = /#\[tool\(([\s\S]*?)\)\]\s*(?:pub\s+)?async\s+fn\s+([a-z0-9_]+)/g;
  let m;
  while ((m = re.exec(source)) !== null) {
    const explicit = /\bname\s*=\s*"([^"]+)"/.exec(m[1]);
    names.push(explicit ? explicit[1] : m[2]);
  }
  return names;
}

const libReport = { path: null, found: [], pending: [] };
if (existsSync(libPath)) {
  const libTools = toolsFromLibRs(readText(libPath));
  const rel = relative(REPO_ROOT, libPath);
  libReport.path = (rel && !rel.startsWith("..") ? rel : libPath).replace(/\\/g, "/");
  libReport.found = libTools;
  const where = libReport.path;
  if (libTools.length === 0) err(where, "no se encontró ningún #[tool(...)]; el extractor o la ruta no son válidos");
  for (const name of libTools) {
    if (!tools.has(name)) err(where, `la herramienta '${name}' existe en el código pero no está en catalog.json`);
  }
  for (const t of catalog.tools) {
    if (libTools.includes(t.name)) continue;
    if (t.available_on === "main") {
      err(where, `catalog.json declara '${t.name}' disponible en main, pero no aparece en este lib.rs`);
    } else {
      libReport.pending.push(t.name);
    }
  }
} else {
  warn("catalog.json", `no se encontró ${libPath}; no se contrastan las herramientas con el código`);
}

// ------------------------------------------------------------- front-matter
function parseScalar(raw) {
  const v = raw.trim();
  if (v === "true") return true;
  if (v === "false") return false;
  if (/^\[.*\]$/.test(v)) {
    const inner = v.slice(1, -1).trim();
    return inner === "" ? [] : inner.split(",").map((s) => parseScalar(s));
  }
  if (/^".*"$/.test(v) || /^'.*'$/.test(v)) return v.slice(1, -1);
  return v;
}

function parseFrontMatter(text, file) {
  if (!text.startsWith("---\n")) {
    err(file, "falta el bloque front-matter inicial '---'");
    return null;
  }
  const end = text.indexOf("\n---\n", 4);
  if (end < 0) {
    err(file, "el front-matter no se cierra con '---'");
    return null;
  }
  const data = {};
  for (const [i, line] of text.slice(4, end).split("\n").entries()) {
    if (line.trim() === "") continue;
    const m = /^([a-z_]+):\s*(.*)$/.exec(line);
    if (!m) {
      err(file, `línea ${i + 2} del front-matter no es 'clave: valor'`);
      continue;
    }
    if (m[1] in data) err(file, `clave duplicada '${m[1]}'`);
    data[m[1]] = parseScalar(m[2]);
  }
  return { data, body: text.slice(end + 5) };
}

// ------------------------------------------------------------------ cuerpo
function sectionText(body, heading) {
  const start = body.indexOf(`\n${heading}\n`);
  if (start < 0) return null;
  const from = start + heading.length + 2;
  const next = body.indexOf("\n## ", from);
  return body.slice(from, next < 0 ? undefined : next).trim();
}

function promptBlock(section) {
  const m = /```text\n([\s\S]*?)\n```/.exec(section ?? "");
  return m ? m[1] : null;
}

function firstParagraph(section) {
  return (section ?? "").split(/\n\s*\n/)[0].replace(/\s+/g, " ").trim();
}

const SECRET_PATTERNS = [
  [/\b(?:\d{1,3}\.){3}\d{1,3}\b/, "dirección IPv4"],
  [/\b[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){7}\b/i, "dirección IPv6"],
  [/https?:\/\//i, "URL (los prompts no llevan hosts)"],
  [/\blocalhost\b/i, "nombre de host"],
  [/\b(?:ghp|gho|ghs|github_pat)_[A-Za-z0-9_]{10,}/, "token de GitHub"],
  [/\bsk-[A-Za-z0-9]{16,}/, "clave de API"],
  [/\bAKIA[0-9A-Z]{16}\b/, "clave de AWS"],
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----/, "clave privada"],
  [/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/, "JWT"],
];

// ---------------------------------------------------------------- recorrido
const promptFiles = [];
for (const entry of readdirSync(PROMPTS_DIR).sort()) {
  const dir = join(PROMPTS_DIR, entry);
  if (!statSync(dir).isDirectory()) continue;
  if (!categories.has(entry)) {
    err(entry, "directorio que no corresponde a ninguna categoría de catalog.json");
    continue;
  }
  for (const f of readdirSync(dir).sort()) {
    if (f.endsWith(".md")) promptFiles.push(join(dir, f));
  }
}

const seenIds = new Map();
const seenTitles = new Map();
const entries = [];

for (const path of promptFiles) {
  const file = relative(PROMPTS_DIR, path).replace(/\\/g, "/");
  const parsed = parseFrontMatter(readText(path), file);
  if (!parsed) continue;
  const { data, body } = parsed;

  for (const k of REQUIRED_FIELDS) if (!(k in data)) err(file, `falta el campo obligatorio '${k}'`);
  for (const k of Object.keys(data)) if (!REQUIRED_FIELDS.includes(k)) err(file, `campo desconocido '${k}'`);
  if (REQUIRED_FIELDS.some((k) => !(k in data))) continue;

  const { id, title, category, tools_used: used, requires_approval: approval, risk } = data;

  if (typeof id !== "string" || !ID_PATTERN.test(id)) err(file, `id '${id}' no es kebab-case`);
  if (basename(path) !== `${id}.md`) err(file, `el nombre del archivo debe ser '${id}.md'`);
  if (seenIds.has(id)) err(file, `id duplicado; ya lo usa ${seenIds.get(id)}`);
  seenIds.set(id, file);

  if (typeof title !== "string" || title.length < 4) err(file, "title vacío o demasiado corto");
  if (seenTitles.has(title)) err(file, `title duplicado; ya lo usa ${seenTitles.get(title)}`);
  seenTitles.set(title, file);

  if (!categories.has(category)) err(file, `category '${category}' no existe en catalog.json`);
  if (basename(dirname(path)) !== category) err(file, `está en '${basename(dirname(path))}/' pero su category es '${category}'`);

  if (typeof approval !== "boolean") err(file, "requires_approval debe ser true o false");
  if (!RISKS.includes(risk)) err(file, `risk '${risk}' no es uno de ${RISKS.join(" | ")}`);

  if (!Array.isArray(used) || used.length === 0) {
    err(file, "tools_used debe ser una lista no vacía");
    continue;
  }
  const unknown = used.filter((t) => !tools.has(t));
  for (const t of unknown) err(file, `tools_used nombra '${t}', que no es una herramienta real de Vör Commander`);
  if (new Set(used).size !== used.length) err(file, "tools_used tiene nombres repetidos");
  const known = used.filter((t) => tools.has(t));

  // Coherencia entre herramientas, riesgo y aprobación.
  const needsApproval = known.some((t) => tools.get(t).requires_approval);
  if (approval !== needsApproval) {
    err(file, `requires_approval es ${approval} pero sus herramientas implican ${needsApproval}`);
  }
  const maxRisk = known.reduce((acc, t) => (RISK_ORDER[tools.get(t).risk] > RISK_ORDER[acc] ? tools.get(t).risk : acc), "read-only");
  if (RISKS.includes(risk) && risk !== maxRisk) err(file, `risk es '${risk}' pero sus herramientas implican '${maxRisk}'`);

  const pairs = [
    ["prepare_write", "commit_write"],
    ["prepare_edit", "commit_write"],
    ["prepare_terminal", "commit_terminal"],
    ["commit_terminal", "prepare_terminal"],
    ["commit_terminal", "poll_terminal"],
  ];
  for (const [a, b] of pairs) if (used.includes(a) && !used.includes(b)) err(file, `usa '${a}' sin '${b}'`);
  if (used.includes("commit_write") && !used.includes("prepare_write") && !used.includes("prepare_edit")) {
    err(file, "usa 'commit_write' sin 'prepare_write' ni 'prepare_edit'");
  }

  // Cuerpo.
  let last = -1;
  for (const s of SECTIONS) {
    const at = body.indexOf(`\n${s}\n`);
    if (at < 0) err(file, `falta la sección '${s}'`);
    else if (at < last) err(file, `la sección '${s}' está fuera de orden`);
    last = Math.max(last, at);
  }
  const promptSection = sectionText(body, "## Prompt");
  const promptText = promptBlock(promptSection);
  if (promptSection !== null && promptText === null) err(file, "la sección Prompt debe contener un bloque ```text");
  const whatSection = sectionText(body, "## Qué hace");
  const limitsSection = sectionText(body, "## Límites");
  if (whatSection !== null && whatSection.length < 40) err(file, "la sección 'Qué hace' está casi vacía");
  if (limitsSection !== null && limitsSection.length < 40) err(file, "la sección 'Límites' está casi vacía");

  if (promptText) {
    for (const t of known) {
      if (!new RegExp(`\\b${t}\\b`).test(promptText)) err(file, `tools_used declara '${t}' pero el prompt no lo nombra`);
    }
    if (!/device_id/.test(promptText) || !/workspace_id/.test(promptText)) {
      err(file, "el prompt debe indicar device_id y workspace_id");
    }
    if (approval && !/aprob/i.test(promptText)) err(file, "usa herramientas con aprobación y el prompt no lo dice");
  }
  for (const t of tools.keys()) {
    if (!known.includes(t) && new RegExp(`\\b${t}\\b`).test(promptText ?? "")) {
      err(file, `el prompt nombra '${t}' pero no está en tools_used`);
    }
  }
  for (const t of forbidden) {
    if (new RegExp(`\\b${t}\\b`).test(body)) err(file, `menciona '${t}', que no es una herramienta de Vör Commander`);
  }
  for (const [re, what] of SECRET_PATTERNS) {
    if (re.test(body)) err(file, `posible fuga de datos: ${what}`);
  }

  const pendingTools = known.filter((t) => tools.get(t).available_on !== "main");
  const placeholders = [...new Set([...(promptText ?? "").matchAll(/<([A-Z0-9_]+)>/g)].map((m) => m[1]))];

  entries.push({
    id,
    title,
    category,
    tools_used: used,
    requires_approval: approval,
    risk,
    path: file,
    summary: firstParagraph(whatSection),
    placeholders,
    requires_unmerged_tools: pendingTools,
    prompt: promptText ?? "",
  });
}

// ------------------------------------------------------------------- índice
const categoryOrder = catalog.categories.map((c) => c.id);
entries.sort((a, b) => categoryOrder.indexOf(a.category) - categoryOrder.indexOf(b.category) || a.id.localeCompare(b.id));

const index = {
  version: catalog.version,
  generated_by: "prompts/validate.mjs --write",
  categories: catalog.categories.map((c) => ({ ...c, count: entries.filter((e) => e.category === c.id).length })),
  tools: catalog.tools.map(({ name, risk, requires_approval, available_on, summary }) => ({
    name,
    risk,
    requires_approval,
    available_on,
    summary,
  })),
  prompts: entries,
};
const rendered = JSON.stringify(index, null, 2) + "\n";

if (errors.length === 0) {
  if (writeMode) {
    writeFileSync(INDEX_PATH, rendered, "utf8");
  } else if (!existsSync(INDEX_PATH)) {
    err("index.json", "no existe; ejecuta con --write");
  } else if (readText(INDEX_PATH) !== rendered) {
    err("index.json", "no coincide con el front-matter; ejecuta con --write");
  }
}

// ------------------------------------------------------------------ informe
const byRisk = RISKS.map((r) => `${r}=${entries.filter((e) => e.risk === r).length}`).join(" ");
console.log(`Vör Commander prompt library validator`);
console.log(`prompts: ${entries.length} en ${promptFiles.length} archivos`);
for (const c of index.categories) console.log(`  ${c.id.padEnd(14)} ${String(c.count).padStart(2)}  ${c.title}`);
console.log(`riesgo: ${byRisk}; con aprobación: ${entries.filter((e) => e.requires_approval).length}`);
if (libReport.path) {
  console.log(`herramientas en ${libReport.path}: ${libReport.found.length} (${libReport.found.join(", ")})`);
  if (libReport.pending.length) {
    console.log(`en catálogo pero aún no en ese lib.rs (pendientes de merge): ${libReport.pending.join(", ")}`);
    const affected = entries.filter((e) => e.tools_used.some((t) => libReport.pending.includes(t))).length;
    console.log(`prompts que dependen de herramientas pendientes: ${affected}`);
  }
}
console.log(`index.json: ${errors.length ? "no generado" : writeMode ? "regenerado" : "al día"}`);
for (const w of warnings) console.log(`AVISO  ${w}`);
for (const e of errors) console.log(`ERROR  ${e}`);
console.log(errors.length ? `RESULTADO: FALLA (${errors.length} errores)` : "RESULTADO: OK (0 errores)");
process.exit(errors.length ? 1 : 0);
