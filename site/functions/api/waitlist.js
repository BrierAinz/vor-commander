// POST /api/waitlist: lista de espera del acceso remoto (Cloudflare Pages Functions).
//
// Entradas: email (obligatorio), name, use_case (máx. 1000 caracteres),
// cf-turnstile-response (obligatorio) y lang (opcional: "es" por defecto o "en";
// cualquier otro valor se ignora y cuenta como "es"). Acepta JSON, x-www-form-urlencoded y
// multipart/form-data.
//
// Respuesta: JSON { ok, code, message }. Nunca devuelve lo que envió el usuario,
// y un correo nuevo y uno repetido reciben exactamente la misma respuesta.
// El mensaje sale en el idioma de lang. Si el cliente no pide JSON (formulario
// sin JavaScript), redirige con 303 a /lista-espera#<code>, o a
// /en/lista-espera#<code> con lang=en, para que el envío nativo también tenga
// respuesta. Los errores anteriores a leer el cuerpo (405, 413, 415) no conocen
// lang y responden en español.
//
// Entorno:
//   WAITLIST_DB       binding D1 (base vor-waitlist)
//   TURNSTILE_SECRET  secreto de Turnstile (secreto de Pages)
//   IP_HASH_SALT      opcional; clave del HMAC de la IP. Si falta, se deriva
//                     de TURNSTILE_SECRET (rotar ese secreto solo reinicia el
//                     límite por IP, no rompe nada).

const SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
const MAX_BODY_BYTES = 16 * 1024;
const MAX_EMAIL = 254;
const MAX_NAME = 200;
const MAX_USE_CASE = 1000;
const MAX_UA = 200;
const RATE_LIMIT = 5; // envíos permitidos por IP y hora
const RATE_WINDOW_MS = 60 * 60 * 1000;
const ATTEMPT_RETENTION_MS = 24 * 60 * 60 * 1000;

// Sin cuantificadores anidados: no hay retroceso catastrófico.
const EMAIL_RE = /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/;

const MESSAGES_ES = {
  ok: "Gracias. Si hay plaza en el acceso remoto, te escribiremos a ese correo.",
  invalid_email: "Revisa el correo: no parece una dirección válida.",
  invalid_input: "Revisa los datos del formulario.",
  use_case_too_long: "El uso previsto admite como máximo 1000 caracteres.",
  turnstile_missing: "Falta la verificación anti-bots. Espera a que se complete e inténtalo de nuevo.",
  turnstile_failed: "No hemos podido verificar que no eres un bot. Inténtalo de nuevo.",
  rate_limited: "Demasiados envíos desde tu conexión. Inténtalo dentro de una hora.",
  payload_too_large: "El envío es demasiado grande.",
  unsupported_media_type: "Formato de envío no admitido.",
  method_not_allowed: "Método no permitido.",
  server_error: "Error interno. Inténtalo más tarde o escríbenos a contact@brierstudios.com.",
};

const MESSAGES_EN = {
  ok: "Thank you. If a spot opens up in remote access, we will write to you at that address.",
  invalid_email: "Check the email address: it does not look valid.",
  invalid_input: "Check the form fields.",
  use_case_too_long: "The intended use field allows at most 1000 characters.",
  turnstile_missing: "The anti-bot verification is missing. Wait for it to finish and try again.",
  turnstile_failed: "We could not verify that you are not a bot. Try again.",
  rate_limited: "Too many submissions from your connection. Try again in an hour.",
  payload_too_large: "The submission is too large.",
  unsupported_media_type: "Unsupported submission format.",
  method_not_allowed: "Method not allowed.",
  server_error: "Internal error. Try again later or write to us at contact@brierstudios.com.",
};

// Idiomas admitidos: mensajes y página de resultado para el envío sin JavaScript.
const LANGS = {
  es: { messages: MESSAGES_ES, resultPath: "/lista-espera" },
  en: { messages: MESSAGES_EN, resultPath: "/en/lista-espera" },
};
const DEFAULT_LANG = "es";

const STATUS = {
  ok: 200,
  invalid_email: 400,
  invalid_input: 400,
  use_case_too_long: 400,
  turnstile_missing: 400,
  turnstile_failed: 403,
  rate_limited: 429,
  payload_too_large: 413,
  unsupported_media_type: 415,
  method_not_allowed: 405,
  server_error: 500,
};

export async function onRequest(context) {
  const { request } = context;
  if (request.method !== "POST") {
    return reply(request, "method_not_allowed", DEFAULT_LANG, { Allow: "POST" });
  }
  // state.lang pasa a ser el del formulario en cuanto se lee el cuerpo, para que
  // un error interno posterior también responda en ese idioma.
  const state = { lang: DEFAULT_LANG };
  try {
    return await handlePost(context, state);
  } catch (err) {
    console.error("waitlist: error inesperado", err && err.message ? err.message : String(err));
    return reply(request, "server_error", state.lang);
  }
}

async function handlePost({ request, env }, state) {
  if (!env.WAITLIST_DB || !env.TURNSTILE_SECRET) {
    console.error("waitlist: falta WAITLIST_DB o TURNSTILE_SECRET");
    return reply(request, "server_error", state.lang);
  }

  const declared = Number(request.headers.get("Content-Length") || "0");
  if (declared > MAX_BODY_BYTES) return reply(request, "payload_too_large", state.lang);

  const raw = await request.arrayBuffer();
  if (raw.byteLength > MAX_BODY_BYTES) return reply(request, "payload_too_large", state.lang);

  const fields = await parseBody(request.headers.get("Content-Type") || "", raw);
  if (fields === null) return reply(request, "unsupported_media_type", state.lang);

  state.lang = pickLang(field(fields, "lang"));
  const lang = state.lang;

  const email = field(fields, "email").trim().toLowerCase();
  const name = field(fields, "name").trim();
  const useCase = field(fields, "use_case").trim();
  const token = field(fields, "cf-turnstile-response").trim();

  if (!email || email.length > MAX_EMAIL || !EMAIL_RE.test(email)) {
    return reply(request, "invalid_email", lang);
  }
  if (charLength(name) > MAX_NAME) return reply(request, "invalid_input", lang);
  if (charLength(useCase) > MAX_USE_CASE) return reply(request, "use_case_too_long", lang);
  if (!token || token.length > 2048) return reply(request, "turnstile_missing", lang);

  const ip = request.headers.get("CF-Connecting-IP") || "";
  const ipHash = await hashIp(ip, env.IP_HASH_SALT || env.TURNSTILE_SECRET);
  const db = env.WAITLIST_DB;
  const now = Date.now();

  // Límite: más de 5 envíos en la última hora desde la misma IP (hash) se rechaza.
  const since = new Date(now - RATE_WINDOW_MS).toISOString();
  const row = await db
    .prepare("SELECT COUNT(*) AS n FROM waitlist_attempts WHERE ip_hash = ?1 AND created_at > ?2")
    .bind(ipHash, since)
    .first();
  if (row && Number(row.n) >= RATE_LIMIT) return reply(request, "rate_limited", lang);

  // Cada envío que llega hasta aquí cuenta para el límite, pase o no Turnstile.
  const nowIso = new Date(now).toISOString();
  await db.batch([
    db.prepare("INSERT INTO waitlist_attempts (ip_hash, created_at) VALUES (?1, ?2)").bind(ipHash, nowIso),
    db.prepare("DELETE FROM waitlist_attempts WHERE created_at < ?1")
      .bind(new Date(now - ATTEMPT_RETENTION_MS).toISOString()),
  ]);

  const human = await verifyTurnstile(env.TURNSTILE_SECRET, token, ip);
  if (!human) return reply(request, "turnstile_failed", lang);

  const userAgent = truncate(request.headers.get("User-Agent") || "", MAX_UA);

  // Upsert por correo: un duplicado actualiza la fila, no crea otra, y conserva
  // created_at. Los campos opcionales vacíos no borran lo que ya había.
  await db
    .prepare(
      `INSERT INTO waitlist (email, name, use_case, ip_hash, user_agent, created_at, updated_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
       ON CONFLICT(email) DO UPDATE SET
         name       = COALESCE(excluded.name, waitlist.name),
         use_case   = COALESCE(excluded.use_case, waitlist.use_case),
         ip_hash    = excluded.ip_hash,
         user_agent = excluded.user_agent,
         updated_at = excluded.updated_at`
    )
    .bind(email, name || null, useCase || null, ipHash, userAgent || null, nowIso)
    .run();

  // Misma respuesta para un correo nuevo y uno repetido.
  return reply(request, "ok", lang);
}

async function parseBody(contentType, raw) {
  const type = contentType.split(";")[0].trim().toLowerCase();
  if (type === "application/json") {
    let data;
    try {
      data = JSON.parse(new TextDecoder().decode(raw));
    } catch {
      return {};
    }
    return data && typeof data === "object" && !Array.isArray(data) ? data : {};
  }
  if (type === "application/x-www-form-urlencoded" || type === "multipart/form-data") {
    let form;
    try {
      form = await new Response(raw, { headers: { "Content-Type": contentType } }).formData();
    } catch {
      return {};
    }
    const out = {};
    for (const [key, value] of form.entries()) {
      if (typeof value === "string" && !(key in out)) out[key] = value;
    }
    return out;
  }
  return null;
}

// Solo "es" y "en"; cualquier otro valor (o ninguno) cuenta como "es".
function pickLang(value) {
  const v = value.trim().toLowerCase();
  return Object.prototype.hasOwnProperty.call(LANGS, v) ? v : DEFAULT_LANG;
}

function field(fields, key) {
  const value = fields[key];
  return typeof value === "string" ? value : "";
}

function charLength(s) {
  return Array.from(s).length;
}

function truncate(s, max) {
  const chars = Array.from(s);
  return chars.length > max ? chars.slice(0, max).join("") : s;
}

async function hashIp(ip, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode("vor-waitlist-ip:" + secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const mac = await crypto.subtle.sign("HMAC", key, enc.encode(ip));
  return Array.from(new Uint8Array(mac), (b) => b.toString(16).padStart(2, "0")).join("");
}

async function verifyTurnstile(secret, token, ip) {
  const body = new FormData();
  body.append("secret", secret);
  body.append("response", token);
  if (ip) body.append("remoteip", ip);
  try {
    const res = await fetch(SITEVERIFY_URL, {
      method: "POST",
      body,
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) return false;
    const outcome = await res.json();
    return outcome && outcome.success === true;
  } catch (err) {
    console.error("waitlist: siteverify no respondió", err && err.message ? err.message : String(err));
    return false;
  }
}

function wantsJson(request) {
  const accept = request.headers.get("Accept") || "";
  const type = (request.headers.get("Content-Type") || "").toLowerCase();
  return accept.includes("application/json") || type.startsWith("application/json") || !accept.includes("text/html");
}

function reply(request, code, lang = DEFAULT_LANG, extraHeaders = {}) {
  const status = STATUS[code] || 500;
  const locale = LANGS[lang] || LANGS[DEFAULT_LANG];
  const headers = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    ...extraHeaders,
  };

  // Envío nativo del formulario (sin JavaScript): redirección a una página estática.
  if (request.method === "POST" && !wantsJson(request)) {
    const target = new URL(locale.resultPath + "#" + code, request.url);
    return new Response(null, { status: 303, headers: { ...headers, Location: target.toString() } });
  }

  const messages = locale.messages;
  const payload = { ok: code === "ok", code, message: messages[code] || messages.server_error };
  return new Response(JSON.stringify(payload), {
    status,
    headers: { ...headers, "Content-Type": "application/json; charset=utf-8" },
  });
}
