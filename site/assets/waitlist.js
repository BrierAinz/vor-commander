// Formulario de la lista de espera del acceso remoto.
// Mejora progresiva: sin este script el formulario se envía de forma nativa a
// /api/waitlist y la función redirige a /lista-espera (o a /en/waitlist si el
// formulario lleva lang=en) con el resultado.
// Los textos propios del cliente salen de atributos data-msg-* del formulario,
// para que el mismo script sirva a la página en español y a la inglesa; los
// mensajes del resultado los da el servidor en el idioma del campo lang.
(function () {
  var form = document.getElementById("waitlist-form");
  if (!form || !window.fetch || !window.FormData) return;

  var status = document.getElementById("waitlist-status");
  var button = form.querySelector("button[type='submit']");
  var email = form.querySelector("#wl-email");
  var useCase = form.querySelector("#wl-use-case");
  var counter = document.getElementById("wl-use-case-count");
  var TURNSTILE_LOAD_TIMEOUT_MS = 8000;
  var turnstileUnavailable = false;

  // Textos por defecto (español) si la página no los declara.
  var DEFAULTS = {
    turnstilePending: "Espera a que termine la verificación anti-bots e inténtalo de nuevo.",
    turnstileUnavailable: "No se pudo cargar la verificación anti-bots. Pausa el bloqueador de anuncios o privacidad y recarga la página, o escríbenos:",
    sending: "Enviando…",
    badResponse: "Respuesta inesperada del servidor. Inténtalo más tarde.",
    unexpected: "Error inesperado.",
    network: "No hay conexión con el servidor. Inténtalo de nuevo o escríbenos a contact@brierstudios.com.",
  };

  function msg(key) {
    var attr = "msg" + key.charAt(0).toUpperCase() + key.slice(1);
    var value = form.dataset ? form.dataset[attr] : null;
    return typeof value === "string" && value ? value : DEFAULTS[key];
  }

  function show(kind, text) {
    status.textContent = text;
    status.className = "form-status form-status-" + kind;
    if (email) {
      if (kind === "error") email.setAttribute("aria-invalid", "true");
      else email.removeAttribute("aria-invalid");
    }
    if (kind === "error") status.focus();
  }

  function showTurnstileUnavailable() {
    show("error", msg("turnstileUnavailable") + " ");
    var contact = document.createElement("a");
    contact.href = "mailto:contact@brierstudios.com";
    contact.textContent = "contact@brierstudios.com";
    status.appendChild(contact);
  }

  window.setTimeout(function () {
    if (!window.turnstile) {
      turnstileUnavailable = true;
    }
  }, TURNSTILE_LOAD_TIMEOUT_MS);

  function updateCounter() {
    if (!useCase || !counter) return;
    counter.textContent = Array.from(useCase.value).length + " / 1000";
  }

  function resetTurnstile() {
    try {
      if (window.turnstile) window.turnstile.reset();
    } catch (e) {
      /* el widget se reinicia solo al caducar */
    }
  }

  if (useCase) {
    useCase.addEventListener("input", updateCounter);
    updateCounter();
  }

  form.addEventListener("submit", function (event) {
    event.preventDefault();

    if (!form.checkValidity()) {
      form.reportValidity();
      return;
    }

    var data = new FormData(form);
    if (!data.get("cf-turnstile-response")) {
      if (turnstileUnavailable && !window.turnstile) showTurnstileUnavailable();
      else show("error", msg("turnstilePending"));
      return;
    }

    button.disabled = true;
    show("pending", msg("sending"));

    fetch(form.action, {
      method: "POST",
      body: new URLSearchParams(data),
      headers: { Accept: "application/json" },
      credentials: "same-origin",
    })
      .then(function (res) {
        return res.json().catch(function () {
          return { ok: false, message: msg("badResponse") };
        });
      })
      .then(function (body) {
        var message = body && typeof body.message === "string" ? body.message : msg("unexpected");
        if (body && body.ok) {
          form.reset();
          updateCounter();
          show("ok", message);
        } else {
          show("error", message);
        }
      })
      .catch(function () {
        show("error", msg("network"));
      })
      .then(function () {
        button.disabled = false;
        resetTurnstile();
      });
  });
})();
