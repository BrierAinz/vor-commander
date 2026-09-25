// Formulario de la lista de espera del acceso remoto.
// Mejora progresiva: sin este script el formulario se envía de forma nativa a
// /api/waitlist y la función redirige a /lista-espera (o a /en/lista-espera si el
// formulario lleva lang=en) con el resultado.
// Los textos propios del cliente salen de atributos data-msg-* del formulario,
// para que el mismo script sirva a la página en español y a la inglesa; los
// mensajes del resultado los da el servidor en el idioma del campo lang.
(function () {
  var form = document.getElementById("waitlist-form");
  if (!form || !window.fetch || !window.FormData) return;

  var status = document.getElementById("waitlist-status");
  var button = form.querySelector("button[type='submit']");
  var useCase = form.querySelector("#wl-use-case");
  var counter = document.getElementById("wl-use-case-count");

  // Textos por defecto (español) si la página no los declara.
  var DEFAULTS = {
    turnstilePending: "Espera a que termine la verificación anti-bots e inténtalo de nuevo.",
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
  }

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
      show("error", msg("turnstilePending"));
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
