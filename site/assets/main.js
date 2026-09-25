// Interruptor de tema claro/oscuro. El resto del sitio funciona sin JavaScript.
(function () {
  var root = document.documentElement;
  var btn = document.getElementById("theme-toggle");
  if (!btn) return;

  function current() {
    var t = root.getAttribute("data-theme");
    if (t === "light" || t === "dark") return t;
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }

  function sync() {
    var dark = current() === "dark";
    btn.setAttribute("aria-pressed", dark ? "true" : "false");
    btn.setAttribute("aria-label", dark ? "Cambiar a tema claro" : "Cambiar a tema oscuro");
  }

  sync();

  btn.addEventListener("click", function () {
    var next = current() === "dark" ? "light" : "dark";
    root.setAttribute("data-theme", next);
    try {
      localStorage.setItem("vor-theme", next);
    } catch (e) {
      /* sin almacenamiento: el cambio dura solo esta visita */
    }
    sync();
  });

  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", sync);
})();
