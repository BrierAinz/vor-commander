// Aplica el tema guardado antes del primer pintado para evitar parpadeo.
(function () {
  try {
    var t = localStorage.getItem("vor-theme");
    if (t === "light" || t === "dark") {
      document.documentElement.setAttribute("data-theme", t);
    }
  } catch (e) {
    /* sin almacenamiento: se usa el tema del sistema */
  }
})();
