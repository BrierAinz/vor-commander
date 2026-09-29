// Selector de idioma: enlaces normales a la página equivalente del otro idioma.
// Sin redirección automática por idioma del navegador. Mejora progresiva: si la
// página actual tiene un fragmento (#seccion, o el #codigo del resultado de la
// lista de espera), se conserva o se traduce al cambiar de idioma. Sin este
// script, el enlace lleva al inicio de la página equivalente.
(function () {
  var links = document.querySelectorAll("a.lang-switch");
  var fragments = {
    "como-funciona": "how-it-works",
    seguridad: "security",
    comparativa: "comparison",
    instalacion: "installation",
    "lista-espera": "waitlist",
  };

  function keepHash(link) {
    var hash = window.location.hash;
    if (!/^#[A-Za-z0-9_-]{1,64}$/.test(hash)) return;
    var name = hash.slice(1);
    if (document.documentElement.lang === "es" && fragments[name]) {
      hash = "#" + fragments[name];
    } else if (document.documentElement.lang === "en") {
      for (var source in fragments) {
        if (fragments[source] === name) hash = "#" + source;
      }
    }
    var base = link.getAttribute("href").split("#")[0];
    link.setAttribute("href", base + hash);
  }

  for (var i = 0; i < links.length; i++) {
    (function (link) {
      link.addEventListener("click", function () {
        keepHash(link);
      });
    })(links[i]);
  }
})();
