// Selector de idioma: enlaces normales a la página equivalente del otro idioma.
// Sin redirección automática por idioma del navegador. Mejora progresiva: si la
// página actual tiene un fragmento (#seccion, o el #codigo del resultado de la
// lista de espera), se conserva al cambiar de idioma, porque los id son los
// mismos en las dos versiones. Sin este script, el enlace lleva al inicio de la
// página equivalente.
(function () {
  var links = document.querySelectorAll("a.lang-switch");

  function keepHash(link) {
    var hash = window.location.hash;
    if (!/^#[A-Za-z0-9_-]{1,64}$/.test(hash)) return;
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
