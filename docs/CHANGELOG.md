# Registro de cambios

## 0.1.0-beta.4

### Seguridad

- Elimina `--confirmed` de `vor-approver`, que permitía firmar una solicitud sin mostrar el diálogo de confirmación. El diálogo ahora muestra el digest completo y revalida la solicitud después de confirmar.
- Añade una comprobación de release en CI para impedir que vuelva a publicarse un aprobador con ese bypass.
- Incorpora una lista configurable de terminal segura sin firma, con coincidencia por ejecutable absoluto y argumentos exactos. Por defecto solo admite subcomandos de lectura de Git y los ejecuta con Git endurecido.
- Excluye deliberadamente Cargo, npm y pytest de la lista segura porque pueden ejecutar código del proyecto. El modo `strict` desactiva por completo la terminal segura sin firma.

### Exploración pública

- Expone `list_directory`, `search_files`, `search_content` y `file_info` como herramientas de solo lectura.

### Calidad

- Hace deterministas las pruebas para evitar resultados dependientes del entorno local.

## 0.1.0-beta.3

### Seguridad

- Actualiza `rustls` a 0.23.45 para corregir RUSTSEC-2026-0285.
- Refuerza las rutas de persistencia mediante firma y verificación de integridad.
- Aplica un presupuesto de bytes a la escritura automática para limitar el volumen de cada operación.

### Calidad

- Incorpora `vor-path` para centralizar y endurecer el tratamiento de rutas.
- Amplía CI con `clippy`, `cargo audit`, `pytest` y comprobaciones de release.
- Añade una prueba del control plane para cubrir su flujo principal.

### Web

- Mejora la guía de instalación rápida.
- Añade mejoras de accesibilidad.
- Completa las rutas en inglés bajo `/en/`.
