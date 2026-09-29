# Registro de cambios

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
