# Blueprint P0

Fecha de decisión: 2026-09-16.

## Arquitectura aprobada

1. Núcleo propio; terceros sólo como dependencias o referencias sustituibles.
2. Device Agent en Rust.
3. Local primero; remoto después de certificar P1-P3.
4. Tailscale + relay HTTPS propio; Cloudflare como edge opcional, no autoridad.
5. Contextos de privilegio separados: normal y elevado.
6. Policy Engine con `AUTO`, `APPROVAL` y `DENY`.
7. Filesystem con reglas por ruta y operación.
8. Terminal persistente mediante ConPTY en Windows.
9. Browser Bridge híbrido: WebDriver BiDi/Selenium + DOM + screenshots.
10. Desktop Computer Use se implementa después del Browser Bridge.
11. Auditoría SQLite + JSONL + hash chain + checkpoints firmados.
12. SecretStore: abstracción propia con backend inicial Windows/DPAPI.
13. Dashboard web local antes de empaquetado desktop.
14. Clientes desacoplados: MCP, REST y WebSocket donde corresponda.
15. Ruta canónica: `D:\Proyectos\10_Active\vor-commander`.
16. Protobuf común; gRPC/mTLS privado y WSS+Protobuf para relay público.
17. Identidad: certificado por dispositivo + mTLS + tokens cortos por sesión.
18. Ejecución por broker + workers aislables.19. Escrituras: journal + atomic replace cuando el filesystem lo permita.
20. Terminal persistente con lifecycle explícito.
21. Approval Engine desacoplado; web primero, adapters después.
22. Sesiones autenticadas de navegador utilizables; extracción de secretos denegada.
23. Ledger con checkpoints firmados.
24. Relay en VPS independiente; Cloudflare delante del origin.

## Capas

```text
MCP clients / agents
        |
        v
Cloud Edge (replaceable)
        |
        v
Vör Cloud Gateway / Relay
        |
   Tailscale or WSS
        |
        v
Vör Device Agent
   |       |       |
 files  terminal  browser
```

## Regla de transporte

LAN y Tailscale prefieren gRPC/mTLS. El fallback público usa WSS con frames Protobuf. El Device Agent nunca debe abrir automáticamente un puerto público para recuperar conectividad.## MCP externo

El target de interoperabilidad es MCP `2026-07-28` con compatibilidad heredada sólo donde la librería oficial lo haga razonable. La capa MCP se trata como stateless; las tareas largas usan la extensión Tasks, no una sesión de servidor implícita.

El endpoint cloud previsto es conceptualmente `https://mcp.<dominio>/mcp`. OAuth/OIDC se implementará conforme a Protected Resource Metadata y descubrimiento estándar; CIMD se prefiere a nuevo acoplamiento con DCR.

## Cloudflare

Cloudflare puede proveer DNS, edge, WAF, DDoS, Access y Tunnel. No almacena la autoridad final de dispositivo ni decide capacidades Vör. Los Tunnel tokens se consideran secretos de infraestructura y no sustituyen certificados de dispositivo.

## No objetivos iniciales

- RDP/VNC genérico.
- keylogging o captura indiscriminada.
- extracción de passwords/cookies/tokens.
- bypass de UAC o seguridad del OS.
- auto-publicación o compras.
- ejecución remota sin identidad y trazabilidad.

## Frontera Lilith

Vör Commander puede documentar un adapter futuro, pero no puede modificar la implementación, configuración, launcher, permisos ni contratos internos de Lilith sin aviso previo y confirmación de Ainz.