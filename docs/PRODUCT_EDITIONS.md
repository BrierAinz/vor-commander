# Product editions and code boundary

## Community / Local

Objetivo: generar confianza, adopción e interoperabilidad local.

Incluye:
- Device Agent.
- Local MCP endpoint.
- Filesystem, terminal, process y Git tools.
- Policy Engine local.
- Audit ledger local.
- Dashboard local básico.
- Un operador y una máquina sin cloud obligatorio.

No incluye como servicio hospedado:
- relay administrado;
- control plane multi-tenant;
- billing;
- organización/equipos;
- retención cloud de auditoría.

## Personal Cloud

Community + pairing de dispositivos, Remote MCP, OAuth, relay administrado, Browser Bridge remoto, aprobaciones remotas, historial cloud y varios dispositivos según plan.

Stripe product: paid hosted subscription. Prices may vary by monthly, annual or currency variant.

## Teams

Personal Cloud + Organizations, RBAC, shared device ownership, central policy, approval routing, team audit, service accounts y administración de miembros.

Stripe product: paid hosted subscription for organization features and team capacity.

## Enterprise / Self-hosted

Teams + Gateway/Relay desplegable por el cliente, SSO/OIDC/SAML según demanda, private networking, políticas organizacionales, retención configurable y soporte empresarial.

Stripe product: custom or mirrored contract only; not self-serve by default.

## Ownership recomendado

Código portable/reutilizable:
- `protocol`: contratos Protobuf, IDs, errors y compatibility.
- `device-agent`: runtime local.
- `policy`: evaluación local y tipos de decisión.
- `audit`: formato verificable del ledger.
- `local-gateway`: endpoint local y dashboard mínimo.

Código cloud privado:
- multi-tenant control plane;
- managed relay orchestration;
- hosted OAuth/account service;
- billing/entitlements;
- organization management;
- abuse prevention and cloud operations.

## Tenant model

Canonical chain:
`user -> organization -> membership -> device -> session -> action`.

Toda fila cloud sensible debe estar ligada a `organization_id`; ningún lookup de device o session puede depender sólo de un ID global aportado por el cliente.

Billing follows the same boundary: cada `stripe_customer_id`, subscription externa y entitlement hospedado debe mapearse a una sola organización. La suscripción puede limitar capacidad cloud, pero no concede permisos locales ni autoridad del sistema operativo.

## Licensing decision D25 — accepted

Local/open reusable core is licensed under **MPL-2.0**. The hosted cloud/control-plane code is separately licensable and may remain proprietary.

**Update 2026-09-25 (owner decision):** the owner chose to publish **all** the code, including the gateway, relay, control plane and billing integration, under MPL-2.0 in the public repository `BrierAinz/vor-commander`. The hosted service operated by Brier Studios is the commercial offering; the "Vör Commander" name is covered by `TRADEMARKS.md`, not by the code license.

This preserves file-level reciprocity for modifications to MPL-covered files while allowing integration into larger proprietary systems under MPL-2.0 terms. The canonical license text is in `LICENSE`.
