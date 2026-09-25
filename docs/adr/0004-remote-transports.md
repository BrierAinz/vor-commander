# ADR-0004 — Remote transport split

Status: Accepted for P4 local foundation; production deployment pending.

## Decision

Vör Commander has one canonical application wire contract (`RelayFrame`) with two replaceable transport classes:

1. **Private route:** bidirectional gRPC + mutual TLS, intended for LAN/Tailscale/private routing.
2. **Public fallback:** outbound WebSocket Secure + Protobuf through the managed relay/edge.

The Device Agent never opens a public listener automatically. Transport failure may cause retry/backoff only; it cannot modify firewall, expose a port, install a VPN, or weaken TLS.

## Device identity

Device private keys are generated on the workstation and stored with Windows DPAPI. Enrollment sends only a CSR. The issuer assigns the authorized device identity and signs the client certificate.

Private gRPC binds the TLS peer certificate SHA-256 fingerprint to the registered `device_id`. The first frame must be `DeviceHello`; later frames cannot change device identity.

## Public relay identity

The development relay uses a short-lived `relay.connect` bearer grant bound to one device. Remote URLs must use `wss://`; plain `ws://` is accepted only for loopback testing. Production relay auth may additionally use edge/mTLS controls, but they do not replace Vör authorization.

## Execution boundary

Transport success is not execution authority. `ActionRequest`, approval and worker dispatch remain disabled in the P4 transport foundation. Enabling them requires policy evaluation, immutable-request binding, signed approval when required, and auditable execution in a later gate.

## Replaceability

Cloudflare, Tailscale and the VPS provider are deployment dependencies, not protocol authorities. The Device Agent and wire contract must survive replacing any of them.