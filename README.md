# Vör Commander

Vör Commander is a local MCP gateway and device agent for Windows that gives AI assistants controlled access to your filesystem, Git, processes and a bounded terminal on your machine. The local core is written in Rust and published as open source.

All the code in this repository (device agent, core crates, MCP gateway, relay, control plane and billing integration) is open source under MPL-2.0. The hosted service operated by Brier Studios is a separate offering; the code it runs is the code you see here.

- Project: https://vorcommander.app
- Repository: https://github.com/BrierAinz/vor-commander
- Contact: contact@brierstudios.com
- License: MPL-2.0 (see `LICENSE`)
- Trademark notice: see `TRADEMARKS.md`

## What it is

Vör Commander is a local MCP server plus a device agent that runs on a Windows PC. Through MCP it exposes controlled tools to AI assistants (Claude, ChatGPT, Cursor, VS Code) so they can read files, inspect Git, list processes, run a bounded terminal and, with a signed approval, write files or execute commands.

A signed approval is an Ed25519 signature over the exact request digest (action, target, policy, required capability, expiry, nonce). Each approval is one-shot: replaying it returns `approval_replayed`.

## Why it is different

- **Signed approvals.** Writes and terminal commands require an Ed25519 signature bound to the request digest. There is no shortcut `approved=true`.
- **Tamper-evident audit.** Authorisations, approvals and executions are recorded in SQLite with a JSONL mirror, chained by hash. Signed checkpoints are stored outside the mutable event stream.
- **Private transport, no inbound ports.** The agent dials out to the gateway over a private mTLS tunnel (with WSS as fallback). It never opens a public port to recover connectivity.
- **Rooted folders, no escape.** Operations are confined to the folders you authorise. `..` and Windows reparse points (junctions, symbolic links) are rejected before policy is evaluated.
- **Replay protection.** Every approval is consumed once and that consumption is persisted.

Application policy is a guardrail, not a sandbox. Security claims about containment require OS-enforced process/token/ACL boundaries and adversarial testing; the project makes no claim that such containment already exists.

## Honest status (private pilot)

The project is in a **private pilot** on Windows. The website distinguishes what is available today from what is "in the pilot" or "coming soon"; the repository mirrors those labels and nothing more. Anything marked "in the pilot" or "coming soon" is not a public capability yet, regardless of what is implemented in source or tested locally. A local PASS is not the same as live certification.

**Available today** (per the website):

- MCP server and device agent on Windows.
- Read files (`filesystem.read` / `read_file`) inside authorised folders.
- `git.status` and `git.diff`.
- `process.list` and `process.inspect`.
- File writes via the two-step `prepare_write` / `commit_write` flow with a signed approval (up to 1 MiB per write, SHA-256 before/after check, atomic replace with backup).
- Bounded terminal via `prepare_terminal` / `commit_terminal`: structured argv only (no opaque shell strings), confined working directory, 120 s max, 1 MiB output cap, plus `terminal.poll` and `terminal.cancel` for your own sessions.
- Ed25519 signed approvals with replay protection.
- Hash-chained audit log (SQLite + JSONL).
- Outbound private mTLS tunnel; no inbound public ports.

**In the pilot** (not yet a public capability):

- `list_directory`, `search_files`, `search_content` and `file_info` for project exploration.
- `read_file` by byte ranges.
- Connector wiring for Cursor and VS Code from the local installer.

**Coming soon:**

- Policy-based auto-approval for low-risk operations inside allowed folders (destructive operations still require a signed approval).
- Local stdio adapter for Claude Desktop.
- Multi-tenant isolation between organisations (implemented locally; not deployed).

**Not available and not planned as a goal:**

- Generic RDP/VNC, keylogging, indiscriminate capture, password/cookie/token extraction, UAC bypass, auto-publish, unattended purchases, or remote execution without identity and traceability.

## Architecture

```text
+--------------------+
|  AI assistant      |   Claude (remote connector, OAuth + PKCE)
|  (Claude, ChatGPT, |   ChatGPT (read-only connector, validated)
|   Cursor, VS Code) |   Cursor / VS Code (in the pilot)
+--------------------+
           |
           v
+--------------------+
|  MCP Gateway       |   authenticates, scopes the session,
|                    |   exposes only controlled tools
+--------------------+
           |
           v
+--------------------+
|  Private tunnel    |   outbound gRPC + mTLS
|                    |   (WSS as fallback)
+--------------------+
           |
           v
+--------------------+
|  Device Agent      |   re-evaluates policy locally,
|  on your Windows   |   confines paths, executes only
|  PC                |   inside authorised folders
+--------------------+
           |
   +-------+-------+-------+
   |       |       |       |
 files  terminal  browser  (process, git)
```

Cross-cutting rails run alongside every step: **approvals** (signed, one-shot) and **audit** (hash-chained, append-only, signed checkpoints).

## MCP tools

Tool surface follows what is documented as available today. Tools in the pilot or coming soon are listed for transparency but are not part of the public, live surface.

Read-only, live:

- `commander_status`
- `filesystem.read` / `read_file`
- `git.status`
- `git.diff`
- `process.list`
- `process.inspect`

Mutation, requires signed approval:

- `filesystem.write` via `prepare_write` / `commit_write`
- `terminal.exec` via `prepare_terminal` / `commit_terminal`
- `terminal.poll`, `terminal.cancel` (your own sessions only)

In the pilot (source-only, not a public live capability yet):

- `filesystem.list` / `list_directory`
- `filesystem.search_files` / `search_files`
- `filesystem.search_content` / `search_content`
- `filesystem.info` / `file_info`
- `prepare_edit`: diff-based edits (up to 20 exact replacements, computed on the device, preserving encoding and line endings), committed through the same signed `commit_write` flow

Browser remote actions, desktop remote actions, process termination and self-maintenance apply are not exposed as MCP tools. Multi-tenant isolation, the relay, the control plane and the Stripe billing integration (sandbox only) are in this repository but are not a deployed public capability yet.

## Build

Requirements:

- Rust **1.96** (edition 2024 compatible).
- Windows 10/11 with the **MSVC** toolchain.
- PowerShell 5.1+ (for installer scripts).

Build the whole workspace:

```powershell
cargo build --workspace
```

Run all tests:

```powershell
cargo test --workspace
```

The repository is structured as a Cargo workspace:

```
apps/        # user-facing entry points (gateway, agent, CLI)
crates/      # reusable libraries (protocol, policy, audit, ...)
docs/        # capability matrix, blueprint, threat model, editions
prompts/     # prompt assets for assistants
site/        # website source (https://vorcommander.app)
scripts/     # installer, CI helpers, packaging
```

## Security

- Report vulnerabilities in private: see `SECURITY.md`.
- Threat model and required mitigations: see `docs/THREAT_MODEL.md`.

## License and trademark

- Code is licensed under **MPL-2.0** unless otherwise noted. See `LICENSE`.
- "Vör Commander" and the Vör Commander logo are trademarks of Brier Studios. The MPL-2.0 license covers the code, not the mark. See `TRADEMARKS.md` for permitted and non-permitted uses.

## Contributing

Contributions are welcome. See `CONTRIBUTING.md` for the process, coding style and the Developer Certificate of Origin (DCO) requirement.

---

## Resumen en español

Vör Commander es un agente local para Windows con gateway MCP, escrito en Rust. Permite que asistentes de IA (Claude, ChatGPT, Cursor, VS Code) accedan de forma controlada a ficheros, git, procesos y un terminal acotado dentro de las carpetas que tu autorices.

Lo que lo distingue: aprobaciones firmadas con Ed25519 ligadas a la peticion exacta y de un solo uso (sin atajos `approved=true`), auditoria encadenada por hash a prueba de manipulacion, transporte privado por tunel mTLS saliente sin abrir puertos en tu PC, y rutas confinadas a tus carpetas raiz (se rechazan `..` y los junctions o enlaces simbolicos de Windows).

Estado honesto: el proyecto esta en un **piloto privado**. La web distingue entre lo que esta disponible hoy, lo que esta "en el piloto" y lo que es "proximamente"; el repositorio refleja exactamente esas etiquetas. Un PASS local no equivale a certificacion en produccion.

Para compilar se necesita Rust 1.96 y el toolchain MSVC en Windows. Basta con `cargo build --workspace` y `cargo test --workspace`. El codigo se distribuye bajo MPL-2.0; la marca "Vör Commander" pertenece a Brier Studios y se rige por `TRADEMARKS.md`.
