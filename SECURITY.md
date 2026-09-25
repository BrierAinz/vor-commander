# Security

Vör Commander is a local MCP gateway and device agent for Windows that gives AI assistants controlled access to your files, Git, processes and a bounded terminal. Security is central to the design: every mutation requires a signed approval, every action is recorded in a hash-chained audit log and the agent never opens an inbound port on your machine.

We take reports of vulnerabilities seriously and ask you to disclose them to us privately first.

## How to report a vulnerability

Please report vulnerabilities **by email** to:

- **contact@brierstudios.com**
- Subject: `SECURITY`

Encrypting the report is not currently required. If we need to exchange sensitive material, we will agree on a channel with you in the reply.

## What to include in a report

To help us act quickly, please include as much of the following as you can:

- A clear description of the issue and its impact.
- The affected component (e.g. gateway, device agent, MCP tool, transport, audit) and, if known, the file or crate.
- Steps to reproduce, ideally with a minimal, self-contained example.
- The version, commit hash or build you tested against.
- Your environment (Windows edition and version, Rust toolchain version, transport mode).
- Any relevant logs, traces, hashes or screenshots.
- Whether the issue affects only your machine, multiple users or the hosted service.
- Your name and how you would like to be credited (or "anonymous").

If you are unsure whether something is a vulnerability, report it anyway. We would rather investigate a non-issue than miss a real one.

## What to expect

We aim to:

- Acknowledge receipt within a reasonable time.
- Triage the report and assess severity.
- Keep you informed of our progress.
- Credit reporters who help us improve the project, unless you prefer to stay anonymous.

We do **not** promise a contractual service-level agreement (SLA) for acknowledgement or fix timelines. Our goal is to be transparent and timely without binding ourselves to terms we cannot guarantee.

## Scope

This security policy applies to **the source code in this repository** (the local MCP gateway, the device agent, the supporting workspace crates, the installer scripts and the documentation that ships with the code).

Out of scope for this policy:

- The **hosted Vör Commander service**, including the cloud control plane, the managed relay, billing and account services. Its deployment and configuration are not in this repository, although the code it runs is. Reports about the hosted service are still welcome at the same address; we will route them to the appropriate team.
- Third-party dependencies, except where a vulnerability is reachable through this project. For upstream issues, please report upstream as well.
- Social engineering, physical access or compromise of the operator's machine outside the project's threat model.

## Coordinated disclosure

We follow a coordinated disclosure model:

- Please give us a reasonable opportunity to investigate and fix the issue before any public disclosure.
- Avoid actions that go beyond what is necessary to demonstrate the vulnerability, such as accessing, modifying or persisting data that is not yours, or degrading service for other users.
- Once a fix is available, we are happy to coordinate a joint disclosure timeline.

## Threat model and mitigations

For the project's threat model and the mitigations required before a remote beta, see `docs/THREAT_MODEL.md` in this repository.

A reminder of the project's boundary: application policy is a guardrail, not a sandbox. Security claims about containment require OS-enforced process/token/ACL boundaries and adversarial testing. The project makes no claim that such containment already exists.

## Contact

- Email: contact@brierstudios.com
- Subject line: `SECURITY`
- Project: https://vorcommander.app
- Repository: https://github.com/BrierAinz/vor-commander
