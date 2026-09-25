# Contributing to Vör Commander

Thank you for your interest in Vör Commander. Vör Commander is a local MCP gateway and device agent for Windows, written in Rust. All the code in this repository, including the MCP gateway, relay, control plane and billing integration, is open source under the MPL-2.0 license.

This document explains how to propose changes, the project conventions and the legal requirement that applies to every contribution.

## How to propose a change

1. **Discuss first.** Open an issue describing the problem you want to solve and the approach you have in mind. For security-relevant changes, do **not** open a public issue; follow `SECURITY.md` instead.
2. **Fork and branch.** Create a topic branch from `main`. Keep the change focused; prefer several small pull requests over one large one.
3. **Sign your work.** Every commit must include a `Signed-off-by` line (see DCO below). We use the Developer Certificate of Origin 1.1.
4. **Open a pull request.** Reference the issue it addresses. Describe user-visible behaviour, the tests you ran and any backwards-compatibility impact.
5. **Iterate.** A maintainer will review and may request changes. CI on Windows must be green before merge.

## Developer Certificate of Origin (DCO) 1.1 — required

By contributing, you certify that you have the right to submit the work under the project's open-source license, in line with the Developer Certificate of Origin 1.1.

Add a `Signed-off-by` line to every commit, for example:

```
Signed-off-by: Jane Developer <jane@example.com>
```

The easiest way is to use Git's built-in sign-off:

```bash
git commit -s
```

This appends a `Signed-off-by` line based on your `user.name` and `user.email`.

The full text of the DCO 1.1 is at https://developercertificate.org. By signing off, you agree to its terms.

## Style and quality

- **Formatting.** Run `cargo fmt` before pushing. CI will reject unformatted code.
- **Lints.** Keep `cargo clippy --workspace --all-targets -- -D warnings` clean.
- **Tests.** All tests must pass locally before opening a PR. Add or update tests for any behaviour change.
- **CI.** Our CI runs on Windows with the MSVC toolchain, matching the documented build instructions.
- **Commit messages.** Imperative mood, short subject line, meaningful body when needed.
- **Scope.** Keep changes scoped. Refactors that touch many crates should be split or discussed first.

## Security-relevant changes

Do **not** open a public issue or pull request that discloses a vulnerability. Report it in private following `SECURITY.md`. Security fixes are coordinated through a private disclosure process.

## Licensing of contributions

- The local core is licensed under **MPL-2.0**. By submitting a contribution to files under MPL-2.0, you agree to license your contribution under the same terms.
- Anything you add must be compatible with that license, including dependencies you introduce in `Cargo.toml`.
- Do not contribute code that you do not have the right to license, or that incorporates incompatible third-party material without a clear notice.
- The deployment and operations of the hosted service run by Brier Studios are out of scope; contributions to the code (including the control plane and relay) are welcome here.

## Code of conduct

Be respectful and constructive. Assume good faith. Disagree on the technical merits, not on the person. Harassment or abusive behaviour is not tolerated.

## Questions

For general questions about contributing, open an issue. For security matters, see `SECURITY.md`. For everything else, contact contact@brierstudios.com.
