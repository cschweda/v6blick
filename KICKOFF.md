# v6blick — Claude Code kickoff prompt (Phase 0)

Paste everything below the line into Claude Code, started in the root of this repository.

---

You are starting the implementation of **v6blick**, a command-line tool written in Rust that tests whether a website works for someone who has no IPv4. The full design is in `DESIGN.md` in this repository. Read it completely before doing anything else. It is the source of truth; where this prompt and the design doc disagree, stop and ask me.

v6blick is a companion to **zoneblick**, an existing Rust project of mine at https://github.com/cschweda/zoneblick. Follow its conventions wherever this prompt is silent: check IDs, severity levels, exit codes, JSON shape, a `DECISIONS.md` file, plain wording in messages.

## Scope of this session: Phase 0 only

Build two commands:

```
v6blick check <host-or-url> [--json]
v6blick doctor
```

`check` looks up the host, connects to it over IPv4 and over IPv6 separately, compares the two, prints the findings and exits. `doctor` reports whether this machine has working IPv6 and whether Chrome or Chromium is installed. No browser is started in this phase, and no proxy is built.

### In scope

1. **Lookup.** A and AAAA records for the host, following CNAMEs.
2. **IPv6-only walk.** Resolve the host's zone from the root using IPv6 transport only, and record the level at which it fails, if it does.
3. **Probing.** For each address family on its own: open a TCP connection to port 443 (and 80), complete a TLS handshake, send one HTTP GET, and record connect time, the certificate, the status, the redirect target, and the size and a hash of the body.
4. **Checks.** Pure functions over the recorded observations, with no network access inside a check:
   - `ADR-01` to `ADR-03`
   - `RCH-01` to `RCH-04`
   - `EQV-01` to `EQV-03`
5. **Output.** Human-readable text by default, grouped by severity, each finding showing its check ID, the host and the evidence. `--json` prints one stable JSON document.
6. **Exit codes.** `0` clean, `1` notices or warnings only, `2` at least one critical, `3` the run itself failed.
7. **No IPv6 on this machine.** Detect it at the start. `check` must then say so and exit with `3`. It must never report a site as broken because the test machine has no IPv6.

### Out of scope for this session

The mode proxy, the browser driver, `page`, the `PGE`, `LIT` and `MTU` checks, NAT64 simulation, the HTML report, `--urls`, packaging, the website.

## Shared code with zoneblick

zoneblick already has an iterative resolver, per-server transports and a rate limiter, under `src/resolver/`. The design doc (section 8) recommends **copying** the modules you need into this repository, not depending on zoneblick.

Before you copy anything: clone zoneblick next to this repository, read its resolver, and tell me which modules you propose to copy and what you would leave behind. Record the zoneblick commit they came from in `DECISIONS.md`. Do not add zoneblick as a dependency unless I say so.

## Technical constraints

- **Rust, stable toolchain, edition 2024.** Async with `tokio`.
- **DNS:** `hickory-proto` for the wire format, the same version zoneblick uses.
- **TLS:** `rustls` with `tokio-rustls`, built the way zoneblick builds them.
- **CLI:** `clap` with derive. **JSON:** `serde` and `serde_json`. **Errors:** `thiserror` in library code, `anyhow` only at the binary edge.
- Check each crate's current documentation before relying on any API from memory.
- Ask me before adding any dependency not listed here.
- One Cargo package, with modules that match the design doc: `resolve`, `probe`, `observe` (the recorded observations), `checks`, `output`, `cli`. Keep `checks` free of any I/O.
- Licence: MIT or Apache-2.0, the same as zoneblick. Ask me before adding the licence files.

## Safety rules for the tool

- Refuse private, loopback and link-local destinations by default. `--allow-private` permits them.
- Bounded concurrency, a timeout on every network step, and no retries beyond one.
- Follow at most a small fixed number of redirects, and record each one.
- Never send anything but a plain GET with a clear `User-Agent` that names v6blick.

## Testing

- Unit tests must not use the network. Test checks against hand-built observations and against recorded exchanges in `tests/fixtures/`.
- For the probe, start a local test server in the test itself, with one IPv4 and one IPv6 listener that can be made to differ.
- Put any test that needs the live network behind `#[ignore]`.
- `cargo fmt --check`, `cargo clippy -- -D warnings` and `cargo test` must all pass before you call anything done.

## How to work

1. Read `DESIGN.md`. Then give me a short plan for Phase 0: the module layout, the core data types for observations and findings, what you propose to copy from zoneblick, and the build order. Wait for my go-ahead before writing code.
2. Build in small steps: observation types, lookup, probing, checks, output, CLI, `doctor`.
3. Commit after each working step with a clear message. Do not push; I will push.
4. When the design doc is ambiguous or looks wrong, ask. Note each decision in `DECISIONS.md`, one line each.
5. Run the tool only against hosts I name, `zoneblick.com`, or `example.com` and `example.org`.

## Definition of done for Phase 0

- `v6blick doctor` reports IPv6 and Chrome correctly on this machine.
- `v6blick check zoneblick.com` prints addresses, both probes and all findings.
- A test with a deliberately different IPv6 listener produces `EQV-01` and `EQV-02`, and one with a dead IPv6 listener produces `RCH-01`.
- `--json` output is stable and described in the README.
- Formatting, clippy and tests pass.
- The README has a short "Try it" section.

Start by reading `DESIGN.md` and giving me the plan.
