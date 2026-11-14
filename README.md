# v6blick

Does your site work for someone who has no IPv4?

v6blick tests a host or a whole page from three kinds of network: an ordinary dual-stack connection, an IPv6-only network with a NAT64 translator, and an IPv6-only network with no translator. It reports what breaks in each, down to the one third-party script that has no IPv6 address.

**Status:** in design, with Phase 0 (`check` and `doctor`) being built. Nothing is released yet. Sections below say which parts are planned.

- Design document: [DESIGN.md](DESIGN.md)
- Decisions made while building: [DECISIONS.md](DECISIONS.md)
- Companion project: [zoneblick](https://zoneblick.com), which watches DNS zones over time
- Who it is for, with the command for each case: [Who it is for](#who-it-is-for)

![The v6blick social card: "See your site without IPv4." Below it, a one-line description, three sample findings (a literal IPv4 address and two hosts with no AAAA record), the labels three network modes, whole-page test, JSON for CI, no account and one binary, and one page loaded in three networks: 42 of 42 requests ok on a dual-stack connection, 41 of 42 with a NAT64 translator, and 33 of 42 on IPv6 only](docs/og-image.png)

## Contents

- [Why this is needed](#why-this-is-needed)
- [What it looks like](#what-it-looks-like)
- [Who it is for](#who-it-is-for)
- [The three networks](#the-three-networks)
- [Commands](#commands)
- [Checks](#checks)
- [Exit codes](#exit-codes)
- [How it works](#how-it-works)
- [Safety and politeness](#safety-and-politeness)
- [How it divides the work with zoneblick](#how-it-divides-the-work-with-zoneblick)
- [Build phases](#build-phases)
- [Development](#development)
- [Repository layout](#repository-layout)
- [Responsible use](#responsible-use)
- [License](#license)

## Why this is needed

A growing share of clients have no IPv4 address of their own: many mobile networks, and a rising number of corporate and cloud networks now that providers charge for IPv4 addresses. They reach the IPv4 internet through a translator, or not at all.

The failures hide behind fallback. A browser on a dual-stack connection that cannot reach a site over IPv6 quietly retries over IPv4, so the site's owner never sees the fault. The owner's own connection is the one place where the problem cannot be seen.

The gap is wide. One 2025 study that used full browser page loads rated 12.5% of the top 100,000 sites as fully IPv6-ready. Internet Society measurements put IPv6 support at 67% for first-party domains and at 47% for the third-party domains they depend on. A site can publish an AAAA record and still break, because a font, a script or a tracking pixel comes from a host that has none.

Existing tools leave a gap:

| Tool | What it does | What is missing |
|---|---|---|
| NAT64Check (Internet Society) | Loads a URL over IPv4, IPv6 and NAT64 and compares the results | A hosted service from 2017; its design needs four servers |
| IETF 124 hackathon "IPv6 Web Resource Checker" (2025) | Checks a page's resources with a real browser | A hackathon project |
| test-ipv6.com and similar | Tells a visitor about their own connection | Tests the client, not the site |

v6blick is a tool you run yourself, against a local build or a live URL, that covers the whole page.

## What it looks like

There are no screenshots yet, because no command runs yet. They will be added here as each command is built, starting with `v6blick check`.

This is the output the design aims at for a page test. It is a sketch, not real output:

```
v6blick page https://example.org        IPv6 on this machine: working

  dual     42 requests   42 ok
  nat64    42 requests   41 ok    1 refused
  v6only   42 requests   33 ok    9 failed

  warning  LIT-01  http://192.0.2.44/track.gif            literal IPv4 address
  warning  PGE-02  static.example.org      3 requests     no AAAA record
  notice   PGE-02  fonts.thirdparty.example 4 requests    no AAAA record (third party)
  notice   PGE-02  cdn.widgets.example      2 requests    no AAAA record (third party)
```

## Who it is for

Eight situations v6blick is designed for, each with the command that answers it. `check` and `doctor` are Phase 0; `page` comes in Phases 1 to 3.

**1. "We published an AAAA record last year. Does it still work?"** A dual-stack browser would hide a dead IPv6 address by falling back. `check` connects over each family on its own, so an address that no longer answers is a critical finding (RCH-01).

```
v6blick check example.org
```

**2. "Our IPv6 traffic goes through a different load balancer. Does it serve the same site?"** `check` compares the certificate, the status, the redirect and the body between the two families (EQV-01 to EQV-03). A stale certificate or an old redirect on the IPv6 side shows up here.

```
v6blick check https://example.org/
```

**3. "A pull request must not add something that breaks for IPv6-only visitors."** Run it in CI against the preview build. It exits `2` on a critical finding and `1` on warnings.

```yaml
- run: v6blick check preview.example.org --json > v6blick.json
```

**4. "We want to stop paying for IPv4 addresses. What would break?"** The `v6only` mode is the true dependency list: every host the page needs that has no working IPv6 address, grouped by who serves it.

```
v6blick page https://example.org --mode v6only
```

**5. "Most of our visitors are on mobile networks. What do they hit today?"** Many mobile networks are IPv6-only with a NAT64 translator. That rescues IPv4-only hostnames, and it does not rescue an IPv4 address written straight into a page or a script (LIT-01).

```
v6blick page https://example.org --mode nat64
```

**6. "Which of our third parties hold us back?"** A third-party failure is a notice, because the site owner cannot fix it, only replace or self-host it. The page report groups failures by registrable domain, so the list reads as a list of suppliers to talk to.

```
v6blick page https://example.org --json
```

**7. "I am testing a build on my own machine before it goes live."** Private and loopback addresses are refused by default, so a page cannot steer the tool at an internal host. One flag permits them.

```
v6blick check localhost --allow-private
```

**8. "The check says IPv6 fails everywhere. Is it the sites, or is it this machine?"** `doctor` says whether this machine has working IPv6 and whether a Chrome or Chromium is installed. Without working IPv6, `check` says so and exits `3`; it never reports a site as broken because the test machine has no IPv6.

```
v6blick doctor
```

## The three networks

| Mode | Simulates | What can break |
|---|---|---|
| `dual` | An ordinary connection. The baseline. | Nothing, by definition |
| `nat64` | An IPv6-only network with a translator, as on many mobile networks | IPv4 addresses written directly into pages or scripts |
| `v6only` | An IPv6-only network with no translator | Every host without a working IPv6 address |

`v6only` gives the true dependency list. `nat64` shows what a real mobile user without IPv4 would hit today.

### How NAT64 is simulated

A real NAT64 network lets a client reach an IPv4-only **hostname**, because the network's DNS invents an IPv6 address for it and a gateway translates the traffic. It does not help with an IPv4 address used **directly**, because no DNS lookup happens.

The simulation applies exactly that rule:

- A hostname with an IPv6 address: connect over IPv6.
- A hostname with only an IPv4 address: allowed. Connect over IPv4 and mark the request "reached through translation".
- A literal IPv4 address: refused, and reported.

This needs no gateway and no special network. A `--nat64-prefix` option will point the tool at a real gateway for verification.

One caveat is stated in every report: many phones run a second translator on the device (CLAT) that makes literal IPv4 addresses work too. A literal-address finding therefore reads "fails on IPv6-only networks without CLAT".

## Commands

```
v6blick check <host-or-url>                   # DNS and connection checks, no browser    (Phase 0)
v6blick check <host-or-url> --json            # one JSON document for CI                 (Phase 0)
v6blick doctor                                # does this machine have IPv6? is Chrome found?  (Phase 0)
v6blick page <url>                            # whole page, all three modes              (Phases 1-2)
v6blick page <url> --mode v6only              # one mode
v6blick page <url> --html report.html         # self-contained report                    (Phase 3)
v6blick page --urls urls.txt                  # many pages                               (Phase 3)
```

### What `check` does

1. **Looks up the host.** A and AAAA records, following CNAMEs. v6blick resolves from the root servers itself and asks no recursive resolver.
2. **Walks the delegation over IPv6 only.** It resolves the host's zone from the root again, this time using only IPv6 to reach each nameserver, and records the level at which that fails, if it does.
3. **Probes each address family on its own.** A TCP connection to port 443 and to port 80, a TLS handshake, and one HTTP `GET`. It records the time to connect, the certificate, the status, each redirect, and the size and a hash of the body.
4. **Runs the checks.** Each check is a function over what was recorded. No check touches the network.
5. **Prints the findings** grouped by severity, each with its check ID, the host and the evidence, and exits with a code that CI can use.

## Checks

Severity levels are the same as zoneblick's: **critical**, **warning**, **notice**, **info**. Check IDs are stable.

### Addresses (`ADR`), Phase 0

| ID | Check | Severity |
|---|---|---|
| ADR-01 | The host has an A record and no AAAA record | warning |
| ADR-02 | An AAAA record holds an address no client can use: loopback, private, IPv4-mapped, or a retired transition range | warning |
| ADR-03 | The host's zone cannot be resolved over IPv6 alone: at some level of the delegation no nameserver is reachable over IPv6 | warning |

### Reachability (`RCH`), Phase 0

| ID | Check | Severity |
|---|---|---|
| RCH-01 | An AAAA record is published and nothing accepts a connection there | critical |
| RCH-02 | The TLS handshake fails over IPv6 and succeeds over IPv4 | critical |
| RCH-03 | A connection over IPv6 takes much longer to open than one over IPv4 | notice |
| RCH-04 | A client that tries IPv6 first waits more than a set time before IPv4 answers | notice |

RCH-01 is critical because a published address that does not answer is worse than none: every IPv6-capable client tries it first.

### Equivalence (`EQV`), Phase 0

| ID | Check | Severity |
|---|---|---|
| EQV-01 | The host serves a different certificate over IPv6 than over IPv4 | warning |
| EQV-02 | The host gives a different HTTP status or redirect over IPv6 than over IPv4 | warning |
| EQV-03 | The response body differs in a way that is not explained by per-request content | notice |

EQV-03 is a notice because dynamic pages differ between any two requests. It compares the structure of the page, not its bytes.

### Page (`PGE`), needs a browser, Phase 1

| ID | Check | Severity |
|---|---|---|
| PGE-01 | The page's own document cannot be loaded in this mode | critical |
| PGE-02 | A resource fails in `v6only` because its host has no IPv6 address | warning; notice for a third party |
| PGE-03 | A resource's host has an IPv6 address and the request still fails over IPv6 | warning |
| PGE-04 | A redirect leads to a host that is unreachable in this mode | warning |

### Literal addresses (`LIT`), needs a browser, Phase 2

| ID | Check | Severity |
|---|---|---|
| LIT-01 | The page requests a URL whose host is a literal IPv4 address | warning |
| LIT-02 | A literal IPv4 address appears in the page's HTML, CSS or script text and was not requested | notice |

### Packet size (`MTU`), Phase 4

| ID | Check | Severity |
|---|---|---|
| MTU-01 | A large response stalls over IPv6 and not over IPv4, which points to a path that drops "packet too big" messages | warning |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Clean: no findings above `info` |
| `1` | Notices or warnings, nothing critical |
| `2` | At least one critical finding |
| `3` | The run itself failed: a bad command line, a name that does not exist, or no working IPv6 on this machine |

These are zoneblick's exit codes.

## How it works

```
                 ┌──────────────────────────────────────────────────┐
                 │                 v6blick (one binary)              │
                 │                                                  │
   check <host> ─┼─► Resolver ─► Prober ─────────────┐               │
                 │   (A, AAAA,   (connect, TLS,       │               │
                 │    IPv6-only   HTTP, both          ▼               │
                 │    walk)       families)        Findings ─► Report │
                 │                                    ▲      (text,  │
   page <url> ───┼─► Browser driver ──► Mode proxy ───┘       JSON,  │
                 │   (Chrome over       (allows or             HTML) │
                 │    DevTools)          refuses each                │
                 │                       connection)                 │
                 └──────────────────────────────────────────────────┘
                          │                    │
                    installed Chrome      the network
```

- **Resolver.** An iterative resolver that starts at the root hints and follows referrals down, one server at a time, keeping every referral it saw. It is copied from zoneblick, with the zoneblick commit recorded in `DECISIONS.md`. Run with IPv4 switched off, the same code is the IPv6-only walk behind ADR-03.
- **Prober.** Connects to one address of one family, completes TLS under the host's name, and sends one HTTP/1.1 `GET`. It is written directly on `tokio` and `rustls`, because the probe has to choose the address itself and keep the certificate and the timings, which a general HTTP client hides.
- **Mode proxy** (Phase 1). A forward proxy on `127.0.0.1`, alive only for the run. The browser sends it every request by hostname; the proxy resolves the name itself, applies the rules of the current mode, connects or refuses, and records the outcome. This is where `v6only` and `nat64` are enforced.
- **Browser driver** (Phase 1). Finds an installed Chrome or Chromium, starts it headless with a fresh temporary profile and the proxy set, loads the URL, waits for the page to settle, and collects the list of requests and the page source.
- **Findings.** Pure functions from recorded observations to findings. Every check can be tested offline against hand-built or recorded observations.
- **Report.** Terminal text and JSON; a self-contained HTML report in Phase 3.

### Why a proxy and not a real IPv6-only network

A real IPv6-only test network needs root, a second interface and a gateway. A proxy needs none of that, works the same on Linux and macOS, and runs in CI. It also sees each request as a hostname, which is what makes the literal-address check possible.

The cost: HTTP/3 does not pass through an ordinary proxy, so the browser runs with QUIC switched off. HTTP/3 over IPv6 is outside version 1.

### Stack

| Layer | Choice |
|---|---|
| Language | Rust, stable toolchain, edition 2024 |
| Async runtime | `tokio` |
| DNS wire format | `hickory-proto`, the version zoneblick uses |
| TLS | `rustls` with `tokio-rustls` and the `ring` provider |
| CLI | `clap` with derive |
| JSON | `serde`, `serde_json` |
| Errors | `thiserror` in library code, `anyhow` at the binary edge |
| Browser control | Chrome DevTools Protocol; crate or hand-written client still to be decided |

### Source layout

One Cargo package. All network I/O is in `resolve` and `probe`; `checks` has none.

| Module | Contents |
|---|---|
| `observe` | Plain data: everything one run recorded |
| `resolve` | DNS: transport, rate limiter, root hints, the iterative resolver, host lookup, the IPv6-only walk |
| `probe` | TCP, TLS and HTTP for one address of one family |
| `checks` | Pure functions from observations to findings |
| `output` | The report, as text or JSON, and the exit code |
| `cli` | Argument parsing, `check` and `doctor` |

## Safety and politeness

- **Working IPv6 is required on the test machine.** `v6blick doctor` checks it. Without it the IPv6 half of every comparison cannot run; the tool says so and exits `3` instead of reporting false failures.
- **Private addresses are refused.** Private, loopback and link-local destinations are not contacted unless `--allow-private` is given.
- **It connects only to what was asked for.** The given host, the hosts its redirects name and, for a page, the resources the page loads. No crawling.
- **Polite.** Bounded concurrency, a timeout on every network step, a per-server rate cap on DNS queries, and no more than one retry.
- **Plain requests only.** One `GET` per probe, with a `User-Agent` that names v6blick. A small fixed number of redirects is followed, and each one is recorded.
- **The proxy is local and short-lived** (Phase 1). It binds to `127.0.0.1` on a random port for the length of the run and is not usable as a general proxy.
- **The browser is isolated** (Phase 1). A fresh temporary profile per run, deleted afterwards. No saved logins, no extensions.

## How it divides the work with zoneblick

| | zoneblick `IPV` (proposed) | v6blick |
|---|---|---|
| Unit | A zone and its names | A URL and everything it loads |
| When | On a schedule, with history | Once, on demand or in CI |
| Needs a browser | No | For the page test |
| Third-party hosts | Out of scope | The main subject |
| User | Whoever runs the DNS | Whoever builds the site |

v6blick follows zoneblick's habits: stable check IDs, the same four severities, JSON output, the same exit codes, and a `DECISIONS.md` that records each choice in one line.

## Build phases

| Phase | Deliverable | State |
|---|---|---|
| 0 | `v6blick check` and `doctor`: ADR, RCH and EQV checks, text and JSON output | In progress |
| 1 | `v6blick page --mode v6only`: mode proxy, browser driver, PGE checks | Planned |
| 2 | `nat64` simulation and LIT checks; all three modes in one run | Planned |
| 3 | HTML report, `--urls`, a GitHub Action | Planned |
| 4 | MTU-01 | Planned |
| 5 | Packaging and the project site at v6blick.zoneblick.com | Planned |

## Development

```
cargo fmt --check
cargo clippy -- -D warnings
cargo test
```

Unit tests do not use the network. Checks are tested against hand-built observations and recorded exchanges in `tests/fixtures/`. The probe is tested against a local server started by the test itself, with one IPv4 and one IPv6 listener that can be made to differ. Tests that need the live network are marked `#[ignore]`.

## Repository layout

| Path | Contents |
|---|---|
| `DESIGN.md` | High-level design |
| `KICKOFF.md` | The prompt that started Phase 0 |
| `docs/og-image.png`, `docs/favicon.svg` | The social card (1200x630) and the icon, for the project site |
| `packaging/og-image.html` | Source of the social card, with the command that renders it |

## Responsible use

Test your own sites, or sites you have permission to test. A check is ordinary traffic: a few DNS queries and a handful of HTTP requests.

## License

MIT or Apache-2.0, at your option, the same as zoneblick. The licence files are added with Phase 0.
