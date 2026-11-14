# v6blick — High-Level Design

**Author:** Christopher Schweda · **Date:** 2026-11-14 · **Status:** Draft v0.1

> *v6blick* — a look at how a site behaves over IPv6. Companion to [zoneblick](https://zoneblick.com).

---

## 1. Summary

v6blick answers one question about a website: **does it work for someone who has no IPv4?**

It tests a host or a whole page from three kinds of network: a normal dual-stack connection, an IPv6-only network with a NAT64 translator, and an IPv6-only network with no translator at all. It reports what breaks in each, down to the single third-party script that has no IPv6 address.

It is a command-line tool, run locally or in CI. One binary. The page test also needs Chrome or Chromium installed.

## 2. Goals and non-goals

### Goals

- **Run locally and in CI.** No hosted service, no account, no test servers to deploy.
- **Useful without a browser.** `v6blick check <host>` does the DNS and connection tests with nothing else installed.
- **Show the dependency list.** For a page, name every resource that fails without IPv4 and group it by the third party that serves it.
- **Compare, do not just probe.** The most telling faults are differences between IPv4 and IPv6 for the same name.
- **Honest about what it simulates.** NAT64 is simulated by default; the report says so.
- **Same habits as zoneblick.** Stable check IDs, severity levels, JSON output, exit codes that work in CI.

### Non-goals

- **Not a monitor.** It runs once and exits. Watching names over time is zoneblick's job (its `IPV` check group).
- **Not a browser.** It drives an installed Chrome; it does not ship or embed one.
- **Not a general web auditor.** No performance scores, no accessibility, no security headers.
- **Not a client-side test.** It does not tell a visitor whether their own connection has IPv6.
- **Not a NAT64 gateway.** It can use a real one; it does not provide one.

## 3. Why this is needed

A growing share of clients have no IPv4 address of their own: many mobile networks, and a rising number of corporate and cloud networks now that providers charge for IPv4 addresses. They reach the IPv4 internet through a translator, or not at all.

Failures hide behind fallback. A browser on a dual-stack connection that cannot reach a site over IPv6 quietly retries over IPv4, so the owner never sees the fault.

Published measurements show how common the gap is. A 2025 study (Thottungal Valapu and Heidemann, "Towards a Non-Binary View of IPv6 Adoption") found that only 12.6% of the top 100,000 websites qualify as fully IPv6-ready, because the rest rely on IPv4-only resources. Internet Society Pulse measurements put IPv6 support at 67% for the domains pages are first loaded from and 47% for the third-party domains they depend on.

### Prior art

| Tool | What it does | Why it leaves a gap |
|---|---|---|
| NAT64Check (Internet Society) | Loads a URL over IPv4, IPv6 and NAT64 and compares the results, including whether images, stylesheets and scripts load | A hosted service (2017, version 2 in 2019); running your own takes four servers |
| IETF 124 hackathon "IPv6 Web Resource Checker" (2025) | Checks a page's resources with a real browser | A hackathon project; confirms that a real browser is needed |
| test-ipv6.com and similar | Tells a visitor about their own connection | Tests the client, not the site |
| zoneblick `IPV` group (proposed) | Watches a zone's names for IPv6 faults over time | Works on names and servers, not on whole pages |

**The gap:** a tool you run yourself, against a local build or a live URL, that covers the whole page.

### How it divides the work with zoneblick

| | zoneblick `IPV` | v6blick |
|---|---|---|
| Unit | A zone and its names | A URL and everything it loads |
| When | On a schedule, with history | Once, on demand or in CI |
| Needs a browser | No | For the page test |
| Third-party hosts | Out of scope | The main subject |
| User | Whoever runs the DNS | Whoever builds the site |

## 4. The three networks

| Mode | Simulates | What can break |
|---|---|---|
| `dual` | An ordinary connection. The baseline. | Nothing, by definition |
| `nat64` | An IPv6-only network with a translator, as on many mobile networks | IPv4 addresses written directly into pages or scripts |
| `v6only` | An IPv6-only network with no translator | Every host without a working IPv6 address |

`v6only` gives the true dependency list. `nat64` shows what a real mobile user without IPv4 would hit today.

### How NAT64 is simulated

A real NAT64 network lets a client reach an IPv4-only **hostname**, because the network's DNS invents an IPv6 address for it and a gateway translates the traffic. It does not help with an IPv4 address used **directly**, because no DNS lookup happens.

The simulation applies exactly that rule:

- Destination is a hostname with an IPv6 address: connect over IPv6.
- Destination is a hostname with only an IPv4 address: allowed. Connect over IPv4 and mark the request "reached through translation".
- Destination is a literal IPv4 address: refused, and reported.

This needs no gateway and no special network. A `--nat64-prefix` option points the tool at a real gateway for verification.

One caveat is stated in every report: many phones run a second translator on the device (CLAT) that makes literal IPv4 addresses work too. A literal-address finding therefore reads "fails on IPv6-only networks without CLAT".

## 5. Check catalog

Severity levels follow zoneblick: **critical**, **warning**, **notice**, **info**.

### Addresses (`ADR`)

| ID | Check | Severity |
|---|---|---|
| ADR-01 | The host has an A record and no AAAA record | warning |
| ADR-02 | An AAAA record holds an address no client can use: loopback, private, IPv4-mapped, or a retired transition range | warning |
| ADR-03 | The host's zone cannot be resolved over IPv6 alone: at some level of the delegation no nameserver is reachable over IPv6 | warning |

### Reachability (`RCH`)

| ID | Check | Severity |
|---|---|---|
| RCH-01 | An AAAA record is published and nothing accepts a connection there | critical |
| RCH-02 | The TLS handshake fails over IPv6 and succeeds over IPv4 | critical |
| RCH-03 | A connection over IPv6 takes much longer to open than one over IPv4 | notice |
| RCH-04 | A client that tries IPv6 first waits more than a set time before IPv4 answers | notice |

RCH-01 is critical because a published address that does not answer is worse than none: every IPv6-capable client tries it first.

### Equivalence (`EQV`)

| ID | Check | Severity |
|---|---|---|
| EQV-01 | The host serves a different certificate over IPv6 than over IPv4 | warning |
| EQV-02 | The host gives a different HTTP status or redirect over IPv6 than over IPv4 | warning |
| EQV-03 | The response body differs in a way that is not explained by per-request content | notice |

EQV-03 compares size and a normalised hash, and is a notice because dynamic pages differ between any two requests.

### Page (`PGE`), needs a browser

| ID | Check | Severity |
|---|---|---|
| PGE-01 | The page's own document cannot be loaded in this mode | critical |
| PGE-02 | A resource fails in `v6only` because its host has no IPv6 address | warning; notice for a third party |
| PGE-03 | A resource's host has an IPv6 address and the request still fails over IPv6 | warning |
| PGE-04 | A redirect leads to a host that is unreachable in this mode | warning |

Resources are grouped by registrable domain, first party first. A third-party failure is a notice because the site owner cannot fix it, only replace or self-host it.

### Literal addresses (`LIT`), needs a browser

| ID | Check | Severity |
|---|---|---|
| LIT-01 | The page requests a URL whose host is a literal IPv4 address | warning |
| LIT-02 | A literal IPv4 address appears in the page's HTML, CSS or script text and was not requested | notice |

### Packet size (`MTU`)

| ID | Check | Severity |
|---|---|---|
| MTU-01 | A large response stalls over IPv6 and not over IPv4, which points to a path that drops "packet too big" messages | warning |

## 6. Architecture

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

### Components

- **Resolver.** Looks up A and AAAA for a host, and walks the delegation with IPv6 transport only for ADR-03. Starts from zoneblick's iterative resolver (see section 8).
- **Prober.** Opens connections to a host over each address family separately, completes TLS, sends one HTTP request, and records timings, the certificate and the response. No browser.
- **Mode proxy.** A forward proxy on `127.0.0.1`, alive only for the run. The browser sends it every request by hostname. The proxy resolves the name itself, applies the rules of the current mode, connects or refuses, and records the outcome. This is where `v6only` and `nat64` are enforced.
- **Browser driver.** Finds an installed Chrome or Chromium, starts it headless with a fresh temporary profile and the proxy set, loads the URL, waits for the page to settle, and collects the list of requests and the page source.
- **Findings.** Pure functions from recorded observations to findings. No network access inside a check, as in zoneblick.
- **Report.** Terminal text, JSON, and a self-contained HTML report.

### Stack

| Layer | Choice | Notes |
|---|---|---|
| Core | Rust, `tokio` | Same as zoneblick |
| DNS | `hickory-proto` | Same as zoneblick |
| TLS | `rustls` with `tokio-rustls` | Same as zoneblick |
| CLI | `clap` | |
| JSON | `serde`, `serde_json` | |
| Browser control | Chrome DevTools Protocol | Crate, or a small hand-written client over a WebSocket: **to be decided** |
| HTML report | A static template in the binary | No front-end framework |

**Flag:** the usual Nuxt stack does not fit. This is a command-line tool with no server and no UI beyond a static report. The project website is a plain static page, like zoneblick's.

### Why a proxy and not a network namespace

A real IPv6-only test network needs root, a second interface and a gateway. A proxy needs none of that, works the same on Linux and macOS, and runs in CI. It also sees each request as a hostname, which is what makes the literal-address check possible.

The cost: HTTP/3 does not pass through an ordinary proxy, so the browser runs with QUIC switched off. HTTP/3 over IPv6 is outside version 1.

## 7. Interfaces

### CLI

```
v6blick check <host-or-url>                   # DNS and connection checks, no browser
v6blick page <url>                            # whole page, all three modes
v6blick page <url> --mode v6only              # one mode
v6blick page <url> --json                     # machine output for CI
v6blick page <url> --html report.html         # self-contained report
v6blick page --urls urls.txt                  # many pages
v6blick doctor                                # does this machine have IPv6? is Chrome found?
```

### Exit codes

`0` clean, `1` notices or warnings only, `2` at least one critical, `3` the run itself failed. Same as zoneblick.

### Sketch of the output

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

## 8. Sharing code with zoneblick

zoneblick 0.14 already has an iterative resolver, per-server transports, a rate limiter and a TLS client. v6blick needs the first three at once.

| Option | For | Against |
|---|---|---|
| **Copy the resolver modules** into v6blick, noting the zoneblick commit they came from | No coupling; v6blick compiles only what it uses | Two copies to keep in step |
| Depend on zoneblick as a git dependency | One copy | Pulls in zoneblick's whole dependency tree (web server, database, mail), since it has no feature flags; its library API was not written for outside use |
| Extract a shared crate now | Clean in the long run | Restructures a released project for a tool that does not exist yet |

**Recommendation:** copy for version 1. Extract a shared crate once v6blick works and the shared surface is known. Both projects have the same owner and the same licence, so copying raises no licensing question.

## 9. Requirements and safety

- **Working IPv6 on the test machine.** `v6blick doctor` checks it. Without it, `v6only` and the IPv6 half of every comparison cannot run; the tool says so and exits with code 3 instead of reporting false failures.
- **It connects only to what the page asks for.** The URL's host and the resources the page loads. No crawling beyond the given URLs.
- **Polite.** Bounded concurrency, timeouts, no retries beyond what a browser would do.
- **Private addresses.** Refused by default, so a page cannot steer the tool at an internal address. `--allow-private` permits them, for testing a local build.
- **The proxy is local and short-lived.** It binds to `127.0.0.1` on a random port, accepts connections only for the length of the run, and is not usable as a general proxy.
- **The browser is isolated.** A fresh temporary profile per run, deleted afterwards. No saved logins, no extensions.
- **Test only sites you are entitled to test.** A page load is ordinary traffic, but run it against your own sites or with permission.

## 10. Build phases

| Phase | Deliverable | Proves |
|---|---|---|
| 0 | `v6blick check` and `doctor`: ADR, RCH and EQV checks, text and JSON output | The two-family comparison works |
| 1 | `v6blick page --mode v6only`: mode proxy, browser driver, PGE checks | The proxy design works |
| 2 | `nat64` simulation and LIT checks; all three modes in one run | The full picture |
| 3 | HTML report, `--urls`, a GitHub Action | It is usable on a real site |
| 4 | MTU-01 | The hard low-level check |
| 5 | Packaging and the project site at v6blick.zoneblick.com | Anyone can run it |

Phase 0 is useful on its own and needs no browser.

**Testing approach:** record real exchanges as fixtures and replay them, so checks are tested offline. For the proxy, a local test server with deliberately broken IPv6 listeners. Tests that need the live network or a browser are marked and skipped by default.

## 11. Risks and open questions

### Risks

- **Browser automation is the fragile part.** Chrome's flags and protocol change. Mitigation: use a small, stable subset of the DevTools Protocol, and keep `check` fully independent of it.
- **Pages that load on interaction.** A page that fetches content on scroll or click shows only its first view. Mitigation: report "first view only", and consider scripted steps later.
- **Simulated NAT64 is not a real network.** It does not reproduce DNS64 with DNSSEC, or a gateway's own faults. Mitigation: say so in the report, and offer `--nat64-prefix`.
- **False alarms from dynamic content.** EQV-03 can fire on pages that differ on every request. Mitigation: it is a notice, and it compares structure, not bytes.
- **Scope creep toward a general site auditor.** Every check must be about IPv6.

### Open questions

1. **Browser control:** an existing crate, or a small hand-written DevTools client? Either is a dependency decision for the owner.
2. **Shared code:** copy from zoneblick now, as recommended in section 8, or extract a crate first?
3. **Licence:** MIT or Apache-2.0, as zoneblick uses, is assumed. Confirm.
4. **Thresholds:** what counts as "much longer" in RCH-03 and RCH-04? Start from the delays browsers use before falling back.
5. **HTTP/3 over IPv6:** leave out of version 1, or add a separate probe later?
6. **Name:** v6blick.com, .dev, .net, .org and .app, and the `v6blick` name on npm and crates.io, showed no registration on 2026-11-14. Trademarks are unchecked.

---

## References

- zoneblick — https://zoneblick.com
- NAT64Check v2 (Internet Society) — https://www.internetsociety.org/blog/2019/01/nat64check-version-2-is-launched/
- IETF 124 hackathon, IPv6 Web Resource Checker — https://datatracker.ietf.org/meeting/124/materials/slides-124-hackathon-sessd-ipv6-web-resource-checker-00
- Towards a Non-Binary View of IPv6 Adoption (arXiv 2507.11678) — https://arxiv.org/abs/2507.11678
- Internet Society Pulse, IPv6 readiness beneath the surface — https://pulse.internetsociety.org/en/blog/the-web-looks-ipv6-ready-until-you-look-beneath-the-surface/
