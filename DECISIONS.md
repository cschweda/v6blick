# Decisions

Choices made during implementation where `DESIGN.md` was silent or loose. One line each.

## Phase 0

### Code shared with zoneblick

- The resolver is copied from zoneblick, not depended on (design section 8). Source: zoneblick commit `849da4d169e3aa9dc11a9390702649e7ebcef368` (release 0.15.0).
- Copied whole: `src/resolver/hints.rs` and `src/resolver/limiter.rs`, as `src/resolve/hints.rs` and `src/resolve/limiter.rs`.
- Copied in part: `src/resolver/transport.rs`, the DNS half only (live, replay and recording client, UDP and TCP sending, `never_contacted`). Its HTTP half, which needs `reqwest`, and the deep-probe query variants are left behind.
- Copied and changed: `src/resolver/iterate.rs`. `find_delegation` is gone; `lookup` returns every alias in an answer, not the first; a new `trace` keeps the referrals it followed when the walk fails; a zone none of whose nameservers has an address of a usable family says so.
- Copied as types and helpers into `src/observe.rs`: `Vantage`, `ReferralStep`, `Glue`, `Transport`, a `QType` cut down to NS, A, AAAA and CNAME, `is_ancestor_or_equal`, `parent_name`.
- Copied from `src/resolver/probe.rs`: `detect_vantage`. From `src/resolver/smtp.rs`: the `AnyCertificate` verifier and the DER reader for a certificate's names and expiry.
- Left behind: zoneblick's `chain`, `deep`, `exposure`, `policy`, `probe`, `signed` and `smtp` resolver modules, and everything outside the resolver.
- The test helper `tests/common/mod.rs` (hand-built DNS worlds) follows zoneblick's, cut down to what the resolver tests need.

### Dependencies and licence

- SHA-256 comes from `ring` 0.17, which rustls already compiles as its crypto provider, so no crate is added to the tree (agreed with the author).
- The licence is MIT or Apache-2.0, at the user's option; both files are copied from zoneblick unchanged (agreed with the author).

### Resolving

- Names are resolved from the root by v6blick's own iterative resolver. No recursive resolver is asked, and the operating system's resolver is used in one case only, below.
- DNS politeness is zoneblick's (16 queries in flight, 5 per second per server address, 3 s UDP and 5 s TCP timeouts), except that a timed-out query is retried once, not twice.
- An alias is followed from zone to zone, at most eight times; a loop or a longer chain is a failed lookup.
- The IPv6-only walk is the same resolver with IPv4 switched off. It is run for the host and, when the host is an alias, for the name its addresses belong to. Each walk starts with an empty cache so that its path is complete.
- A walk that ends in "no such name" or "no such data" counts as reached: the zone's servers answered over IPv6.
- Names in observations and output are lowercase and fully qualified, with a trailing dot, as in zoneblick.
- With `--allow-private`, a name the public DNS does not know (`localhost`, a name in a hosts file) is looked up with the operating system's resolver. Such a name has no delegation, so no IPv6-only walk is made, and ADR-02 does not judge its addresses.
- After a security review of the copied resolver: one run sends at most 600 DNS queries, and only the first level of a glueless delegation tries more than one nameserver name. zoneblick's copy has neither limit.

### Probing

- The HTTP request is written by hand on `tokio` and `tokio-rustls`: HTTP/1.1, `Connection: close`, `Accept-Encoding: identity`. No HTTP client crate is used, because the probe must choose the address and keep the certificate and the timings.
- Certificates are accepted without checking them against trusted authorities, as zoneblick's certificate probe does. The fingerprint, names, expiry and whether a name matches the host are recorded (agreed with the author).
- At most four addresses of each family are probed, four probes at a time. A probe is never retried.
- A bare host is probed as `https://host/` and `http://host/`; a full address as given. An IP address in place of a host name is a failed run.
- Timeouts: 5 s to connect, 5 s for the TLS handshake, 10 s for the request and the whole response. At most 1 MiB of a body is read.
- At most five redirects are followed. They stay in the address family the probe started in: the same address for the same host, and for another host an address of that family, found by the same resolver. A redirect to a host with no such address ends the chain and is recorded.
- Private, loopback and link-local destinations are refused unless `--allow-private` is given, also as the target of a redirect. Unspecified, multicast, documentation, IPv4-mapped and other special addresses are refused always.
- The request to an address is an exchange only when a request was sent. A connection or handshake that failed is told by `connect` and `tls`.

### Checks

- A difference between the families is reported only when no IPv6 address agrees with any IPv4 address, since the servers behind several addresses need not be identical.
- ADR-01 needs a definite "no record" for AAAA; a failed lookup is not one.
- ADR-02's unusable ranges: loopback, unspecified, unique-local, link-local, multicast, documentation, IPv4-mapped, IPv4-compatible, 6to4, Teredo, the 6bone, site-local, the well-known NAT64 prefix and the discard prefix.
- ADR-03 is reported once for each zone the walk stops at, also when the host and its alias target both stop there.
- RCH-01 is per IPv6 address, and fires when every port that was tried failed to open. An address that was not contacted says nothing.
- RCH-02 needs a successful handshake on the same port over IPv4.
- RCH-03: the fastest address of each family is compared on each port, and fires when IPv6 takes more than 250 ms longer, the delay after which a browser that races the families (RFC 8305) starts its IPv4 attempt. One measurement, no averaging; the widest gap is reported (agreed with the author).
- RCH-04: a failing IPv6 attempt that takes more than 1 s to fail, while an IPv4 address on that port works. A refusal is quiet; a silent drop is reported (agreed with the author).
- EQV-02 compares the first response (status and `Location`) and where the redirects end. A redirect that works over IPv4 and cannot be followed over IPv6 is EQV-02.
- A fault behind the redirect from `http://` to `https://` is reported once, for the `https://` address.
- EQV-03's "normalised hash" is a hash of the sequence of HTML tag names, without text, attributes, comments, or what is inside script and style elements. It fires when that differs, or when the sizes differ by more than a fifth and by more than 256 bytes. It is not run where EQV-02 fired (agreed with the author).
- Every finding carries what it means for visitors and how to fix it, in the text output and as `meaning` and `fix` in the JSON; each severity heading says in a line what the severity means (asked for by the author).

### Output and commands

- The `--json` document is the observation followed by the findings, the summary and the exit code. A saved document can be read back as an observation and checked again.
- With `--json`, a failed run prints a short JSON error document on stdout, as zoneblick does.
- A command-line usage error exits `3`, not clap's default `2`.
- `check` exits `3` when this machine has no working IPv6, no working IPv4, or no network, before anything is said about the host.
- `doctor` exits `0` when IPv4 and IPv6 both work and `3` otherwise. A missing browser does not change the code in Phase 0, because `check` does not need one.
- `doctor` looks for Chrome or Chromium in the usual places and on the search path. It never starts it.
- Test fixtures: recorded runs are saved `--json` documents, written by an ignored test, not by a command-line option.

### After the security audit of 0.1.0

- The address rule is one rule for web servers, redirect targets and nameservers. zoneblick lets DNS queries go to private nameservers; v6blick does not, without `--allow-private`.
- A replaying DNS client, which sends nothing, also answers for servers in the documentation ranges, because the test worlds live there.
- One probe with all its redirects has 30 s. The whole run has 120 s; a run that is stopped reports nothing, since half a comparison would mislead.
- EQV-03: a body with no HTML tags must be the same bytes over both families, and a page must have the same title. A page's title is recorded.
- A response whose body ends before its announced length, or before its last chunk, is a failed response.
- An address longer than 2,048 characters is not followed; printed header values stop at 1,024 characters.
- With `--allow-private`, the system resolver is asked only after a definite "no such name" from the public DNS, not after any failed lookup.
- A run in which no connection opens on either family is a failed run (`unreachable`, or `not_contacted` when every address was refused), not a list of findings. RCH-01 needs a working IPv4 address when IPv4 was tried.
- An IPv6-only walk cut short by the query limit is marked `unfinished` and is not judged by ADR-03.
- No line of the text output begins with an address.
- The red team's attack tests are kept as regression tests in `tests/redteam_*.rs`.

## Phase 1

- The browser is controlled by a DevTools client written in this repository, over a WebSocket written in this repository, with no new dependency for either (chosen by the author on 2026-11-14, settling open question 1 of the design).
- First party and third party are told apart by the Public Suffix List, through the `psl` crate (chosen by the author). It brings one further crate, `psl-types`.
- Every page run loads the page in `dual` first, as the baseline, in a browser and behind a proxy of its own. A request counts against `v6only` only when it worked in `dual`. This is an addition to the design's Phase 1 (agreed with the author).
- A page that does not load in `dual` is a failed run, since there is nothing to compare.
- `page` takes a full address, or a host name, which is loaded over `https://`. `--mode` has one value in this phase, `v6only`, which is also the default.
- In `dual` the proxy tries IPv6 first and gives it 2 s before IPv4, as a browser that prefers IPv6 falls back. In `v6only` it tries IPv6 only: a host with no IPv6 address is refused, and so is a literal IPv4 address.
- The proxy uses the prober's address rule, and tries at most four addresses of a host.
- A refused HTTPS tunnel is answered with a 502, which the browser reports as a failed connection. A refused plain request is dropped without an answer, because an answer from the proxy would look like the site's own page.
- A plain HTTP connection through the proxy carries one request and is then closed, so that each host is decided for itself.
- The proxy carries only what the page asked for. The driver holds every request in the browser (the DevTools `Fetch` domain) until its host has been announced to the proxy; a connection for a host nobody announced waits 1.5 s and is then refused. This keeps the browser's own traffic (update checks, sign-in services) from leaving the machine and from being counted.
- The navigation is started without waiting for its answer, and frames and workers are set up the same way: while a request is held, the browser puts other commands off.
- Frames of other sites and workers are attached to as they start, held until their network events are on, so that their requests are seen too.
- The page counts as settled after its load event, when nothing is under way and 1.5 s have passed without a network event; a page that keeps a request open settles after 3 s of quiet. A load has 30 s, a run 150 s.
- The browser repeats a failed navigation for its error page and cancels that itself; a cancelled request is not the page and is not counted.
- One resolver serves the whole page run, one lookup at a time, each host once, spreading its queries over the servers of each zone. A page run may send 5,000 DNS queries.
- The browser gets a fresh profile directory that only the user can read, deleted when the load ends, and cannot outlive the call that started it.
- PGE-01 is reported for the host that failed: the page's own, or the one it redirects to. A resource redirected to an unreachable host is PGE-04; the page itself redirected to one is PGE-01.
- PGE-02 to PGE-04 are one finding per host, with the number of requests. A literal IPv4 address is left to the LIT checks of Phase 2.
- The summary of a finding is wrapped at 96 characters in the text output.
- At most 2,000 requests of a page are kept.

### Project site

- The site is one static page in `docs/`, served by GitHub Pages from `main`, at https://cschweda.github.io/v6blick/ until the design's v6blick.zoneblick.com is set up (asked for by the author).
- Examples, screenshots and the social card use the author's own sites, metaincognita.com and zoneblick.com, with real output (asked for by the author).
