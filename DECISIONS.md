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
