# v6blick

Does your site work for someone who has no IPv4?

v6blick tests a host or a whole page from three kinds of network: a normal dual-stack connection, an IPv6-only network with a NAT64 translator, and an IPv6-only network with no translator. It reports what breaks in each, down to the third-party script that has no IPv6 address.

**Status:** in design. Nothing is built yet.

- Design document: [DESIGN.md](DESIGN.md)
- Companion project: [zoneblick](https://zoneblick.com), which watches DNS zones over time

## What it will do

- **`v6blick check <host>`** — DNS and connection checks over IPv4 and IPv6, and a comparison of the two. No browser needed.
- **`v6blick page <url>`** — loads the page in an installed Chrome through a local proxy that enforces each network mode, and lists every resource that fails.
- **`v6blick doctor`** — whether this machine has working IPv6 and a usable browser.

## Repository layout

| Path | Contents |
|---|---|
| `DESIGN.md` | High-level design |
| `KICKOFF.md` | Claude Code prompt for Phase 0 |

## Responsible use

Test your own sites, or sites you have permission to test.

## License

Not added yet. MIT or Apache-2.0, as zoneblick uses, is the working assumption.
