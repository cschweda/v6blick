//! v6blick: tests whether a website works for someone who has no IPv4.
//!
//! Phase 0 provides `check` and `doctor`. The modules follow the
//! components in `DESIGN.md`:
//!
//! - [`observe`]: the recorded observations of one run (plain data, no I/O)
//! - [`resolve`]: DNS lookups from the root, and the IPv6-only walk (network I/O)
//! - [`probe`]: TCP, TLS and HTTP to one address of one family (network I/O)
//! - [`checks`]: pure functions from observations to findings (no I/O)
//! - [`output`]: human and JSON rendering, and the exit code
//! - [`cli`]: argument parsing and the commands

pub mod observe;
pub mod resolve;
