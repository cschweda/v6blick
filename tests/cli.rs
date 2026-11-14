//! The binary itself, for what it does before it touches the network.

use std::process::{Command, Output};

fn v6blick(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_v6blick"))
        .args(args)
        .env("NO_COLOR", "1")
        .output()
        .unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).to_string()
}

#[test]
fn help_names_the_commands_and_the_exit_codes() {
    let out = v6blick(&["--help"]);
    assert_eq!(out.status.code(), Some(0));
    let help = text(&out.stdout);
    assert!(help.contains("check") && help.contains("doctor"), "{help}");
    assert!(help.contains("Exit codes: 0 clean"), "{help}");

    let out = v6blick(&["check", "--help"]);
    let help = text(&out.stdout);
    assert!(
        help.contains("--json") && help.contains("--allow-private"),
        "{help}"
    );
}

#[test]
fn the_version_is_printed() {
    let out = v6blick(&["--version"]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        text(&out.stdout).trim(),
        format!("v6blick {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn a_bad_command_line_is_a_failed_run_not_a_critical_finding() {
    for args in [
        &[][..],
        &["check"],
        &["page", "https://example.org"],
        &["check", "a", "b"],
    ] {
        let out = v6blick(args);
        assert_eq!(out.status.code(), Some(3), "{args:?}");
        assert!(out.stdout.is_empty());
    }
}

#[test]
fn an_address_in_place_of_a_host_is_refused_before_any_network_use() {
    let out = v6blick(&["check", "192.0.2.1"]);
    assert_eq!(out.status.code(), Some(3));
    assert!(out.stdout.is_empty());
    let err = text(&out.stderr);
    assert!(
        err.starts_with("v6blick: '192.0.2.1' is an address, not a host name"),
        "{err}"
    );

    let out = v6blick(&["check", "ftp://example.org/", "--json"]);
    assert_eq!(out.status.code(), Some(3));
    assert!(out.stderr.is_empty());
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["schema_version"], 1);
    assert_eq!(doc["target"], "ftp://example.org/");
    assert_eq!(doc["error"]["kind"], "invalid_target");
    assert_eq!(doc["exit_code"], 3);
}
