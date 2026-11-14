//! What `v6blick doctor` looks at on this machine, apart from the network
//! test it shares with `check`: the address IPv6 traffic would leave
//! from, and whether a Chrome or Chromium is installed. The browser is
//! only looked for. It is never started.

use std::ffi::OsString;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};

/// The address this machine would send from to reach `target`. Nothing
/// is sent: connecting a UDP socket only asks the system for a route.
pub fn source_address(target: IpAddr) -> Option<IpAddr> {
    let local: SocketAddr = match target {
        IpAddr::V4(_) => "0.0.0.0:0".parse().expect("valid address"),
        IpAddr::V6(_) => "[::]:0".parse().expect("valid address"),
    };
    let socket = UdpSocket::bind(local).ok()?;
    socket.connect(SocketAddr::new(target, 53)).ok()?;
    socket.local_addr().ok().map(|a| a.ip())
}

/// The names a Chrome or Chromium binary goes by on a search path.
const NAMES: &[&str] = &[
    "google-chrome",
    "google-chrome-stable",
    "chromium",
    "chromium-browser",
    "chrome",
];

/// Where a Chrome or Chromium may be, most likely first. `var` reads an
/// environment variable, so that tests can supply their own.
pub fn chrome_candidates(var: impl Fn(&str) -> Option<OsString>) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let home = var("HOME").map(PathBuf::from);
    if cfg!(target_os = "macos") {
        let apps = [
            "Google Chrome.app/Contents/MacOS/Google Chrome",
            "Chromium.app/Contents/MacOS/Chromium",
        ];
        for app in apps {
            out.push(Path::new("/Applications").join(app));
        }
        if let Some(home) = &home {
            for app in apps {
                out.push(home.join("Applications").join(app));
            }
        }
    }
    if cfg!(windows) {
        for base in ["ProgramFiles", "ProgramFiles(x86)", "LocalAppData"] {
            if let Some(dir) = var(base) {
                let dir = PathBuf::from(dir);
                out.push(dir.join("Google/Chrome/Application/chrome.exe"));
                out.push(dir.join("Chromium/Application/chrome.exe"));
            }
        }
    }
    if let Some(path) = var("PATH") {
        for dir in std::env::split_paths(&path) {
            for name in NAMES {
                out.push(dir.join(name));
                if cfg!(windows) {
                    out.push(dir.join(format!("{name}.exe")));
                }
            }
        }
    }
    if cfg!(target_os = "linux") {
        out.push(PathBuf::from("/snap/bin/chromium"));
    }
    out
}

/// The first candidate that is a file.
pub fn find_chrome(candidates: &[PathBuf]) -> Option<&PathBuf> {
    candidates.iter().find(|p| p.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_browser_on_the_search_path_is_found() {
        let dir = std::env::temp_dir().join(format!("v6blick-doctor-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let var = |name: &str| (name == "PATH").then(|| dir.clone().into_os_string());
        let candidates = chrome_candidates(var);
        assert!(candidates.contains(&dir.join("chromium")));
        // Nothing is there yet. (A browser installed on this machine in
        // its usual place would be found first, so look only in `dir`.)
        let in_dir: Vec<PathBuf> = candidates
            .into_iter()
            .filter(|p| p.starts_with(&dir))
            .collect();
        assert_eq!(find_chrome(&in_dir), None);
        let name = if cfg!(windows) {
            "chromium.exe"
        } else {
            "chromium"
        };
        std::fs::write(dir.join(name), b"").unwrap();
        assert_eq!(find_chrome(&in_dir), Some(&dir.join(name)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_source_address_is_of_the_family_asked_for() {
        // Loopback always has a route, with or without a network.
        let v4 = source_address("127.0.0.1".parse().unwrap());
        assert_eq!(v4, Some("127.0.0.1".parse().unwrap()));
    }
}
