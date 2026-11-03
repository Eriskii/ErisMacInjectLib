//! The root daemon's loop: watches for apps of the logged-in user starting and, once each is far
//! enough along, hands it to a [`Client`] to load into. Apps that keep crashing right after a load
//! are left alone until the daemon restarts.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use crate::{inject, log, procs};

const POLL: Duration = Duration::from_millis(100);
/// An app that hasn't finished starting by then isn't going to.
const GIVE_UP: Duration = Duration::from_secs(15);
/// An app that dies this soon after a load is checked for a crash report.
const CRASH_WINDOW: Duration = Duration::from_secs(10);
/// How long ReportCrash gets to write the report of an app that died.
const REPORT_WAIT: Duration = Duration::from_secs(5);
/// A process that isn't (yet) an app of the user's is looked at again for this long, in case it's
/// still on its way there: launchd starts apps through `xpcproxy`, as root, under the same pid.
const RECHECK: Duration = Duration::from_secs(15);
const CRASHES_BEFORE_BLOCKING: usize = 2;

/// System UI that isn't an ordinary app, and apps holding secrets: what [`Client::wants`] leaves
/// out by default.
pub const ALWAYS_SKIPPED: &[&str] = &[
    "com.apple.dock",
    "com.apple.loginwindow",
    "com.apple.WindowManager",
    "com.apple.controlcenter",
    "com.apple.notificationcenterui",
    "com.apple.Spotlight",
    "com.apple.systemuiserver",
    "com.apple.SecurityAgent",
    "com.apple.Passwords",
    "com.apple.keychainaccess",
    "com.1password.1password",
    "com.agilebits.onepassword7",
    "com.bitwarden.desktop",
];

/// What a daemon does with the apps it finds.
pub trait Client {
    /// Someone new is at the screen (or the daemon just started), before anything is loaded for
    /// them.
    fn user_changed(&mut self, _uid: u32, _home: &Path) {}

    /// Whether to load into `app`, run by the console user whose home is `home`. By default, regular
    /// apps that aren't in [`ALWAYS_SKIPPED`].
    fn wants(&mut self, app: &procs::App, _home: &Path) -> bool {
        regular(app)
    }

    /// Loads into `pid`, which is ready (see [`inject::ready`]).
    fn load(&mut self, pid: i32, bundle_id: &str) -> Result<(), inject::Error>;
}

/// A regular app (see [`procs::App::is_regular`]) that isn't in [`ALWAYS_SKIPPED`].
pub fn regular(app: &procs::App) -> bool {
    app.is_regular() && !ALWAYS_SKIPPED.contains(&app.id.as_str())
}

enum Seen {
    /// `recheck` until when to look again if the executable changes (see [`RECHECK`]).
    Ignored { recheck: Option<Instant>, exe: Option<PathBuf> },
    Starting { since: Instant, bundle: String },
    Loaded { at: Instant, wall: SystemTime, bundle: String, name: String },
}

/// An app that died soon after a load, waiting on a crash report.
struct Death {
    bundle: String,
    pid: i32,
    name: String,
    loaded: SystemTime,
    at: Instant,
}

/// Runs forever.
pub fn run(client: &mut impl Client) -> ! {
    let mut user: Option<(u32, PathBuf)> = None;
    let mut seen: HashMap<i32, Seen> = HashMap::new();
    let mut crashes: HashMap<String, Vec<Instant>> = HashMap::new();
    let mut deaths: Vec<Death> = Vec::new();
    let mut blocked: HashSet<String> = HashSet::new();
    let me = std::process::id() as i32;

    loop {
        std::thread::sleep(POLL);
        let Some((uid, home)) = procs::console_user() else {
            continue;
        };
        if user.as_ref().map(|u| u.0) != Some(uid) {
            client.user_changed(uid, &home);
            user = Some((uid, home.clone()));
        }

        let pids: HashSet<i32> = procs::all_pids().into_iter().collect();
        seen.retain(|pid, state| {
            if pids.contains(pid) {
                return true;
            }
            if let Seen::Loaded { at, wall, bundle, name } = state
                && at.elapsed() < CRASH_WINDOW
            {
                let (bundle, name) = (std::mem::take(bundle), std::mem::take(name));
                deaths.push(Death { bundle, pid: *pid, name, loaded: *wall, at: Instant::now() });
            }
            false
        });

        // Quitting an app soon after it started is no crash; only a crash report makes it one.
        deaths.retain(|d| {
            let crashed = crash_reported(&home, &d.name, d.loaded);
            if !crashed && d.at.elapsed() < REPORT_WAIT {
                return true;
            }
            if crashed {
                let recent = crashes.entry(d.bundle.clone()).or_default();
                recent.push(Instant::now());
                recent.retain(|t| t.elapsed() < Duration::from_secs(300));
                log!("{} (pid {}) crashed soon after loading", d.bundle, d.pid);
                if recent.len() >= CRASHES_BEFORE_BLOCKING && blocked.insert(d.bundle.clone()) {
                    log!("{} keeps crashing after loading; leaving it alone until the daemon restarts", d.bundle);
                }
            }
            false
        });

        for &pid in &pids {
            if pid == me {
                continue;
            }
            match seen.entry(pid) {
                Entry::Vacant(entry) => {
                    entry.insert(classify(pid, uid, &home, client, &blocked, Instant::now() + RECHECK));
                }
                Entry::Occupied(mut entry) => {
                    if let Seen::Ignored { recheck: Some(until), exe } = entry.get()
                        && Instant::now() < *until
                        && procs::executable(pid) != *exe
                    {
                        let until = *until;
                        entry.insert(classify(pid, uid, &home, client, &blocked, until));
                    }
                }
            }
            let Some(Seen::Starting { since, bundle }) = seen.get(&pid) else {
                continue;
            };
            let next = match inject::ready(pid) {
                Ok(false) if since.elapsed() < GIVE_UP => continue,
                Ok(false) => {
                    log!("{bundle} (pid {pid}) never finished starting");
                    done()
                }
                Ok(true) => match client.load(pid, bundle) {
                    Ok(()) => {
                        log!("loaded into {bundle} (pid {pid})");
                        let name = procs::executable(pid)
                            .and_then(|e| e.file_name().map(|n| n.to_string_lossy().into_owned()))
                            .unwrap_or_default();
                        Seen::Loaded { at: Instant::now(), wall: SystemTime::now(), bundle: bundle.clone(), name }
                    }
                    Err(e) => {
                        log!("loading into {bundle} (pid {pid}) failed: {e}");
                        done()
                    }
                },
                Err(e) => {
                    log!("checking {bundle} (pid {pid}) failed: {e}");
                    done()
                }
            };
            seen.insert(pid, next);
        }
    }
}

/// Ignored for good: not looked at again.
fn done() -> Seen {
    Seen::Ignored { recheck: None, exe: None }
}

/// A process that isn't an app of the user's (yet) is looked at again until `recheck`.
fn classify(pid: i32, uid: u32, home: &Path, client: &mut impl Client, blocked: &HashSet<String>, recheck: Instant) -> Seen {
    let exe = procs::executable(pid);
    let ignored = |exe: Option<PathBuf>| Seen::Ignored { recheck: Some(recheck), exe };
    if procs::owner(pid) != Some(uid) {
        return ignored(exe);
    }
    let Some(app) = exe.as_deref().and_then(procs::app) else {
        return ignored(exe);
    };
    if blocked.contains(&app.id) || !client.wants(&app, home) {
        return done();
    }
    Seen::Starting { since: Instant::now(), bundle: app.id }
}

/// Whether ReportCrash wrote a report for a process named `name` since `since`, in the user's or the
/// system's DiagnosticReports.
fn crash_reported(home: &Path, name: &str, since: SystemTime) -> bool {
    if name.is_empty() {
        return false;
    }
    let prefix = format!("{name}-");
    [home.join("Library/Logs/DiagnosticReports"), PathBuf::from("/Library/Logs/DiagnosticReports")].iter().any(|dir| {
        std::fs::read_dir(dir).into_iter().flatten().flatten().any(|entry| {
            let file = entry.file_name();
            let file = file.to_string_lossy();
            file.starts_with(&prefix)
                && file.ends_with(".ips")
                && entry.metadata().and_then(|m| m.modified()).is_ok_and(|m| m >= since)
        })
    })
}
