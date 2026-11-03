//! The root daemon's loop: watches for apps of the logged-in user starting and, once each is far
//! enough along, hands it to a [`Client`] to load into. Apps that keep dying right after a load
//! are left alone until the daemon restarts.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::{inject, log, procs};

const POLL: Duration = Duration::from_millis(100);
/// An app that hasn't finished starting by then isn't going to.
const GIVE_UP: Duration = Duration::from_secs(15);
/// An app that dies this soon after a load counts as a crash.
const CRASH_WINDOW: Duration = Duration::from_secs(10);
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
    Ignored,
    Starting { since: Instant, bundle: String },
    Loaded { at: Instant, bundle: String },
}

/// Runs forever.
pub fn run(client: &mut impl Client) -> ! {
    let mut user: Option<(u32, PathBuf)> = None;
    let mut seen: HashMap<i32, Seen> = HashMap::new();
    let mut crashes: HashMap<String, Vec<Instant>> = HashMap::new();
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
            if let Seen::Loaded { at, bundle } = state
                && at.elapsed() < CRASH_WINDOW
            {
                let recent = crashes.entry(bundle.clone()).or_default();
                recent.push(Instant::now());
                recent.retain(|t| t.elapsed() < Duration::from_secs(300));
                log!("{bundle} (pid {pid}) exited {:.1}s after loading", at.elapsed().as_secs_f32());
                if recent.len() >= CRASHES_BEFORE_BLOCKING && blocked.insert(bundle.clone()) {
                    log!("{bundle} keeps dying after loading; leaving it alone until the daemon restarts");
                }
            }
            false
        });

        for &pid in &pids {
            if pid == me {
                continue;
            }
            if let Entry::Vacant(entry) = seen.entry(pid) {
                entry.insert(classify(pid, uid, &home, client, &blocked));
            }
            let Some(Seen::Starting { since, bundle }) = seen.get(&pid) else {
                continue;
            };
            let next = match inject::ready(pid) {
                Ok(false) if since.elapsed() < GIVE_UP => continue,
                Ok(false) => {
                    log!("{bundle} (pid {pid}) never finished starting");
                    Seen::Ignored
                }
                Ok(true) => match client.load(pid, bundle) {
                    Ok(()) => {
                        log!("loaded into {bundle} (pid {pid})");
                        Seen::Loaded { at: Instant::now(), bundle: bundle.clone() }
                    }
                    Err(e) => {
                        log!("loading into {bundle} (pid {pid}) failed: {e}");
                        Seen::Ignored
                    }
                },
                Err(e) => {
                    log!("checking {bundle} (pid {pid}) failed: {e}");
                    Seen::Ignored
                }
            };
            seen.insert(pid, next);
        }
    }
}

fn classify(pid: i32, uid: u32, home: &Path, client: &mut impl Client, blocked: &HashSet<String>) -> Seen {
    if procs::owner(pid) != Some(uid) {
        return Seen::Ignored;
    }
    let Some(exe) = procs::executable(pid) else {
        return Seen::Ignored;
    };
    let Some(app) = procs::app(&exe) else {
        return Seen::Ignored;
    };
    if blocked.contains(&app.id) || !client.wants(&app, home) {
        return Seen::Ignored;
    }
    Seen::Starting { since: Instant::now(), bundle: app.id }
}
