//! Finding app processes and who's at the keyboard.

use std::ffi::{CStr, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

pub fn all_pids() -> Vec<i32> {
    let mut pids = vec![0 as libc::pid_t; 4096];
    loop {
        let bytes = (pids.len() * size_of::<libc::pid_t>()) as c_int;
        let n = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast::<c_void>(), bytes) };
        if n < 0 {
            return Vec::new();
        }
        if (n as usize) < pids.len() {
            pids.truncate(n as usize);
            return pids.into_iter().filter(|&p| p > 0).collect();
        }
        pids.resize(pids.len() * 2, 0);
    }
}

pub fn executable(pid: i32) -> Option<PathBuf> {
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), buf.len() as u32) };
    (n > 0).then(|| PathBuf::from(std::ffi::OsStr::from_bytes(&buf[..n as usize])))
}

pub fn owner(pid: i32) -> Option<u32> {
    let mut info: libc::proc_bsdshortinfo = unsafe { std::mem::zeroed() };
    let size = size_of::<libc::proc_bsdshortinfo>() as c_int;
    let n = unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDT_SHORTBSDINFO, 0, (&raw mut info).cast(), size) };
    (n == size).then_some(info.pbsi_uid)
}

/// What kind of process an app bundle's main executable runs as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// An ordinary app, with a Dock icon.
    Regular,
    /// A UI app without a Dock icon (`LSUIElement`): menu bar extras, agents, login items.
    Agent,
    /// An XPC service that runs AppKit's app loop (`XPCService.RunLoopType = NSApplicationMain`):
    /// the UI services behind open and save panels, System Settings panes and the like.
    Service,
    /// An app extension (`.appex`).
    Extension,
    /// No UI: `LSBackgroundOnly`, or an XPC service that doesn't run AppKit's app loop.
    Background,
}

/// The app (or XPC service) bundle a process runs from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct App {
    pub id: String,
    pub bundle: PathBuf,
    pub kind: Kind,
    /// Part of the system rather than something a person opens: inside /System/Library (bar
    /// Finder and CoreServices/Applications) or a framework.
    pub system: bool,
    /// Inside another app bundle.
    pub nested: bool,
    /// Inside a framework or a Frameworks folder, where browsers and Electron keep their helper
    /// processes.
    pub in_frameworks: bool,
}

impl App {
    /// An ordinary app a person opened: a Dock icon, not part of the system, not a helper.
    pub fn is_regular(&self) -> bool {
        self.kind == Kind::Regular && !self.system && !self.nested
    }
}

/// The bundle `executable` is the main executable of, if it's an app, app extension or XPC
/// service bundle.
pub fn app(executable: &Path) -> Option<App> {
    let macos = executable.parent()?;
    let contents = macos.parent()?;
    let bundle = contents.parent()?;
    let extension = bundle.extension()?;
    if macos.file_name()? != "MacOS" || contents.file_name()? != "Contents" || !["app", "appex", "xpc"].iter().any(|e| extension == *e) {
        return None;
    }
    let info: plist::Dictionary = plist::from_file(contents.join("Info.plist")).ok()?;
    if executable.file_name()? != info.get("CFBundleExecutable")?.as_string()? {
        return None;
    }
    let kind = if extension == "xpc" {
        let run_loop = info.get("XPCService").and_then(|v| v.as_dictionary()).and_then(|d| d.get("RunLoopType"));
        if run_loop.and_then(|t| t.as_string()).is_some_and(|t| t.contains("NSApplicationMain")) {
            Kind::Service
        } else {
            Kind::Background
        }
    } else if extension == "appex" {
        Kind::Extension
    } else if flag(&info, "LSBackgroundOnly") {
        Kind::Background
    } else if flag(&info, "LSUIElement") {
        Kind::Agent
    } else {
        Kind::Regular
    };
    let ancestors = || bundle.ancestors().skip(1);
    Some(App {
        id: info.get("CFBundleIdentifier")?.as_string()?.to_string(),
        bundle: bundle.to_path_buf(),
        kind,
        system: is_system_component(bundle),
        nested: ancestors().any(|a| a.extension().is_some_and(|e| e == "app")),
        in_frameworks: ancestors().any(|a| a.extension().is_some_and(|e| e == "framework") || a.file_name().is_some_and(|n| n == "Frameworks")),
    })
}

/// System components that happen to be packaged as apps; Finder and the utilities in
/// CoreServices/Applications are real apps.
fn is_system_component(bundle: &Path) -> bool {
    let s = bundle.to_string_lossy();
    let user_facing = s == "/System/Library/CoreServices/Finder.app" || s.starts_with("/System/Library/CoreServices/Applications/");
    s.contains(".framework/") || ((s.starts_with("/System/Library/") || s.starts_with("/Library/Apple/")) && !user_facing)
}

fn flag(info: &plist::Dictionary, key: &str) -> bool {
    match info.get(key) {
        Some(plist::Value::Boolean(b)) => *b,
        Some(plist::Value::String(s)) => matches!(s.as_str(), "1" | "YES" | "yes" | "true"),
        Some(plist::Value::Integer(i)) => i.as_signed() == Some(1),
        _ => false,
    }
}

/// Whoever is logged in at the screen, with their home directory.
pub fn console_user() -> Option<(u32, PathBuf)> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::stat(c"/dev/console".as_ptr(), &mut st) } != 0 || st.st_uid == 0 {
        return None;
    }
    Some((st.st_uid, home_of(st.st_uid)?))
}

pub fn home_of(uid: u32) -> Option<PathBuf> {
    let pw = unsafe { libc::getpwuid(uid) };
    if pw.is_null() {
        return None;
    }
    let dir = unsafe { CStr::from_ptr((*pw).pw_dir) };
    Some(PathBuf::from(std::ffi::OsStr::from_bytes(dir.to_bytes())))
}

pub fn uid_of(name: &str) -> Option<u32> {
    let name = std::ffi::CString::new(name).ok()?;
    let pw = unsafe { libc::getpwnam(name.as_ptr()) };
    (!pw.is_null()).then(|| unsafe { (*pw).pw_uid })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exe(bundle: &str) -> PathBuf {
        let info: plist::Dictionary = plist::from_file(Path::new(bundle).join("Contents/Info.plist")).unwrap();
        Path::new(bundle).join("Contents/MacOS").join(info.get("CFBundleExecutable").unwrap().as_string().unwrap())
    }

    #[test]
    fn finder_is_a_regular_app() {
        let finder = app(&exe("/System/Library/CoreServices/Finder.app")).unwrap();
        assert_eq!(finder.id, "com.apple.finder");
        assert!(finder.is_regular());
    }

    #[test]
    fn system_ui_agents_and_view_services_are_told_apart() {
        let control_center = app(&exe("/System/Library/CoreServices/ControlCenter.app")).unwrap();
        assert_eq!(control_center.kind, Kind::Agent);
        assert!(control_center.system && !control_center.is_regular());
        let panels = app(&exe("/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/com.apple.appkit.xpc.openAndSavePanelService.xpc")).unwrap();
        assert_eq!(panels.kind, Kind::Service);
        assert!(panels.in_frameworks);
        let web = app(&exe("/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.WebContent.xpc")).unwrap();
        assert_eq!(web.kind, Kind::Background);
    }

    #[test]
    fn only_bundles_main_executables_count() {
        assert_eq!(app(Path::new("/usr/bin/login")), None);
        assert_eq!(app(Path::new("/System/Library/CoreServices/Finder.app/Contents/MacOS/not-finder")), None);
    }

    #[test]
    fn system_components_are_not_apps() {
        let component = |p: &str| is_system_component(Path::new(p));
        assert!(!component("/System/Library/CoreServices/Finder.app"));
        assert!(!component("/System/Applications/TextEdit.app"));
        assert!(!component("/System/Library/CoreServices/Applications/Screen Sharing.app"));
        assert!(component("/System/Library/CoreServices/UserNotificationCenter.app"));
        assert!(component("/Library/Apple/System/Library/CoreServices/XProtect.app"));
        assert!(component("/System/Library/PrivateFrameworks/AppSSO.framework/Support/AppSSOAgent.app"));
    }
}
