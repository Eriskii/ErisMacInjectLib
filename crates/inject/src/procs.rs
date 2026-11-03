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

/// The app bundle whose main executable this is. Helper apps nested inside another bundle
/// (browser renderers and the like) don't count.
pub fn app_bundle(executable: &Path) -> Option<PathBuf> {
    let macos = executable.parent()?;
    let contents = macos.parent()?;
    let bundle = contents.parent()?;
    let is_app = macos.file_name()? == "MacOS"
        && contents.file_name()? == "Contents"
        && bundle.extension()? == "app";
    let nested = bundle.ancestors().skip(1).any(|a| a.extension().is_some_and(|e| e == "app"));
    (is_app && !nested).then(|| bundle.to_path_buf())
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

/// The bundle identifier, if `executable` is the main executable of an ordinary app: one with a
/// Dock icon (not a menu bar agent or background-only helper), and not a system component.
pub fn regular_app(bundle: &Path, executable: &Path) -> Option<String> {
    if is_system_component(bundle) {
        return None;
    }
    let info: plist::Dictionary = plist::from_file(bundle.join("Contents/Info.plist")).ok()?;
    let main = info.get("CFBundleExecutable")?.as_string()?;
    if executable.file_name()? != main || flag(&info, "LSUIElement") || flag(&info, "LSBackgroundOnly") {
        return None;
    }
    info.get("CFBundleIdentifier")?.as_string().map(String::from)
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

    #[test]
    fn recognises_top_level_apps_only() {
        let app = |p: &str| app_bundle(Path::new(p));
        assert_eq!(app("/Applications/Helium.app/Contents/MacOS/Helium"), Some("/Applications/Helium.app".into()));
        assert_eq!(app("/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder"), Some("/System/Library/CoreServices/Finder.app".into()));
        assert_eq!(
            app("/Applications/Helium.app/Contents/Frameworks/Helium Framework.framework/Helpers/Helium Helper.app/Contents/MacOS/Helium Helper"),
            None
        );
        assert_eq!(app("/usr/bin/login"), None);
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
