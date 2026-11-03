//! Loading a payload dylib into running macOS apps, and the root daemon that does it for every app
//! as it starts.
//!
//! A payload is a `no_std` arm64 dylib built on `eris-inject-payload`, whose `payload!` macro
//! exports `_<name>_bootstrap` and `_<name>_main`. [`inject::inject`] maps it into an app without
//! dyld, so library validation never sees it, and has `eris-inject-thread` (an arm64e helper that
//! has to sit next to the running executable) start it. Needs root, SIP's debugging restrictions
//! off and, for arm64e apps, the `-arm64e_preview_abi` boot-arg.
//!
//! Based on the technique yabai uses for its scripting addition (MIT, Åsmund Vikane; arm64e path
//! after Jeremy Legendre), by way of apple-sharpenerer; the code is our own.

pub mod daemon;
pub mod inject;
pub mod launchd;
pub mod macho;
pub mod notify;
pub mod procs;

/// The local time, for log lines.
pub fn timestamp() -> String {
    let now = unsafe { libc::time(std::ptr::null_mut()) };
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let mut buf = [0u8; 32];
    let n = unsafe {
        libc::localtime_r(&now, &mut tm);
        libc::strftime(buf.as_mut_ptr().cast(), buf.len(), c"%Y-%m-%d %H:%M:%S".as_ptr(), &tm)
    };
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

/// A timestamped line on stderr, which launchd sends to the daemon's log.
#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => { eprintln!("{} {}", $crate::timestamp(), format!($($arg)*)) };
}
