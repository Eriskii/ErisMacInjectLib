//! Installing a daemon: its files in a root-owned folder (they end up inside every app), a
//! LaunchDaemon that keeps it running, and a link to its command on the PATH.

use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;

/// A daemon as installed.
#[derive(Clone, Copy, Debug)]
pub struct Service<'a> {
    pub label: &'a str,
    /// Where its files go, e.g. `/Library/Application Support/<name>`.
    pub dir: &'a str,
    /// Its stdout and stderr, e.g. `/Library/Logs/<name>.log`.
    pub log: &'a str,
    /// The files copied from next to the running executable, with their modes. The first is the
    /// command launchd runs.
    pub files: &'a [(&'a str, u32)],
    /// launchd runs `<dir>/<first file> <arguments>`.
    pub arguments: &'a [&'a str],
    /// A link to the command, e.g. `/usr/local/bin/<name>`.
    pub link: Option<&'a str>,
}

pub fn require_root() -> Result<(), String> {
    if unsafe { libc::geteuid() } == 0 { Ok(()) } else { Err("this needs root; run it with sudo".into()) }
}

fn launchctl(args: &[&str]) -> Result<(), String> {
    let out = Command::new("/bin/launchctl").args(args).output().map_err(|e| format!("launchctl: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!("launchctl {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim()))
    }
}

impl Service<'_> {
    pub fn plist_path(&self) -> PathBuf {
        PathBuf::from(format!("/Library/LaunchDaemons/{}.plist", self.label))
    }

    pub fn file(&self, name: &str) -> PathBuf {
        Path::new(self.dir).join(name)
    }

    fn plist(&self) -> String {
        let (label, log) = (self.label, self.log);
        let mut program = format!("        <string>{}</string>\n", self.file(self.files[0].0).display());
        for argument in self.arguments {
            program.push_str(&format!("        <string>{argument}</string>\n"));
        }
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
{program}    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{log}</string>
    <key>StandardErrorPath</key>
    <string>{log}</string>
</dict>
</plist>
"#
        )
    }

    /// Copies this build (the files next to the running executable) into place and (re)starts
    /// the daemon. Needs root.
    pub fn install(&self) -> Result<(), String> {
        require_root()?;
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let from = exe.parent().ok_or("can't tell where this build lives")?;
        let to = Path::new(self.dir);
        std::fs::create_dir_all(to).map_err(|e| format!("{}: {e}", self.dir))?;

        // Stop the old daemon first so nothing is mid-injection with files we replace.
        let _ = launchctl(&["bootout", &format!("system/{}", self.label)]);
        if from.canonicalize().ok() != to.canonicalize().ok() {
            for &(name, mode) in self.files {
                let (src, dst) = (from.join(name), to.join(name));
                // Copy then rename, so apps that already mapped an old payload keep a valid file.
                let tmp = to.join(format!(".{name}.new"));
                std::fs::copy(&src, &tmp).map_err(|e| format!("{}: {e}", src.display()))?;
                std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode)).map_err(|e| e.to_string())?;
                std::fs::rename(&tmp, &dst).map_err(|e| format!("{}: {e}", dst.display()))?;
            }
        }
        let _ = Command::new("/usr/sbin/chown").args(["-R", "root:wheel", self.dir]).status();

        if let Some(link) = self.link {
            if let Some(parent) = Path::new(link).parent() {
                std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
            }
            let _ = std::fs::remove_file(link);
            symlink(self.file(self.files[0].0), link).map_err(|e| format!("{link}: {e}"))?;
        }

        let plist = self.plist_path();
        std::fs::write(&plist, self.plist()).map_err(|e| format!("{}: {e}", plist.display()))?;
        launchctl(&["bootstrap", "system", &plist.to_string_lossy()])
    }

    /// Stops the daemon and removes its files. Needs root.
    pub fn uninstall(&self) -> Result<(), String> {
        require_root()?;
        let _ = launchctl(&["bootout", &format!("system/{}", self.label)]);
        let _ = std::fs::remove_file(self.plist_path());
        if let Some(link) = self.link {
            let _ = std::fs::remove_file(link);
        }
        std::fs::remove_dir_all(self.dir)
            .or_else(|e| if e.kind() == std::io::ErrorKind::NotFound { Ok(()) } else { Err(e) })
            .map_err(|e| format!("{}: {e}", self.dir))
    }

    /// The daemon's pid if launchd has it running.
    pub fn pid(&self) -> Option<u32> {
        let out = Command::new("/bin/launchctl").args(["print", &format!("system/{}", self.label)]).output().ok()?;
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .find_map(|l| l.trim().strip_prefix("pid = ").and_then(|p| p.trim().parse().ok()))
    }

    pub fn installed(&self) -> bool {
        self.plist_path().exists()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_plist_runs_the_first_file_with_the_arguments() {
        let service = Service {
            label: "io.example.thing",
            dir: "/Library/Application Support/Thing",
            log: "/Library/Logs/thing.log",
            files: &[("thing", 0o755), ("libthing.dylib", 0o644)],
            arguments: &["daemon"],
            link: None,
        };
        let plist = service.plist();
        assert!(plist.contains("<string>/Library/Application Support/Thing/thing</string>\n        <string>daemon</string>"));
        assert!(plist.contains("<string>io.example.thing</string>"));
        assert_eq!(service.plist_path(), PathBuf::from("/Library/LaunchDaemons/io.example.thing.plist"));
    }
}
