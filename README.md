# ErisMacInjectLib

Loading our own code into every macOS app: a payload dylib mapped into running apps without dyld,
and the root daemon that does it as each app starts. Shared by
[apple-sharpenerer](https://github.com/Eriskii/apple-sharpenerer) and
[ErisMenus](../../apps/ErisMenus). Rust, for Apple Silicon on macOS 26.

- **`eris-inject`** (`crates/inject`), for the command that installs and runs the daemon:
  - `inject`: map a payload into a process, apply chained fixups against the shared cache, patch
    values into its statics, and start it; `ready` says whether a process has come far enough
    along. `self_test` maps a payload into the calling process without root.
  - `daemon`: the loop that finds the logged-in user's apps as they start and hands each to a
    `Client` to load into. System UI and password managers are never loaded into, and apps that
    die twice right after a load are left alone until the daemon restarts.
  - `launchd`: install and uninstall the daemon's files, its LaunchDaemon and its command link.
  - `notify`: live settings as the state of a Darwin notification, which payloads can watch even
    in the sandbox.
  - `procs`: processes, app bundles and the console user.
- **`eris-inject-payload`** (`crates/payload`), the `no_std` runtime a payload is built on: PAC
  signing, Objective-C messaging and swizzling, an allocator, a panic handler, unified-log logging,
  Darwin notifications, and `payload!`, which exports the entry points the injector starts.
- **`eris-inject-thread`** (`crates/thread`), the arm64e helper that starts a payload's thread with
  properly signed registers. It ships next to the command that injects.

## Requirements

- SIP's debugging restrictions off and the `-arm64e_preview_abi` boot-arg (for arm64e apps, which
  is all of Apple's), as for yabai's scripting addition
- Root, to get other processes' task ports

## Writing a payload

A `cdylib` crate, `no_std`, built for `aarch64-apple-darwin` with `-Zbuild-std=core,alloc` and
`MACOSX_DEPLOYMENT_TARGET=26.0` (which makes the linker emit chained fixups, the only kind the
mapper reads):

```rust
#![no_std]
extern crate alloc;

pub(crate) use eris_inject_payload::{log, msg, objc};

eris_inject_payload::payload!(name: "thing", log: "Thing", start: start);

// `injected` is true when started by the injector, false when just dlopened.
fn start(injected: bool) {
    log!("hello from pid {}", unsafe { eris_inject_payload::rt::getpid() });
}
```

Any code pointer handed to the system (method implementations, callbacks) must go through
`pac::sign`; `objc::swizzle` and `sys::on_main` already do. std can't be used: in arm64e apps its
thread-locals are reached through pointers rustc doesn't sign.

The injecting side, run as root, with `eris-inject-thread` next to its executable:

```rust
use eris_inject::inject::{self, Payload};

let payload = Payload { path: "/path/to/libthing.dylib".as_ref(), name: "thing", patches: &[] };
inject::inject(pid, &payload)?;
```

Build the helper with
`cargo build --release -p eris-inject-thread -Zbuild-std=core,alloc --target arm64e-apple-darwin`.

## Credits

The technique is yabai's, for its scripting addition (MIT, Åsmund Vikane; the arm64e path is based
on work by Jeremy Legendre). It came here by way of apple-sharpenerer; the code is our own.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
