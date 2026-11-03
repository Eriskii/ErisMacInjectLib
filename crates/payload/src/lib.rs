//! The runtime for a payload eris-inject loads into apps: PAC signing, a bit of the Objective-C
//! runtime, an allocator, a panic handler, logging, and [`payload!`], which exports the entry
//! points the injector starts.
//!
//! Payloads are `no_std` on purpose. Apple's own apps are arm64e, where every code pointer that
//! crosses into system code is PAC-signed, and rustc doesn't emit that signing for arm64 code, so
//! std (whose thread-locals are reached through such pointers) crashes there. Everything that
//! hands code to the system goes through [`pac`] instead.
//!
//! A payload crate is a `cdylib` that depends on this one and invokes [`payload!`] once.
#![no_std]

#[doc(hidden)]
pub extern crate alloc;

pub mod objc;
pub mod pac;
pub mod rt;
pub mod sys;

/// What a payload's thread leaves in x0 once it has handed over to a pthread; the thread helper
/// waits for it. "eris" in memory.
pub const DONE_MARKER: u64 = 0x7369_7265;

/// Exports a payload's entry points:
///
/// - `_<name>_bootstrap`, where the injector starts a bare Mach thread. Such a thread can't run
///   normal code, so it asks for a real pthread to run `_<name>_main`, then parks with
///   [`DONE_MARKER`] in x0 for the injector to see;
/// - `_<name>_main`, which calls `start(true)`;
/// - a constructor calling `start(false)`, for when the dylib is just `dlopen`ed during
///   development.
///
/// `log` is the prefix of the payload's lines in the unified log.
#[macro_export]
macro_rules! payload {
    (name: $name:literal, log: $log:literal, start: $start:path $(,)?) => {
        core::arch::global_asm!(
            concat!(".globl _", $name, "_bootstrap"),
            concat!(".no_dead_strip _", $name, "_bootstrap"),
            ".p2align 2",
            concat!("_", $name, "_bootstrap:"),
            "  sub sp, sp, #0x20",
            "  mov x0, sp",
            "  mov x1, #0",
            concat!("  adrp x2, _", $name, "_main@PAGE"),
            concat!("  add x2, x2, _", $name, "_main@PAGEOFF"),
            "  paciza x2",
            "  mov x3, #0",
            "  bl _pthread_create_from_mach_thread",
            "  movz x0, #0x7265",
            "  movk x0, #0x7369, lsl #16",
            "1: b 1b",
        );

        #[unsafe(export_name = concat!($name, "_main"))]
        pub extern "C" fn __eris_payload_main(_: *mut core::ffi::c_void) -> *mut core::ffi::c_void {
            $crate::rt::set_log_prefix(concat!("[", $log, "] "));
            $start(true);
            core::ptr::null_mut()
        }

        #[used]
        #[unsafe(link_section = "__DATA,__mod_init_func")]
        static __ERIS_PAYLOAD_INIT: extern "C" fn() = __eris_payload_loaded_by_dyld;

        extern "C" fn __eris_payload_loaded_by_dyld() {
            $crate::rt::set_log_prefix(concat!("[", $log, "] "));
            $start(false);
        }
    };
}
