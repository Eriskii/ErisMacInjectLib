//! Pointer authentication. The payload is one arm64 build used in every app: in arm64e apps these
//! instructions sign and strip for real, in plain arm64 apps the keys are off and they do nothing.

use core::arch::asm;
use core::ffi::c_void;

/// Signs a code pointer we hand to system code (IMPs, callbacks) the way arm64e C code would:
/// IA key, zero discriminator.
#[inline(always)]
pub fn sign(f: *const c_void) -> *const c_void {
    let mut v = f as usize;
    unsafe { asm!("paciza {0}", inout(reg) v, options(pure, nomem, nostack)) };
    v as *const c_void
}

/// Strips the signature from a code pointer we got from system code, so Rust can call it with a
/// plain branch.
#[inline(always)]
pub fn strip(f: *const c_void) -> *const c_void {
    let mut v = f as usize;
    unsafe { asm!("xpaci {0}", inout(reg) v, options(pure, nomem, nostack)) };
    v as *const c_void
}
