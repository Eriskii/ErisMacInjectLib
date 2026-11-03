//! The bits of a runtime a no_std dylib needs: allocator, panic handler, logging.

use core::alloc::{GlobalAlloc, Layout};
use core::ffi::{c_char, c_int, c_void};
use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

#[link(name = "System")]
unsafe extern "C" {
    pub fn getpid() -> c_int;
    pub fn usleep(micros: u32) -> c_int;
    fn abort() -> !;
    fn malloc(size: usize) -> *mut c_void;
    fn free(p: *mut c_void);
    fn posix_memalign(out: *mut *mut c_void, align: usize, size: usize) -> c_int;
    fn syslog(priority: c_int, format: *const c_char, ...);
}

struct Malloc;

unsafe impl GlobalAlloc for Malloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // malloc already guarantees 16-byte alignment on Darwin.
        if layout.align() <= 16 {
            return unsafe { malloc(layout.size()) as *mut u8 };
        }
        let mut p = core::ptr::null_mut();
        match unsafe { posix_memalign(&mut p, layout.align(), layout.size()) } {
            0 => p as *mut u8,
            _ => core::ptr::null_mut(),
        }
    }

    unsafe fn dealloc(&self, p: *mut u8, _: Layout) {
        unsafe { free(p as *mut c_void) }
    }
}

#[global_allocator]
static ALLOCATOR: Malloc = Malloc;

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    crate::log!("panic: {info}");
    unsafe { abort() }
}

static PREFIX: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());
static PREFIX_LEN: AtomicUsize = AtomicUsize::new(0);

/// Set by [`crate::payload!`] before the payload starts.
pub fn set_log_prefix(prefix: &'static str) {
    PREFIX_LEN.store(prefix.len(), Ordering::Relaxed);
    PREFIX.store(prefix.as_ptr() as *mut u8, Ordering::Release);
}

fn prefix() -> &'static [u8] {
    let p = PREFIX.load(Ordering::Acquire);
    if p.is_null() {
        return b"";
    }
    unsafe { core::slice::from_raw_parts(p, PREFIX_LEN.load(Ordering::Relaxed)) }
}

/// Writes one line to the unified log, after the payload's prefix
/// (`log stream --predicate 'eventMessage BEGINSWITH "[prefix]"'`).
pub fn log_line(message: &str) {
    let prefix = prefix();
    let mut line = alloc::vec::Vec::with_capacity(prefix.len() + message.len() + 1);
    line.extend_from_slice(prefix);
    line.extend(message.bytes().filter(|&b| b != 0));
    line.push(0);
    const LOG_NOTICE: c_int = 5;
    unsafe { syslog(LOG_NOTICE, c"%s".as_ptr(), line.as_ptr()) };
}

#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => { $crate::rt::log_line(&$crate::alloc::format!($($arg)*)) };
}
