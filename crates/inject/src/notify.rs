//! Live settings for loaded payloads: a packed 64-bit value travels as the state of a Darwin
//! notification, which payloads watch (see `eris_inject_payload::sys::observe_darwin`). Works for
//! sandboxed apps and needs no root.

use std::ffi::{CStr, c_char, c_int};

unsafe extern "C" {
    fn notify_register_check(name: *const c_char, token: *mut c_int) -> u32;
    fn notify_set_state(token: c_int, state: u64) -> u32;
    fn notify_get_state(token: c_int, state: *mut u64) -> u32;
    fn notify_post(name: *const c_char) -> u32;
    fn notify_cancel(token: c_int) -> u32;
}

/// A registration for a notification. Holding one keeps its state alive.
pub struct Channel {
    name: &'static CStr,
    token: c_int,
}

impl Channel {
    pub fn open(name: &'static CStr) -> Result<Self, String> {
        let mut token = 0;
        match unsafe { notify_register_check(name.as_ptr(), &mut token) } {
            0 => Ok(Channel { name, token }),
            status => Err(format!("can't register for {} (status {status})", name.to_string_lossy())),
        }
    }

    /// Stores `packed` and tells every payload to pick it up.
    pub fn publish(&self, packed: u64) -> Result<(), String> {
        match unsafe { (notify_set_state(self.token, packed), notify_post(self.name.as_ptr())) } {
            (0, 0) => Ok(()),
            (a, b) => Err(format!("can't publish {} (status {a}/{b})", self.name.to_string_lossy())),
        }
    }

    /// The published value; None while nothing (or 0) has been published.
    pub fn current(&self) -> Option<u64> {
        let mut state = 0;
        (unsafe { notify_get_state(self.token, &mut state) } == 0 && state != 0).then_some(state)
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        unsafe { notify_cancel(self.token) };
    }
}
