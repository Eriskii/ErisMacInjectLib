//! Just enough of the Objective-C runtime: messaging, method swizzling, runtime-defined classes,
//! strings and retain counts.

use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::{CStr, c_char, c_void};
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::pac;

pub type Id = *mut c_void;
pub type Sel = *const c_void;
pub type Imp = *const c_void;
pub const NIL: Id = core::ptr::null_mut();

#[link(name = "objc")]
unsafe extern "C" {
    pub fn objc_msgSend();
    fn objc_getClass(name: *const c_char) -> Id;
    fn sel_registerName(name: *const c_char) -> Sel;
    fn class_getInstanceMethod(cls: Id, sel: Sel) -> *mut c_void;
    fn class_getClassMethod(cls: Id, sel: Sel) -> *mut c_void;
    fn method_getImplementation(method: *mut c_void) -> Imp;
    fn method_setImplementation(method: *mut c_void, imp: Imp) -> Imp;
    fn objc_allocateClassPair(superclass: Id, name: *const c_char, extra_bytes: usize) -> Id;
    fn objc_registerClassPair(cls: Id);
    fn class_addMethod(cls: Id, sel: Sel, imp: Imp, types: *const c_char) -> bool;
    fn objc_retain(obj: Id) -> Id;
    fn objc_release(obj: Id);
    fn objc_autoreleasePoolPush() -> *mut c_void;
    fn objc_autoreleasePoolPop(pool: *mut c_void);
}

pub fn class(name: &CStr) -> Id {
    unsafe { objc_getClass(name.as_ptr()) }
}

pub fn sel(name: &CStr) -> Sel {
    unsafe { sel_registerName(name.as_ptr()) }
}

/// `msg!(ReturnType; receiver, c"selector:", arg => ArgType, ...)`
#[macro_export]
macro_rules! msg {
    ($ret:ty; $obj:expr, $sel:expr $(, $arg:expr => $ty:ty)* $(,)?) => {{
        #[allow(unused_unsafe)]
        let result = unsafe {
            let send: unsafe extern "C" fn($crate::objc::Id, $crate::objc::Sel $(, $ty)*) -> $ret =
                core::mem::transmute($crate::objc::objc_msgSend as *const ());
            send($obj, $crate::objc::sel($sel) $(, $arg)*)
        };
        result
    }};
}

pub fn responds(obj: Id, name: &CStr) -> bool {
    !obj.is_null() && msg!(bool; obj, c"respondsToSelector:", sel(name) => Sel)
}

pub fn retain(obj: Id) -> Id {
    if obj.is_null() { obj } else { unsafe { objc_retain(obj) } }
}

pub fn release(obj: Id) {
    if !obj.is_null() {
        unsafe { objc_release(obj) }
    }
}

/// Runs `f` inside an autorelease pool.
pub fn autoreleasing<R>(f: impl FnOnce() -> R) -> R {
    let pool = unsafe { objc_autoreleasePoolPush() };
    let r = f();
    unsafe { objc_autoreleasePoolPop(pool) };
    r
}

/// An autoreleased NSString.
pub fn ns(s: &str) -> Id {
    const UTF8: usize = 4;
    let string = msg!(Id; class(c"NSString"), c"alloc");
    let string = msg!(Id; string, c"initWithBytes:length:encoding:", s.as_ptr() => *const u8, s.len() => usize, UTF8 => usize);
    msg!(Id; string, c"autorelease")
}

pub fn nsstring(s: &CStr) -> Id {
    msg!(Id; class(c"NSString"), c"stringWithUTF8String:", s.as_ptr() => *const c_char)
}

/// An NSString's text; empty for nil.
pub fn string(s: Id) -> String {
    if s.is_null() {
        return String::new();
    }
    let p = msg!(*const c_char; s, c"UTF8String");
    if p.is_null() {
        return String::new();
    }
    String::from(unsafe { CStr::from_ptr(p) }.to_str().unwrap_or(""))
}

/// An NSString's UTF-16 code units; empty for nil.
pub fn utf16(s: Id) -> Vec<u16> {
    if s.is_null() {
        return Vec::new();
    }
    let len = msg!(usize; s, c"length");
    (0..len).map(|i| msg!(u16; s, c"characterAtIndex:", i => usize)).collect()
}

/// A method's implementation from before we replaced it, stripped so Rust can call it.
pub struct Original(AtomicPtr<c_void>);

impl Original {
    pub const fn new() -> Self {
        Self(AtomicPtr::new(core::ptr::null_mut()))
    }

    pub fn get(&self) -> Imp {
        self.0.load(Ordering::Acquire)
    }
}

impl Default for Original {
    fn default() -> Self {
        Self::new()
    }
}

fn replace(m: *mut c_void, imp: Imp, original: &Original) -> bool {
    if m.is_null() {
        return false;
    }
    // Publish the original before our implementation can be called.
    original.0.store(pac::strip(unsafe { method_getImplementation(m) }) as *mut c_void, Ordering::Release);
    unsafe { method_setImplementation(m, pac::sign(imp)) };
    true
}

/// Replaces `class`'s instance method; false if either doesn't exist.
pub fn swizzle(class_name: &CStr, method: &CStr, imp: Imp, original: &Original) -> bool {
    let cls = class(class_name);
    !cls.is_null() && replace(unsafe { class_getInstanceMethod(cls, sel(method)) }, imp, original)
}

/// Replaces `class`'s class method; false if either doesn't exist.
pub fn swizzle_class(class_name: &CStr, method: &CStr, imp: Imp, original: &Original) -> bool {
    let cls = class(class_name);
    !cls.is_null() && replace(unsafe { class_getClassMethod(cls, sel(method)) }, imp, original)
}

/// Creates and registers an NSObject-style class; nil if a class with that name already exists.
pub fn define_class(name: &CStr, superclass: &CStr, methods: &[(&CStr, Imp, &CStr)]) -> Id {
    let cls = unsafe { objc_allocateClassPair(class(superclass), name.as_ptr(), 0) };
    if cls.is_null() {
        return NIL;
    }
    for &(method, imp, types) in methods {
        unsafe { class_addMethod(cls, sel(method), pac::sign(imp), types.as_ptr()) };
    }
    unsafe { objc_registerClassPair(cls) };
    cls
}
