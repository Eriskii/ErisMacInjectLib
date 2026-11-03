//! Starts a thread inside another process at a given address.
//!
//! This is its own arm64e binary because, when the target is arm64e, the kernel only accepts the
//! thread's start address if the caller signed it with pointer-authentication keys of its own, and
//! plain arm64 processes (like the CLIs that use eris-inject) have none. It's no_std for the same reason
//! the payload is: Rust's std crashes in arm64e processes.
//!
//! usage: eris-inject-thread <pid> <pc> <sp>    addresses in hex; needs root
//!        eris-inject-thread --self-test        starts a thread in itself, no root needed
//!
//! The code at <pc> must park with 0x73697265 ("eris") in x0 when it no longer needs the thread;
//! the thread is then terminated.
#![no_std]
#![no_main]

use core::ffi::{CStr, c_char, c_int, c_void};
use core::fmt::{self, Write};

type KernReturn = c_int;
type MachPort = u32;

#[link(name = "System")]
unsafe extern "C" {
    static mach_task_self_: MachPort;
    fn task_for_pid(task: MachPort, pid: c_int, out: *mut MachPort) -> KernReturn;
    fn mach_port_deallocate(task: MachPort, port: MachPort) -> KernReturn;
    fn mach_vm_allocate(task: MachPort, addr: *mut u64, size: u64, flags: c_int) -> KernReturn;
    fn thread_create(task: MachPort, out: *mut MachPort) -> KernReturn;
    fn thread_create_running(task: MachPort, flavor: c_int, state: *const u32, count: u32, out: *mut MachPort) -> KernReturn;
    fn thread_terminate(thread: MachPort) -> KernReturn;
    fn thread_get_state(thread: MachPort, flavor: c_int, state: *mut u32, count: *mut u32) -> KernReturn;
    fn thread_convert_thread_state(
        thread: MachPort,
        direction: c_int,
        flavor: c_int,
        in_state: *const u32,
        in_count: u32,
        out_state: *mut u32,
        out_count: *mut u32,
    ) -> KernReturn;
    fn mach_error_string(kr: KernReturn) -> *const c_char;
    fn usleep(micros: u32) -> c_int;
    fn write(fd: c_int, buf: *const c_void, len: usize) -> isize;
    fn abort() -> !;
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { abort() }
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct ArmThreadState64 {
    x: [u64; 29],
    fp: u64,
    lr: u64,
    sp: u64,
    pc: u64,
    cpsr: u32,
    flags: u32,
}

const ARM_THREAD_STATE64: c_int = 6;
const STATE_COUNT: u32 = (size_of::<ArmThreadState64>() / 4) as u32;
const THREAD_CONVERT_THREAD_STATE_FROM_SELF: c_int = 2;
/// `ptrauth_string_discriminator("pc")`
const PC_DISCRIMINATOR: u64 = 0x7481;
/// `ptrauth_string_discriminator("sp")`
const SP_DISCRIMINATOR: u64 = 0xCBED;
const DONE_MARKER: u64 = 0x7369_7265;

struct Stderr;

impl Write for Stderr {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        unsafe { write(2, s.as_ptr().cast(), s.len()) };
        Ok(())
    }
}

struct Failure(&'static str, KernReturn);

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg = unsafe { CStr::from_ptr(mach_error_string(self.1)) };
        write!(f, "{}: {} ({})", self.0, msg.to_str().unwrap_or("?"), self.1)
    }
}

fn check(step: &'static str, kr: KernReturn) -> Result<(), Failure> {
    if kr == 0 { Ok(()) } else { Err(Failure(step, kr)) }
}

/// Signs `pc` the way `__darwin_arm_thread_state64_set_pc_fptr` does: IA key, "pc" discriminator.
fn sign_pc(pc: u64) -> u64 {
    let mut v = pc;
    unsafe { core::arch::asm!("pacia {0}, {1}", inout(reg) v, in(reg) PC_DISCRIMINATOR, options(pure, nomem, nostack)) };
    v
}

/// Signs `sp` the way `__darwin_arm_thread_state64_set_sp` does: DA key, "sp" discriminator.
/// Unsigned, the kernel's check fails and the thread starts on a poisoned stack pointer.
fn sign_sp(sp: u64) -> u64 {
    let mut v = sp;
    unsafe { core::arch::asm!("pacda {0}, {1}", inout(reg) v, in(reg) SP_DISCRIMINATOR, options(pure, nomem, nostack)) };
    v
}

fn run_thread(task: MachPort, pc: u64, sp: u64) -> Result<(), Failure> {
    let state = ArmThreadState64 { pc: sign_pc(pc), sp: sign_sp(sp), ..Default::default() };
    let mut converted = ArmThreadState64::default();
    let mut count = STATE_COUNT;
    // The kernel re-signs the state for the target, but needs a thread of the target to do it.
    let mut scratch = 0;
    check("create thread", unsafe { thread_create(task, &mut scratch) })?;
    let kr = unsafe {
        thread_convert_thread_state(
            scratch,
            THREAD_CONVERT_THREAD_STATE_FROM_SELF,
            ARM_THREAD_STATE64,
            (&raw const state).cast(),
            STATE_COUNT,
            (&raw mut converted).cast(),
            &mut count,
        )
    };
    unsafe {
        thread_terminate(scratch);
        mach_port_deallocate(mach_task_self_, scratch);
    }
    check("convert thread state", kr)?;

    let mut thread = 0;
    check("start thread", unsafe {
        thread_create_running(task, ARM_THREAD_STATE64, (&raw const converted).cast(), count, &mut thread)
    })?;
    let result = (|| {
        for _ in 0..200 {
            unsafe { usleep(10_000) };
            let mut s = ArmThreadState64::default();
            let mut c = STATE_COUNT;
            check("read thread state", unsafe { thread_get_state(thread, ARM_THREAD_STATE64, (&raw mut s).cast(), &mut c) })?;
            if s.x[0] == DONE_MARKER {
                return Ok(());
            }
        }
        Err(Failure("thread never reported back", 0))
    })();
    unsafe {
        thread_terminate(thread);
        mach_port_deallocate(mach_task_self_, thread);
    }
    result
}

fn inject(pid: c_int, pc: u64, sp: u64) -> Result<(), Failure> {
    let mut task = 0;
    check("task_for_pid", unsafe { task_for_pid(mach_task_self_, pid, &mut task) })?;
    let result = run_thread(task, pc, sp);
    unsafe { mach_port_deallocate(mach_task_self_, task) };
    result
}

core::arch::global_asm!(
    ".p2align 2",
    ".globl _eris_inject_thread_self_test",
    "_eris_inject_thread_self_test:",
    // Touch the stack: a badly signed stack pointer only shows up once it's used.
    "  stp x29, x30, [sp, #-16]!",
    "  ldp x29, x30, [sp], #16",
    "  movz x0, #0x7265",
    "  movk x0, #0x7369, lsl #16",
    "1: b 1b",
);

unsafe extern "C" {
    fn eris_inject_thread_self_test();
}

/// Runs a parked thread in this very process, which exercises the same signing path.
fn self_test() -> Result<(), Failure> {
    let task = unsafe { mach_task_self_ };
    let mut stack = 0u64;
    check("allocate stack", unsafe { mach_vm_allocate(task, &mut stack, 16 * 1024, 1) })?;
    run_thread(task, eris_inject_thread_self_test as *const () as u64, stack + 8 * 1024)
}

fn parse_hex(arg: &[u8]) -> Option<u64> {
    let digits = arg.strip_prefix(b"0x").unwrap_or(arg);
    if digits.is_empty() {
        return None;
    }
    digits.iter().try_fold(0u64, |acc, &d| {
        let v = (d as char).to_digit(16)? as u64;
        acc.checked_mul(16)?.checked_add(v)
    })
}

fn parse_pid(arg: &[u8]) -> Option<c_int> {
    core::str::from_utf8(arg).ok()?.parse().ok()
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: c_int, argv: *const *const c_char) -> c_int {
    let args: [&[u8]; 4] = core::array::from_fn(|i| {
        if (i as c_int) < argc { unsafe { CStr::from_ptr(*argv.add(i)) }.to_bytes() } else { b"" }
    });
    let result = match (argc, args) {
        (2, [_, b"--self-test", ..]) => self_test(),
        (4, [_, pid, pc, sp]) => match (parse_pid(pid), parse_hex(pc), parse_hex(sp)) {
            (Some(pid), Some(pc), Some(sp)) => inject(pid, pc, sp),
            _ => Err(Failure("bad arguments", 0)),
        },
        _ => {
            let _ = writeln!(Stderr, "usage: eris-inject-thread <pid> <pc> <sp> | --self-test");
            return 2;
        }
    };
    match result {
        Ok(()) => 0,
        Err(e) => {
            let _ = writeln!(Stderr, "eris-inject-thread: {e}");
            1
        }
    }
}
