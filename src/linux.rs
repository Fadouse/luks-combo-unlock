// SPDX-License-Identifier: GPL-3.0-only
// Linux x86-64 glibc ABI. Other targets are rejected at compile time.
#![allow(dead_code)]
use std::ffi::{c_char, c_int, c_ulong, c_void};
#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
compile_error!("only x86_64-unknown-linux-gnu is supported");
pub const O_NOFOLLOW: c_int = 0x20000;
pub const O_CLOEXEC: c_int = 0x80000;
pub const O_NONBLOCK: c_int = 0x800;
pub const F_GETFL: c_int = 3;
pub const F_SETFL: c_int = 4;
pub const LOCK_EX: c_int = 2;
pub const LOCK_NB: c_int = 4;
pub const MS_NOSUID: c_ulong = 2;
pub const MS_NODEV: c_ulong = 4;
pub const MS_NOEXEC: c_ulong = 8;
#[repr(C)]
pub struct Rlimit {
    pub current: u64,
    pub maximum: u64,
}
unsafe extern "C" {
    pub fn geteuid() -> u32;
    pub fn umask(mask: u32) -> u32;
    pub fn setrlimit(resource: c_int, limits: *const Rlimit) -> c_int;
    pub fn prctl(option: c_int, arg2: usize, arg3: usize, arg4: usize, arg5: usize) -> c_int;
    pub fn signal(signal: c_int, handler: usize) -> usize;
    pub fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
    pub fn flock(fd: c_int, operation: c_int) -> c_int;
    pub fn mount(
        source: *const c_char,
        target: *const c_char,
        kind: *const c_char,
        flags: c_ulong,
        data: *const c_void,
    ) -> c_int;
    pub fn umount2(target: *const c_char, flags: c_int) -> c_int;
    pub fn mlock(addr: *const c_void, len: usize) -> c_int;
    pub fn munlock(addr: *const c_void, len: usize) -> c_int;
}
