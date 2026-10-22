//! Raw Landlock ABI: constants and structures from `include/uapi/linux/landlock.h`.

use std::io;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};

pub const CREATE_RULESET_VERSION: u32 = 1 << 0;
pub const RULE_PATH_BENEATH: libc::c_int = 1;
pub const RULE_NET_PORT: libc::c_int = 2;

/// Size and layout must match the kernel. Trailing fields the running kernel
/// does not know are accepted as long as they are zero.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct RulesetAttr {
    pub handled_access_fs: u64,
    pub handled_access_net: u64,
    pub scoped: u64,
}

/// `struct landlock_path_beneath_attr` is declared `__attribute__((packed))`.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct PathBeneathAttr {
    pub allowed_access: u64,
    pub parent_fd: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NetPortAttr {
    pub allowed_access: u64,
    pub port: u64,
}

fn check(ret: libc::c_long) -> io::Result<libc::c_long> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

/// Returns the highest ABI version the kernel supports.
pub fn abi_version() -> io::Result<u32> {
    // SAFETY: documented probe form: NULL attr, size 0, VERSION flag.
    let r = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<RulesetAttr>(),
            0usize,
            CREATE_RULESET_VERSION,
        )
    };
    check(r).map(|v| v as u32)
}

pub fn create_ruleset(attr: &RulesetAttr) -> io::Result<OwnedFd> {
    // SAFETY: attr points to a live, correctly sized struct.
    let r = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            attr as *const RulesetAttr,
            std::mem::size_of::<RulesetAttr>(),
            0u32,
        )
    };
    // SAFETY: on success the kernel returned a new, owned file descriptor.
    check(r).map(|fd| unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

pub fn add_path_rule(ruleset: RawFd, attr: &PathBeneathAttr) -> io::Result<()> {
    // SAFETY: attr is a valid packed struct for the duration of the call.
    let r = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset,
            RULE_PATH_BENEATH,
            attr as *const PathBeneathAttr,
            0u32,
        )
    };
    check(r).map(drop)
}

pub fn add_net_rule(ruleset: RawFd, attr: &NetPortAttr) -> io::Result<()> {
    // SAFETY: attr is valid for the duration of the call.
    let r = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset,
            RULE_NET_PORT,
            attr as *const NetPortAttr,
            0u32,
        )
    };
    check(r).map(drop)
}

pub fn set_no_new_privs() -> io::Result<()> {
    // SAFETY: plain prctl with integer arguments.
    let r = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    check(r as libc::c_long).map(drop)
}

pub fn restrict_self(ruleset: RawFd) -> io::Result<()> {
    // SAFETY: ruleset is a Landlock ruleset fd owned by the caller.
    let r = unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset, 0u32) };
    check(r).map(drop)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layouts_match_uapi() {
        assert_eq!(std::mem::size_of::<RulesetAttr>(), 24);
        assert_eq!(std::mem::size_of::<PathBeneathAttr>(), 12);
        assert_eq!(std::mem::size_of::<NetPortAttr>(), 16);
    }
}
