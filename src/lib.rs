//! Minimal Landlock bindings written directly against the kernel ABI.
//!
//! Landlock restrictions apply to the calling **thread** and everything it
//! later spawns or execs; they can never be lifted. [`Ruleset::restrict_self`]
//! therefore consumes the builder and should be the last thing a thread does
//! before running untrusted work.

pub mod sys;

use std::fmt;
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// A set of access-right bits (filesystem, network or scope, depending on use).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Access(pub u64);

impl std::ops::BitOr for Access {
    type Output = Access;
    fn bitor(self, o: Access) -> Access {
        Access(self.0 | o.0)
    }
}
impl std::ops::BitAnd for Access {
    type Output = Access;
    fn bitand(self, o: Access) -> Access {
        Access(self.0 & o.0)
    }
}
impl std::ops::Not for Access {
    type Output = Access;
    fn not(self) -> Access {
        Access(!self.0)
    }
}
impl Access {
    pub const EMPTY: Access = Access(0);
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }
    pub fn contains(self, o: Access) -> bool {
        self.0 & o.0 == o.0
    }
}
impl fmt::Debug for Access {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Access({:#x})", self.0)
    }
}

/// Filesystem rights (`LANDLOCK_ACCESS_FS_*`).
pub mod fs {
    use super::Access;
    pub const EXECUTE: Access = Access(1 << 0);
    pub const WRITE_FILE: Access = Access(1 << 1);
    pub const READ_FILE: Access = Access(1 << 2);
    pub const READ_DIR: Access = Access(1 << 3);
    pub const REMOVE_DIR: Access = Access(1 << 4);
    pub const REMOVE_FILE: Access = Access(1 << 5);
    pub const MAKE_CHAR: Access = Access(1 << 6);
    pub const MAKE_DIR: Access = Access(1 << 7);
    pub const MAKE_REG: Access = Access(1 << 8);
    pub const MAKE_SOCK: Access = Access(1 << 9);
    pub const MAKE_FIFO: Access = Access(1 << 10);
    pub const MAKE_BLOCK: Access = Access(1 << 11);
    pub const MAKE_SYM: Access = Access(1 << 12);
    /// ABI 2: link/rename across directories.
    pub const REFER: Access = Access(1 << 13);
    /// ABI 3: truncate(2), ftruncate(2), O_TRUNC.
    pub const TRUNCATE: Access = Access(1 << 14);
    /// ABI 5: ioctl(2) on character/block devices.
    pub const IOCTL_DEV: Access = Access(1 << 15);

    /// Rights that are meaningful on a regular file (rules on non-directories
    /// may only carry these, otherwise the kernel answers EINVAL).
    pub const FILE_RIGHTS: Access =
        Access(EXECUTE.0 | WRITE_FILE.0 | READ_FILE.0 | TRUNCATE.0 | IOCTL_DEV.0);
    /// Read-only view of a tree: read files, list directories, execute.
    pub const READ: Access = Access(EXECUTE.0 | READ_FILE.0 | READ_DIR.0);
    /// Everything up to ABI 5.
    pub const ALL: Access = Access((1 << 16) - 1);
}

/// TCP rights (`LANDLOCK_ACCESS_NET_*`, ABI 4).
pub mod net {
    use super::Access;
    pub const BIND_TCP: Access = Access(1 << 0);
    pub const CONNECT_TCP: Access = Access(1 << 1);
    pub const ALL: Access = Access(0b11);
}

/// IPC scoping (`LANDLOCK_SCOPE_*`, ABI 6).
pub mod scope {
    use super::Access;
    pub const ABSTRACT_UNIX_SOCKET: Access = Access(1 << 0);
    pub const SIGNAL: Access = Access(1 << 1);
    pub const ALL: Access = Access(0b11);
}

/// What a given ABI version can enforce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Supported {
    pub abi: u32,
    pub fs: Access,
    pub net: Access,
    pub scope: Access,
}

impl Supported {
    pub fn for_abi(abi: u32) -> Supported {
        let fs_bits = match abi {
            0 => 0,
            1 => (1 << 13) - 1,
            2 => (1 << 14) - 1,
            3 | 4 => (1 << 15) - 1,
            _ => (1 << 16) - 1,
        };
        Supported {
            abi,
            fs: Access(fs_bits),
            net: if abi >= 4 { net::ALL } else { Access::EMPTY },
            scope: if abi >= 6 { scope::ALL } else { Access::EMPTY },
        }
    }

    /// Probes the running kernel. ENOSYS/EOPNOTSUPP (not built or disabled at
    /// boot) map to ABI 0; any other error is returned.
    pub fn probe() -> io::Result<Supported> {
        match sys::abi_version() {
            Ok(v) => Ok(Supported::for_abi(v)),
            Err(e)
                if matches!(
                    e.raw_os_error(),
                    Some(libc::ENOSYS) | Some(libc::EOPNOTSUPP)
                ) =>
            {
                Ok(Supported::for_abi(0))
            }
            Err(e) => Err(e),
        }
    }
}

/// How to react when the kernel cannot enforce something that was asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compat {
    /// Drop unsupported rights and report [`Status::Partial`].
    BestEffort,
    /// Fail with [`Error::Unsupported`] instead of silently weakening the policy.
    Strict,
}

/// Outcome of a successful [`Ruleset::restrict_self`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    /// Every requested right is enforced.
    Full,
    /// Some requested rights were dropped because the kernel is too old.
    Partial {
        dropped_fs: Access,
        dropped_net: Access,
        dropped_scope: Access,
    },
    /// Landlock is unavailable; nothing is enforced.
    NotEnforced,
}

#[derive(Debug)]
pub enum Error {
    Unsupported {
        abi: u32,
        missing_fs: Access,
        missing_net: Access,
        missing_scope: Access,
    },
    Path {
        path: PathBuf,
        source: io::Error,
    },
    Syscall {
        op: &'static str,
        source: io::Error,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Unsupported {
                abi,
                missing_fs,
                missing_net,
                missing_scope,
            } => write!(
                f,
                "kernel Landlock ABI {abi} cannot enforce fs={:#x} net={:#x} scope={:#x}",
                missing_fs.0, missing_net.0, missing_scope.0
            ),
            Error::Path { path, source } => write!(f, "{}: {source}", path.display()),
            Error::Syscall { op, source } => write!(f, "{op}: {source}"),
        }
    }
}
impl std::error::Error for Error {}

#[derive(Debug, Clone)]
enum Rule {
    Path(PathBuf, Access),
    Port(u16, Access),
}

/// Builder for a Landlock domain.
#[derive(Debug, Clone)]
pub struct Ruleset {
    handled_fs: Access,
    handled_net: Access,
    scoped: Access,
    rules: Vec<Rule>,
    compat: Compat,
}

impl Default for Ruleset {
    fn default() -> Self {
        Self::new()
    }
}

impl Ruleset {
    pub fn new() -> Ruleset {
        Ruleset {
            handled_fs: Access::EMPTY,
            handled_net: Access::EMPTY,
            scoped: Access::EMPTY,
            rules: Vec::new(),
            compat: Compat::BestEffort,
        }
    }
    pub fn compat(mut self, c: Compat) -> Self {
        self.compat = c;
        self
    }
    /// Rights listed here are denied unless a rule grants them.
    pub fn handle_fs(mut self, a: Access) -> Self {
        self.handled_fs = self.handled_fs | a;
        self
    }
    pub fn handle_net(mut self, a: Access) -> Self {
        self.handled_net = self.handled_net | a;
        self
    }
    pub fn scope(mut self, a: Access) -> Self {
        self.scoped = self.scoped | a;
        self
    }
    pub fn allow_path(mut self, p: impl AsRef<Path>, a: Access) -> Self {
        self.rules.push(Rule::Path(p.as_ref().to_path_buf(), a));
        self
    }
    pub fn allow_port(mut self, port: u16, a: Access) -> Self {
        self.rules.push(Rule::Port(port, a));
        self
    }

    /// Computes the attributes the given ABI will actually receive.
    pub fn effective(&self, sup: &Supported) -> Result<(sys::RulesetAttr, Status), Error> {
        let fs = self.handled_fs & sup.fs;
        let net = self.handled_net & sup.net;
        let sc = self.scoped & sup.scope;
        let dropped_fs = self.handled_fs & !sup.fs;
        let dropped_net = self.handled_net & !sup.net;
        let dropped_scope = self.scoped & !sup.scope;
        let any_dropped =
            !(dropped_fs.is_empty() && dropped_net.is_empty() && dropped_scope.is_empty());
        if any_dropped && self.compat == Compat::Strict {
            return Err(Error::Unsupported {
                abi: sup.abi,
                missing_fs: dropped_fs,
                missing_net: dropped_net,
                missing_scope: dropped_scope,
            });
        }
        let status = if sup.abi == 0 || (fs.is_empty() && net.is_empty() && sc.is_empty()) {
            Status::NotEnforced
        } else if any_dropped {
            Status::Partial {
                dropped_fs,
                dropped_net,
                dropped_scope,
            }
        } else {
            Status::Full
        };
        let attr = sys::RulesetAttr {
            handled_access_fs: fs.0,
            handled_access_net: net.0,
            scoped: sc.0,
        };
        Ok((attr, status))
    }

    /// Applies the ruleset to the calling thread (and its future children).
    pub fn restrict_self(self) -> Result<Status, Error> {
        let sup = Supported::probe().map_err(|source| Error::Syscall {
            op: "landlock_create_ruleset(VERSION)",
            source,
        })?;
        self.restrict_self_with(&sup)
    }

    /// Same as [`Ruleset::restrict_self`] but with an explicit (possibly
    /// lowered) ABI, which is how the best-effort paths are tested on new kernels.
    pub fn restrict_self_with(self, sup: &Supported) -> Result<Status, Error> {
        let (attr, status) = self.effective(sup)?;
        if status == Status::NotEnforced {
            return Ok(status);
        }
        let rs = sys::create_ruleset(&attr).map_err(|source| Error::Syscall {
            op: "landlock_create_ruleset",
            source,
        })?;
        let fs_handled = Access(attr.handled_access_fs);
        let net_handled = Access(attr.handled_access_net);
        for rule in &self.rules {
            match rule {
                Rule::Path(path, want) => {
                    let mut access = *want & fs_handled;
                    if access.is_empty() {
                        continue;
                    }
                    let file = File::options()
                        .read(true)
                        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
                        .open(path)
                        .map_err(|source| Error::Path {
                            path: path.clone(),
                            source,
                        })?;
                    let is_dir = file
                        .metadata()
                        .map_err(|source| Error::Path {
                            path: path.clone(),
                            source,
                        })?
                        .is_dir();
                    if !is_dir {
                        access = access & fs::FILE_RIGHTS;
                    }
                    let a = sys::PathBeneathAttr {
                        allowed_access: access.0,
                        parent_fd: file.as_raw_fd(),
                    };
                    sys::add_path_rule(rs.as_raw_fd(), &a).map_err(|source| Error::Path {
                        path: path.clone(),
                        source,
                    })?;
                }
                Rule::Port(port, want) => {
                    let access = *want & net_handled;
                    if access.is_empty() {
                        continue;
                    }
                    let a = sys::NetPortAttr {
                        allowed_access: access.0,
                        port: u64::from(*port),
                    };
                    sys::add_net_rule(rs.as_raw_fd(), &a).map_err(|source| Error::Syscall {
                        op: "landlock_add_rule(net_port)",
                        source,
                    })?;
                }
            }
        }
        sys::set_no_new_privs().map_err(|source| Error::Syscall {
            op: "prctl(NO_NEW_PRIVS)",
            source,
        })?;
        sys::restrict_self(rs.as_raw_fd()).map_err(|source| Error::Syscall {
            op: "landlock_restrict_self",
            source,
        })?;
        Ok(status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abi_masks_grow_monotonically() {
        let mut prev = Supported::for_abi(0);
        for abi in 1..=7 {
            let s = Supported::for_abi(abi);
            assert!(
                s.fs.contains(prev.fs) && s.net.contains(prev.net) && s.scope.contains(prev.scope)
            );
            prev = s;
        }
        assert_eq!(Supported::for_abi(1).fs.0, 0x1fff);
        assert!(Supported::for_abi(2).fs.contains(fs::REFER));
        assert!(!Supported::for_abi(2).fs.contains(fs::TRUNCATE));
        assert!(Supported::for_abi(5).fs.contains(fs::IOCTL_DEV));
        assert_eq!(Supported::for_abi(3).net, Access::EMPTY);
        assert_eq!(Supported::for_abi(4).net, net::ALL);
        assert_eq!(Supported::for_abi(6).scope, scope::ALL);
    }

    #[test]
    fn best_effort_drops_and_reports() {
        let rs = Ruleset::new()
            .handle_fs(fs::ALL)
            .handle_net(net::ALL)
            .scope(scope::SIGNAL);
        let (attr, st) = rs.effective(&Supported::for_abi(3)).unwrap();
        assert_eq!(attr.handled_access_fs, 0x7fff);
        assert_eq!(attr.handled_access_net, 0);
        assert_eq!(attr.scoped, 0);
        assert_eq!(
            st,
            Status::Partial {
                dropped_fs: fs::IOCTL_DEV,
                dropped_net: net::ALL,
                dropped_scope: scope::SIGNAL
            }
        );
    }

    #[test]
    fn strict_refuses_to_weaken() {
        let rs = Ruleset::new()
            .compat(Compat::Strict)
            .handle_fs(fs::TRUNCATE);
        match rs.effective(&Supported::for_abi(2)) {
            Err(Error::Unsupported {
                abi: 2, missing_fs, ..
            }) => assert_eq!(missing_fs, fs::TRUNCATE),
            other => panic!("expected Unsupported, got {other:?}"),
        }
        let ok = Ruleset::new()
            .compat(Compat::Strict)
            .handle_fs(fs::TRUNCATE);
        assert_eq!(
            ok.effective(&Supported::for_abi(3)).unwrap().1,
            Status::Full
        );
    }

    #[test]
    fn abi_zero_is_not_enforced() {
        let (_, st) = Ruleset::new()
            .handle_fs(fs::ALL)
            .effective(&Supported::for_abi(0))
            .unwrap();
        assert_eq!(st, Status::NotEnforced);
    }

    #[test]
    fn nothing_handled_is_not_enforced() {
        let (_, st) = Ruleset::new()
            .allow_path("/", fs::READ)
            .effective(&Supported::for_abi(6))
            .unwrap();
        assert_eq!(st, Status::NotEnforced);
    }
}
