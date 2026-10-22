//! Kernel self-test: each scenario restricts a fresh thread, probes what the
//! kernel allows and denies, and reports. The calling thread is never restricted.

use crate::{fs, net, scope, Ruleset, Status, Supported};
use std::fs::{self as stdfs, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Pass,
    Fail(String),
    Skip(String),
}

pub struct Scenario {
    pub name: &'static str,
    pub min_abi: u32,
    pub what: &'static str,
    run: fn(&Path, &Supported) -> Result<(), String>,
}

/// Scratch layout shared by the scenarios: `ro/`, `rw/`, `secret/`, `a/`, `b/`.
pub struct Scratch {
    pub root: PathBuf,
}

impl Scratch {
    pub fn new(tag: &str) -> std::io::Result<Scratch> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let root = std::env::temp_dir().join(format!(
            "landlock-smoke-{tag}-{}-{nanos}",
            std::process::id()
        ));
        for d in ["ro", "rw", "secret", "a", "b"] {
            stdfs::create_dir_all(root.join(d))?;
        }
        stdfs::write(root.join("ro/data.txt"), b"read me")?;
        stdfs::write(root.join("secret/key.txt"), b"do not read")?;
        stdfs::write(root.join("rw/log.txt"), b"0123456789")?;
        stdfs::write(root.join("a/moved.txt"), b"x")?;
        Ok(Scratch { root })
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = stdfs::remove_dir_all(&self.root);
    }
}

fn expect_denied<T: std::fmt::Debug>(
    what: &str,
    r: std::io::Result<T>,
    errno: i32,
) -> Result<(), String> {
    match r {
        Err(e) if e.raw_os_error() == Some(errno) => Ok(()),
        Err(e) => Err(format!("{what}: expected errno {errno}, got {e}")),
        Ok(v) => Err(format!("{what}: expected denial, succeeded with {v:?}")),
    }
}

fn expect_ok<T>(what: &str, r: std::io::Result<T>) -> Result<T, String> {
    r.map_err(|e| format!("{what}: expected success, got {e}"))
}

fn enforce(rs: Ruleset, sup: &Supported) -> Result<Status, String> {
    rs.restrict_self_with(sup)
        .map_err(|e| format!("restrict_self: {e}"))
}

fn read_only_tree(root: &Path, sup: &Supported) -> Result<(), String> {
    enforce(
        Ruleset::new()
            .handle_fs(fs::ALL)
            .allow_path(root.join("ro"), fs::READ),
        sup,
    )?;
    let mut s = String::new();
    expect_ok(
        "read ro/data.txt",
        File::open(root.join("ro/data.txt")).and_then(|mut f| f.read_to_string(&mut s)),
    )?;
    if s != "read me" {
        return Err(format!("unexpected content {s:?}"));
    }
    expect_ok(
        "list ro/",
        stdfs::read_dir(root.join("ro")).map(|d| d.count()),
    )?;
    expect_denied(
        "write ro/data.txt",
        OpenOptions::new()
            .write(true)
            .open(root.join("ro/data.txt")),
        libc::EACCES,
    )?;
    expect_denied(
        "create ro/new.txt",
        File::create(root.join("ro/new.txt")),
        libc::EACCES,
    )?;
    expect_denied(
        "read secret/key.txt",
        File::open(root.join("secret/key.txt")),
        libc::EACCES,
    )?;
    expect_denied(
        "list secret/",
        stdfs::read_dir(root.join("secret")),
        libc::EACCES,
    )
}

fn read_write_subtree(root: &Path, sup: &Supported) -> Result<(), String> {
    enforce(
        Ruleset::new()
            .handle_fs(fs::ALL)
            .allow_path(root.join("rw"), fs::ALL),
        sup,
    )?;
    let p = root.join("rw/new.txt");
    expect_ok(
        "create rw/new.txt",
        File::create(&p).and_then(|mut f| f.write_all(b"hi")),
    )?;
    expect_ok("mkdir rw/sub", stdfs::create_dir(root.join("rw/sub")))?;
    expect_ok("rmdir rw/sub", stdfs::remove_dir(root.join("rw/sub")))?;
    expect_ok("unlink rw/new.txt", stdfs::remove_file(&p))?;
    expect_denied(
        "create secret/x",
        File::create(root.join("secret/x")),
        libc::EACCES,
    )?;
    expect_denied(
        "unlink secret/key.txt",
        stdfs::remove_file(root.join("secret/key.txt")),
        libc::EACCES,
    )
}

fn single_file_rule(root: &Path, sup: &Supported) -> Result<(), String> {
    // Directory-only rights on a file rule are masked off instead of failing with EINVAL.
    enforce(
        Ruleset::new()
            .handle_fs(fs::ALL)
            .allow_path(root.join("ro/data.txt"), fs::ALL),
        sup,
    )?;
    expect_ok(
        "read the one allowed file",
        stdfs::read(root.join("ro/data.txt")),
    )?;
    expect_denied(
        "list its directory",
        stdfs::read_dir(root.join("ro")),
        libc::EACCES,
    )?;
    expect_denied(
        "sibling create",
        File::create(root.join("ro/other")),
        libc::EACCES,
    )
}

fn refer_across_dirs(root: &Path, sup: &Supported) -> Result<(), String> {
    let no_refer = fs::ALL & !fs::REFER;
    enforce(
        Ruleset::new()
            .handle_fs(fs::ALL)
            .allow_path(root.join("a"), no_refer)
            .allow_path(root.join("b"), no_refer),
        sup,
    )?;
    // Landlock reports a forbidden reparenting as EXDEV so tools fall back to copy+unlink.
    expect_denied(
        "rename a/ -> b/",
        stdfs::rename(root.join("a/moved.txt"), root.join("b/moved.txt")),
        libc::EXDEV,
    )?;
    expect_ok(
        "rename within a/",
        stdfs::rename(root.join("a/moved.txt"), root.join("a/renamed.txt")),
    )?;
    Ok(())
}

fn truncate_right(root: &Path, sup: &Supported) -> Result<(), String> {
    let rights = fs::READ_FILE | fs::WRITE_FILE | fs::READ_DIR;
    enforce(
        Ruleset::new()
            .handle_fs(fs::ALL)
            .allow_path(root.join("rw"), rights),
        sup,
    )?;
    let p = root.join("rw/log.txt");
    expect_denied(
        "open O_TRUNC",
        OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_TRUNC)
            .open(&p),
        libc::EACCES,
    )?;
    let f = expect_ok("open for write", OpenOptions::new().write(true).open(&p))?;
    expect_denied("ftruncate", f.set_len(2), libc::EACCES)?;
    expect_ok("plain write", (&f).write_all(b"ab"))
}

fn best_effort_lower_abi(root: &Path, sup: &Supported) -> Result<(), String> {
    // Pretend the kernel only speaks ABI 2: TRUNCATE must be dropped, not enforced.
    let lowered = Supported::for_abi(2.min(sup.abi));
    let st = enforce(
        Ruleset::new()
            .handle_fs(fs::ALL)
            .allow_path(root.join("rw"), fs::READ_FILE | fs::WRITE_FILE),
        &lowered,
    )?;
    match st {
        Status::Partial { dropped_fs, .. } if dropped_fs.contains(fs::TRUNCATE) => {}
        other => return Err(format!("expected Partial dropping TRUNCATE, got {other:?}")),
    }
    let f = expect_ok(
        "open O_TRUNC under ABI-2 policy",
        OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_TRUNC)
            .open(root.join("rw/log.txt")),
    )?;
    drop(f);
    expect_denied(
        "read secret/ still denied",
        File::open(root.join("secret/key.txt")),
        libc::EACCES,
    )
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .unwrap_or(0)
}

fn tcp_bind(_: &Path, sup: &Supported) -> Result<(), String> {
    let (ok_port, bad_port) = (free_port(), free_port());
    enforce(
        Ruleset::new()
            .handle_net(net::BIND_TCP)
            .allow_port(ok_port, net::BIND_TCP),
        sup,
    )?;
    expect_ok(
        "bind allowed port",
        TcpListener::bind(("127.0.0.1", ok_port)),
    )?;
    expect_denied(
        "bind other port",
        TcpListener::bind(("127.0.0.1", bad_port)),
        libc::EACCES,
    )
}

fn tcp_connect(_: &Path, sup: &Supported) -> Result<(), String> {
    // Listeners are created by this thread *before* it restricts itself.
    let allowed = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let blocked = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let ap = allowed.local_addr().unwrap().port();
    let bp = blocked.local_addr().unwrap().port();
    enforce(
        Ruleset::new()
            .handle_net(net::CONNECT_TCP)
            .allow_port(ap, net::CONNECT_TCP),
        sup,
    )?;
    expect_ok(
        "connect allowed port",
        TcpStream::connect(("127.0.0.1", ap)),
    )?;
    expect_denied(
        "connect other port",
        TcpStream::connect(("127.0.0.1", bp)),
        libc::EACCES,
    )
}

fn signal_scope(_: &Path, sup: &Supported) -> Result<(), String> {
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .map_err(|e| format!("spawn sleep: {e}"))?;
    let pid = child.id() as libc::pid_t;
    let sup = *sup;
    // Restrict a nested thread so this one can still reap the child afterwards.
    let res = std::thread::spawn(move || {
        enforce(Ruleset::new().scope(scope::SIGNAL), &sup)?;
        // SAFETY: kill with signal 0 only performs the permission check.
        let r = unsafe { libc::kill(pid, 0) };
        expect_denied(
            "kill(outside child, 0)",
            if r == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            },
            libc::EPERM,
        )
    })
    .join()
    .unwrap_or_else(|_| Err("signal thread panicked".into()));
    expect_ok("unrestricted thread can still kill the child", child.kill())?;
    let _ = child.wait();
    res
}

fn abstract_unix_scope(_: &Path, sup: &Supported) -> Result<(), String> {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixListener, UnixStream};
    let name = format!(
        "landlock-smoke-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    );
    let addr = SocketAddr::from_abstract_name(name.as_bytes()).map_err(|e| e.to_string())?;
    let _listener = UnixListener::bind_addr(&addr).map_err(|e| format!("bind abstract: {e}"))?;
    expect_ok(
        "connect before restriction",
        UnixStream::connect_addr(&addr),
    )?;
    enforce(Ruleset::new().scope(scope::ABSTRACT_UNIX_SOCKET), sup)?;
    expect_denied(
        "connect after restriction",
        UnixStream::connect_addr(&addr),
        libc::EPERM,
    )
}

pub fn scenarios() -> Vec<Scenario> {
    vec![
        Scenario {
            name: "fs-read-only-tree",
            min_abi: 1,
            what: "ro/ readable, not writable; secret/ invisible",
            run: read_only_tree,
        },
        Scenario {
            name: "fs-read-write-subtree",
            min_abi: 1,
            what: "create/mkdir/unlink only under rw/",
            run: read_write_subtree,
        },
        Scenario {
            name: "fs-single-file-rule",
            min_abi: 1,
            what: "rule on a file grants that file only",
            run: single_file_rule,
        },
        Scenario {
            name: "fs-refer",
            min_abi: 2,
            what: "rename across dirs without REFER -> EXDEV",
            run: refer_across_dirs,
        },
        Scenario {
            name: "fs-truncate",
            min_abi: 3,
            what: "O_TRUNC and ftruncate need TRUNCATE",
            run: truncate_right,
        },
        Scenario {
            name: "best-effort-abi2",
            min_abi: 3,
            what: "policy built for ABI 2 drops TRUNCATE, still denies reads",
            run: best_effort_lower_abi,
        },
        Scenario {
            name: "net-bind-tcp",
            min_abi: 4,
            what: "bind only to the allowed port",
            run: tcp_bind,
        },
        Scenario {
            name: "net-connect-tcp",
            min_abi: 4,
            what: "connect only to the allowed port",
            run: tcp_connect,
        },
        Scenario {
            name: "scope-signal",
            min_abi: 6,
            what: "cannot signal a process outside the domain",
            run: signal_scope,
        },
        Scenario {
            name: "scope-abstract-unix",
            min_abi: 6,
            what: "cannot connect to an abstract socket outside the domain",
            run: abstract_unix_scope,
        },
    ]
}

/// Runs one scenario in a dedicated thread so the restriction dies with it,
/// then checks from the unrestricted caller that it really was thread-scoped.
pub fn run_one(sc: &Scenario, sup: &Supported) -> Outcome {
    if sup.abi < sc.min_abi {
        return Outcome::Skip(format!("needs ABI {}, kernel has {}", sc.min_abi, sup.abi));
    }
    let scratch = match Scratch::new(sc.name) {
        Ok(s) => s,
        Err(e) => return Outcome::Fail(format!("scratch: {e}")),
    };
    let root = scratch.root.clone();
    let sup2 = *sup;
    let run = sc.run;
    let res = std::thread::spawn(move || run(&root, &sup2)).join();
    let res = match res {
        Ok(r) => r,
        Err(_) => Err("scenario panicked".into()),
    };
    if let Err(e) = res {
        return Outcome::Fail(e);
    }
    // The caller thread was never restricted: the secret must still be readable.
    match stdfs::read(scratch.root.join("secret/key.txt")) {
        Ok(_) => Outcome::Pass,
        Err(e) if e.kind() == ErrorKind::PermissionDenied => {
            Outcome::Fail("restriction leaked to the calling thread".into())
        }
        Err(e) => Outcome::Fail(format!("post-check: {e}")),
    }
}
