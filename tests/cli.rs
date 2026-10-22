//! End-to-end: the binary restricts itself and execs real commands.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_landlock-smoke");

fn abi() -> u32 {
    let out = Command::new(BIN).arg("abi").output().unwrap();
    let s = String::from_utf8_lossy(&out.stdout);
    s.split_whitespace()
        .next()
        .and_then(|t| t.strip_prefix("abi="))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

struct Tmp(PathBuf);
impl Tmp {
    fn new(tag: &str) -> Tmp {
        let p = std::env::temp_dir().join(format!("ll-cli-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        for d in ["ro", "rw", "secret"] {
            std::fs::create_dir_all(p.join(d)).unwrap();
        }
        std::fs::write(p.join("ro/data.txt"), "public\n").unwrap();
        std::fs::write(p.join("secret/key.txt"), "hidden\n").unwrap();
        Tmp(p)
    }
}
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Read-only grants for the system directories a dynamically linked `sh`/`cat` needs.
fn system_ro() -> Vec<String> {
    let mut v = Vec::new();
    for d in ["/usr", "/bin", "/lib", "/lib64", "/etc"] {
        if Path::new(d).exists() {
            v.push("--ro".into());
            v.push(d.into());
        }
    }
    v
}

fn run(args: &[String]) -> Output {
    Command::new(BIN).args(args).output().unwrap()
}

fn s(x: impl AsRef<std::ffi::OsStr>) -> String {
    x.as_ref().to_string_lossy().into_owned()
}

#[test]
fn usage_errors_exit_2() {
    assert_eq!(run(&[]).status.code(), Some(2));
    assert_eq!(run(&["exec".into(), "--ro".into()]).status.code(), Some(2));
    assert_eq!(
        run(&[
            "exec".into(),
            "--bind".into(),
            "x".into(),
            "--".into(),
            "true".into()
        ])
        .status
        .code(),
        Some(2)
    );
    assert_eq!(
        run(&["exec".into(), "--ro".into(), "/".into()])
            .status
            .code(),
        Some(2),
        "missing -- CMD"
    );
}

#[test]
fn abi_reports_masks() {
    let out = run(&["abi".into()]);
    assert!(out.status.success());
    let line = String::from_utf8(out.stdout).unwrap();
    assert!(
        line.starts_with("abi=") && line.contains(" fs=0x") && line.contains(" net=0x"),
        "{line}"
    );
}

#[test]
fn exec_reads_granted_tree_and_nothing_else() {
    if abi() == 0 {
        eprintln!("SKIP: Landlock unavailable");
        return;
    }
    let t = Tmp::new("read");
    let mut a = vec!["exec".into()];
    a.extend(system_ro());
    a.extend([
        "--ro".into(),
        s(t.0.join("ro")),
        "--".into(),
        "cat".into(),
        s(t.0.join("ro/data.txt")),
    ]);
    let ok = run(&a);
    assert!(
        ok.status.success(),
        "{}",
        String::from_utf8_lossy(&ok.stderr)
    );
    assert_eq!(ok.stdout, b"public\n");

    let last = a.len() - 1;
    a[last] = s(t.0.join("secret/key.txt"));
    let denied = run(&a);
    assert!(!denied.status.success());
    assert!(denied.stdout.is_empty());
    assert!(String::from_utf8_lossy(&denied.stderr).contains("Permission denied"));
}

#[test]
fn exec_writes_only_under_rw() {
    if abi() == 0 {
        eprintln!("SKIP: Landlock unavailable");
        return;
    }
    let t = Tmp::new("write");
    let base = {
        let mut a = vec!["exec".into()];
        a.extend(system_ro());
        a.extend([
            "--rw".into(),
            s(t.0.join("rw")),
            "--".into(),
            "sh".into(),
            "-c".into(),
        ]);
        a
    };
    let mut ok = base.clone();
    ok.push(format!("echo hi > '{}'", t.0.join("rw/out.txt").display()));
    assert!(run(&ok).status.success());
    assert_eq!(
        std::fs::read_to_string(t.0.join("rw/out.txt")).unwrap(),
        "hi\n"
    );

    let mut bad = base;
    bad.push(format!(
        "echo hi > '{}'",
        t.0.join("secret/out.txt").display()
    ));
    let out = run(&bad);
    assert!(!out.status.success());
    assert!(!t.0.join("secret/out.txt").exists());
}

#[test]
fn exec_restriction_survives_into_grandchildren() {
    if abi() == 0 {
        eprintln!("SKIP: Landlock unavailable");
        return;
    }
    let t = Tmp::new("nest");
    let mut a = vec!["exec".into()];
    a.extend(system_ro());
    // The inner sh tries to escape by spawning another shell; the domain is inherited.
    let target = t.0.join("secret/key.txt");
    a.extend([
        "--".into(),
        "sh".into(),
        "-c".into(),
        format!("sh -c \"cat '{}'\"", target.display()),
    ]);
    let out = run(&a);
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
}

#[test]
fn exec_tcp_connect_filter() {
    if abi() < 4 {
        eprintln!("SKIP: needs ABI 4");
        return;
    }
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let probe = format!("exec 3<>/dev/tcp/127.0.0.1/{port}");
    let have_bash = Path::new("/bin/bash").exists() || Path::new("/usr/bin/bash").exists();
    if !have_bash {
        eprintln!("SKIP: needs bash for /dev/tcp");
        return;
    }
    let mut base = vec!["exec".into()];
    base.extend(system_ro());
    let mut allowed = base.clone();
    allowed.extend([
        "--connect".into(),
        port.to_string(),
        "--".into(),
        "bash".into(),
        "-c".into(),
        probe.clone(),
    ]);
    assert!(run(&allowed).status.success());
    let mut denied = base;
    denied.extend([
        "--no-net".into(),
        "--".into(),
        "bash".into(),
        "-c".into(),
        probe,
    ]);
    let out = run(&denied);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("Permission denied"));
}

#[test]
fn exec_missing_command_is_127() {
    let out = run(&[
        "exec".into(),
        "--ro".into(),
        "/".into(),
        "--".into(),
        "/nonexistent/cmd".into(),
    ]);
    assert_eq!(out.status.code(), Some(127));
}

#[test]
fn selftest_passes_and_require_abi_is_enforced() {
    let out = run(&["selftest".into()]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let fail = run(&["selftest".into(), "--require-abi".into(), "99".into()]);
    assert_eq!(fail.status.code(), Some(1));
}
