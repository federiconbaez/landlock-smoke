//! `landlock-smoke`: probe the kernel, run the self-test matrix, or exec a
//! command inside a Landlock domain.

use landlock_smoke::selftest::{self, Outcome};
use landlock_smoke::{fs, net, scope, Compat, Ruleset, Status, Supported};
use std::os::unix::process::CommandExt;
use std::process::{Command, ExitCode};

const USAGE: &str = "\
usage:
  landlock-smoke abi
  landlock-smoke selftest [--require-abi N]
  landlock-smoke exec [--ro PATH]... [--rw PATH]... [--bind PORT]... [--connect PORT]...
                      [--no-net] [--scope-signal] [--scope-unix] [--strict] -- CMD [ARGS]...

exec handles every filesystem right the kernel knows: anything not granted by
--ro/--rw is denied. --bind/--connect/--no-net turn on TCP filtering (ABI 4+).";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("abi") => cmd_abi(),
        Some("selftest") => cmd_selftest(&args[1..]),
        Some("exec") => cmd_exec(&args[1..]),
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn probe() -> Result<Supported, ExitCode> {
    Supported::probe().map_err(|e| {
        eprintln!("landlock-smoke: probing Landlock failed: {e}");
        ExitCode::from(3)
    })
}

fn cmd_abi() -> ExitCode {
    let sup = match probe() {
        Ok(s) => s,
        Err(c) => return c,
    };
    println!(
        "abi={} fs={:#x} net={:#x} scope={:#x}",
        sup.abi, sup.fs.0, sup.net.0, sup.scope.0
    );
    ExitCode::SUCCESS
}

fn cmd_selftest(args: &[String]) -> ExitCode {
    let mut require = 0u32;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match (a.as_str(), it.next()) {
            ("--require-abi", Some(n)) => match n.parse() {
                Ok(v) => require = v,
                Err(_) => return usage_error("--require-abi expects a number"),
            },
            _ => return usage_error(&format!("unexpected argument {a}")),
        }
    }
    let sup = match probe() {
        Ok(s) => s,
        Err(c) => return c,
    };
    println!("kernel Landlock ABI {}", sup.abi);
    if sup.abi < require {
        eprintln!(
            "FAIL: --require-abi {require} but kernel reports {}",
            sup.abi
        );
        return ExitCode::FAILURE;
    }
    let (mut pass, mut fail, mut skip) = (0, 0, 0);
    for sc in selftest::scenarios() {
        let out = selftest::run_one(&sc, &sup);
        let (tag, note) = match &out {
            Outcome::Pass => ("PASS", String::new()),
            Outcome::Fail(m) => ("FAIL", format!(" — {m}")),
            Outcome::Skip(m) => ("SKIP", format!(" — {m}")),
        };
        println!(
            "{tag}  abi>={}  {:<22} {}{note}",
            sc.min_abi, sc.name, sc.what
        );
        match out {
            Outcome::Pass => pass += 1,
            Outcome::Fail(_) => fail += 1,
            Outcome::Skip(_) if sc.min_abi <= require => {
                fail += 1;
                println!("      ^ counted as failure: within --require-abi");
            }
            Outcome::Skip(_) => skip += 1,
        }
    }
    println!("{pass} passed, {fail} failed, {skip} skipped");
    if fail == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn usage_error(msg: &str) -> ExitCode {
    eprintln!("landlock-smoke: {msg}\n\n{USAGE}");
    ExitCode::from(2)
}

/// Parses `exec` flags into a ruleset and the command line to run.
pub fn parse_exec(args: &[String]) -> Result<(Ruleset, Vec<String>), String> {
    let mut rs = Ruleset::new().handle_fs(fs::ALL);
    let mut i = 0;
    let val = |i: usize, flag: &str| {
        args.get(i + 1)
            .cloned()
            .ok_or_else(|| format!("{flag} needs a value"))
    };
    while i < args.len() {
        let flag = args[i].as_str();
        match flag {
            "--ro" => rs = rs.allow_path(val(i, flag)?, fs::READ),
            "--rw" => rs = rs.allow_path(val(i, flag)?, fs::ALL),
            "--bind" | "--connect" => {
                let port: u16 = val(i, flag)?
                    .parse()
                    .map_err(|_| format!("{flag}: bad port"))?;
                let right = if flag == "--bind" {
                    net::BIND_TCP
                } else {
                    net::CONNECT_TCP
                };
                rs = rs.handle_net(net::ALL).allow_port(port, right);
            }
            "--no-net" => rs = rs.handle_net(net::ALL),
            "--scope-signal" => rs = rs.scope(scope::SIGNAL),
            "--scope-unix" => rs = rs.scope(scope::ABSTRACT_UNIX_SOCKET),
            "--strict" => rs = rs.compat(Compat::Strict),
            "--" => return Ok((rs, args[i + 1..].to_vec())),
            other => return Err(format!("unexpected argument {other}")),
        }
        i += if matches!(flag, "--ro" | "--rw" | "--bind" | "--connect") {
            2
        } else {
            1
        };
    }
    Ok((rs, Vec::new()))
}

fn cmd_exec(args: &[String]) -> ExitCode {
    let (rs, cmd) = match parse_exec(args) {
        Ok(v) => v,
        Err(m) => return usage_error(&m),
    };
    if cmd.is_empty() {
        return usage_error("exec needs `-- CMD`");
    }
    match rs.restrict_self() {
        Ok(Status::Full) => {}
        Ok(Status::Partial { dropped_fs, dropped_net, dropped_scope }) => eprintln!(
            "landlock-smoke: warning: partially enforced (kernel lacks fs={:#x} net={:#x} scope={:#x})",
            dropped_fs.0, dropped_net.0, dropped_scope.0
        ),
        Ok(Status::NotEnforced) => eprintln!("landlock-smoke: warning: Landlock unavailable, running unconfined"),
        Err(e) => {
            eprintln!("landlock-smoke: {e}");
            return ExitCode::from(3);
        }
    }
    let err = Command::new(&cmd[0]).args(&cmd[1..]).exec();
    eprintln!("landlock-smoke: exec {}: {err}", cmd[0]);
    ExitCode::from(127)
}
