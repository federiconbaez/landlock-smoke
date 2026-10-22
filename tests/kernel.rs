//! One test per kernel scenario. Scenarios above the running kernel's ABI are
//! skipped unless LANDLOCK_SMOKE_REQUIRE_ABI says that ABI must be present.

use landlock_smoke::selftest::{run_one, scenarios, Outcome};
use landlock_smoke::Supported;

fn check(name: &str) {
    let sup = Supported::probe().expect("probe Landlock");
    let require: u32 = std::env::var("LANDLOCK_SMOKE_REQUIRE_ABI")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let sc = scenarios()
        .into_iter()
        .find(|s| s.name == name)
        .expect("scenario exists");
    match run_one(&sc, &sup) {
        Outcome::Pass => {}
        Outcome::Fail(m) => panic!("{name}: {m}"),
        Outcome::Skip(m) if sc.min_abi <= require => panic!("{name}: skipped but required: {m}"),
        Outcome::Skip(m) => eprintln!("{name}: SKIP ({m})"),
    }
}

#[test]
fn fs_read_only_tree() {
    check("fs-read-only-tree");
}
#[test]
fn fs_read_write_subtree() {
    check("fs-read-write-subtree");
}
#[test]
fn fs_single_file_rule() {
    check("fs-single-file-rule");
}
#[test]
fn fs_refer() {
    check("fs-refer");
}
#[test]
fn fs_truncate() {
    check("fs-truncate");
}
#[test]
fn best_effort_abi2() {
    check("best-effort-abi2");
}
#[test]
fn net_bind_tcp() {
    check("net-bind-tcp");
}
#[test]
fn net_connect_tcp() {
    check("net-connect-tcp");
}
#[test]
fn scope_signal() {
    check("scope-signal");
}
#[test]
fn scope_abstract_unix() {
    check("scope-abstract-unix");
}

#[test]
fn every_scenario_has_a_test() {
    let src = include_str!("kernel.rs");
    for sc in scenarios() {
        assert!(
            src.contains(&format!("check(\"{}\")", sc.name)),
            "no test for {}",
            sc.name
        );
    }
}
