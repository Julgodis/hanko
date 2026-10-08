use std::{env, path::PathBuf, process::Command};

fn command_output(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?.trim().to_owned();
    (!value.is_empty()).then_some(value)
}

fn watch_git_path(path: &str) {
    let Some(path) = command_output("git", &["rev-parse", "--git-path", path]) else {
        return;
    };
    let path = PathBuf::from(path);
    let path = if path.is_absolute() {
        path
    } else {
        env::current_dir().unwrap_or_default().join(path)
    };
    println!("cargo:rerun-if-changed={}", path.display());
}

fn configured_value(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn main() {
    println!("cargo:rerun-if-env-changed=HANKO_VERSION");
    println!("cargo:rerun-if-env-changed=HANKO_GIT_COMMIT");
    println!("cargo:rerun-if-env-changed=HANKO_BUILD_DATE");
    for path in ["src", "migrations", "shared"] {
        println!("cargo:rerun-if-changed={path}");
    }

    watch_git_path("HEAD");
    if let Some(reference) = command_output("git", &["symbolic-ref", "--quiet", "HEAD"]) {
        watch_git_path(&reference);
    }
    watch_git_path("packed-refs");

    let commit = configured_value("HANKO_GIT_COMMIT")
        .or_else(|| command_output("git", &["rev-parse", "--verify", "HEAD"]))
        .unwrap_or_else(|| "unknown".to_owned());
    let version =
        configured_value("HANKO_VERSION").unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_owned());
    let build_date = configured_value("HANKO_BUILD_DATE")
        .or_else(|| command_output("date", &["-u", "+%Y-%m-%dT%H:%M:%SZ"]))
        .unwrap_or_else(|| "unknown".to_owned());

    println!("cargo:rustc-env=HANKO_VERSION={version}");
    println!("cargo:rustc-env=HANKO_GIT_COMMIT={commit}");
    println!("cargo:rustc-env=HANKO_BUILD_DATE={build_date}");
}
