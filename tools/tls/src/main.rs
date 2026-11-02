use std::path::PathBuf;
use std::process::ExitCode;

use wpt_tls_server::{load_config, start};

fn usage() {
    println!("usage: wpt-tls-server --config <config.json>");
}

fn main() -> ExitCode {
    let mut config_path: Option<PathBuf> = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => config_path = args.next().map(PathBuf::from),
            "-h" | "--help" => {
                usage();
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("unexpected argument: {other}");
                usage();
                return ExitCode::FAILURE;
            }
        }
    }

    let Some(config_path) = config_path else {
        usage();
        return ExitCode::FAILURE;
    };

    let config = match load_config(&config_path) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("failed to load {}: {err}", config_path.display());
            return ExitCode::FAILURE;
        }
    };

    let running = match start(config) {
        Ok(running) => running,
        Err(err) => {
            eprintln!("failed to start: {err}");
            return ExitCode::FAILURE;
        }
    };

    for (name, addr) in &running.addrs {
        println!("listening {name} on {addr}");
    }

    running.wait();
    ExitCode::SUCCESS
}
