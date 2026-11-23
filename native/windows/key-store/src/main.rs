use std::ffi::OsString;
use std::io::{stdin, stdout};

use computer_access_key_store::run_cli;

fn main() {
    let args: Vec<OsString> = std::env::args_os().collect();
    let mut input = stdin().lock();
    let mut output = stdout().lock();
    let code = run_cli(&args, &mut input, &mut output);
    drop(output);
    drop(input);
    std::process::exit(code);
}
