use std::ffi::OsString;
use std::io::{self, ErrorKind, Read, Write};
use std::process;

use history_contract::{ContractValidator, JsonlValidator, ValidationResult};

fn run() -> Result<(), ()> {
    let validator = ContractValidator::new().map_err(|_| ())?;
    let mut stream = JsonlValidator::new(validator);

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();

    let mut emit = |result: ValidationResult| -> Result<(), ()> {
        let line = result.encoded_line().map_err(|_| ())?;
        writer.write_all(&line).map_err(|_| ())
    };

    let mut buf = [0u8; 8_192];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => stream.push(&buf[..n], &mut emit)?,
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return Err(()),
        }
    }

    stream.finish(&mut emit)?;
    writer.flush().map_err(|_| ())?;
    Ok(())
}

fn main() {
    // This executable only validates stdin. It cannot read or operate any desktop.
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let valid_args = args.is_empty() || (args.len() == 1 && args[0] == "--validate-jsonl");
    if !valid_args {
        let _ = io::stderr().write_all(b"usage: contract-check [--validate-jsonl]\n");
        let _ = io::stderr().flush();
        process::exit(64);
    }

    if run().is_err() {
        // Never print OS/std errors: they can include file paths or input fragments.
        let _ = io::stderr().write_all(b"contract-check: I/O or contract initialization failure\n");
        let _ = io::stderr().flush();
        process::exit(74);
    }
}
