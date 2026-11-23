pub mod base64;
pub mod dpapi;
pub mod request;
pub mod response;
pub mod zeroize;

use std::ffi::OsString;
use std::io::{Read, Write};

use crate::dpapi::execute_request;
use crate::request::read_request;
use crate::response::KeyStoreResponse;

pub const EXIT_OK: i32 = 0;
pub const EXIT_ENCODE_ERROR: i32 = 1;
pub const EXIT_INVALID_USAGE: i32 = 64;

fn write_response(writer: &mut dyn Write, response: &KeyStoreResponse) -> bool {
    let Ok(line) = response.encode_line() else {
        return false;
    };
    if writer.write_all(line.as_slice()).is_err() {
        return false;
    }
    writer.flush().is_ok()
}

/// Runs the key-store CLI protocol end-to-end and returns the process exit code.
pub fn run_cli(args: &[OsString], stdin: &mut dyn Read, stdout: &mut dyn Write) -> i32 {
    let request = match read_request(args, stdin) {
        Ok(req) => req,
        Err(_) => {
            let err_resp = KeyStoreResponse::error(None, None);
            if !write_response(stdout, &err_resp) {
                return EXIT_ENCODE_ERROR;
            }
            return EXIT_INVALID_USAGE;
        }
    };

    let response = execute_request(&request);
    if !write_response(stdout, &response) {
        return EXIT_ENCODE_ERROR;
    }
    EXIT_OK
}
