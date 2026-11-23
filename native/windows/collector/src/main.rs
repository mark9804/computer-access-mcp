use std::env;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use access_contract::{ContractValidator, JsonValue, ValidationResult};
use collector_core::desktop::{run_permissions_cli, PermissionAction};
use collector_core::engine::{
    CollectorEngine, CollectorEnvironment, EngineOutput, WindowsEnvironment,
};
use collector_core::navigation::{run_navigate_source_cli, SourceNavigationRequest};
use collector_core::ownership::{parent_pid, CliOptions, OwnerLock, ParentProcessHandle};
use collector_core::protocol_model::{hello_message, SystemCollectorClock};
use collector_core::transport::{BoundedOutput, InputFrames};
use collector_core::worker_ipc::run_worker_cli;
use windows::core::BOOL;
use windows::Win32::System::Console::SetConsoleCtrlHandler;

static SIGNAL_STOP: AtomicBool = AtomicBool::new(false);

unsafe extern "system" fn console_ctrl_handler(_ctrl_type: u32) -> BOOL {
    SIGNAL_STOP.store(true, Ordering::Release);
    BOOL(1)
}

fn dispatch_outputs(
    outputs: Vec<EngineOutput>,
    output: &BoundedOutput,
) {
    for action in outputs {
        match action {
            EngineOutput::Emit(msg) => output.enqueue(&msg),
            EngineOutput::DiscardQueuedObservations => output.discard_observations(),
        }
    }
}

fn run_control_process(options: CliOptions) -> i32 {
    let Ok(validator) = ContractValidator::new() else {
        return 70;
    };
    let output = BoundedOutput::new(validator.clone());

    // CRITICAL Startup Order: emit and flush `hello` BEFORE acquiring `OwnerLock`.
    output.enqueue(&hello_message(&options.instance, options.fixture));
    if !output.flush_sync(250) {
        return 74;
    }

    let owner_lock = match OwnerLock::acquire(options.fixture, options.fixture_lock.as_deref()) {
        Ok(lock) => lock,
        Err(_) => return 73,
    };

    let Some(ppid) = parent_pid() else {
        return 70;
    };
    let Some(parent) = ParentProcessHandle::open(ppid) else {
        return 70;
    };

    let Ok(executable) = env::current_exe() else {
        return 70;
    };

    // Register Ctrl-C / Ctrl-Break / Close handler for clean stop.
    unsafe {
        let _ = SetConsoleCtrlHandler(Some(console_ctrl_handler), true);
    }

    let desktop_id = if options.fixture {
        "fixture-desktop".to_string()
    } else {
        format!("winsta0-default-{}", owner_lock.session_id)
    };
    let environment = WindowsEnvironment::new(executable, options.fixture, options.scenario.clone());
    let mut engine = CollectorEngine::new(
        options.owner,
        options.instance,
        options.device,
        owner_lock.session_id.clone(),
        desktop_id,
        options.fixture,
        environment,
        SystemCollectorClock,
        validator.clone(),
    );

    let mut input = InputFrames::spawn(validator);

    loop {
        if !engine.should_exit() {
            if SIGNAL_STOP.load(Ordering::Acquire) {
                engine.stop("signal", "owner");
            }
            if !parent.is_alive() {
                engine.stop("parent-death", "owner");
            }

            let alive = input.drain(32, |result| match result {
                ValidationResult::Valid(message) => {
                    if message.get("type").and_then(JsonValue::as_str) == Some("configure") {
                        if let Some(max_p) = message
                            .get("policy")
                            .and_then(|p| p.get("maxPending"))
                            .and_then(JsonValue::as_u64)
                        {
                            output.set_max_pending(max_p as usize);
                        }
                    }
                    engine.receive(&message);
                }
                ValidationResult::Invalid(err) => {
                    engine.failure(err.code(), "invalid");
                }
            });
            if !alive {
                engine.stop("owner-eof", "owner");
            }

            engine.tick(parent.is_alive());
            if !engine.should_exit() {
                engine.poll_environment();
            }
        }

        let outputs = engine.drain_outputs();
        dispatch_outputs(outputs, &output);

        if !output.poll_health() {
            engine.stop("stdout-backpressure", "owner");
            let final_outputs = engine.drain_outputs();
            dispatch_outputs(final_outputs, &output);
        }

        if engine.should_exit() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    engine.environment.cancel_read();
    engine.environment.end_monitoring();
    let drained_ok = output.close_and_drain(250);
    drop(owner_lock);

    if output.is_failed() || !drained_ok {
        74
    } else {
        0
    }
}

fn run() -> i32 {
    let args: Vec<String> = env::args().skip(1).collect();

    if args.first().map(String::as_str) == Some("--navigate-source") {
        if SourceNavigationRequest::accepts_arguments(&args) {
            return run_navigate_source_cli();
        }
        return 64;
    }

    if args.first().map(String::as_str) == Some("--permissions") {
        if let Some(action) = PermissionAction::parse_args(&args) {
            return run_permissions_cli(action.as_str());
        }
        return 64;
    }

    let Some(options) = CliOptions::parse(&args) else {
        return 64;
    };

    if options.worker {
        return run_worker_cli(&options);
    }

    run_control_process(options)
}

fn main() {
    let code = run();
    std::process::exit(code);
}
