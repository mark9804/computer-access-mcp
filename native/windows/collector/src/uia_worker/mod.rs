//! Phase 3/4 Windows UI Automation Core Capture Engine.
//!
//! Runs exclusively inside the isolated out-of-process `--ax-worker` child process (one-shot or
//! `--session-worker yes`). Enforces all Non-Negotiable Invariant #2 privacy gates before and
//! after every UIA read, normalizes DPI via Per-Monitor V2, reads focused text (`uia.text` /
//! `uia.value`), selection (`uia.text`), and bounded surface trees (`uia.tree`, unified through
//! `adapters::kernel::SurfaceCaptureRunner::run` and `LiveUiaSurfaceBackend`) with `SurfaceNodeMap`
//! and `SurfaceBaseline` full/diff snapshots, while listening for WinEvent dirty notifications on a
//! clean background message-pump thread.
//!
//! Strictly acyclic 4-layer submodule architecture:
//! - Layer 0 (leaves, zero sibling imports): `target_verify`, `text_read`
//! - Layer 1: `surface_backend` (imports `target_verify`, `text_read`)
//! - Layer 2: `read_pipeline` (imports `target_verify`, `text_read`, `surface_backend`)
//! - Layer 3: `session` (imports `target_verify`, `read_pipeline`)

mod read_pipeline;
mod session;
mod surface_backend;
mod target_verify;
mod text_read;

pub use session::{
    execute_live_one_shot, read_window_for_test, read_window_with_identity_for_test,
    LiveUiaSession,
};
pub use target_verify::{
    resolve_application_for_hwnd, resolve_application_identity_for_hwnd,
    resolve_foreground_application,
};
pub use text_read::sanitize_display_url;
