//! Bounded post-gate UIA text readers, static-text 0-IPC fast path, and display URL sanitization.
//!
//! Layer 0 leaf module — imports no sibling `uia_worker` modules.

use history_contract::utf16_len;
use windows::Win32::UI::Accessibility::IUIAutomationElement;

use crate::adapters::{AppAdapterSpec, SafeDisplayText, StaticTextPolicy};
use crate::policy::{is_effectively_empty_text, is_private_use_only_text, TextSecurityGate};
use crate::protocol_model::{bounded_utf16_slice, CollectorClock, GapDiagnosticCode, TextRead};
use crate::uia_com::{UiaCallError, UiaClient, UiaElementMetadata};
use crate::worker_ipc::ReadTicket;

pub(super) fn read_focused_text(
    uia: &UiaClient,
    focused_elem: &IUIAutomationElement,
    focused_meta: &UiaElementMetadata,
    ticket: &ReadTicket,
    clock: &dyn CollectorClock,
) -> Result<TextRead, GapDiagnosticCode> {
    let budget = ticket.policy.max_text_code_units.clamp(1, 8_192);
    let visible = ticket.policy.text_range.as_deref() == Some("visible");
    let deadline = ticket.deadline_monotonic_ms;
    let mut before_ipc = || -> Option<i64> {
        let rem = deadline.saturating_sub(clock.monotonic_ms());
        (rem > 0).then_some(rem)
    };

    if visible {
        let pat = uia
            .get_text_pattern_budgeted(focused_elem, true, true, &mut before_ipc)
            .map_err(|_| GapDiagnosticCode::VisibleRangeUnavailable)?
            .ok_or(GapDiagnosticCode::VisibleRangeUnavailable)?;
        let vis = uia
            .read_text_pattern_visible_budgeted(
                &pat,
                budget,
                || clock.monotonic_ms() + 30 < deadline,
                &mut before_ipc,
            )
            .ok_or(GapDiagnosticCode::VisibleRangeUnavailable)?;
        return Ok(TextRead {
            text: vis.text,
            source: "uia.text".to_string(),
            total_length: Some(vis.total_length),
            selection: vis.selection,
            range_start: vis.range_start,
            range_basis: "visible".to_string(),
            complete: false,
            truncated: vis.truncated,
            missing_reasons: vis.missing_reasons,
            read_units: None,
        });
    }

    // Primary: IUIAutomationTextPattern / TextPattern2 (prefix mode).
    match uia.get_text_pattern_budgeted(focused_elem, true, true, &mut before_ipc) {
        Ok(Some(pat)) => {
            if let Some(pref) = uia.read_text_pattern_prefix_budgeted(
                &pat,
                budget,
                || clock.monotonic_ms() + 30 < deadline,
                &mut before_ipc,
            ) {
                return Ok(TextRead {
                    text: pref.text,
                    source: "uia.text".to_string(),
                    total_length: pref.total_length,
                    selection: pref.selection,
                    range_start: 0,
                    range_basis: "prefix".to_string(),
                    complete: pref.complete,
                    truncated: pref.truncated,
                    missing_reasons: pref.missing_reasons,
                    read_units: None,
                });
            }
        }
        Err(UiaCallError::AccessDenied) => return Err(GapDiagnosticCode::TextReadUnavailable),
        Ok(None) | Err(UiaCallError::Unavailable) => {}
    }

    if clock.monotonic_ms() >= deadline {
        return Err(GapDiagnosticCode::ReadDeadline);
    }

    // Fallback: IUIAutomationValuePattern (prefix mode ONLY).
    match uia.get_value_pattern_budgeted(focused_elem, &mut before_ipc) {
        Ok(Some(val_pat)) => {
            if let Some(pref) =
                uia.read_value_pattern_prefix_budgeted(&val_pat, budget, &mut before_ipc)
            {
                return Ok(TextRead {
                    text: pref.text,
                    source: "uia.value".to_string(),
                    total_length: pref.total_length,
                    selection: None,
                    range_start: 0,
                    range_basis: "prefix".to_string(),
                    complete: pref.complete,
                    truncated: pref.truncated,
                    missing_reasons: pref.missing_reasons,
                    read_units: None,
                });
            }
        }
        Err(UiaCallError::AccessDenied) => return Err(GapDiagnosticCode::TextReadUnavailable),
        Ok(None) | Err(UiaCallError::Unavailable) => {}
    }

    // Static text fallback: Win32 STATIC / UIA Text controls expose label text via cached Name.
    if focused_meta.mapped.ax_role == Some("AXStaticText") {
        if let Some(ref name) = focused_meta.name {
            let total = utf16_len(name);
            let (text, complete, truncated, missing_reasons) = if total <= budget {
                (name.clone(), true, false, Vec::new())
            } else {
                let sliced = bounded_utf16_slice(name, 0, budget)
                    .ok_or(GapDiagnosticCode::TextResultInvalid)?;
                (sliced, false, true, vec!["text-budget".to_string()])
            };
            return Ok(TextRead {
                text,
                source: "uia.value".to_string(),
                total_length: Some(total),
                selection: None,
                range_start: 0,
                range_basis: "prefix".to_string(),
                complete,
                truncated,
                missing_reasons,
                read_units: None,
            });
        }
    }

    Err(GapDiagnosticCode::TextReadUnavailable)
}

/// Strictly validate and sanitize a candidate display URL (`http://` or `https://` ONLY):
/// - Rejects empty / whitespace / invisible-only strings (including `U+200B`, `U+FEFF`, etc.)
///   and any control characters (`\r`, `\n`, `\0`, `\t`, etc.).
/// - Requires an explicit `http://` or `https://` scheme (case-insensitive), rejecting
///   `javascript:`, `data:`, `file://`, `blob:`, `about:`, and arbitrary non-URL text.
/// - Strips any `userinfo` (`user:pass@` or `user@`) strictly from the authority component
///   (between `scheme://` and the first `/`, `?`, `#`, or `\`) using the last `@` in the
///   authority so `@` in path/query/fragment (e.g. `?email=a@b`) is preserved.
/// - Rejects empty or malformed hosts after stripping `userinfo`.
pub fn sanitize_display_url(raw: &str) -> Option<String> {
    if is_effectively_empty_text(raw) || raw.chars().any(char::is_control) {
        return None;
    }
    let trimmed = SafeDisplayText::clean(Some(raw))?;
    let scheme_len =
        if trimmed.len() >= 8 && trimmed.as_bytes()[..8].eq_ignore_ascii_case(b"https://") {
            8
        } else if trimmed.len() >= 7 && trimmed.as_bytes()[..7].eq_ignore_ascii_case(b"http://") {
            7
        } else {
            return None;
        };
    let scheme = &trimmed[..scheme_len];
    let rest = &trimmed[scheme_len..];
    let auth_end = rest.find(['/', '?', '#', '\\']).unwrap_or(rest.len());
    let authority = &rest[..auth_end];
    let suffix = &rest[auth_end..];
    let host_port = match authority.rfind('@') {
        Some(at_idx) => &authority[at_idx + 1..],
        None => authority,
    };
    if host_port.is_empty()
        || is_effectively_empty_text(host_port)
        || is_private_use_only_text(host_port)
        || host_port.chars().any(|c| {
            c.is_whitespace()
                || matches!(
                    c,
                    '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}' | '\u{00AD}'
                )
        })
    {
        return None;
    }
    if host_port.starts_with('[') {
        let close = host_port.find(']')?;
        if close <= 1 {
            return None;
        }
        let after = &host_port[close + 1..];
        if !after.is_empty() {
            let port = after.strip_prefix(':')?;
            if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
        }
    } else if let Some((host, port)) = host_port.split_once(':') {
        if host.is_empty() || port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
    }
    Some(format!("{scheme}{host_port}{suffix}"))
}

/// Post-security-gate bounded `ValuePattern` URL reader strictly restricted to non-sensitive
/// `AXWebArea` and `AXLink` elements (e.g. Figma `/design/...`, `/slides/...` and Slack URLs).
///
/// Runs all security, `may_traverse`, and role gates BEFORE inspecting `cached_url`, meters and
/// timeout-refreshes every COM IPC individually, sanitizes the URL (`http://`/`https://` only,
/// `userinfo` stripped), and propagates `UiaCallError::AccessDenied` without swallowing.
#[allow(clippy::too_many_arguments)]
pub(super) fn read_safe_display_url_post_gate(
    uia: &UiaClient,
    elem: &IUIAutomationElement,
    meta: &UiaElementMetadata,
    cached_url: &mut Option<Option<String>>,
    spec: &AppAdapterSpec,
    active_deadline_ms: i64,
    clock: &dyn CollectorClock,
    mut consume_call: impl FnMut() -> bool,
) -> Result<Option<String>, UiaCallError> {
    let ax_role = meta.mapped.ax_role;
    if !matches!(ax_role, Some("AXWebArea" | "AXLink"))
        || !meta.supports_value_pattern
        || meta.is_sensitive()
        || !TextSecurityGate::may_traverse(&meta.subrole_read, meta.is_password)
    {
        *cached_url = Some(None);
        return Ok(None);
    }
    if let Some(ref cached) = cached_url {
        return Ok(cached.clone());
    }

    let cap = spec.max_node_text_units.clamp(1, 512);
    let raw_read_cap = cap.clamp(1024, 8_192);
    let mut ipc_aborted = false;
    let mut before_ipc = || -> Option<i64> {
        let rem = active_deadline_ms.saturating_sub(clock.monotonic_ms());
        if rem <= 0 || !consume_call() {
            ipc_aborted = true;
            return None;
        }
        Some(rem)
    };

    let Some(vpat) = uia.get_value_pattern_budgeted(elem, &mut before_ipc)? else {
        if !ipc_aborted {
            *cached_url = Some(None);
        }
        return Ok(None);
    };
    let pref_opt = match uia.read_value_pattern_prefix_budgeted_checked(
        &vpat,
        raw_read_cap,
        &mut before_ipc,
    ) {
        Ok(opt) => opt,
        Err(UiaCallError::AccessDenied) => return Err(UiaCallError::AccessDenied),
        Err(UiaCallError::Unavailable) => return Ok(None),
    };
    let Some(pref) = pref_opt else {
        if !ipc_aborted {
            *cached_url = Some(None);
        }
        return Ok(None);
    };
    let url = sanitize_display_url(&pref.text).and_then(|clean| {
        if utf16_len(&clean) <= cap {
            Some(clean)
        } else {
            bounded_utf16_slice(&clean, 0, cap).filter(|s| !s.is_empty())
        }
    });
    *cached_url = Some(url.clone());
    Ok(url)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum UiaNodeTextOutcome {
    Text {
        value: String,
        truncated: bool,
        reasons: Vec<String>,
        /// True when text is unfocused pure-PUA static text kept solely so `WeightedSurfaceTraversal`
        /// drops the leaf cleanly without charging `ProviderRefused` or text budget.
        is_unfocused_pua_static: bool,
    },
    Unavailable,
}

fn effective_static_text_cap(node_cap: usize, static_text_probe: StaticTextPolicy) -> usize {
    match static_text_probe {
        StaticTextPolicy::Standard => node_cap,
        StaticTextPolicy::BoundedRangeProbe { max_units } => node_cap.min(max_units),
    }
}

fn slice_node_text_bounded(raw: &str, cap: usize) -> UiaNodeTextOutcome {
    let units = utf16_len(raw);
    let (sliced, trunc) = if units <= cap {
        (raw.to_string(), false)
    } else if let Some(s) = bounded_utf16_slice(raw, 0, cap) {
        (s, true)
    } else {
        return UiaNodeTextOutcome::Unavailable;
    };
    UiaNodeTextOutcome::Text {
        value: sliced,
        truncated: trunc,
        reasons: if trunc {
            vec!["text-budget".to_string()]
        } else {
            Vec::new()
        },
        is_unfocused_pua_static: false,
    }
}

/// 0-IPC fast path for `AXStaticText` reading pre-cached `meta.name` / `meta.safe_description()`,
/// strictly clamping to `effective_static_text_cap(node_cap, static_text_probe)` so
/// `StaticTextPolicy::BoundedRangeProbe { max_units }` is honored even without pattern IPCs.
/// Returns `None` only when cached fields are absent/empty and pattern fallback may proceed.
fn read_cached_static_text_bounded(
    meta: &UiaElementMetadata,
    node_cap: usize,
    static_text_probe: StaticTextPolicy,
    is_focused: bool,
) -> Option<UiaNodeTextOutcome> {
    let effective_cap = effective_static_text_cap(node_cap, static_text_probe);
    if effective_cap == 0 || meta.is_sensitive() {
        return Some(UiaNodeTextOutcome::Unavailable);
    }

    if let Some(ref name) = meta.name {
        if !is_effectively_empty_text(name) {
            if !is_focused && is_private_use_only_text(name) {
                if let Some(desc) = meta.safe_description() {
                    if !is_effectively_empty_text(desc) && !is_private_use_only_text(desc) {
                        return Some(slice_node_text_bounded(desc, effective_cap));
                    }
                }
                return Some(UiaNodeTextOutcome::Text {
                    value: name.clone(),
                    truncated: false,
                    reasons: Vec::new(),
                    is_unfocused_pua_static: true,
                });
            }
            return Some(slice_node_text_bounded(name, effective_cap));
        }
    }

    if let Some(desc) = meta.safe_description() {
        if !is_effectively_empty_text(desc) && (is_focused || !is_private_use_only_text(desc)) {
            return Some(slice_node_text_bounded(desc, effective_cap));
        }
    }

    None
}

/// Shared post-security-gate bounded node text reader used by `LiveUiaSurfaceBackend`:
/// - For `AXStaticText`, reads pre-cached `meta.name` FIRST (0 extra COM IPCs, skipping unfocused
///   PUA-only text), falling back to `meta.safe_description()`, and ONLY querying `TextPattern` /
///   `ValuePattern` when `name` is empty AND cached pattern availability flags are true (honoring
///   `StaticTextPolicy::BoundedRangeProbe { max_units }` on BOTH the 0-IPC fast path and pattern
///   fallbacks).
/// - For `AXTextField` / `AXTextArea`, gates `TextPattern` / `ValuePattern` on cached availability.
/// - Every COM IPC is individually budgeted and timeout-refreshed via `*_budgeted`.
#[allow(clippy::too_many_arguments)]
pub(super) fn read_uia_node_text_bounded(
    uia: &UiaClient,
    elem: &IUIAutomationElement,
    meta: &UiaElementMetadata,
    expected_role: &str,
    node_cap: usize,
    static_text_probe: StaticTextPolicy,
    is_focused: bool,
    already_read_focus_text: Option<&str>,
    active_deadline_ms: i64,
    clock: &dyn CollectorClock,
    mut consume_call: impl FnMut() -> bool,
) -> UiaNodeTextOutcome {
    let effective_cap = if expected_role == "AXStaticText" {
        effective_static_text_cap(node_cap, static_text_probe)
    } else {
        node_cap
    };
    if effective_cap == 0 || meta.is_sensitive() {
        return UiaNodeTextOutcome::Unavailable;
    }

    if is_focused {
        if let Some(ft) = already_read_focus_text {
            return slice_node_text_bounded(ft, effective_cap);
        }
    }

    let mut before_ipc = || -> Option<i64> {
        let rem = active_deadline_ms.saturating_sub(clock.monotonic_ms());
        if rem <= 0 || !consume_call() {
            return None;
        }
        Some(rem)
    };

    if expected_role == "AXStaticText" {
        if let Some(outcome) =
            read_cached_static_text_bounded(meta, node_cap, static_text_probe, is_focused)
        {
            return outcome;
        }

        if meta.supports_text_pattern || meta.supports_text_pattern2 {
            match uia.get_text_pattern_budgeted(
                elem,
                meta.supports_text_pattern,
                meta.supports_text_pattern2,
                &mut before_ipc,
            ) {
                Ok(Some(pat)) => {
                    if let Some(pref) = uia.read_text_pattern_prefix_budgeted(
                        &pat,
                        effective_cap,
                        || false,
                        &mut before_ipc,
                    ) {
                        return UiaNodeTextOutcome::Text {
                            value: pref.text,
                            truncated: pref.truncated,
                            reasons: pref.missing_reasons,
                            is_unfocused_pua_static: false,
                        };
                    }
                }
                Err(UiaCallError::AccessDenied) => return UiaNodeTextOutcome::Unavailable,
                Ok(None) | Err(UiaCallError::Unavailable) => {}
            }
        }

        if meta.supports_value_pattern {
            if let Ok(Some(vpat)) = uia.get_value_pattern_budgeted(elem, &mut before_ipc) {
                if let Some(pref) =
                    uia.read_value_pattern_prefix_budgeted(&vpat, effective_cap, &mut before_ipc)
                {
                    return UiaNodeTextOutcome::Text {
                        value: pref.text,
                        truncated: pref.truncated,
                        reasons: pref.missing_reasons,
                        is_unfocused_pua_static: false,
                    };
                }
            }
        }

        return UiaNodeTextOutcome::Unavailable;
    }

    // Editable controls (`AXTextField` / `AXTextArea`).
    let try_text = meta.supports_text_pattern || meta.supports_text_pattern2;
    let try_value = meta.supports_value_pattern || (!try_text && meta.control_type == 50004);

    if try_text {
        match uia.get_text_pattern_budgeted(
            elem,
            meta.supports_text_pattern,
            meta.supports_text_pattern2,
            &mut before_ipc,
        ) {
            Ok(Some(pat)) => {
                if let Some(pref) = uia.read_text_pattern_prefix_budgeted(
                    &pat,
                    effective_cap,
                    || false,
                    &mut before_ipc,
                ) {
                    return UiaNodeTextOutcome::Text {
                        value: pref.text,
                        truncated: pref.truncated,
                        reasons: pref.missing_reasons,
                        is_unfocused_pua_static: false,
                    };
                }
            }
            Err(UiaCallError::AccessDenied) => return UiaNodeTextOutcome::Unavailable,
            Ok(None) | Err(UiaCallError::Unavailable) => {}
        }
    }

    if try_value {
        if let Ok(Some(vpat)) = uia.get_value_pattern_budgeted(elem, &mut before_ipc) {
            if let Some(pref) =
                uia.read_value_pattern_prefix_budgeted(&vpat, effective_cap, &mut before_ipc)
            {
                return UiaNodeTextOutcome::Text {
                    value: pref.text,
                    truncated: pref.truncated,
                    reasons: pref.missing_reasons,
                    is_unfocused_pua_static: false,
                };
            }
        }
    }

    UiaNodeTextOutcome::Unavailable
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{MappedRole, ProtectedContentRead, SubroleRead};
    use crate::uia_traversal::RuntimeIdKey;

    fn sample_static_text_meta(
        name: Option<&str>,
        help_text: Option<&str>,
        is_password: ProtectedContentRead,
    ) -> UiaElementMetadata {
        UiaElementMetadata {
            runtime_id: RuntimeIdKey(vec![42, 7]),
            process_id: 1234,
            control_type: 50020,
            is_password,
            is_enabled: Some(true),
            is_control_element: Some(true),
            is_content_element: Some(true),
            is_offscreen: Some(false),
            is_keyboard_focusable: Some(false),
            has_keyboard_focus: Some(false),
            native_hwnd: None,
            name: name.map(str::to_string),
            localized_control_type: Some("text".to_string()),
            automation_id: None,
            class_name: None,
            aria_role: None,
            aria_properties: None,
            landmark_type: None,
            help_text: help_text.map(str::to_string),
            full_description: None,
            heading_level: 0,
            supports_text_pattern: false,
            supports_text_pattern2: false,
            supports_text_edit_pattern: false,
            supports_value_pattern: false,
            supports_scroll_pattern: false,
            value_is_read_only: None,
            is_read_only: true,
            logical_rect: None,
            subrole_read: SubroleRead::Value("AXStaticText".to_string()),
            mapped: MappedRole {
                ax_role: Some("AXStaticText"),
                subrole: None,
                category: "text",
            },
        }
    }

    #[test]
    fn sanitize_display_url_allows_http_https_strips_userinfo_and_rejects_unsafe_inputs() {
        assert_eq!(
            sanitize_display_url("https://www.figma.com/design/abc?node-id=1").as_deref(),
            Some("https://www.figma.com/design/abc?node-id=1")
        );
        assert_eq!(
            sanitize_display_url("HTTP://user:secret@example.com:8080/path?q=a@b").as_deref(),
            Some("HTTP://example.com:8080/path?q=a@b")
        );
        assert_eq!(
            sanitize_display_url("https://token@example.com/a").as_deref(),
            Some("https://example.com/a")
        );
        assert_eq!(
            sanitize_display_url("https://example.com/user?email=a@b#sec@1").as_deref(),
            Some("https://example.com/user?email=a@b#sec@1")
        );
        assert_eq!(
            sanitize_display_url("https://user:p@ss@example.com/user?email=a@b").as_deref(),
            Some("https://example.com/user?email=a@b")
        );
        assert_eq!(
            sanitize_display_url("  \u{200B}https://[::1]:3000/test\u{FEFF}  ").as_deref(),
            Some("https://[::1]:3000/test")
        );

        for rejected in [
            "",
            "   ",
            "\u{200B}",
            "\u{FEFF}  \u{200D}",
            "javascript:alert(1)",
            "JAVASCRIPT:alert(1)",
            "data:text/html,<h1>x</h1>",
            "file:///C:/secret.txt",
            "blob:https://example.com/123",
            "about:blank",
            "Just some document text",
            "https://",
            "https:///path",
            "https://user:pass@/path",
            "https://user:pass@:8080/path",
            "https://user:pass@\\evil.com",
            "https://example.com/a\nb",
            "https://example.com/a\r\nb",
            "https://example.com/\0",
            "https://example.com/\t",
            "https://foo bar/path",
            "https://\u{200B}/path",
            "https://example.com:notaport/path",
        ] {
            assert_eq!(
                sanitize_display_url(rejected),
                None,
                "expected URL to be rejected: {rejected:?}"
            );
        }
    }

    #[test]
    fn ax_static_text_bounded_range_probe_clamps_zero_ipc_fast_path() {
        let meta = sample_static_text_meta(
            Some("Hello 可见🙂 world 1234567890"),
            Some("Fallback description text"),
            ProtectedContentRead::Value(false),
        );

        // Standard policy uses full `node_cap`.
        assert_eq!(
            read_cached_static_text_bounded(&meta, 256, StaticTextPolicy::Standard, false),
            Some(UiaNodeTextOutcome::Text {
                value: "Hello 可见🙂 world 1234567890".to_string(),
                truncated: false,
                reasons: Vec::new(),
                is_unfocused_pua_static: false,
            })
        );

        // BoundedRangeProbe { max_units: 9 } MUST clamp the 0-IPC `meta.name` fast path to
        // `node_cap.min(9)` without bisecting the UTF-16 surrogate pair "🙂" at indices 8..10.
        assert_eq!(
            read_cached_static_text_bounded(
                &meta,
                256,
                StaticTextPolicy::BoundedRangeProbe { max_units: 9 },
                false,
            ),
            Some(UiaNodeTextOutcome::Text {
                value: "Hello 可见".to_string(),
                truncated: true,
                reasons: vec!["text-budget".to_string()],
                is_unfocused_pua_static: false,
            })
        );

        // Also clamps the 0-IPC `safe_description()` path when `name` is absent or unfocused PUA.
        let desc_only = sample_static_text_meta(
            None,
            Some("Fallback description text"),
            ProtectedContentRead::Value(false),
        );
        assert_eq!(
            read_cached_static_text_bounded(
                &desc_only,
                256,
                StaticTextPolicy::BoundedRangeProbe { max_units: 8 },
                false,
            ),
            Some(UiaNodeTextOutcome::Text {
                value: "Fallback".to_string(),
                truncated: true,
                reasons: vec!["text-budget".to_string()],
                is_unfocused_pua_static: false,
            })
        );

        let pua_with_desc = sample_static_text_meta(
            Some("\u{E000}\u{E001}"),
            Some("Fallback description text"),
            ProtectedContentRead::Value(false),
        );
        assert_eq!(
            read_cached_static_text_bounded(
                &pua_with_desc,
                256,
                StaticTextPolicy::BoundedRangeProbe { max_units: 8 },
                false,
            ),
            Some(UiaNodeTextOutcome::Text {
                value: "Fallback".to_string(),
                truncated: true,
                reasons: vec!["text-budget".to_string()],
                is_unfocused_pua_static: false,
            })
        );

        // Zero probe budget fails closed with Unavailable.
        assert_eq!(
            read_cached_static_text_bounded(
                &meta,
                256,
                StaticTextPolicy::BoundedRangeProbe { max_units: 0 },
                false,
            ),
            Some(UiaNodeTextOutcome::Unavailable)
        );

        // Sensitive metadata always fails closed on the 0-IPC fast path.
        let secret = sample_static_text_meta(
            Some("ShouldNeverRead"),
            None,
            ProtectedContentRead::Value(true),
        );
        assert_eq!(
            read_cached_static_text_bounded(&secret, 256, StaticTextPolicy::Standard, false),
            Some(UiaNodeTextOutcome::Unavailable)
        );
    }
}
