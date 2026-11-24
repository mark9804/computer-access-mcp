//! Custom WeChat surface extractor (Qt 4.x macOS/Windows + Win32 DuiLib 3.x parity).
//!
//! Interacts exclusively through `&mut dyn SafeSurfaceContext` and public contract types
//! from `super`; never imports `super::kernel`.

use std::collections::{HashSet, VecDeque};

use super::{
    ActivationMode, AdapterNodeInfo, AppAdapter, AppAdapterSpec, CustomSurfaceNode,
    CustomSurfaceResult, SafeSurfaceContext, StaticTextPolicy, SurfaceHandle, WindowAnchorPolicy,
};
use crate::policy::is_private_use_only_text;

pub const WECHAT_ADAPTER_SPEC: AppAdapterSpec = AppAdapterSpec {
    id: "wechat",
    display_name: "WeChat",
    match_application_ids: &["com.tencent.xinwechat", "wechat.exe", "weixin.exe"],
    activation: ActivationMode::None,
    window_anchor: WindowAnchorPolicy::AllowUnfocusedWindow,
    static_text_probe: StaticTextPolicy::BoundedRangeProbe { max_units: 256 },
    preferred_roles: &[
        "AXList",
        "AXTable",
        "AXRow",
        "AXScrollArea",
        "AXStaticText",
        "AXTextArea",
        "AXTextField",
    ],
    ignored_roles: &["AXMenuBar", "AXMenu", "AXScrollBar"],
    ignored_subroles: &[],
    page_size: 16,
    max_node_text_units: 256,
    block_private_windows: false,
    collapse_empty_containers: false,
    expand_text_wrapper_ids: &["big_title_line_h_view"],
};

pub static WECHAT_ADAPTER: WeChatAdapter = WeChatAdapter;
/// Matches either exact Qt `objectName` / macOS `AXIdentifier` (`"chat_message_list"`)
/// OR the final `.`-delimited segment of Windows Qt `AutomationId` paths
/// (`"MainWindow.centralWidget.splitter.chat_message_list"`).
pub fn matches_wechat_id(identifier: Option<&str>, target: &str) -> bool {
    let Some(id) = identifier else {
        return false;
    };
    id == target || id.rsplit('.').next() == Some(target)
}

pub struct WeChatAdapter;

impl WeChatAdapter {
    const TAIL_MESSAGE_LIMIT: usize = 32;
    const MAX_LOCATOR_DEPTH: usize = 12;
    const MAX_LOCATOR_VISITS: usize = 80;
    const SKIPPED_CONTAINER_ROLES: &'static [&'static str] = &[
        "AXButton",
        "AXToolbar",
        "AXMenuBar",
        "AXMenu",
        "AXMenuItem",
        "AXScrollBar",
        "AXImage",
        "AXTable",
        "AXOutline",
    ];

    fn is_skipped_container_role(role: &str) -> bool {
        Self::SKIPPED_CONTAINER_ROLES.contains(&role)
    }

    fn is_duilib_session_list(info: &AdapterNodeInfo) -> bool {
        info.role == "AXList"
            && info.identifier.is_none()
            && info
                .label
                .as_deref()
                .is_some_and(|l| matches!(l, "会话" | "Chats" | "Session"))
    }

    fn is_duilib_message_list(info: &AdapterNodeInfo) -> bool {
        info.role == "AXList"
            && info.identifier.is_none()
            && info
                .label
                .as_deref()
                .is_some_and(|l| matches!(l, "消息" | "Messages"))
    }
}

impl AppAdapter for WeChatAdapter {
    fn spec(&self) -> &'static AppAdapterSpec {
        &WECHAT_ADAPTER_SPEC
    }

    fn has_custom_extractor(&self) -> bool {
        true
    }

    fn extract_surface(&self, ctx: &mut dyn SafeSurfaceContext) -> Option<CustomSurfaceResult> {
        let root_handle = ctx.root();
        let root_info = ctx.inspect(root_handle)?;

        let mut chat_name_info: Option<AdapterNodeInfo> = None;
        let mut fallback_title_info: Option<AdapterNodeInfo> = None;
        let mut message_list_info: Option<AdapterNodeInfo> = None;
        let mut duilib_message_list_info: Option<AdapterNodeInfo> = None;
        let mut input_info: Option<AdapterNodeInfo> = None;

        // Check focused handle first when it directly identifies chat_input_field.
        if let Some(focus) = ctx.focus() {
            if let Some(focus_info) = ctx.inspect(focus) {
                if matches_wechat_id(focus_info.identifier.as_deref(), "chat_input_field") {
                    input_info = Some(focus_info);
                }
            }
        }
        if ctx.is_aborted() {
            return None;
        }

        // Shallow BFS locating right chat pane elements while NEVER expanding session_list.
        let mut queue: VecDeque<(SurfaceHandle, usize)> = VecDeque::new();
        queue.push_back((root_handle, 0));
        let mut visited: HashSet<SurfaceHandle> = HashSet::new();
        visited.insert(root_handle);
        let mut inspected_count = 1usize;

        while let Some((handle, depth)) = queue.pop_front() {
            if inspected_count >= Self::MAX_LOCATOR_VISITS
                || !ctx.can_continue()
                || (chat_name_info.is_some()
                    && message_list_info.is_some()
                    && input_info.is_some())
            {
                break;
            }
            let info = if handle == root_handle {
                root_info.clone()
            } else {
                inspected_count += 1;
                let Some(fresh) = ctx.inspect(handle) else {
                    continue;
                };
                fresh
            };

            let id = info.identifier.as_deref();
            if matches_wechat_id(id, "session_list")
                || matches_wechat_id(id, "virtual_cell")
                || Self::is_duilib_session_list(&info)
            {
                continue;
            }
            if handle != root_handle && Self::is_skipped_container_role(&info.role) {
                continue;
            }

            if matches_wechat_id(id, "current_chat_name_label") {
                chat_name_info = Some(info);
                continue;
            }
            if matches_wechat_id(id, "big_title_line_h_view") && info.role == "AXStaticText" {
                fallback_title_info = Some(info);
                // Qt header views may nest current_chat_name_label inside AXStaticText!
                if chat_name_info.is_none() && depth < Self::MAX_LOCATOR_DEPTH {
                    if let Some(nested) = ctx.children(handle, 0, 8) {
                        for child in nested {
                            if visited.insert(child) {
                                queue.push_back((child, depth + 1));
                            }
                        }
                    }
                }
                continue;
            }
            if matches_wechat_id(id, "chat_message_list") {
                message_list_info = Some(info);
                continue;
            }
            if matches_wechat_id(id, "chat_input_field") {
                input_info = Some(info);
                continue;
            }
            if duilib_message_list_info.is_none() && Self::is_duilib_message_list(&info) {
                duilib_message_list_info = Some(info);
                continue;
            }

            if chat_name_info.is_some() && message_list_info.is_some() && input_info.is_some() {
                break;
            }
            if depth >= Self::MAX_LOCATOR_DEPTH
                || info.child_count == 0
                || matches!(
                    info.role.as_str(),
                    "AXList" | "AXStaticText" | "AXTextArea" | "AXTextField"
                )
            {
                continue;
            }

            if let Some(children) = ctx.children(handle, 0, 32) {
                for child in children {
                    if visited.insert(child) {
                        queue.push_back((child, depth + 1));
                    }
                }
            }
        }

        if ctx.is_aborted() {
            return None;
        }

        let using_duilib = message_list_info.is_none() && duilib_message_list_info.is_some();
        if message_list_info.is_none() {
            message_list_info = duilib_message_list_info;
        }

        // Accept focused AXTextArea fallback only when chat_message_list confirms chat UI.
        if input_info.is_none() && message_list_info.is_some() {
            if let Some(focus) = ctx.focus() {
                if let Some(focus_info) = ctx.inspect(focus) {
                    if focus_info.role == "AXTextArea"
                        || (using_duilib && focus_info.role == "AXTextField")
                    {
                        input_info = Some(focus_info);
                    }
                }
            }
        }
        if ctx.is_aborted() {
            return None;
        }

        // Fall back to standard weighted traversal when neither chat list nor input is present
        // (e.g. login QR screen, settings, contacts).
        if message_list_info.is_none() && input_info.is_none() {
            return None;
        }

        let max_nodes = ctx.max_output_nodes().clamp(1, 96);
        let focus_handle = ctx.focus();
        let mut seen: HashSet<SurfaceHandle> = HashSet::new();
        seen.insert(root_handle);
        let mut focus_assigned = false;

        let make_node = |ctx: &mut dyn SafeSurfaceContext,
                         focus_assigned: &mut bool,
                         info: &AdapterNodeInfo,
                         parent: Option<SurfaceHandle>,
                         role: &'static str,
                         text: Option<String>|
         -> CustomSurfaceNode {
            let bounds = ctx.bounds(info.handle);
            let is_focused = !*focus_assigned
                && focus_handle
                    .map(|fh| fh == info.handle)
                    .unwrap_or(info.is_focused);
            if is_focused {
                *focus_assigned = true;
            }
            CustomSurfaceNode {
                handle: info.handle,
                parent,
                role,
                ax_role: Some(info.role.clone()),
                text,
                is_focused,
                observed_at_ms: info.observed_at_ms,
                bounds: bounds.map(|(b, _)| b),
                bounds_observed_at_ms: bounds.map(|(_, ts)| ts),
            }
        };

        let has_zero_size = |ctx: &mut dyn SafeSurfaceContext, handle: SurfaceHandle| -> bool {
            ctx.bounds(handle)
                .is_some_and(|(r, _)| r.width <= 0.0 || r.height <= 0.0)
        };

        let mut nodes: Vec<CustomSurfaceNode> =
            vec![make_node(ctx, &mut focus_assigned, &root_info, None, "container", None)];

        if let Some(ref title_info) = chat_name_info.or(fallback_title_info) {
            if nodes.len() < max_nodes && seen.insert(title_info.handle) {
                if let Some(title_text) = ctx.text(title_info.handle, None) {
                    if !title_text.trim().is_empty() {
                        nodes.push(make_node(
                            ctx,
                            &mut focus_assigned,
                            title_info,
                            Some(root_handle),
                            "text",
                            Some(title_text),
                        ));
                    }
                }
            }
        }

        let reserve_input_slot = usize::from(
            input_info
                .as_ref()
                .is_some_and(|inp| !seen.contains(&inp.handle)),
        );
        let mut truncated_tail = false;

        if let Some(ref list_info) = message_list_info {
            if nodes.len() + reserve_input_slot < max_nodes {
                let list_ready = list_info.handle == root_handle || seen.insert(list_info.handle);
                if list_ready {
                    if list_info.handle != root_handle {
                        nodes.push(make_node(
                            ctx,
                            &mut focus_assigned,
                            list_info,
                            Some(root_handle),
                            "container",
                            None,
                        ));
                    }
                    let message_slots = max_nodes.saturating_sub(nodes.len() + reserve_input_slot);
                    if list_info.child_count > Self::TAIL_MESSAGE_LIMIT {
                        truncated_tail = true;
                    }
                    if list_info.child_count > 0 && message_slots > 0 && ctx.can_continue() {
                        if let Some(tail_children) =
                            ctx.tail_children(list_info.handle, Self::TAIL_MESSAGE_LIMIT)
                        {
                            if ctx.last_children_truncated() {
                                truncated_tail = true;
                            }
                            let mut collected: Vec<CustomSurfaceNode> = Vec::new();
                            for child in tail_children.into_iter().rev() {
                                if collected.len() >= message_slots || !ctx.can_continue() {
                                    truncated_tail = true;
                                    break;
                                }
                                let Some(child_info) = ctx.inspect(child) else {
                                    continue;
                                };
                                if matches_wechat_id(
                                    child_info.identifier.as_deref(),
                                    "virtual_cell",
                                ) || has_zero_size(ctx, child)
                                {
                                    continue;
                                }
                                if child_info.role == "AXStaticText" {
                                    if collected.len() < message_slots
                                        && seen.insert(child_info.handle)
                                    {
                                        if let Some(body) = ctx.text(child_info.handle, None) {
                                            if !body.trim().is_empty() {
                                                collected.push(make_node(
                                                    ctx,
                                                    &mut focus_assigned,
                                                    &child_info,
                                                    Some(list_info.handle),
                                                    "text",
                                                    Some(body),
                                                ));
                                            }
                                        }
                                    }
                                } else if child_info.child_count > 0
                                    && !Self::is_skipped_container_role(&child_info.role)
                                {
                                    let before_unwrap = collected.len();
                                    if let Some(nested) = ctx.children(child, 0, 8) {
                                        for sub in nested.into_iter().rev() {
                                            if collected.len() >= message_slots
                                                || !ctx.can_continue()
                                            {
                                                truncated_tail = true;
                                                break;
                                            }
                                            let Some(sub_info) = ctx.inspect(sub) else {
                                                continue;
                                            };
                                            if matches_wechat_id(
                                                sub_info.identifier.as_deref(),
                                                "virtual_cell",
                                            ) || sub_info.role != "AXStaticText"
                                                || has_zero_size(ctx, sub)
                                            {
                                                continue;
                                            }
                                            if collected.len() < message_slots
                                                && seen.insert(sub_info.handle)
                                            {
                                                if let Some(body) = ctx.text(sub_info.handle, None)
                                                {
                                                    if !body.trim().is_empty() {
                                                        collected.push(make_node(
                                                            ctx,
                                                            &mut focus_assigned,
                                                            &sub_info,
                                                            Some(list_info.handle),
                                                            "text",
                                                            Some(body),
                                                        ));
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    // Windows UIA ListItem (AXRow) fallback when row exposes message in Name.
                                    if collected.len() == before_unwrap
                                        && child_info.role == "AXRow"
                                        && collected.len() < message_slots
                                        && seen.insert(child_info.handle)
                                    {
                                        if let Some(label) = ctx.display_text(child_info.handle) {
                                            let trimmed = label.trim();
                                            if !trimmed.is_empty()
                                                && !is_private_use_only_text(trimmed)
                                            {
                                                collected.push(make_node(
                                                    ctx,
                                                    &mut focus_assigned,
                                                    &child_info,
                                                    Some(list_info.handle),
                                                    "text",
                                                    Some(trimmed.to_string()),
                                                ));
                                            }
                                        }
                                    }
                                } else if child_info.role == "AXRow"
                                    && collected.len() < message_slots
                                    && seen.insert(child_info.handle)
                                {
                                    // Leaf Windows UIA ListItem (AXRow) with message body directly in Name.
                                    if let Some(label) = ctx.display_text(child_info.handle) {
                                        let trimmed = label.trim();
                                        if !trimmed.is_empty()
                                            && !is_private_use_only_text(trimmed)
                                        {
                                            collected.push(make_node(
                                                ctx,
                                                &mut focus_assigned,
                                                &child_info,
                                                Some(list_info.handle),
                                                "text",
                                                Some(trimmed.to_string()),
                                            ));
                                        }
                                    }
                                }
                            }
                            nodes.extend(collected.into_iter().rev());
                        }
                    }
                }
            }
        }

        if let Some(ref inp) = input_info {
            if nodes.len() < max_nodes && seen.insert(inp.handle) {
                let draft = ctx.text(inp.handle, None);
                if draft.is_some() || ctx.has_inspected(inp.handle) {
                    nodes.push(make_node(
                        ctx,
                        &mut focus_assigned,
                        inp,
                        Some(root_handle),
                        "editable",
                        draft,
                    ));
                }
            }
        }

        if ctx.is_aborted() {
            return None;
        }
        Some(CustomSurfaceResult {
            nodes,
            complete: false,
            missing_reasons: if truncated_tail {
                vec!["tree-output-budget".to_string()]
            } else {
                Vec::new()
            },
        })
    }
}
