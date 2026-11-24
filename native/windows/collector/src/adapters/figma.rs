//! Custom Figma surface extractor (macOS + Windows 11 Electron Design & Slides parity).
//!
//! Interacts exclusively through `&mut dyn SafeSurfaceContext` and public contract types
//! from `super`; never imports `super::kernel`.

use std::collections::{HashMap, HashSet, VecDeque};

use super::{
    ActivationMode, AdapterNodeInfo, AppAdapter, AppAdapterSpec, CustomSurfaceNode,
    CustomSurfaceResult, SafeSurfaceContext, StaticTextPolicy, SurfaceHandle, WindowAnchorPolicy,
};
use crate::policy::is_private_use_only_text;
use crate::protocol_model::SurfaceBounds;

pub const FIGMA_ADAPTER_SPEC: AppAdapterSpec = AppAdapterSpec {
    id: "figma",
    display_name: "Figma",
    match_application_ids: &["com.figma.desktop", "figma.exe"],
    activation: ActivationMode::EnhancedUi,
    window_anchor: WindowAnchorPolicy::AllowUnfocusedWindow,
    static_text_probe: StaticTextPolicy::BoundedRangeProbe { max_units: 256 },
    preferred_roles: &[
        "AXWebArea",
        "AXHeading",
        "AXStaticText",
        "AXTextField",
        "AXTextArea",
        "AXComboBox",
        "AXCheckBox",
        "AXRadioButton",
        "AXButton",
        "AXRow",
    ],
    ignored_roles: &[
        "AXMenuBar",
        "AXMenu",
        "AXMenuItem",
        "AXToolbar",
        "AXScrollBar",
        "AXSlider",
    ],
    ignored_subroles: &[],
    page_size: 16,
    max_node_text_units: 256,
    block_private_windows: false,
    collapse_empty_containers: true,
    expand_text_wrapper_ids: &[],
};

pub static FIGMA_ADAPTER: FigmaAdapter = FigmaAdapter;
pub struct FigmaAdapter;

impl FigmaAdapter {
    const MAX_SHELL_DEPTH: usize = 12;
    const MAX_SHELL_VISITS: usize = 64;
    const MAX_LANDMARK_DEPTH: usize = 12;
    const MAX_LANDMARK_VISITS: usize = 96;
    const MAX_ZONE_DEPTH: usize = 12;
    const MAX_TAB_DEPTH: usize = 10;
    const MAX_TAB_VISITS: usize = 64;
    const MAX_CANVAS_VISITS: usize = 80;
    const MAX_SIDEBAR_VISITS: usize = 120;

    const IGNORED_CHROME_ROLES: &'static [&'static str] = &[
        "AXToolbar",
        "AXMenuBar",
        "AXMenu",
        "AXMenuItem",
        "AXScrollBar",
        "AXSlider",
        "AXImage",
    ];

    const SHELL_SKIPPED_ROLES: &'static [&'static str] = &[
        "AXButton",
        "AXToolbar",
        "AXMenuBar",
        "AXMenu",
        "AXMenuItem",
        "AXScrollBar",
        "AXSlider",
        "AXStaticText",
        "AXTextField",
        "AXTextArea",
        "AXImage",
    ];

    const LANDMARK_LOCATOR_SKIPPED_ROLES: &'static [&'static str] = &[
        "AXButton",
        "AXToolbar",
        "AXMenuBar",
        "AXMenu",
        "AXMenuItem",
        "AXScrollBar",
        "AXSlider",
        "AXStaticText",
        "AXTextField",
        "AXTextArea",
        "AXComboBox",
        "AXCheckBox",
        "AXRadioButton",
        "AXTabButton",
        "AXTabGroup",
        "AXTable",
        "AXColumn",
        "AXOutline",
        "AXList",
        "AXImage",
        "AXHeading",
        "AXLink",
    ];

    const TAB_CHROME_NOISE: &'static [&'static str] = &[
        // macOS & shared Figma tab bar chrome
        "Close tab",
        "New file",
        "Open tabs and recently closed items",
        // Windows Electron titlebar chrome
        "Close",
        "Maximize",
        "Minimize",
        "Menu",
        "Restore",
    ];

    const RIGHT_SIDEBAR_CHROME_NOISE: &'static [&'static str] = &[
        "Apply variable",
        "Apply variable mode",
        "Apply variable/property",
        "Toggle visibility",
        "Prototype view",
        "Add fill",
        "Add stroke",
        "Add effect",
        "Add layout guide",
        "Add export settings",
        "Align left",
        "Align horizontal centers",
        "Align right",
        "Align top",
        "Align vertical centers",
        "Align bottom",
        "Distribute horizontal spacing",
        "Distribute vertical spacing",
        "Ignore auto layout",
        "Edit object",
        "Create link",
        "Create instance swap property",
        "Component configuration",
        "Edit template style",
        "Remix template colors",
        "Adjust tone",
        "Resize handle",
        "Select matching layers",
        "More actions",
        "Present",
        "Share",
        "Help",
        "Multiplayer tools",
        "Start with an AI draft",
        "AI, Learn more",
    ];

    const LEFT_SIDEBAR_CHROME_NOISE: &'static [&'static str] = &[
        "Minimize UI",
        "Collapse layers",
        "Find",
        "Add new page",
        "Navigation Bar",
        "Resize handle",
        "Main menu",
        "Missing fonts",
        "Edit file menu",
        "New slide",
        "Add blank slide",
        "View mode",
        "Grid view",
        "Slide view",
    ];

    const LEFT_SIDEBAR_ITEM_ROLES: &'static [&'static str] = &[
        "AXRow",
        "AXCell",
        "AXStaticText",
        "AXHeading",
        "AXButton",
        "AXRadioButton",
        "AXTabButton",
        "AXTextField",
        "AXTextArea",
    ];

    fn is_ignored_chrome_role(role: &str) -> bool {
        Self::IGNORED_CHROME_ROLES.contains(&role)
    }

    fn is_shell_skipped_role(role: &str) -> bool {
        Self::SHELL_SKIPPED_ROLES.contains(&role)
    }

    fn is_landmark_skipped_role(role: &str) -> bool {
        Self::LANDMARK_LOCATOR_SKIPPED_ROLES.contains(&role)
    }

    fn is_tab_noise(label: &str) -> bool {
        Self::TAB_CHROME_NOISE.contains(&label)
    }

    fn is_right_sidebar_noise(label: &str) -> bool {
        Self::RIGHT_SIDEBAR_CHROME_NOISE.contains(&label)
    }

    fn is_left_sidebar_noise(label: &str) -> bool {
        Self::LEFT_SIDEBAR_CHROME_NOISE.contains(&label)
    }

    fn is_left_sidebar_item_role(role: &str) -> bool {
        Self::LEFT_SIDEBAR_ITEM_ROLES.contains(&role)
    }
}

struct FigmaEmitState {
    max_nodes: usize,
    focus_handle: Option<SurfaceHandle>,
    seen: HashSet<SurfaceHandle>,
    focus_assigned: bool,
    truncated: bool,
    nodes: Vec<CustomSurfaceNode>,
}

impl FigmaEmitState {
    fn make_node(
        &mut self,
        ctx: &mut dyn SafeSurfaceContext,
        info: &AdapterNodeInfo,
        parent: Option<SurfaceHandle>,
        role: &'static str,
        text: Option<String>,
    ) -> CustomSurfaceNode {
        let bounds = ctx.bounds(info.handle);
        let is_focused = !self.focus_assigned
            && self
                .focus_handle
                .map(|fh| fh == info.handle)
                .unwrap_or(info.is_focused);
        if is_focused {
            self.focus_assigned = true;
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
    }

    fn has_zero_size(ctx: &mut dyn SafeSurfaceContext, handle: SurfaceHandle) -> bool {
        ctx.bounds(handle)
            .is_some_and(|(r, _)| r.width <= 0.0 || r.height <= 0.0)
    }

    #[allow(clippy::too_many_arguments)]
    fn walk_canvas(
        &mut self,
        ctx: &mut dyn SafeSurfaceContext,
        parent_info: &AdapterNodeInfo,
        emitted_parent: SurfaceHandle,
        depth: usize,
        canvas_limit: usize,
        canvas_emitted: &mut usize,
        canvas_visits: &mut usize,
        canvas_visited: &mut HashSet<SurfaceHandle>,
    ) {
        if *canvas_emitted >= canvas_limit
            || self.nodes.len() >= self.max_nodes
            || *canvas_visits >= FigmaAdapter::MAX_CANVAS_VISITS
            || depth >= FigmaAdapter::MAX_ZONE_DEPTH
            || parent_info.child_count == 0
            || !ctx.can_continue()
            || ctx.is_aborted()
        {
            if parent_info.child_count > 0 && *canvas_emitted >= canvas_limit {
                self.truncated = true;
            }
            return;
        }
        let page_limit = 24usize;
        if parent_info.child_count > page_limit {
            self.truncated = true;
        }
        let Some(children) = ctx.children(parent_info.handle, 0, page_limit) else {
            return;
        };
        if ctx.last_children_truncated() {
            self.truncated = true;
        }
        for child in children {
            if *canvas_emitted >= canvas_limit || self.nodes.len() >= self.max_nodes {
                self.truncated = true;
                return;
            }
            if *canvas_visits >= FigmaAdapter::MAX_CANVAS_VISITS
                || !ctx.can_continue()
                || ctx.is_aborted()
            {
                return;
            }
            if !canvas_visited.insert(child) {
                continue;
            }
            *canvas_visits += 1;
            let Some(info) = ctx.inspect(child) else {
                continue;
            };
            if FigmaAdapter::is_ignored_chrome_role(&info.role) {
                continue;
            }
            let is_focus_node = self.focus_handle == Some(info.handle) || info.is_focused;
            // Prune offscreen / zero-size / negative-y / off-left non-focused canvas noise.
            if !is_focus_node {
                if info.is_offscreen {
                    continue;
                }
                if let Some((rect, _)) = ctx.bounds(info.handle) {
                    if rect.width <= 0.0
                        || rect.height <= 0.0
                        || rect.y < 0.0
                        || rect.x + rect.width <= 0.0
                    {
                        continue;
                    }
                }
            }
            if info.subrole.as_deref() == Some("AXApplicationGroup") {
                let label = ctx.display_text(info.handle);
                let mut next_parent = emitted_parent;
                if (label.is_some() || is_focus_node) && self.seen.insert(info.handle) {
                    let node =
                        self.make_node(ctx, &info, Some(emitted_parent), "container", label);
                    self.nodes.push(node);
                    *canvas_emitted += 1;
                    next_parent = info.handle;
                }
                if info.child_count > 0 {
                    self.walk_canvas(
                        ctx,
                        &info,
                        next_parent,
                        depth + 1,
                        canvas_limit,
                        canvas_emitted,
                        canvas_visits,
                        canvas_visited,
                    );
                }
            } else if info.role == "AXStaticText" {
                let Some(raw) = ctx.text(info.handle, None) else {
                    continue;
                };
                let trimmed = raw.trim();
                if trimmed.is_empty()
                    || is_private_use_only_text(trimmed)
                    || trimmed == "Dimensions"
                {
                    continue;
                }
                if self.seen.insert(info.handle) {
                    let node = self.make_node(
                        ctx,
                        &info,
                        Some(emitted_parent),
                        "text",
                        Some(trimmed.to_string()),
                    );
                    self.nodes.push(node);
                    *canvas_emitted += 1;
                }
            } else if matches!(info.role.as_str(), "AXTextField" | "AXTextArea") {
                let Some(raw) = ctx.text(info.handle, None) else {
                    continue;
                };
                let trimmed = raw.trim();
                if !is_focus_node && (trimmed.is_empty() || is_private_use_only_text(trimmed)) {
                    continue;
                }
                if self.seen.insert(info.handle) {
                    let node =
                        self.make_node(ctx, &info, Some(emitted_parent), "editable", Some(raw));
                    self.nodes.push(node);
                    *canvas_emitted += 1;
                }
            } else if info.role == "AXHeading" {
                if let Some(label) = ctx.display_text(info.handle) {
                    if !is_private_use_only_text(&label)
                        && label != "Dimensions"
                        && self.seen.insert(info.handle)
                    {
                        let node =
                            self.make_node(ctx, &info, Some(emitted_parent), "text", Some(label));
                        self.nodes.push(node);
                        *canvas_emitted += 1;
                        continue;
                    }
                }
                if info.child_count > 0 {
                    self.walk_canvas(
                        ctx,
                        &info,
                        emitted_parent,
                        depth + 1,
                        canvas_limit,
                        canvas_emitted,
                        canvas_visits,
                        canvas_visited,
                    );
                }
            } else if info.child_count > 0 {
                self.walk_canvas(
                    ctx,
                    &info,
                    emitted_parent,
                    depth + 1,
                    canvas_limit,
                    canvas_emitted,
                    canvas_visits,
                    canvas_visited,
                );
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn walk_right_sidebar(
        &mut self,
        ctx: &mut dyn SafeSurfaceContext,
        parent_info: &AdapterNodeInfo,
        emitted_parent: SurfaceHandle,
        parent_text: Option<&str>,
        depth: usize,
        right_limit: usize,
        right_emitted: &mut usize,
        right_visits: &mut usize,
        right_visited: &mut HashSet<SurfaceHandle>,
    ) {
        if *right_emitted >= right_limit
            || self.nodes.len() >= self.max_nodes
            || *right_visits >= FigmaAdapter::MAX_SIDEBAR_VISITS
            || depth >= FigmaAdapter::MAX_ZONE_DEPTH
            || parent_info.child_count == 0
            || !ctx.can_continue()
            || ctx.is_aborted()
        {
            if parent_info.child_count > 0 && *right_emitted >= right_limit {
                self.truncated = true;
            }
            return;
        }
        let page_limit = 24usize;
        if parent_info.child_count > page_limit {
            self.truncated = true;
        }
        let Some(children) = ctx.children(parent_info.handle, 0, page_limit) else {
            return;
        };
        if ctx.last_children_truncated() {
            self.truncated = true;
        }
        for child in children {
            if *right_emitted >= right_limit || self.nodes.len() >= self.max_nodes {
                self.truncated = true;
                return;
            }
            if *right_visits >= FigmaAdapter::MAX_SIDEBAR_VISITS
                || !ctx.can_continue()
                || ctx.is_aborted()
            {
                return;
            }
            if !right_visited.insert(child) {
                continue;
            }
            *right_visits += 1;
            let Some(info) = ctx.inspect(child) else {
                continue;
            };
            if FigmaAdapter::is_ignored_chrome_role(&info.role)
                || Self::has_zero_size(ctx, info.handle)
            {
                continue;
            }
            if info
                .label
                .as_deref()
                .is_some_and(FigmaAdapter::is_right_sidebar_noise)
            {
                continue;
            }
            let is_focus_node = self.focus_handle == Some(info.handle) || info.is_focused;
            match info.role.as_str() {
                "AXRadioButton" | "AXTabButton" | "AXButton" | "AXCheckBox" => {
                    if let Some(label) = ctx.display_text(info.handle) {
                        if !is_private_use_only_text(&label)
                            && !FigmaAdapter::is_right_sidebar_noise(&label)
                        {
                            if self.seen.insert(info.handle) {
                                let node = self.make_node(
                                    ctx,
                                    &info,
                                    Some(emitted_parent),
                                    "container",
                                    Some(label),
                                );
                                self.nodes.push(node);
                                *right_emitted += 1;
                            }
                            continue;
                        }
                    }
                    if info.child_count > 0 {
                        self.walk_right_sidebar(
                            ctx,
                            &info,
                            emitted_parent,
                            parent_text,
                            depth + 1,
                            right_limit,
                            right_emitted,
                            right_visits,
                            right_visited,
                        );
                    }
                }
                "AXHeading" => {
                    if let Some(label) = ctx.display_text(info.handle) {
                        if !is_private_use_only_text(&label)
                            && !FigmaAdapter::is_right_sidebar_noise(&label)
                        {
                            if self.seen.insert(info.handle) {
                                let node = self.make_node(
                                    ctx,
                                    &info,
                                    Some(emitted_parent),
                                    "text",
                                    Some(label),
                                );
                                self.nodes.push(node);
                                *right_emitted += 1;
                            }
                            continue;
                        }
                    }
                    if info.child_count > 0 {
                        self.walk_right_sidebar(
                            ctx,
                            &info,
                            emitted_parent,
                            parent_text,
                            depth + 1,
                            right_limit,
                            right_emitted,
                            right_visits,
                            right_visited,
                        );
                    }
                }
                "AXComboBox" | "AXPopUpButton" => {
                    let mut next_parent = emitted_parent;
                    let mut next_parent_text: Option<String> = parent_text.map(str::to_string);
                    if let Some(label) = ctx.display_text(info.handle) {
                        if !is_private_use_only_text(&label)
                            && !FigmaAdapter::is_right_sidebar_noise(&label)
                            && self.seen.insert(info.handle)
                        {
                            let node = self.make_node(
                                ctx,
                                &info,
                                Some(emitted_parent),
                                "container",
                                Some(label.clone()),
                            );
                            self.nodes.push(node);
                            *right_emitted += 1;
                            next_parent = info.handle;
                            next_parent_text = Some(label);
                        }
                    }
                    if info.child_count > 0 {
                        self.walk_right_sidebar(
                            ctx,
                            &info,
                            next_parent,
                            next_parent_text.as_deref(),
                            depth + 1,
                            right_limit,
                            right_emitted,
                            right_visits,
                            right_visited,
                        );
                    }
                }
                "AXTextField" | "AXTextArea" => {
                    let Some(raw) = ctx.text(info.handle, None) else {
                        continue;
                    };
                    let trimmed = raw.trim();
                    if !is_focus_node
                        && (trimmed.is_empty() || is_private_use_only_text(trimmed))
                    {
                        continue;
                    }
                    if self.seen.insert(info.handle) {
                        let node = self.make_node(
                            ctx,
                            &info,
                            Some(emitted_parent),
                            "editable",
                            Some(raw),
                        );
                        self.nodes.push(node);
                        *right_emitted += 1;
                    }
                }
                "AXStaticText" => {
                    let Some(raw) = ctx.text(info.handle, None) else {
                        continue;
                    };
                    let trimmed = raw.trim();
                    if trimmed.is_empty()
                        || is_private_use_only_text(trimmed)
                        || FigmaAdapter::is_right_sidebar_noise(trimmed)
                        || Some(trimmed) == parent_text
                    {
                        continue;
                    }
                    if self.seen.insert(info.handle) {
                        let node = self.make_node(
                            ctx,
                            &info,
                            Some(emitted_parent),
                            "text",
                            Some(trimmed.to_string()),
                        );
                        self.nodes.push(node);
                        *right_emitted += 1;
                    }
                }
                _ => {
                    if info.child_count > 0 {
                        self.walk_right_sidebar(
                            ctx,
                            &info,
                            emitted_parent,
                            parent_text,
                            depth + 1,
                            right_limit,
                            right_emitted,
                            right_visits,
                            right_visited,
                        );
                    }
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn walk_left_sidebar(
        &mut self,
        ctx: &mut dyn SafeSurfaceContext,
        parent_info: &AdapterNodeInfo,
        left_sidebar_handle: SurfaceHandle,
        left_sidebar_bounds: Option<SurfaceBounds>,
        window_height: f64,
        depth: usize,
        left_visits: &mut usize,
        left_visited: &mut HashSet<SurfaceHandle>,
    ) {
        if self.nodes.len() >= self.max_nodes
            || *left_visits >= FigmaAdapter::MAX_SIDEBAR_VISITS
            || depth >= FigmaAdapter::MAX_ZONE_DEPTH
            || parent_info.child_count == 0
            || !ctx.can_continue()
            || ctx.is_aborted()
        {
            if parent_info.child_count > 0 && self.nodes.len() >= self.max_nodes {
                self.truncated = true;
            }
            return;
        }
        let page_cap = if matches!(
            parent_info.role.as_str(),
            "AXColumn" | "AXTable" | "AXOutline" | "AXList"
        ) {
            64usize
        } else {
            24usize
        };
        if parent_info.child_count > page_cap {
            self.truncated = true;
        }
        let Some(children) = ctx.children(parent_info.handle, 0, page_cap) else {
            return;
        };
        if ctx.last_children_truncated() {
            self.truncated = true;
        }
        for child in children {
            if self.nodes.len() >= self.max_nodes {
                self.truncated = true;
                return;
            }
            if *left_visits >= FigmaAdapter::MAX_SIDEBAR_VISITS
                || !ctx.can_continue()
                || ctx.is_aborted()
            {
                return;
            }
            if !left_visited.insert(child) {
                continue;
            }
            *left_visits += 1;
            let Some(info) = ctx.inspect(child) else {
                continue;
            };
            if FigmaAdapter::is_ignored_chrome_role(&info.role) {
                continue;
            }
            if info
                .label
                .as_deref()
                .is_some_and(FigmaAdapter::is_left_sidebar_noise)
            {
                continue;
            }
            let is_item = FigmaAdapter::is_left_sidebar_item_role(&info.role);
            if !Self::is_visible_in_left_sidebar(
                ctx,
                &info,
                !is_item,
                left_sidebar_bounds,
                window_height,
            ) {
                continue;
            }
            let is_focus_node = self.focus_handle == Some(info.handle) || info.is_focused;
            match info.role.as_str() {
                "AXRow" | "AXCell" | "AXRadioButton" | "AXTabButton" | "AXButton" => {
                    if let Some(label) = ctx.display_text(info.handle) {
                        if !is_private_use_only_text(&label)
                            && !FigmaAdapter::is_left_sidebar_noise(&label)
                        {
                            if self.seen.insert(info.handle) {
                                let node = self.make_node(
                                    ctx,
                                    &info,
                                    Some(left_sidebar_handle),
                                    "container",
                                    Some(label),
                                );
                                self.nodes.push(node);
                            }
                            continue;
                        }
                    }
                    if info.child_count > 0 {
                        self.walk_left_sidebar(
                            ctx,
                            &info,
                            left_sidebar_handle,
                            left_sidebar_bounds,
                            window_height,
                            depth + 1,
                            left_visits,
                            left_visited,
                        );
                    }
                }
                "AXHeading" => {
                    if let Some(label) = ctx.display_text(info.handle) {
                        if !is_private_use_only_text(&label)
                            && !FigmaAdapter::is_left_sidebar_noise(&label)
                        {
                            if self.seen.insert(info.handle) {
                                let node = self.make_node(
                                    ctx,
                                    &info,
                                    Some(left_sidebar_handle),
                                    "text",
                                    Some(label),
                                );
                                self.nodes.push(node);
                            }
                            continue;
                        }
                    }
                    if info.child_count > 0 {
                        self.walk_left_sidebar(
                            ctx,
                            &info,
                            left_sidebar_handle,
                            left_sidebar_bounds,
                            window_height,
                            depth + 1,
                            left_visits,
                            left_visited,
                        );
                    }
                }
                "AXTextField" | "AXTextArea" => {
                    let Some(raw) = ctx.text(info.handle, None) else {
                        continue;
                    };
                    let trimmed = raw.trim();
                    if !is_focus_node
                        && (trimmed.is_empty() || is_private_use_only_text(trimmed))
                    {
                        continue;
                    }
                    if self.seen.insert(info.handle) {
                        let node = self.make_node(
                            ctx,
                            &info,
                            Some(left_sidebar_handle),
                            "editable",
                            Some(raw),
                        );
                        self.nodes.push(node);
                    }
                }
                "AXStaticText" => {
                    let Some(raw) = ctx.text(info.handle, None) else {
                        continue;
                    };
                    let trimmed = raw.trim();
                    if trimmed.is_empty()
                        || is_private_use_only_text(trimmed)
                        || FigmaAdapter::is_left_sidebar_noise(trimmed)
                    {
                        continue;
                    }
                    if self.seen.insert(info.handle) {
                        let node = self.make_node(
                            ctx,
                            &info,
                            Some(left_sidebar_handle),
                            "text",
                            Some(trimmed.to_string()),
                        );
                        self.nodes.push(node);
                    }
                }
                _ => {
                    if info.child_count > 0 {
                        self.walk_left_sidebar(
                            ctx,
                            &info,
                            left_sidebar_handle,
                            left_sidebar_bounds,
                            window_height,
                            depth + 1,
                            left_visits,
                            left_visited,
                        );
                    }
                }
            }
        }
    }

    fn is_visible_in_left_sidebar(
        ctx: &mut dyn SafeSurfaceContext,
        info: &AdapterNodeInfo,
        is_container: bool,
        left_sidebar_bounds: Option<SurfaceBounds>,
        window_height: f64,
    ) -> bool {
        if info.is_offscreen {
            return false;
        }
        let Some((rect, _)) = ctx.bounds(info.handle) else {
            return true;
        };
        if rect.width <= 0.0 || rect.height <= 1.0 {
            return false;
        }
        if window_height > 0.0 && rect.y >= window_height {
            return false;
        }
        if let Some(sb) = left_sidebar_bounds {
            if rect.y >= sb.y + sb.height {
                return false;
            }
        }
        if is_container {
            rect.y + rect.height > 0.0
        } else {
            rect.y >= 0.0
        }
    }
}

impl AppAdapter for FigmaAdapter {
    fn spec(&self) -> &'static AppAdapterSpec {
        &FIGMA_ADAPTER_SPEC
    }

    fn has_custom_extractor(&self) -> bool {
        true
    }

    fn extract_surface(&self, ctx: &mut dyn SafeSurfaceContext) -> Option<CustomSurfaceResult> {
        let root_handle = ctx.root();
        let root_info = ctx.inspect(root_handle)?;
        if ctx.is_aborted() {
            return None;
        }

        // Step 1: Shallow BFS through outer Electron shell to locate Tab Bar and Main Document AXWebAreas.
        // Bounded strictly by MAX_SHELL_VISITS / MAX_SHELL_DEPTH without descending into AXWebAreas,
        // so a shallow non-canvas overlay AXWebArea at depth D never hides a real document at depth D+1.
        let mut web_areas: Vec<AdapterNodeInfo> = Vec::new();
        let mut shell_queue: VecDeque<(SurfaceHandle, usize)> = VecDeque::new();
        shell_queue.push_back((root_handle, 0));
        let mut shell_visited: HashSet<SurfaceHandle> = HashSet::new();
        shell_visited.insert(root_handle);
        let mut shell_visits = 1usize;

        while let Some((handle, depth)) = shell_queue.pop_front() {
            if shell_visits >= Self::MAX_SHELL_VISITS || !ctx.can_continue() || ctx.is_aborted() {
                break;
            }
            let info = if handle == root_handle {
                root_info.clone()
            } else {
                shell_visits += 1;
                let Some(fresh) = ctx.inspect(handle) else {
                    continue;
                };
                fresh
            };
            if info.role == "AXWebArea" {
                web_areas.push(info);
                continue;
            }
            if handle != root_handle && Self::is_shell_skipped_role(&info.role) {
                continue;
            }
            if depth >= Self::MAX_SHELL_DEPTH || info.child_count == 0 {
                continue;
            }
            if let Some(children) = ctx.children(handle, 0, 32) {
                for child in children {
                    if shell_visited.insert(child) {
                        shell_queue.push_back((child, depth + 1));
                    }
                }
            }
        }
        if ctx.is_aborted() {
            return None;
        }

        let mut tab_bar_web_area: Option<AdapterNodeInfo> = None;
        let mut raw_main_candidates: Vec<(AdapterNodeInfo, bool, f64)> = Vec::new();

        for area in &web_areas {
            if let Some((rect, _)) = ctx.bounds(area.handle) {
                if rect.width > 0.0 && rect.height > 0.0 {
                    if !area.is_offscreen
                        && rect.height <= 60.0
                        && rect.y < 60.0
                        && rect.y + rect.height > 0.0
                    {
                        if tab_bar_web_area
                            .as_ref()
                            .is_none_or(|prev| prev.child_count == 0 && area.child_count > 0)
                        {
                            tab_bar_web_area = Some(area.clone());
                        }
                    } else if rect.y + rect.height > 0.0 || rect.height > 60.0 {
                        let is_onscreen =
                            !area.is_offscreen && rect.y + rect.height > 0.0 && rect.x + rect.width > 0.0;
                        let area_size = rect.width * rect.height;
                        raw_main_candidates.push((area.clone(), is_onscreen, area_size));
                    }
                    continue;
                }
            }
            if !area.is_offscreen && area.label.as_deref() == Some("Figma") {
                if tab_bar_web_area
                    .as_ref()
                    .is_none_or(|prev| prev.child_count == 0 && area.child_count > 0)
                {
                    tab_bar_web_area = Some(area.clone());
                }
            } else {
                raw_main_candidates.push((area.clone(), !area.is_offscreen, -1.0));
            }
        }
        if raw_main_candidates.is_empty() && web_areas.len() == 1 {
            if let Some(only) = web_areas.into_iter().next() {
                let is_onscreen = !only.is_offscreen;
                raw_main_candidates.push((only, is_onscreen, 0.0));
            }
            tab_bar_web_area = None;
        }
        let has_populated_candidate = raw_main_candidates
            .iter()
            .any(|(area, _, _)| area.child_count > 0);
        let mut main_candidates: Vec<(AdapterNodeInfo, bool, f64)> = if has_populated_candidate {
            raw_main_candidates
                .into_iter()
                .filter(|(area, _, _)| area.child_count > 0)
                .collect()
        } else {
            raw_main_candidates
        };
        if main_candidates.is_empty() {
            return None;
        }
        main_candidates.sort_by(|(a_info, a_onscreen, a_area), (b_info, b_onscreen, b_area)| {
            let a_key = (
                a_info.child_count > 0,
                *a_onscreen,
                a_info
                    .label
                    .as_deref()
                    .is_some_and(|s| !s.trim().is_empty()),
            );
            let b_key = (
                b_info.child_count > 0,
                *b_onscreen,
                b_info
                    .label
                    .as_deref()
                    .is_some_and(|s| !s.trim().is_empty()),
            );
            b_key.cmp(&a_key).then_with(|| b_area.total_cmp(a_area))
        });

        // Step 2: Bounded locator BFS inside ranked Main AXWebArea candidates to find
        // Canvas (`AXLandmarkMain`), Right Inspector, and Left Sidebar landmarks/containers.
        struct SelectedMainWebArea {
            main_web_area: AdapterNodeInfo,
            landmark_main: AdapterNodeInfo,
            right_sidebar: Option<AdapterNodeInfo>,
            left_sidebar: Option<AdapterNodeInfo>,
            lm_parents: HashMap<SurfaceHandle, SurfaceHandle>,
            geo_candidates: Vec<(AdapterNodeInfo, usize)>,
        }

        let mut selected: Option<SelectedMainWebArea> = None;

        for (candidate, _, _) in main_candidates {
            if !ctx.can_continue() || ctx.is_aborted() {
                break;
            }
            let mut landmark_main: Option<AdapterNodeInfo> = None;
            let mut right_sidebar: Option<AdapterNodeInfo> = None;
            let mut left_sidebar: Option<AdapterNodeInfo> = None;

            let mut lm_queue: VecDeque<(SurfaceHandle, usize)> = VecDeque::new();
            lm_queue.push_back((candidate.handle, 0));
            let mut lm_visited: HashSet<SurfaceHandle> = HashSet::new();
            lm_visited.insert(candidate.handle);
            let mut lm_parents: HashMap<SurfaceHandle, SurfaceHandle> = HashMap::new();
            let mut geo_candidates: Vec<(AdapterNodeInfo, usize)> = Vec::new();
            let mut lm_visits = 1usize;

            while let Some((handle, depth)) = lm_queue.pop_front() {
                if lm_visits >= Self::MAX_LANDMARK_VISITS
                    || !ctx.can_continue()
                    || ctx.is_aborted()
                    || (landmark_main.is_some()
                        && right_sidebar.is_some()
                        && left_sidebar.is_some())
                {
                    break;
                }
                let info = if handle == candidate.handle {
                    candidate.clone()
                } else {
                    lm_visits += 1;
                    let Some(fresh) = ctx.inspect(handle) else {
                        continue;
                    };
                    fresh
                };
                if handle != candidate.handle {
                    if info.subrole.as_deref() == Some("AXLandmarkMain") {
                        landmark_main = Some(info);
                        continue;
                    }
                    if matches!(
                        info.subrole.as_deref(),
                        Some("AXLandmarkRegion" | "AXApplicationGroup") | None
                    ) {
                        if let Some(ref lbl) = info.label {
                            let lowered = lbl.to_ascii_lowercase();
                            if lowered == "right sidebar" {
                                right_sidebar = Some(info);
                                continue;
                            }
                            if lowered == "left sidebar" {
                                left_sidebar = Some(info);
                                continue;
                            }
                        }
                    }
                    if Self::is_landmark_skipped_role(&info.role) {
                        continue;
                    }
                    if info.child_count > 0 {
                        geo_candidates.push((info.clone(), depth));
                    }
                }
                if depth >= Self::MAX_LANDMARK_DEPTH || info.child_count == 0 {
                    continue;
                }
                if let Some(children) = ctx.children(handle, 0, 32) {
                    for child in children {
                        if lm_visited.insert(child) {
                            lm_parents.insert(child, handle);
                            lm_queue.push_back((child, depth + 1));
                        }
                    }
                }
            }
            if ctx.is_aborted() {
                return None;
            }
            if let Some(lm) = landmark_main {
                selected = Some(SelectedMainWebArea {
                    main_web_area: candidate,
                    landmark_main: lm,
                    right_sidebar,
                    left_sidebar,
                    lm_parents,
                    geo_candidates,
                });
                break;
            }
        }
        if ctx.is_aborted() {
            return None;
        }

        // Fall back to standard weighted traversal on Home / Recents / File Browser screens without canvas.
        let SelectedMainWebArea {
            main_web_area,
            landmark_main,
            mut right_sidebar,
            mut left_sidebar,
            lm_parents,
            geo_candidates,
        } = selected?;

        // Geometric fallback for Windows Electron sidebars lacking explicit "Right/Left sidebar" ARIA label.
        if right_sidebar.is_none() || left_sidebar.is_none() {
            let mut main_ancestors: HashSet<SurfaceHandle> = HashSet::new();
            let mut cur = Some(landmark_main.handle);
            while let Some(h) = cur {
                main_ancestors.insert(h);
                cur = lm_parents.get(&h).copied();
            }
            let win_width = ctx
                .window_size()
                .map(|(w, _)| w)
                .or_else(|| ctx.bounds(main_web_area.handle).map(|(r, _)| r.x + r.width));
            let main_rect = ctx.bounds(landmark_main.handle).map(|(r, _)| r);

            let mut best_right: Option<(AdapterNodeInfo, usize, f64)> = None;
            let mut best_left: Option<(AdapterNodeInfo, usize, f64)> = None;

            for (cand, depth) in geo_candidates {
                if main_ancestors.contains(&cand.handle) {
                    continue;
                }
                let Some((rect, _)) = ctx.bounds(cand.handle) else {
                    continue;
                };
                if rect.width <= 80.0 || rect.width > 420.0 || rect.height <= 200.0 {
                    continue;
                }
                let area = rect.width * rect.height;
                if right_sidebar.is_none() {
                    let on_right = win_width.is_some_and(|ww| rect.x > ww - 320.0)
                        && main_rect.is_none_or(|mr| rect.x >= mr.x + mr.width - 24.0);
                    if on_right
                        && best_right
                            .as_ref()
                            .is_none_or(|(_, d, a)| depth < *d || (depth == *d && area > *a))
                    {
                        best_right = Some((cand.clone(), depth, area));
                    }
                }
                if left_sidebar.is_none() {
                    let on_left = rect.x >= -8.0
                        && rect.x < 320.0
                        && (rect.x + rect.width) <= 420.0
                        && main_rect.is_none_or(|mr| rect.x + rect.width <= mr.x + 24.0);
                    if on_left
                        && best_left
                            .as_ref()
                            .is_none_or(|(_, d, a)| depth < *d || (depth == *d && area > *a))
                    {
                        best_left = Some((cand, depth, area));
                    }
                }
            }
            if right_sidebar.is_none() {
                right_sidebar = best_right.map(|(info, _, _)| info);
            }
            if left_sidebar.is_none() {
                left_sidebar = best_left.map(|(info, _, _)| info);
            }
        }

        // Step 3: Emit four prioritized zones within max_nodes.
        let max_nodes = ctx.max_output_nodes().clamp(1, 96);
        let mut emit = FigmaEmitState {
            max_nodes,
            focus_handle: ctx.focus(),
            seen: HashSet::new(),
            focus_assigned: false,
            truncated: false,
            nodes: Vec::new(),
        };

        // Zone 1: Root + Main AXWebArea (title + URL) + Open File Tabs.
        emit.seen.insert(root_handle);
        let root_text = if main_web_area.handle == root_handle {
            ctx.display_text(main_web_area.handle)
        } else {
            None
        };
        let root_node = emit.make_node(ctx, &root_info, None, "container", root_text);
        emit.nodes.push(root_node);

        if main_web_area.handle != root_handle
            && emit.nodes.len() < max_nodes
            && emit.seen.insert(main_web_area.handle)
        {
            let main_text = ctx.display_text(main_web_area.handle);
            let main_node =
                emit.make_node(ctx, &main_web_area, Some(root_handle), "container", main_text);
            emit.nodes.push(main_node);
        }

        if let Some(ref tab_bar) = tab_bar_web_area {
            if tab_bar.handle != root_handle
                && tab_bar.handle != main_web_area.handle
                && emit.nodes.len() + 2 <= max_nodes
                && ctx.can_continue()
                && !ctx.is_aborted()
            {
                let max_tab_items = max_nodes
                    .saturating_sub(emit.nodes.len() + 1)
                    .clamp(1, 10);
                let mut collected_tabs: Vec<(AdapterNodeInfo, String)> = Vec::new();
                let mut tab_queue: VecDeque<(SurfaceHandle, usize)> = VecDeque::new();
                tab_queue.push_back((tab_bar.handle, 0));
                let mut tab_visited: HashSet<SurfaceHandle> = HashSet::new();
                tab_visited.insert(tab_bar.handle);
                let mut tab_visits = 1usize;

                while let Some((handle, depth)) = tab_queue.pop_front() {
                    if tab_visits >= Self::MAX_TAB_VISITS
                        || collected_tabs.len() >= max_tab_items
                        || !ctx.can_continue()
                        || ctx.is_aborted()
                    {
                        break;
                    }
                    let info = if handle == tab_bar.handle {
                        tab_bar.clone()
                    } else {
                        tab_visits += 1;
                        let Some(fresh) = ctx.inspect(handle) else {
                            continue;
                        };
                        if Self::is_ignored_chrome_role(&fresh.role) {
                            continue;
                        }
                        fresh
                    };
                    if matches!(info.role.as_str(), "AXRadioButton" | "AXTabButton") {
                        // Prune zero-size leaf tabs only; Windows Electron wraps the visible 38pt
                        // tab strip inside a 0x0 CSS layout AXGroup that must still be traversed.
                        if FigmaEmitState::has_zero_size(ctx, info.handle) {
                            continue;
                        }
                        let mut tab_label = ctx.display_text(info.handle);
                        if tab_label.is_none() && info.child_count > 0 {
                            if let Some(tab_children) = ctx.children(info.handle, 0, 4) {
                                for child in tab_children {
                                    if !ctx.can_continue() || ctx.is_aborted() {
                                        break;
                                    }
                                    if let Some(child_info) = ctx.inspect(child) {
                                        if child_info.role == "AXStaticText" {
                                            if let Some(raw) = ctx.text(child, None) {
                                                let trimmed = raw.trim();
                                                if !trimmed.is_empty()
                                                    && !is_private_use_only_text(trimmed)
                                                {
                                                    tab_label = Some(trimmed.to_string());
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        if let Some(label) = tab_label {
                            if !label.is_empty()
                                && !is_private_use_only_text(&label)
                                && !Self::is_tab_noise(&label)
                            {
                                collected_tabs.push((info, label));
                            }
                        }
                        continue;
                    }
                    if depth >= Self::MAX_TAB_DEPTH
                        || info.child_count == 0
                        || matches!(
                            info.role.as_str(),
                            "AXButton" | "AXStaticText" | "AXTextField" | "AXTextArea"
                        )
                    {
                        continue;
                    }
                    if let Some(children) = ctx.children(handle, 0, 24) {
                        for child in children {
                            if tab_visited.insert(child) {
                                tab_queue.push_back((child, depth + 1));
                            }
                        }
                    }
                }

                if !collected_tabs.is_empty()
                    && emit.nodes.len() < max_nodes
                    && emit.seen.insert(tab_bar.handle)
                {
                    let tab_bar_text = ctx.display_text(tab_bar.handle);
                    let tab_bar_node = emit.make_node(
                        ctx,
                        tab_bar,
                        Some(root_handle),
                        "container",
                        tab_bar_text,
                    );
                    emit.nodes.push(tab_bar_node);
                    for (tab_info, tab_text) in collected_tabs {
                        if emit.nodes.len() >= max_nodes {
                            break;
                        }
                        if emit.seen.insert(tab_info.handle) {
                            let tab_node = emit.make_node(
                                ctx,
                                &tab_info,
                                Some(tab_bar.handle),
                                "container",
                                Some(tab_text),
                            );
                            emit.nodes.push(tab_node);
                        }
                    }
                }
            }
        }
        if ctx.is_aborted() {
            return None;
        }

        // Proportional slot reservation so Right Inspector and Left Sidebar are never starved.
        let remaining_after_header = max_nodes.saturating_sub(emit.nodes.len());
        let has_right = right_sidebar.is_some();
        let has_left = left_sidebar.is_some();
        let reserve_pool = remaining_after_header.saturating_sub(1);
        let desired_right = if has_right {
            (remaining_after_header * 45 / 100).clamp(18, 24)
        } else {
            0
        };
        let desired_left = if has_left {
            (remaining_after_header * 25 / 100).clamp(8, 18)
        } else {
            0
        };
        let (right_reserve, left_reserve) = if desired_right + desired_left <= reserve_pool {
            (desired_right, desired_left)
        } else if reserve_pool == 0 {
            (0, 0)
        } else {
            let rr = if has_right {
                (reserve_pool * 2 / 3).max(1)
            } else {
                0
            };
            let lr = if has_left {
                reserve_pool.saturating_sub(rr)
            } else {
                0
            };
            (rr, lr)
        };
        let canvas_limit = remaining_after_header.saturating_sub(right_reserve + left_reserve);

        // Zone 2: Selected Canvas / Slides Hierarchy (`AXLandmarkMain`).
        if canvas_limit > 0
            && emit.nodes.len() < max_nodes
            && emit.seen.insert(landmark_main.handle)
        {
            let lm_text = ctx.display_text(landmark_main.handle);
            let lm_node = emit.make_node(
                ctx,
                &landmark_main,
                Some(main_web_area.handle),
                "container",
                lm_text,
            );
            emit.nodes.push(lm_node);
            let mut canvas_emitted = 1usize;
            let mut canvas_visits = 0usize;
            let mut canvas_visited: HashSet<SurfaceHandle> = HashSet::new();
            canvas_visited.insert(landmark_main.handle);
            emit.walk_canvas(
                ctx,
                &landmark_main,
                landmark_main.handle,
                0,
                canvas_limit,
                &mut canvas_emitted,
                &mut canvas_visits,
                &mut canvas_visited,
            );
        }
        if ctx.is_aborted() {
            return None;
        }

        // Zone 3: Right Design/Prototype/Animate Inspector.
        if let Some(ref right_sb) = right_sidebar {
            if emit.nodes.len() < max_nodes && ctx.can_continue() {
                let remaining_for_right = max_nodes.saturating_sub(emit.nodes.len() + left_reserve);
                let right_limit = if has_left {
                    right_reserve.max(28).min(remaining_for_right)
                } else {
                    max_nodes.saturating_sub(emit.nodes.len())
                };
                if right_limit > 0 && emit.seen.insert(right_sb.handle) {
                    let rs_text = ctx.display_text(right_sb.handle);
                    let rs_node = emit.make_node(
                        ctx,
                        right_sb,
                        Some(main_web_area.handle),
                        "container",
                        rs_text,
                    );
                    emit.nodes.push(rs_node);
                    let mut right_emitted = 1usize;
                    let mut right_visits = 0usize;
                    let mut right_visited: HashSet<SurfaceHandle> = HashSet::new();
                    right_visited.insert(right_sb.handle);
                    emit.walk_right_sidebar(
                        ctx,
                        right_sb,
                        right_sb.handle,
                        None,
                        0,
                        right_limit,
                        &mut right_emitted,
                        &mut right_visits,
                        &mut right_visited,
                    );
                }
            }
        }
        if ctx.is_aborted() {
            return None;
        }

        // Zone 4: Left Sidebar (visible file header + strictly viewport-clipped Pages / Layers / Slides).
        if let Some(ref left_sb) = left_sidebar {
            if emit.nodes.len() < max_nodes && ctx.can_continue() && emit.seen.insert(left_sb.handle)
            {
                let left_sb_bounds = ctx.bounds(left_sb.handle).map(|(b, _)| b);
                let window_height = ctx.window_size().map(|(_, h)| h).unwrap_or(0.0);
                let ls_text = ctx.display_text(left_sb.handle);
                let ls_node = emit.make_node(
                    ctx,
                    left_sb,
                    Some(main_web_area.handle),
                    "container",
                    ls_text,
                );
                emit.nodes.push(ls_node);
                let mut left_visits = 0usize;
                let mut left_visited: HashSet<SurfaceHandle> = HashSet::new();
                left_visited.insert(left_sb.handle);
                emit.walk_left_sidebar(
                    ctx,
                    left_sb,
                    left_sb.handle,
                    left_sb_bounds,
                    window_height,
                    0,
                    &mut left_visits,
                    &mut left_visited,
                );
            }
        }
        if ctx.is_aborted() {
            return None;
        }

        Some(CustomSurfaceResult {
            nodes: emit.nodes,
            complete: false,
            missing_reasons: if emit.truncated {
                vec!["tree-output-budget".to_string()]
            } else {
                Vec::new()
            },
        })
    }
}
