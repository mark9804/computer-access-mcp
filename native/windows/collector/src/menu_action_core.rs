//! Pure, platform-free core logic for Phase 5 `menu.action` capture.
//!
//! Zero Win32/COM dependencies. Mirrors macOS `MenuActionCore.swift` with Windows UIA /
//! classic Win32 `#32768` top-menu-bar ownership verification, surrogate-safe UTF-16 path
//! sanitization and truncation, bounded menu tracking, 250ms deduplication, pending FIFO
//! bounding, and fail-closed browser chrome window privacy gating.

use std::collections::{BTreeMap, VecDeque};

use history_contract::{is_valid_application_id, utf16_len, JsonValue};

use crate::adapters::AppAdapterSpec;
use crate::policy::{
    is_effectively_empty_text, is_private_use_only_text, ApplicationPolicy, BrowserGate,
    ProtectedContentRead, ResolvedAppIdentity, SubroleRead, TextSecurityGate,
};
use crate::protocol_model::{
    bounded_utf16_slice, json_i64, ApplicationIdentity, CapturePolicy, ContentGate, Coverage,
    SecureStatus, Stamp, MAX_SAFE_INTEGER,
};

/// Wire source literal for `menu.action` observations on Windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MenuActionSource {
    UiaMenu,
    Fixture,
}

impl MenuActionSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UiaMenu => "uia.menu",
            Self::Fixture => "fixture",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "uia.menu" => Some(Self::UiaMenu),
            "fixture" => Some(Self::Fixture),
            _ => None,
        }
    }
}

/// Sanitized, bounded menu path resolved from a leaf menu item up to the foreground app menu bar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedMenuPath {
    pub path: Vec<String>,
    pub truncated: bool,
}

/// Shared structural and wire bounds for foreground top menu bar observations.
pub struct MenuPathLimits;

impl MenuPathLimits {
    pub const MAX_PARENT_HOPS: usize = 20;
    pub const MAX_ABOVE_MENU_BAR_HOPS: usize = 20;
    pub const MAX_CONSECUTIVE_WRAPPER_HOPS: usize = 6;
    pub const MIN_SEGMENTS: usize = 2;
    pub const MAX_SEGMENTS: usize = 8;
    pub const MAX_SEGMENT_UTF16_UNITS: usize = 128;
    pub const MAX_TOTAL_UTF16_UNITS: usize = 512;
    pub const MAX_OPEN_MENUS: usize = 8;
    pub const MAX_PENDING_RECORDS: usize = 8;
    pub const MAX_SELECTION_AGE_MS: i64 = 10_000;
    pub const MAX_MENU_TRACKING_MS: i64 = 10_000;
    pub const DEDUP_WINDOW_MS: i64 = 250;
    pub const MAX_SAFE_INTEGER: i64 = MAX_SAFE_INTEGER;

    /// Matches JS `String.prototype.trim()` and `ContractValidator` whitespace parity
    /// (including ASCII whitespace, `\u{00A0}`, `\u{3000}`, and `\u{FEFF}`).
    pub fn is_whitespace(c: char) -> bool {
        c.is_whitespace() || c == '\u{FEFF}'
    }

    /// C0 (`< 0x20`) and C1 (`0x7F..=0x9F`) control scalars rejected on the wire.
    pub const fn is_control(c: char) -> bool {
        let code = c as u32;
        code < 0x20 || (code >= 0x7F && code <= 0x9F)
    }

    /// Collapses CR/LF/TAB runs to a single ASCII space, strips remaining C0/C1 controls,
    /// trims JS-compatible whitespace (including `U+00A0`, `U+3000`, `U+FEFF`), and rejects
    /// effectively empty (ZWSP/invisible) or pure Private Use Area icon-only glyph strings so
    /// callers fall back to `safe_description()`.
    pub fn sanitize_segment(raw: &str) -> Option<String> {
        let mut out = String::with_capacity(raw.len());
        let mut pending_space = false;
        for c in raw.chars() {
            if matches!(c, '\t' | '\n' | '\r') {
                pending_space = true;
                continue;
            }
            if Self::is_control(c) {
                continue;
            }
            if pending_space {
                if !out.is_empty() {
                    out.push(' ');
                }
                pending_space = false;
            }
            out.push(c);
        }
        let trimmed = trim_whitespace(&out)?;
        if is_effectively_empty_text(&trimmed) || is_private_use_only_text(&trimmed) {
            return None;
        }
        Some(trimmed)
    }

    pub fn is_valid_segment(segment: &str) -> bool {
        let units = utf16_len(segment);
        if !(1..=Self::MAX_SEGMENT_UTF16_UNITS).contains(&units) {
            return false;
        }
        if segment.chars().any(Self::is_control) {
            return false;
        }
        if segment.chars().all(Self::is_whitespace)
            || is_effectively_empty_text(segment)
            || is_private_use_only_text(segment)
        {
            return false;
        }
        true
    }

    pub fn is_valid_path(path: &[String]) -> bool {
        if !(Self::MIN_SEGMENTS..=Self::MAX_SEGMENTS).contains(&path.len()) {
            return false;
        }
        let mut total = 0usize;
        for segment in path {
            if !Self::is_valid_segment(segment) {
                return false;
            }
            total = match total.checked_add(utf16_len(segment)) {
                Some(sum) if sum <= Self::MAX_TOTAL_UTF16_UNITS => sum,
                _ => return false,
            };
        }
        true
    }

    /// Bounds already-sanitized segments to 128 UTF-16 units each and 512 total without bisecting
    /// surrogate pairs. Reserves each remaining segment's first scalar so deeper valid paths
    /// cannot starve later segments to zero UTF-16 units.
    pub fn bound_path(sanitized_segments: &[String]) -> Option<ResolvedMenuPath> {
        if !(Self::MIN_SEGMENTS..=Self::MAX_SEGMENTS).contains(&sanitized_segments.len()) {
            return None;
        }
        let mut min_units = Vec::with_capacity(sanitized_segments.len());
        for segment in sanitized_segments {
            let first = segment.chars().next()?;
            if Self::is_control(first) || Self::is_whitespace(first) {
                return None;
            }
            min_units.push(first.len_utf16());
        }

        let mut remaining = Self::MAX_TOTAL_UTF16_UNITS;
        let mut suffix_min: usize = min_units.iter().sum();
        let mut bounded = Vec::with_capacity(sanitized_segments.len());
        let mut truncated = false;

        for (index, segment) in sanitized_segments.iter().enumerate() {
            suffix_min -= min_units[index];
            if remaining < suffix_min {
                return None;
            }
            let cap = Self::MAX_SEGMENT_UTF16_UNITS.min(remaining - suffix_min);
            if cap < min_units[index] {
                return None;
            }
            let units = utf16_len(segment);
            if units <= cap {
                bounded.push(segment.clone());
                remaining -= units;
            } else {
                truncated = true;
                let sliced = bounded_utf16_slice(segment, 0, cap)?;
                let cleaned = trim_trailing_whitespace(&sliced)?;
                if cleaned.is_empty() {
                    return None;
                }
                remaining -= utf16_len(&cleaned);
                bounded.push(cleaned);
            }
        }

        if !Self::is_valid_path(&bounded) {
            return None;
        }
        Some(ResolvedMenuPath {
            path: bounded,
            truncated,
        })
    }
}

fn trim_whitespace(text: &str) -> Option<String> {
    let trimmed = text.trim_matches(MenuPathLimits::is_whitespace);
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn trim_trailing_whitespace(text: &str) -> Option<String> {
    let trimmed = text.trim_end_matches(MenuPathLimits::is_whitespace);
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Immutable worker-to-engine IPC record for one committed foreground menu bar action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MenuActionRecord {
    pub application: ApplicationIdentity,
    /// Internal-only normalized `.exe` basename for dual-ID defense-in-depth
    /// (e.g. MSIX Bitwarden / Arc). NEVER emitted on the external wire protocol.
    pub exe_name: Option<String>,
    pub path: Vec<String>,
    pub truncated: bool,
    pub observed_at_ms: i64,
    pub private_state: String,
    pub stamp: Stamp,
    pub field_security: String,
}

impl MenuActionRecord {
    pub fn resolved_app_identity(&self) -> Option<ResolvedAppIdentity> {
        ResolvedAppIdentity::from_wire_and_exe(
            self.application.application_id.clone(),
            self.exe_name.clone(),
        )
    }

    pub fn content_gate(&self) -> Option<ContentGate> {
        let secure = match self.field_security.as_str() {
            "strict" => SecureStatus::Safe.as_str(),
            "denylist" => SecureStatus::NotDeclaredSensitive.as_str(),
            _ => return None,
        };
        if !matches!(self.private_state.as_str(), "normal" | "user-authorized")
            || !(1..=MenuPathLimits::MAX_SAFE_INTEGER).contains(&self.stamp.policy_revision)
        {
            return None;
        }
        Some(ContentGate {
            secure: secure.to_string(),
            private_state: self.private_state.clone(),
            policy_revision: self.stamp.policy_revision,
        })
    }

    pub fn is_valid(&self) -> bool {
        self.application.process_id > 0
            && self.application.process_id <= i32::MAX as u32
            && is_valid_application_id(&self.application.application_id)
            && self.resolved_app_identity().is_some()
            && !self.application.process_start_time.is_empty()
            && utf16_len(&self.application.process_start_time) <= 128
            && MenuPathLimits::is_valid_path(&self.path)
            && (0..=MenuPathLimits::MAX_SAFE_INTEGER).contains(&self.observed_at_ms)
            && (0..=MenuPathLimits::MAX_SAFE_INTEGER).contains(&self.stamp.capture_epoch)
            && (0..=MenuPathLimits::MAX_SAFE_INTEGER).contains(&self.stamp.foreground_generation)
            && (0..=MenuPathLimits::MAX_SAFE_INTEGER).contains(&self.stamp.focus_generation)
            && self.content_gate().is_some()
    }

    /// Builds the exact 9-field wire-v1 `menu.action` payload (`additionalProperties: false`).
    /// Never emits internal-only `exe_name` and never maps invalid/sensitive states to `"safe"`.
    pub fn payload(&self, fixture: bool) -> JsonValue {
        let source = if fixture {
            MenuActionSource::Fixture
        } else {
            MenuActionSource::UiaMenu
        };
        self.payload_with_source(source)
    }

    /// Fail-closed variant returning `None` if `!self.is_valid()` or `self.content_gate()` is `None`.
    pub fn try_payload_with_source(&self, source: MenuActionSource) -> Option<JsonValue> {
        if !self.is_valid() {
            return None;
        }
        let gate = self.content_gate()?;
        Some(self.build_payload(source, gate))
    }

    pub fn payload_with_source(&self, source: MenuActionSource) -> JsonValue {
        let gate = self.content_gate().unwrap_or_else(|| ContentGate {
            secure: SecureStatus::Unknown.as_str().to_string(),
            private_state: self.private_state.clone(),
            policy_revision: self.stamp.policy_revision,
        });
        self.build_payload(source, gate)
    }

    fn build_payload(&self, source: MenuActionSource, gate: ContentGate) -> JsonValue {
        let mut missing_reasons = vec![
            "menu-bar-only".to_string(),
            "effect-unverified".to_string(),
        ];
        if self.truncated {
            missing_reasons.push("menu-title-truncated".to_string());
        }
        let coverage = Coverage {
            status: "partial".to_string(),
            truncated: self.truncated,
            missing_reasons,
        };

        let mut map = BTreeMap::new();
        map.insert(
            "kind".to_string(),
            JsonValue::String("menu.action".to_string()),
        );
        map.insert(
            "source".to_string(),
            JsonValue::String(source.as_str().to_string()),
        );
        map.insert(
            "scope".to_string(),
            JsonValue::String("menu-bar".to_string()),
        );
        map.insert(
            "path".to_string(),
            JsonValue::Array(self.path.iter().cloned().map(JsonValue::String).collect()),
        );
        map.insert("observedAtMs".to_string(), json_i64(self.observed_at_ms));
        map.insert("gate".to_string(), gate.to_json());
        map.insert(
            "secureInput".to_string(),
            JsonValue::String("inactive".to_string()),
        );
        map.insert("coverage".to_string(), coverage.to_json());
        map.insert(
            "effect".to_string(),
            JsonValue::String("unverified".to_string()),
        );
        JsonValue::Object(map)
    }

    /// Serializes this record for internal worker->parent IPC.
    pub fn to_json(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert("application".to_string(), self.application.to_json());
        if let Some(ref exe) = self.exe_name {
            map.insert("exeName".to_string(), JsonValue::String(exe.clone()));
        }
        map.insert(
            "path".to_string(),
            JsonValue::Array(self.path.iter().cloned().map(JsonValue::String).collect()),
        );
        map.insert("truncated".to_string(), JsonValue::Bool(self.truncated));
        map.insert("observedAtMs".to_string(), json_i64(self.observed_at_ms));
        map.insert(
            "privateState".to_string(),
            JsonValue::String(self.private_state.clone()),
        );
        map.insert("stamp".to_string(), self.stamp.to_json());
        map.insert(
            "fieldSecurity".to_string(),
            JsonValue::String(self.field_security.clone()),
        );
        JsonValue::Object(map)
    }

    /// Deserializes a worker IPC `MenuActionRecord`, failing closed on invalid fields.
    pub fn from_json(value: &JsonValue) -> Option<Self> {
        let obj = value.as_obj()?;
        let application = ApplicationIdentity::from_json(obj.get("application")?)?;
        let exe_name = match obj.get("exeName") {
            None | Some(JsonValue::Null) => None,
            Some(v) => Some(v.as_str()?.to_string()),
        };
        let path_arr = obj.get("path")?.as_array()?;
        let mut path = Vec::with_capacity(path_arr.len());
        for item in path_arr {
            path.push(item.as_str()?.to_string());
        }
        let truncated = obj.get("truncated")?.as_bool()?;
        let observed_at_ms = obj.get("observedAtMs")?.as_i64()?;
        let private_state = obj.get("privateState")?.as_str()?.to_string();
        let stamp_obj = obj.get("stamp")?.as_obj()?;
        let stamp = Stamp {
            capture_epoch: stamp_obj.get("captureEpoch")?.as_i64()?,
            foreground_generation: stamp_obj.get("foregroundGeneration")?.as_i64()?,
            focus_generation: stamp_obj.get("focusGeneration")?.as_i64()?,
            policy_revision: stamp_obj.get("policyRevision")?.as_i64()?,
        };
        let field_security = obj.get("fieldSecurity")?.as_str()?.to_string();
        let record = Self {
            application,
            exe_name,
            path,
            truncated,
            observed_at_ms,
            private_state,
            stamp,
            field_security,
        };
        record.is_valid().then_some(record)
    }
}

/// UIA ControlType IDs relevant to menu ancestor resolution (no Win32 import needed).
pub const UIA_BUTTON_CONTROL_TYPE: i32 = 50000;
pub const UIA_EDIT_CONTROL_TYPE: i32 = 50004;
pub const UIA_IMAGE_CONTROL_TYPE: i32 = 50006;
pub const UIA_MENU_CONTROL_TYPE: i32 = 50009;
pub const UIA_MENU_BAR_CONTROL_TYPE: i32 = 50010;
pub const UIA_MENU_ITEM_CONTROL_TYPE: i32 = 50011;
pub const UIA_TEXT_CONTROL_TYPE: i32 = 50020;
pub const UIA_CUSTOM_CONTROL_TYPE: i32 = 50025;
pub const UIA_GROUP_CONTROL_TYPE: i32 = 50026;
pub const UIA_DOCUMENT_CONTROL_TYPE: i32 = 50030;
pub const UIA_WINDOW_CONTROL_TYPE: i32 = 50032;
pub const UIA_PANE_CONTROL_TYPE: i32 = 50033;

/// Returns `true` only when a direct child's UIA ControlType represents a nested menu structure
/// (`Menu (50009)` or `MenuItem (50011)`), ignoring visual leaf children (`Text`, `Image`, `Group`).
pub const fn is_menu_structure_control_type(control_type: i32) -> bool {
    control_type == UIA_MENU_CONTROL_TYPE || control_type == UIA_MENU_ITEM_CONTROL_TYPE
}

/// Platform-free metadata snapshot for one UIA/AX node in a menu parent chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MenuNodeSnapshot {
    pub pid: u32,
    pub control_type: Option<i32>,
    pub role: Option<String>,
    pub subrole: SubroleRead,
    pub protected_content: ProtectedContentRead,
    pub enabled: Option<bool>,
    pub title: Option<String>,
    pub description: Option<String>,
    pub automation_id: Option<String>,
    pub class_name: Option<String>,
    /// Required on leaf `MenuItem`: must be `Some(0)` so submenu openers are never emitted.
    pub child_count: Option<usize>,
    /// Optional `ExpandCollapsePattern` indicator: `Some(true)` on leaf rejects lazy submenu openers.
    pub is_submenu_opener: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MenuNodeRole {
    MenuBar,
    MenuBarItem,
    Menu,
    MenuItem,
    Window,
    Other,
}

impl MenuNodeSnapshot {
    fn classified_role(&self) -> MenuNodeRole {
        if self.role.as_deref() == Some("AXSecureTextField") {
            return MenuNodeRole::Other;
        }
        match (self.role.as_deref(), self.control_type) {
            (Some("AXMenuBar"), None | Some(UIA_MENU_BAR_CONTROL_TYPE))
            | (None, Some(UIA_MENU_BAR_CONTROL_TYPE)) => MenuNodeRole::MenuBar,
            (Some("AXMenuBarItem"), None | Some(UIA_MENU_ITEM_CONTROL_TYPE)) => {
                MenuNodeRole::MenuBarItem
            }
            (Some("AXMenu"), None | Some(UIA_MENU_CONTROL_TYPE))
            | (None, Some(UIA_MENU_CONTROL_TYPE)) => MenuNodeRole::Menu,
            (Some("AXMenuItem"), None | Some(UIA_MENU_ITEM_CONTROL_TYPE))
            | (None, Some(UIA_MENU_ITEM_CONTROL_TYPE)) => MenuNodeRole::MenuItem,
            (Some("AXWindow"), None | Some(UIA_WINDOW_CONTROL_TYPE))
            | (None, Some(UIA_WINDOW_CONTROL_TYPE)) => MenuNodeRole::Window,
            _ => MenuNodeRole::Other,
        }
    }

    fn is_system_menu_bar(&self) -> bool {
        self.automation_id
            .as_deref()
            .is_some_and(|aid| aid.eq_ignore_ascii_case("SystemMenuBar"))
    }

    /// Identifies web-document / renderer host containers (`Document (50030)`, `AXWebArea`,
    /// `AXDocument`, `Chrome_RenderWidgetHostHWND`, `MozillaCompositorWindowClass`) so browsers
    /// reject webpage `<div role="menubar">` hierarchies when `allow_document_hosted_menu_bar`
    /// is `false`.
    fn is_document_host(&self) -> bool {
        self.control_type == Some(UIA_DOCUMENT_CONTROL_TYPE)
            || matches!(self.role.as_deref(), Some("AXWebArea" | "AXDocument"))
            || self.class_name.as_deref().is_some_and(|cls| {
                cls.eq_ignore_ascii_case("Chrome_RenderWidgetHostHWND")
                    || cls.eq_ignore_ascii_case("MozillaCompositorWindowClass")
            })
    }

    /// Explicit allowlist of safe transparent layout wrappers (Electron DOM `AXGroup` /
    /// `AXScrollArea` and WinUI 3 `Custom` / `Group` / `Pane` popup containers). Strictly
    /// whitelists `role` to `None | Some("AXGroup" | "AXScrollArea")` and rejects `AXHeading`,
    /// `ToolBar`, `TitleBar`, `Tree`, `List`, `Tab`, `Button`, `StatusBar`, `Document`, `Edit`,
    /// `Window`, `ControlType(0)`, renderer hosts, and any sensitive/text/web role.
    fn is_transparent_menu_wrapper(&self) -> bool {
        if self.is_document_host() {
            return false;
        }
        match self.control_type {
            Some(ct) => {
                matches!(
                    ct,
                    UIA_CUSTOM_CONTROL_TYPE | UIA_GROUP_CONTROL_TYPE | UIA_PANE_CONTROL_TYPE
                ) && matches!(self.role.as_deref(), None | Some("AXGroup" | "AXScrollArea"))
            }
            None => matches!(self.role.as_deref(), Some("AXGroup" | "AXScrollArea")),
        }
    }
}

/// Explicit link proving a detached popup menu (`#32768`, WinUI 3 `MenuFlyoutPresenter`, or
/// detached portal `Menu`) was opened from the foreground window's top menu bar — either via
/// classic Win32 `EVENT_SYSTEM_MENUSTART(OBJID_MENU)` OR via focus/invoke on a verified
/// non-`SystemMenuBar` `MenuBar (50010)` item belonging to the bound foreground window (strictly
/// never `OBJID_SYSMENU` or right-click context menus).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Win32MenuBarLink {
    /// Active top-level menu bar item title (e.g., `"File"`).
    pub menu_bar_item_title: String,
    /// Optional outer-to-inner intermediate submenu titles when nested popups are UIA siblings
    /// under the app window/popup root rather than children of their opener menu items.
    pub submenu_titles: Vec<String>,
    /// True ONLY when opened with verified top-menu-bar provenance (`OBJID_MENU` or verified
    /// non-`SystemMenuBar` `MenuBar (50010)` item).
    pub from_menu_bar_start: bool,
}

impl Win32MenuBarLink {
    fn sanitized_prefix_reversed(&self) -> Option<Vec<String>> {
        if !self.from_menu_bar_start {
            return None;
        }
        let bar_title = MenuPathLimits::sanitize_segment(&self.menu_bar_item_title)?;
        let mut rev = Vec::with_capacity(self.submenu_titles.len() + 1);
        for sub in self.submenu_titles.iter().rev() {
            rev.push(MenuPathLimits::sanitize_segment(sub)?);
        }
        rev.push(bar_title);
        Some(rev)
    }
}

/// Classification of an opened `Menu` under the foreground application's top menu bar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenedMenuKind {
    TopLevel,
    Submenu,
}

/// Platform-free ancestor chain resolver proving top-menu-bar ownership without screen
/// coordinates, hit-testing, or full children enumeration.
pub struct MenuPathResolver;

impl MenuPathResolver {
    fn is_safe_menu_node(
        meta: &MenuNodeSnapshot,
        expected_pid: u32,
        raw_host_pid: Option<u32>,
    ) -> bool {
        let pid_ok = meta.pid > 0
            && (meta.pid == expected_pid
                || raw_host_pid.is_some_and(|host| host > 0 && meta.pid == host));
        pid_ok
            && meta.role.as_deref() != Some("AXSecureTextField")
            && TextSecurityGate::may_traverse(&meta.subrole, meta.protected_content)
    }

    fn preferred_title(title: Option<&str>, description: Option<&str>) -> Option<String> {
        if let Some(clean) = title.and_then(MenuPathLimits::sanitize_segment) {
            return Some(clean);
        }
        if let Some(clean) = description.and_then(MenuPathLimits::sanitize_segment) {
            return Some(clean);
        }
        None
    }

    fn append_verified_link_prefix(
        reversed_segments: &mut Vec<String>,
        win32_link: Option<&Win32MenuBarLink>,
    ) -> bool {
        let Some(prefix_rev) = win32_link.and_then(Win32MenuBarLink::sanitized_prefix_reversed)
        else {
            return false;
        };
        let walked_ancestors = &reversed_segments[1..];
        let link_submenus_rev = &prefix_rev[..prefix_rev.len() - 1];
        let max_overlap = walked_ancestors.len().min(link_submenus_rev.len());
        let mut skip = 0usize;
        for k in (1..=max_overlap).rev() {
            if walked_ancestors[walked_ancestors.len() - k..] == link_submenus_rev[..k] {
                skip = k;
                break;
            }
        }
        reversed_segments.extend(prefix_rev.into_iter().skip(skip));
        true
    }

    /// Walks parent links from a leaf `MenuItem` up to the foreground app's top `MenuBar` (or a
    /// verified-provenance detached `#32768` / WinUI 3 / portal popup `Menu`), bounded to
    /// `MenuPathLimits::MAX_PARENT_HOPS` (20) hops.
    ///
    /// Delegates to `resolve_with_policy(..., allow_document_hosted_menu_bar = true)`. Callers
    /// inspecting browsers must call `resolve_with_policy(..., false)` to reject webpage
    /// document-hosted `<div role="menubar">` hierarchies.
    #[allow(clippy::too_many_arguments)]
    pub fn resolve<Handle, Same, Inspect, Parent, ShouldContinue>(
        leaf: Handle,
        expected_pid: u32,
        raw_host_pid: Option<u32>,
        app_menu_bar: Option<&Handle>,
        excluded_bar_item: Option<&Handle>,
        win32_link: Option<&Win32MenuBarLink>,
        same: Same,
        inspect: Inspect,
        parent: Parent,
        should_continue: ShouldContinue,
    ) -> Option<ResolvedMenuPath>
    where
        Same: Fn(&Handle, &Handle) -> bool,
        Inspect: FnMut(&Handle, bool) -> Option<MenuNodeSnapshot>,
        Parent: FnMut(&Handle) -> Option<Handle>,
        ShouldContinue: FnMut() -> bool,
    {
        Self::resolve_with_policy(
            leaf,
            expected_pid,
            raw_host_pid,
            app_menu_bar,
            excluded_bar_item,
            win32_link,
            true,
            same,
            inspect,
            parent,
            should_continue,
        )
    }

    /// Verifies ancestors strictly above a reached `MenuBar` up to `Window` or Desktop root (`None`)
    /// using an independent `MAX_ABOVE_MENU_BAR_HOPS` budget so deep submenus do not share hops with
    /// the `leaf/menu -> MenuBar` walk.
    #[allow(clippy::too_many_arguments)]
    fn verify_above_menu_bar<Handle, Same, Inspect, Parent, ShouldContinue>(
        visited: &mut Vec<Handle>,
        expected_pid: u32,
        raw_host_pid: Option<u32>,
        allow_document_hosted_menu_bar: bool,
        same: &Same,
        inspect: &mut Inspect,
        parent: &mut Parent,
        should_continue: &mut ShouldContinue,
    ) -> bool
    where
        Same: Fn(&Handle, &Handle) -> bool,
        Inspect: FnMut(&Handle) -> Option<MenuNodeSnapshot>,
        Parent: FnMut(&Handle) -> Option<Handle>,
        ShouldContinue: FnMut() -> bool,
    {
        for _ in 0..MenuPathLimits::MAX_ABOVE_MENU_BAR_HOPS {
            if !should_continue() {
                return false;
            }
            let Some(last) = visited.last() else {
                return false;
            };
            let ancestor_opt = parent(last);
            if !should_continue() {
                return false;
            }
            let Some(ancestor) = ancestor_opt else {
                return true;
            };
            if visited.iter().any(|seen| same(seen, &ancestor)) {
                return false;
            }
            let Some(meta) = inspect(&ancestor) else {
                return false;
            };
            if !should_continue() {
                return false;
            }
            if !Self::is_safe_menu_node(&meta, expected_pid, raw_host_pid)
                || meta.is_system_menu_bar()
            {
                return false;
            }
            if !allow_document_hosted_menu_bar && meta.is_document_host() {
                return false;
            }
            if meta.classified_role() == MenuNodeRole::Window {
                return true;
            }
            visited.push(ancestor);
        }
        false
    }

    /// Walks parent links from a leaf `MenuItem` up to the foreground app's top `MenuBar` (or a
    /// verified-provenance detached `#32768` / WinUI 3 / portal popup `Menu`), bounded to
    /// `MenuPathLimits::MAX_PARENT_HOPS` (20) hops and `MAX_CONSECUTIVE_WRAPPER_HOPS` (6).
    ///
    /// When `app_menu_bar` is `None`, encountering a verified non-`SystemMenuBar` `MenuBar`
    /// verifies ancestors up to `Window` or Desktop root (`None`) using an independent
    /// `MAX_ABOVE_MENU_BAR_HOPS` (20) hop budget, checking `is_safe_menu_node` at every hop and
    /// rejecting document/renderer hosts when `!allow_document_hosted_menu_bar`.
    ///
    /// Rejects `SystemMenuBar`, excluded bar items (e.g., Apple/System menu), right-click context
    /// menus, web-document context menus, submenu openers, disabled items/menus, cross-PID hops,
    /// cycles, and sensitive/`!may_traverse` nodes.
    #[allow(clippy::too_many_arguments)]
    pub fn resolve_with_policy<Handle, Same, Inspect, Parent, ShouldContinue>(
        leaf: Handle,
        expected_pid: u32,
        raw_host_pid: Option<u32>,
        app_menu_bar: Option<&Handle>,
        excluded_bar_item: Option<&Handle>,
        win32_link: Option<&Win32MenuBarLink>,
        allow_document_hosted_menu_bar: bool,
        same: Same,
        inspect: Inspect,
        parent: Parent,
        should_continue: ShouldContinue,
    ) -> Option<ResolvedMenuPath>
    where
        Same: Fn(&Handle, &Handle) -> bool,
        Inspect: FnMut(&Handle, bool) -> Option<MenuNodeSnapshot>,
        Parent: FnMut(&Handle) -> Option<Handle>,
        ShouldContinue: FnMut() -> bool,
    {
        Self::resolve_core(
            leaf,
            expected_pid,
            raw_host_pid,
            app_menu_bar,
            excluded_bar_item,
            win32_link,
            allow_document_hosted_menu_bar,
            same,
            inspect,
            parent,
            None,
            should_continue,
        )
    }

    /// Variant of [`Self::resolve_with_policy`] accepting a custom `verify_bar` callback invoked
    /// ONCE when a `MenuBar` is reached with `app_menu_bar == None`, avoiding a duplicate
    /// `MenuBar -> Window` walk when the host verifies HWND ownership directly.
    #[allow(clippy::too_many_arguments)]
    pub fn resolve_with_bar_verifier<Handle, Same, Inspect, Parent, VerifyBar, ShouldContinue>(
        leaf: Handle,
        expected_pid: u32,
        raw_host_pid: Option<u32>,
        app_menu_bar: Option<&Handle>,
        excluded_bar_item: Option<&Handle>,
        win32_link: Option<&Win32MenuBarLink>,
        allow_document_hosted_menu_bar: bool,
        same: Same,
        inspect: Inspect,
        parent: Parent,
        mut verify_bar: VerifyBar,
        should_continue: ShouldContinue,
    ) -> Option<ResolvedMenuPath>
    where
        Same: Fn(&Handle, &Handle) -> bool,
        Inspect: FnMut(&Handle, bool) -> Option<MenuNodeSnapshot>,
        Parent: FnMut(&Handle) -> Option<Handle>,
        VerifyBar: FnMut(&Handle) -> bool,
        ShouldContinue: FnMut() -> bool,
    {
        Self::resolve_core(
            leaf,
            expected_pid,
            raw_host_pid,
            app_menu_bar,
            excluded_bar_item,
            win32_link,
            allow_document_hosted_menu_bar,
            same,
            inspect,
            parent,
            Some(&mut verify_bar),
            should_continue,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn resolve_core<Handle, Same, Inspect, Parent, ShouldContinue>(
        leaf: Handle,
        expected_pid: u32,
        raw_host_pid: Option<u32>,
        app_menu_bar: Option<&Handle>,
        excluded_bar_item: Option<&Handle>,
        win32_link: Option<&Win32MenuBarLink>,
        allow_document_hosted_menu_bar: bool,
        same: Same,
        mut inspect: Inspect,
        mut parent: Parent,
        mut bar_verifier: Option<&mut dyn FnMut(&Handle) -> bool>,
        mut should_continue: ShouldContinue,
    ) -> Option<ResolvedMenuPath>
    where
        Same: Fn(&Handle, &Handle) -> bool,
        Inspect: FnMut(&Handle, bool) -> Option<MenuNodeSnapshot>,
        Parent: FnMut(&Handle) -> Option<Handle>,
        ShouldContinue: FnMut() -> bool,
    {
        if expected_pid == 0 || !should_continue() {
            return None;
        }
        let leaf_meta = inspect(&leaf, true)?;
        if !should_continue() {
            return None;
        }
        if !Self::is_safe_menu_node(&leaf_meta, expected_pid, raw_host_pid)
            || leaf_meta.classified_role() != MenuNodeRole::MenuItem
            || leaf_meta.enabled == Some(false)
            || leaf_meta.child_count != Some(0)
            || leaf_meta.is_submenu_opener == Some(true)
        {
            return None;
        }
        let leaf_title =
            Self::preferred_title(leaf_meta.title.as_deref(), leaf_meta.description.as_deref())?;

        let mut reversed_segments = vec![leaf_title];
        let mut visited = vec![leaf];
        let mut saw_bar_item = false;
        let mut last_was_bar_item_candidate = false;
        let mut saw_menu = false;
        let mut last_menu_title: Option<String> = None;
        let mut reached_app_menu_bar = false;
        let mut verified_above_menu_bar = false;
        let mut consecutive_wrapper_hops = 0usize;

        for _ in 0..MenuPathLimits::MAX_PARENT_HOPS {
            if !should_continue() {
                return None;
            }
            let ancestor_opt = parent(visited.last()?);
            if !should_continue() {
                return None;
            }

            let Some(ancestor) = ancestor_opt else {
                if saw_menu
                    && Self::append_verified_link_prefix(&mut reversed_segments, win32_link)
                {
                    saw_bar_item = true;
                    reached_app_menu_bar = true;
                    verified_above_menu_bar = true;
                    break;
                }
                return None;
            };
            if visited.iter().any(|seen| same(seen, &ancestor)) {
                return None;
            }
            let meta = inspect(&ancestor, false)?;
            if !should_continue() {
                return None;
            }
            if !Self::is_safe_menu_node(&meta, expected_pid, raw_host_pid) {
                return None;
            }

            match meta.classified_role() {
                MenuNodeRole::MenuBar => {
                    if meta.is_system_menu_bar()
                        || (!allow_document_hosted_menu_bar && meta.is_document_host())
                    {
                        return None;
                    }
                    if let Some(expected_bar) = app_menu_bar {
                        if !same(&ancestor, expected_bar) {
                            return None;
                        }
                    }
                    if last_was_bar_item_candidate {
                        saw_bar_item = true;
                    } else if !saw_bar_item {
                        if let Some(menu_title) = last_menu_title.take() {
                            reversed_segments.push(menu_title);
                            saw_bar_item = true;
                        } else if saw_menu
                            && Self::append_verified_link_prefix(&mut reversed_segments, win32_link)
                        {
                            saw_bar_item = true;
                        }
                    }
                    if !saw_bar_item {
                        return None;
                    }
                    reached_app_menu_bar = true;
                    if app_menu_bar.is_some() {
                        verified_above_menu_bar = true;
                        break;
                    }
                    visited.push(ancestor);
                    verified_above_menu_bar = match bar_verifier {
                        Some(ref mut verify) => verify(visited.last()?),
                        None => Self::verify_above_menu_bar(
                            &mut visited,
                            expected_pid,
                            raw_host_pid,
                            allow_document_hosted_menu_bar,
                            &same,
                            &mut |h| inspect(h, false),
                            &mut parent,
                            &mut should_continue,
                        ),
                    };
                    break;
                }
                MenuNodeRole::Menu => {
                    if meta.enabled == Some(false) {
                        return None;
                    }
                    consecutive_wrapper_hops = 0;
                    last_was_bar_item_candidate = false;
                    saw_menu = true;
                    last_menu_title = Self::preferred_title(
                        meta.title.as_deref(),
                        meta.description.as_deref(),
                    );
                }
                MenuNodeRole::MenuItem => {
                    if meta.enabled == Some(false)
                        || excluded_bar_item.is_some_and(|ex| same(&ancestor, ex))
                    {
                        return None;
                    }
                    let title = Self::preferred_title(
                        meta.title.as_deref(),
                        meta.description.as_deref(),
                    )?;
                    reversed_segments.push(title);
                    consecutive_wrapper_hops = 0;
                    last_was_bar_item_candidate = true;
                    saw_menu = false;
                    last_menu_title = None;
                }
                MenuNodeRole::MenuBarItem => {
                    if meta.enabled == Some(false)
                        || excluded_bar_item.is_some_and(|ex| same(&ancestor, ex))
                    {
                        return None;
                    }
                    let title = Self::preferred_title(
                        meta.title.as_deref(),
                        meta.description.as_deref(),
                    )?;
                    reversed_segments.push(title);
                    consecutive_wrapper_hops = 0;
                    saw_bar_item = true;
                    last_was_bar_item_candidate = true;
                    saw_menu = false;
                    last_menu_title = None;
                }
                MenuNodeRole::Window => {
                    if meta.is_document_host() {
                        return None;
                    }
                    if saw_menu
                        && Self::append_verified_link_prefix(&mut reversed_segments, win32_link)
                    {
                        saw_bar_item = true;
                        reached_app_menu_bar = true;
                        verified_above_menu_bar = true;
                        break;
                    }
                    return None;
                }
                MenuNodeRole::Other => {
                    if !meta.is_transparent_menu_wrapper() {
                        return None;
                    }
                    consecutive_wrapper_hops += 1;
                    if consecutive_wrapper_hops > MenuPathLimits::MAX_CONSECUTIVE_WRAPPER_HOPS {
                        return None;
                    }
                }
            }
            visited.push(ancestor);
        }

        if !reached_app_menu_bar || !saw_bar_item || !verified_above_menu_bar {
            return None;
        }
        reversed_segments.reverse();
        MenuPathLimits::bound_path(&reversed_segments)
    }

    /// Classifies an opened `Menu` as either a top-level menu bar dropdown or a nested submenu
    /// under the foreground app's menu bar.
    ///
    /// Delegates to `classify_opened_menu_with_policy(..., allow_document_hosted_menu_bar = true)`.
    #[allow(clippy::too_many_arguments)]
    pub fn classify_opened_menu<Handle, Same, Inspect, Parent, ShouldContinue>(
        menu: Handle,
        expected_pid: u32,
        raw_host_pid: Option<u32>,
        app_menu_bar: Option<&Handle>,
        excluded_bar_item: Option<&Handle>,
        win32_link: Option<&Win32MenuBarLink>,
        open_menus: &[Handle],
        same: Same,
        inspect: Inspect,
        parent: Parent,
        should_continue: ShouldContinue,
    ) -> Option<OpenedMenuKind>
    where
        Same: Fn(&Handle, &Handle) -> bool,
        Inspect: FnMut(&Handle) -> Option<MenuNodeSnapshot>,
        Parent: FnMut(&Handle) -> Option<Handle>,
        ShouldContinue: FnMut() -> bool,
    {
        Self::classify_opened_menu_with_policy(
            menu,
            expected_pid,
            raw_host_pid,
            app_menu_bar,
            excluded_bar_item,
            win32_link,
            open_menus,
            true,
            same,
            inspect,
            parent,
            should_continue,
        )
    }

    /// Classifies an opened `Menu` as either a top-level menu bar dropdown or a nested submenu
    /// under the foreground app's menu bar (excluding `SystemMenuBar`, excluded bar items,
    /// disabled menus/items, context menus, web-document context menus, cross-PID nodes, cycles,
    /// and sensitive nodes). When `app_menu_bar` is `None`, verifies ancestors above `MenuBar` to
    /// `Window` or Desktop root (`None`) using an independent `MAX_ABOVE_MENU_BAR_HOPS` (20) hop
    /// budget, checking `is_safe_menu_node` at every hop and rejecting document/renderer hosts
    /// when `!allow_document_hosted_menu_bar`.
    #[allow(clippy::too_many_arguments)]
    pub fn classify_opened_menu_with_policy<Handle, Same, Inspect, Parent, ShouldContinue>(
        menu: Handle,
        expected_pid: u32,
        raw_host_pid: Option<u32>,
        app_menu_bar: Option<&Handle>,
        excluded_bar_item: Option<&Handle>,
        win32_link: Option<&Win32MenuBarLink>,
        open_menus: &[Handle],
        allow_document_hosted_menu_bar: bool,
        same: Same,
        inspect: Inspect,
        parent: Parent,
        should_continue: ShouldContinue,
    ) -> Option<OpenedMenuKind>
    where
        Same: Fn(&Handle, &Handle) -> bool,
        Inspect: FnMut(&Handle) -> Option<MenuNodeSnapshot>,
        Parent: FnMut(&Handle) -> Option<Handle>,
        ShouldContinue: FnMut() -> bool,
    {
        Self::classify_opened_menu_core(
            menu,
            expected_pid,
            raw_host_pid,
            app_menu_bar,
            excluded_bar_item,
            win32_link,
            open_menus,
            allow_document_hosted_menu_bar,
            same,
            inspect,
            parent,
            None,
            should_continue,
        )
    }

    /// Variant of [`Self::classify_opened_menu_with_policy`] accepting a custom `verify_bar`
    /// callback invoked ONCE when a `MenuBar` is reached with `app_menu_bar == None`, avoiding a
    /// duplicate `MenuBar -> Window` walk when the host verifies HWND ownership directly.
    #[allow(clippy::too_many_arguments)]
    pub fn classify_opened_menu_with_bar_verifier<
        Handle,
        Same,
        Inspect,
        Parent,
        VerifyBar,
        ShouldContinue,
    >(
        menu: Handle,
        expected_pid: u32,
        raw_host_pid: Option<u32>,
        app_menu_bar: Option<&Handle>,
        excluded_bar_item: Option<&Handle>,
        win32_link: Option<&Win32MenuBarLink>,
        open_menus: &[Handle],
        allow_document_hosted_menu_bar: bool,
        same: Same,
        inspect: Inspect,
        parent: Parent,
        mut verify_bar: VerifyBar,
        should_continue: ShouldContinue,
    ) -> Option<OpenedMenuKind>
    where
        Same: Fn(&Handle, &Handle) -> bool,
        Inspect: FnMut(&Handle) -> Option<MenuNodeSnapshot>,
        Parent: FnMut(&Handle) -> Option<Handle>,
        VerifyBar: FnMut(&Handle) -> bool,
        ShouldContinue: FnMut() -> bool,
    {
        Self::classify_opened_menu_core(
            menu,
            expected_pid,
            raw_host_pid,
            app_menu_bar,
            excluded_bar_item,
            win32_link,
            open_menus,
            allow_document_hosted_menu_bar,
            same,
            inspect,
            parent,
            Some(&mut verify_bar),
            should_continue,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn classify_opened_menu_core<Handle, Same, Inspect, Parent, ShouldContinue>(
        menu: Handle,
        expected_pid: u32,
        raw_host_pid: Option<u32>,
        app_menu_bar: Option<&Handle>,
        excluded_bar_item: Option<&Handle>,
        win32_link: Option<&Win32MenuBarLink>,
        open_menus: &[Handle],
        allow_document_hosted_menu_bar: bool,
        same: Same,
        mut inspect: Inspect,
        mut parent: Parent,
        mut bar_verifier: Option<&mut dyn FnMut(&Handle) -> bool>,
        mut should_continue: ShouldContinue,
    ) -> Option<OpenedMenuKind>
    where
        Same: Fn(&Handle, &Handle) -> bool,
        Inspect: FnMut(&Handle) -> Option<MenuNodeSnapshot>,
        Parent: FnMut(&Handle) -> Option<Handle>,
        ShouldContinue: FnMut() -> bool,
    {
        if expected_pid == 0 || !should_continue() {
            return None;
        }
        let menu_meta = inspect(&menu)?;
        if !should_continue()
            || !Self::is_safe_menu_node(&menu_meta, expected_pid, raw_host_pid)
            || menu_meta.classified_role() != MenuNodeRole::Menu
            || menu_meta.enabled == Some(false)
        {
            return None;
        }
        let has_valid_win32_link = win32_link
            .and_then(Win32MenuBarLink::sanitized_prefix_reversed)
            .is_some();

        let mut visited = vec![menu];
        let mut saw_intermediate_menu_item = false;
        let mut menu_item_count = 0usize;
        let mut saw_intermediate_menu = false;
        let mut consecutive_wrapper_hops = 0usize;

        for _ in 0..MenuPathLimits::MAX_PARENT_HOPS {
            if !should_continue() {
                return None;
            }
            let ancestor_opt = parent(visited.last()?);
            if !should_continue() {
                return None;
            }

            let Some(ancestor) = ancestor_opt else {
                let detached_ok = !saw_intermediate_menu_item || saw_intermediate_menu;
                if detached_ok && has_valid_win32_link {
                    return Some(if !saw_intermediate_menu && open_menus.is_empty() {
                        OpenedMenuKind::TopLevel
                    } else {
                        OpenedMenuKind::Submenu
                    });
                }
                return None;
            };
            if visited.iter().any(|seen| same(seen, &ancestor)) {
                return None;
            }

            let meta = inspect(&ancestor)?;
            if !should_continue() || !Self::is_safe_menu_node(&meta, expected_pid, raw_host_pid) {
                return None;
            }
            if open_menus.iter().any(|open| same(open, &ancestor)) {
                if meta.enabled == Some(false) {
                    return None;
                }
                return Some(OpenedMenuKind::Submenu);
            }

            match meta.classified_role() {
                MenuNodeRole::Menu => {
                    if meta.enabled == Some(false) {
                        return None;
                    }
                    saw_intermediate_menu = true;
                    consecutive_wrapper_hops = 0;
                }
                MenuNodeRole::MenuItem | MenuNodeRole::MenuBarItem => {
                    if meta.enabled == Some(false)
                        || excluded_bar_item.is_some_and(|ex| same(&ancestor, ex))
                    {
                        return None;
                    }
                    saw_intermediate_menu_item = true;
                    menu_item_count += 1;
                    consecutive_wrapper_hops = 0;
                }
                MenuNodeRole::MenuBar => {
                    if meta.is_system_menu_bar()
                        || (!allow_document_hosted_menu_bar && meta.is_document_host())
                        || app_menu_bar.is_some_and(|expected| !same(&ancestor, expected))
                    {
                        return None;
                    }
                    let kind = if !saw_intermediate_menu && menu_item_count <= 1 {
                        OpenedMenuKind::TopLevel
                    } else {
                        OpenedMenuKind::Submenu
                    };
                    if app_menu_bar.is_some() {
                        return Some(kind);
                    }
                    visited.push(ancestor);
                    let verified = match bar_verifier {
                        Some(ref mut verify) => verify(visited.last()?),
                        None => Self::verify_above_menu_bar(
                            &mut visited,
                            expected_pid,
                            raw_host_pid,
                            allow_document_hosted_menu_bar,
                            &same,
                            &mut inspect,
                            &mut parent,
                            &mut should_continue,
                        ),
                    };
                    return verified.then_some(kind);
                }
                MenuNodeRole::Window => {
                    if meta.is_document_host() {
                        return None;
                    }
                    let detached_ok = !saw_intermediate_menu_item || saw_intermediate_menu;
                    if detached_ok && has_valid_win32_link {
                        return Some(if !saw_intermediate_menu && open_menus.is_empty() {
                            OpenedMenuKind::TopLevel
                        } else {
                            OpenedMenuKind::Submenu
                        });
                    }
                    return None;
                }
                MenuNodeRole::Other => {
                    if !meta.is_transparent_menu_wrapper() {
                        return None;
                    }
                    consecutive_wrapper_hops += 1;
                    if consecutive_wrapper_hops > MenuPathLimits::MAX_CONSECUTIVE_WRAPPER_HOPS {
                        return None;
                    }
                }
            }
            visited.push(ancestor);
        }
        None
    }
}

/// Transition reported by `MenuTrackingStateMachine` when menus open, close, prune, or reset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MenuTrackingTransition<MenuHandle> {
    pub tracking_changed: Option<bool>,
    pub removed: Vec<MenuHandle>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HighlightedSelection<MenuHandle, Selection> {
    menu: MenuHandle,
    selection: Selection,
    updated_at_ms: i64,
}

/// Pure tracking state machine for open menus (up to `MAX_OPEN_MENUS = 8`) and a single volatile
/// highlighted item. Never emits on hover; `commit(now_ms)` consumes the highlight at most once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MenuTrackingStateMachine<MenuHandle, Selection> {
    max_open_menus: usize,
    max_selection_age_ms: i64,
    open_menus: Vec<MenuHandle>,
    highlighted: Option<HighlightedSelection<MenuHandle, Selection>>,
}

impl<MenuHandle: PartialEq, Selection> Default for MenuTrackingStateMachine<MenuHandle, Selection> {
    fn default() -> Self {
        Self::new()
    }
}

impl<MenuHandle: PartialEq, Selection> MenuTrackingStateMachine<MenuHandle, Selection> {
    pub fn new() -> Self {
        Self::with_limits(
            MenuPathLimits::MAX_OPEN_MENUS,
            MenuPathLimits::MAX_SELECTION_AGE_MS,
        )
    }

    pub fn with_limits(max_open_menus: usize, max_selection_age_ms: i64) -> Self {
        Self {
            max_open_menus: max_open_menus.max(1),
            max_selection_age_ms: max_selection_age_ms.max(1),
            open_menus: Vec::new(),
            highlighted: None,
        }
    }

    pub fn open_menus(&self) -> &[MenuHandle] {
        &self.open_menus
    }

    pub fn is_tracking(&self) -> bool {
        !self.open_menus.is_empty()
    }

    pub fn has_selection(&self) -> bool {
        self.highlighted.is_some()
    }

    pub fn menu_opened(
        &mut self,
        menu: MenuHandle,
        is_top_level: bool,
    ) -> MenuTrackingTransition<MenuHandle> {
        let was_tracking = !self.open_menus.is_empty();
        let mut evicted = Vec::new();

        if is_top_level {
            if self.open_menus.len() == 1 && self.open_menus[0] == menu {
                return MenuTrackingTransition {
                    tracking_changed: None,
                    removed: Vec::new(),
                };
            }
            for old in self.open_menus.drain(..) {
                if old != menu {
                    evicted.push(old);
                }
            }
            self.open_menus.push(menu);
            self.highlighted = None;
        } else {
            if self.open_menus.contains(&menu) {
                return MenuTrackingTransition {
                    tracking_changed: None,
                    removed: Vec::new(),
                };
            }
            if self.open_menus.len() >= self.max_open_menus {
                let dropped = self.open_menus.remove(0);
                if self
                    .highlighted
                    .as_ref()
                    .is_some_and(|current| current.menu == dropped)
                {
                    self.highlighted = None;
                }
                evicted.push(dropped);
            }
            self.open_menus.push(menu);
        }

        let now_tracking = !self.open_menus.is_empty();
        let tracking_changed = (was_tracking != now_tracking).then_some(now_tracking);
        MenuTrackingTransition {
            tracking_changed,
            removed: evicted,
        }
    }

    pub fn menu_closed(&mut self, menu: &MenuHandle) -> MenuTrackingTransition<MenuHandle> {
        let was_tracking = !self.open_menus.is_empty();
        let Some(index) = self.open_menus.iter().position(|open| open == menu) else {
            return MenuTrackingTransition {
                tracking_changed: None,
                removed: Vec::new(),
            };
        };
        // Closing a menu invalidates any nested submenus stacked above it.
        let removed: Vec<MenuHandle> = self.open_menus.drain(index..).collect();
        if self.open_menus.is_empty()
            || self
                .highlighted
                .as_ref()
                .is_some_and(|current| removed.contains(&current.menu))
        {
            self.highlighted = None;
        }
        let now_tracking = !self.open_menus.is_empty();
        let tracking_changed = (was_tracking != now_tracking).then_some(now_tracking);
        MenuTrackingTransition {
            tracking_changed,
            removed,
        }
    }

    /// Prunes a stale menu handle (e.g., after UIA element invalidation).
    pub fn prune(&mut self, menu: &MenuHandle) -> MenuTrackingTransition<MenuHandle> {
        self.menu_closed(menu)
    }

    /// Retains only open menu handles matching `predicate`, clearing any highlighted selection
    /// belonging to a removed handle and emitting `tracking_changed` on state transition.
    pub fn retain_open_menus<F>(&mut self, mut predicate: F) -> MenuTrackingTransition<MenuHandle>
    where
        F: FnMut(&MenuHandle) -> bool,
    {
        let was_tracking = !self.open_menus.is_empty();
        let mut kept = Vec::with_capacity(self.open_menus.len());
        let mut removed = Vec::new();
        for handle in self.open_menus.drain(..) {
            if predicate(&handle) {
                kept.push(handle);
            } else {
                removed.push(handle);
            }
        }
        self.open_menus = kept;
        if self.open_menus.is_empty()
            || self
                .highlighted
                .as_ref()
                .is_some_and(|current| removed.contains(&current.menu))
        {
            self.highlighted = None;
        }
        let now_tracking = !self.open_menus.is_empty();
        let tracking_changed = (was_tracking != now_tracking).then_some(now_tracking);
        MenuTrackingTransition {
            tracking_changed,
            removed,
        }
    }

    /// Updates or clears the single volatile highlighted selection for an open menu.
    pub fn update_selection(
        &mut self,
        selection: Option<Selection>,
        from: MenuHandle,
        now_ms: i64,
    ) {
        let Some(selection) = selection else {
            self.highlighted = None;
            return;
        };
        if !self.open_menus.contains(&from) {
            return;
        }
        self.highlighted = Some(HighlightedSelection {
            menu: from,
            selection,
            updated_at_ms: now_ms,
        });
    }

    /// Clears the highlighted selection (Escape, empty selection, submenu hover, or failed gate).
    pub fn cancel(&mut self) {
        self.highlighted = None;
    }

    /// Resets the open menu stack and highlight on boundary, Secure Input, or teardown.
    pub fn reset(&mut self) -> MenuTrackingTransition<MenuHandle> {
        let was_tracking = !self.open_menus.is_empty();
        let removed = std::mem::take(&mut self.open_menus);
        self.highlighted = None;
        MenuTrackingTransition {
            tracking_changed: was_tracking.then_some(false),
            removed,
        }
    }

    /// Consumes the volatile highlighted selection at most once if a menu is open and the
    /// highlight is within `max_selection_age_ms`.
    pub fn commit(&mut self, now_ms: i64) -> Option<Selection> {
        if self.open_menus.is_empty() {
            return None;
        }
        let current = self.highlighted.take()?;
        if now_ms
            .checked_sub(current.updated_at_ms)
            .is_none_or(|age| age < 0 || age > self.max_selection_age_ms)
        {
            return None;
        }
        Some(current.selection)
    }
}

/// 250ms path deduplicator preventing double-emission when both native `UIA_Invoke_InvokedEventId`
/// and Win32 `#32768` fallback commit fire for the same committed menu action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MenuActionDeduplicator {
    window_ms: i64,
    last_emitted: Option<(Vec<String>, i64)>,
}

impl Default for MenuActionDeduplicator {
    fn default() -> Self {
        Self::new()
    }
}

impl MenuActionDeduplicator {
    pub const fn new() -> Self {
        Self {
            window_ms: MenuPathLimits::DEDUP_WINDOW_MS,
            last_emitted: None,
        }
    }

    pub fn with_window_ms(window_ms: i64) -> Self {
        Self {
            window_ms: window_ms.max(0),
            last_emitted: None,
        }
    }

    pub fn reset(&mut self) {
        self.last_emitted = None;
    }

    /// Returns `true` if `path` at `now_ms` should be emitted (recording it as latest), or `false`
    /// if the identical `path` was already emitted within `window_ms` (inclusive) or if elapsed
    /// time is negative / overflows (fail closed).
    pub fn should_emit(&mut self, path: &[String], now_ms: i64) -> bool {
        if let Some((ref prev_path, prev_ms)) = self.last_emitted {
            if prev_path.as_slice() == path {
                let suppress = match now_ms.checked_sub(prev_ms) {
                    Some(elapsed) => elapsed <= self.window_ms,
                    None => true,
                };
                if suppress {
                    return false;
                }
            }
        }
        self.last_emitted = Some((path.to_vec(), now_ms));
        true
    }
}

/// Bounded FIFO queue holding up to `MAX_PENDING_RECORDS = 8` valid `MenuActionRecord`s.
/// Evicts the oldest record when full (matching macOS `Session.swift`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MenuActionPendingQueue {
    capacity: usize,
    queue: VecDeque<MenuActionRecord>,
}

impl Default for MenuActionPendingQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl MenuActionPendingQueue {
    pub fn new() -> Self {
        Self::with_capacity(MenuPathLimits::MAX_PENDING_RECORDS)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        let cap = capacity.clamp(1, MenuPathLimits::MAX_PENDING_RECORDS);
        Self {
            capacity: cap,
            queue: VecDeque::with_capacity(cap),
        }
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    pub fn clear(&mut self) {
        self.queue.clear();
    }

    /// Enqueues a valid `MenuActionRecord`, evicting the oldest if at capacity.
    /// Returns `false` and ignores the record if `!record.is_valid()`.
    pub fn push(&mut self, record: MenuActionRecord) -> bool {
        if !record.is_valid() {
            return false;
        }
        if self.queue.len() >= self.capacity {
            self.queue.pop_front();
        }
        self.queue.push_back(record);
        true
    }

    pub fn pop_next(&mut self) -> Option<MenuActionRecord> {
        self.queue.pop_front()
    }
}

/// Platform-free 3-state fail-closed verdict for native browser chrome inspection.
/// Mirrors `uia_com::PrivateChromeVerdict` without coupling `menu_action_core` to Win32/COM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserChromeVerdict {
    Private,
    VerifiedNormal,
    Inconclusive,
}

/// Typed window handle lookup for fail-closed browser pre-read checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserWindowReference<Handle> {
    Window(Handle),
    Absent,
    Failure,
}

/// Typed window count read distinguishing positive zero windows from UIA/Win32 lookup failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserWindowCountRead {
    Count(usize),
    Failure,
}

/// Typed browser window metadata snapshot used to verify non-private `AXWindow` state and
/// `BrowserChromeVerdict::VerifiedNormal` chrome inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserWindowInspection {
    Inspected {
        role: Option<String>,
        has_sensitive_evidence: bool,
        safe_title: Option<String>,
        chrome_verdict: BrowserChromeVerdict,
    },
    Failure,
}

/// Fail-closed pre-read privacy gate for browsers (known, MSIX dual-ID, and unlisted http/https
/// candidates) before reading any menu titles or starting menu tracking.
pub struct BrowserMenuWindowGate;

impl BrowserMenuWindowGate {
    #[allow(clippy::too_many_arguments)]
    pub fn allows_menu_read<Handle, Same, Focused, Main, Count, Inspect>(
        identity: &ResolvedAppIdentity,
        is_browser_candidate: bool,
        spec: &AppAdapterSpec,
        policy: &CapturePolicy,
        same: Same,
        focused_window: Focused,
        main_window: Main,
        window_count: Count,
        mut inspect_window: Inspect,
    ) -> bool
    where
        Same: Fn(&Handle, &Handle) -> bool,
        Focused: FnOnce() -> BrowserWindowReference<Handle>,
        Main: FnOnce() -> BrowserWindowReference<Handle>,
        Count: FnOnce() -> BrowserWindowCountRead,
        Inspect: FnMut(&Handle) -> BrowserWindowInspection,
    {
        let is_browser = is_browser_candidate
            || BrowserGate::should_block_private_windows_identity(
                identity,
                spec.block_private_windows,
            );
        if !is_browser {
            return true;
        }
        if !policy.enabled
            || ApplicationPolicy::is_mandatory_denied_identity(identity)
            || policy.application_scope.as_deref() != Some("denylist")
            || policy.allow_browser_content != Some(true)
        {
            return false;
        }

        let mut window_safe = |handle: &Handle| -> bool {
            match inspect_window(handle) {
                BrowserWindowInspection::Failure => false,
                BrowserWindowInspection::Inspected {
                    role,
                    has_sensitive_evidence,
                    safe_title,
                    chrome_verdict,
                } => {
                    if role.as_deref() != Some("AXWindow")
                        || has_sensitive_evidence
                        || chrome_verdict != BrowserChromeVerdict::VerifiedNormal
                    {
                        return false;
                    }
                    let Some(title) = safe_title else {
                        return false;
                    };
                    !BrowserGate::is_private_window_title(&title)
                }
            }
        };

        let focused_handle = match focused_window() {
            BrowserWindowReference::Failure => return false,
            BrowserWindowReference::Absent => None,
            BrowserWindowReference::Window(win) => {
                if !window_safe(&win) {
                    return false;
                }
                Some(win)
            }
        };

        let main_handle = match main_window() {
            BrowserWindowReference::Failure => return false,
            BrowserWindowReference::Absent => None,
            BrowserWindowReference::Window(win) => {
                if focused_handle.as_ref().is_some_and(|f| same(f, &win)) {
                    Some(win)
                } else {
                    if !window_safe(&win) {
                        return false;
                    }
                    Some(win)
                }
            }
        };

        if focused_handle.is_some() || main_handle.is_some() {
            return true;
        }
        // Require positive proof of zero windows so transient absent focus/main during modal
        // menu tracking cannot fail open over an Incognito/InPrivate window.
        window_count() == BrowserWindowCountRead::Count(0)
    }

    /// Single-foreground-window convenience helper for Windows callers with one top-level HWND.
    pub fn allows_foreground_window<Inspect>(
        identity: &ResolvedAppIdentity,
        is_browser_candidate: bool,
        spec: &AppAdapterSpec,
        policy: &CapturePolicy,
        inspect_foreground: Inspect,
    ) -> bool
    where
        Inspect: FnOnce() -> BrowserWindowInspection,
    {
        let mut inspect_opt = Some(inspect_foreground);
        Self::allows_menu_read(
            identity,
            is_browser_candidate,
            spec,
            policy,
            |a: &u8, b: &u8| a == b,
            || BrowserWindowReference::Window(0u8),
            || BrowserWindowReference::Window(0u8),
            || BrowserWindowCountRead::Count(1),
            |_| {
                inspect_opt
                    .take()
                    .map(|f| f())
                    .unwrap_or(BrowserWindowInspection::Failure)
            },
        )
    }
}
