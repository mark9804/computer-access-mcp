//! Bounded weighted surface tree traversal, focus-anchor path planning,
//! pane-header band prioritization, and stable `RuntimeId`-keyed node UUID mapping.

use std::collections::{HashMap, HashSet};
use std::hash::Hash;

use crate::policy::is_private_use_only_text;
use crate::protocol_model::{generate_uuid_v4, SurfaceBounds, SurfaceGeometry, SurfaceNode};

/// Exploration reason codes for bounded surface tree traversal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WeightedSurfaceTraversalReason {
    WorkBudget,
    ProbeBudget,
    PendingBudget,
    OutputBudget,
    DepthBudget,
    TimeBudget,
    ProviderRefused,
    InvalidChildCount,
    InconsistentChildren,
    RepeatedNode,
    UnsupportedRole,
    SecurityPruned,
    AnchorParentUnconfirmed,
}

impl WeightedSurfaceTraversalReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WorkBudget => "weighted-work-budget",
            Self::ProbeBudget => "tree-probe-budget",
            Self::PendingBudget => "tree-pending-budget",
            Self::OutputBudget => "tree-output-budget",
            Self::DepthBudget => "tree-depth-budget",
            Self::TimeBudget => "tree-time-budget",
            Self::ProviderRefused => "tree-provider-refused",
            Self::InvalidChildCount => "tree-child-count-invalid",
            Self::InconsistentChildren => "tree-children-inconsistent",
            Self::RepeatedNode => "tree-cycle-or-shared-node",
            Self::UnsupportedRole => "tree-role-unsupported",
            Self::SecurityPruned => "tree-security-pruned",
            Self::AnchorParentUnconfirmed => "tree-anchor-parent-unconfirmed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WeightedSurfaceRolePolicy {
    Text,
    Wrapper,
    Semantic,
    Composite,
}

impl WeightedSurfaceRolePolicy {
    pub fn reads_text(self) -> bool {
        self == Self::Text
    }

    pub fn inspection_cost(self, child_count: usize) -> usize {
        match self {
            Self::Text => 2,
            Self::Wrapper => {
                if child_count <= 1 {
                    1
                } else {
                    3
                }
            }
            Self::Semantic => {
                if child_count <= 1 {
                    2
                } else {
                    3
                }
            }
            Self::Composite => 4,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct WeightedSurfaceMetadata {
    pub ax_role: Option<String>,
    pub category: &'static str,
    pub subrole: Option<String>,
    pub child_count: usize,
    pub is_focused: bool,
    pub observed_at_ms: i64,
    pub is_enabled: Option<bool>,
    pub display_text: Option<String>,
    pub bounds: Option<SurfaceBounds>,
    pub bounds_observed_at_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum WeightedSurfaceInspection {
    Allowed(WeightedSurfaceMetadata),
    Pruned(WeightedSurfaceTraversalReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WeightedSurfaceChildrenRead<H> {
    Values(Vec<H>),
    /// Returned when a provider lazily enumerates a container's children on its first expansion
    /// (`offset == 0`) and resolves a different exact total count than the initial `inspect` hint.
    ResolvedCount(usize),
    Unavailable(WeightedSurfaceTraversalReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeightedSurfaceTextRead {
    pub text: Option<String>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WeightedSurfaceTraversalLimits {
    pub max_output_nodes: usize,
    pub max_work: usize,
    pub max_probes: usize,
    pub max_pending: usize,
    pub max_depth: usize,
    pub page_size: usize,
    pub max_priority_burst: usize,
}

impl WeightedSurfaceTraversalLimits {
    pub fn new(
        max_output_nodes: usize,
        max_work: Option<usize>,
        max_probes: Option<usize>,
        max_pending: usize,
        max_depth: usize,
        page_size: usize,
        max_priority_burst: usize,
    ) -> Self {
        let output = max_output_nodes.min(96);
        Self {
            max_output_nodes: output,
            max_work: max_work.unwrap_or(output.saturating_mul(8)).min(384),
            max_probes: max_probes.unwrap_or(output.saturating_mul(6)).min(384),
            max_pending: max_pending.min(192),
            max_depth: max_depth.min(64),
            page_size: page_size.clamp(1, 64),
            max_priority_burst: max_priority_burst.clamp(1, 4),
        }
    }
}

impl Default for WeightedSurfaceTraversalLimits {
    fn default() -> Self {
        Self::new(48, None, None, 192, 64, 4, 4)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct WeightedSurfaceSample<H> {
    pub handle: H,
    pub parent: Option<H>,
    pub metadata: WeightedSurfaceMetadata,
    pub text_read: Option<WeightedSurfaceTextRead>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WeightedSurfaceTraversalCounters {
    pub work: usize,
    pub probes: usize,
    pub text_reads: usize,
    pub child_pages: usize,
    pub peak_pending: usize,
    pub sampled_nodes: usize,
    pub max_depth: usize,
    pub max_fanout: usize,
    pub inspected_children: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct WeightedSurfaceTraversalResult<H> {
    pub nodes: Vec<WeightedSurfaceSample<H>>,
    pub reasons: Vec<WeightedSurfaceTraversalReason>,
    pub complete: bool,
    pub counters: WeightedSurfaceTraversalCounters,
}

pub struct SurfaceTextCoverage;

impl SurfaceTextCoverage {
    pub fn priority(
        depth: usize,
        context: bool,
        composite_ancestors: usize,
        fallback: i32,
    ) -> i32 {
        if !context {
            return fallback;
        }
        8_000 + (depth.min(64) as i32) * 30 + fallback / 10
            - (composite_ancestors.min(64) as i32) * 500
    }

    pub fn output_rank(value: Option<&str>, focused: bool, header: bool) -> u8 {
        if focused {
            return 0;
        }
        if let Some(text) = value {
            if text.chars().any(|c| !c.is_whitespace()) {
                return if header { 1 } else { 2 };
            }
            return 3;
        }
        4
    }
}

/// Alternates child pages from tail and head so recent bottom content (chat/editor) is not starved.
#[derive(Debug, Clone, Copy)]
pub struct SurfaceChildFrontier {
    lower: usize,
    upper: usize,
    tail: bool,
}

impl SurfaceChildFrontier {
    pub fn new(count: usize, head_first: bool) -> Self {
        Self {
            lower: 0,
            upper: count.min(1_000_000),
            tail: !head_first,
        }
    }

    pub fn remaining(&self) -> usize {
        self.upper.saturating_sub(self.lower)
    }

    pub fn next(&mut self, max_count: usize) -> Option<(usize, usize, bool)> {
        let count = self.remaining().min(max_count.min(64));
        if count == 0 {
            return None;
        }
        let reverse = self.tail;
        let offset = if self.tail {
            self.upper -= count;
            self.upper
        } else {
            let cur = self.lower;
            self.lower += count;
            cur
        };
        self.tail = !self.tail;
        Some((offset, count, reverse))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SurfaceFocusPathReason {
    Budget,
    Cycle,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SurfaceFocusAnchor<H> {
    pub handle: H,
    pub metadata: WeightedSurfaceMetadata,
}

/// Verified ancestor chain from root to focused element for traversal prioritization.
#[derive(Debug, Clone, PartialEq)]
pub struct SurfaceFocusAnchorPlan<H> {
    pub nodes: Vec<SurfaceFocusAnchor<H>>,
    pub root: H,
    pub focus: H,
    pub work: usize,
    pub probes: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SurfaceFocusAnchorResult<H> {
    pub plan: Option<SurfaceFocusAnchorPlan<H>>,
    pub work: usize,
    pub probes: usize,
    pub reason: Option<SurfaceFocusPathReason>,
}

pub struct SurfaceFocusAnchors;

impl SurfaceFocusAnchors {
    pub const MAXIMUM_HOPS: usize = 48;
    pub const MAXIMUM_WORK: usize = 160;
    pub const MAXIMUM_PROBES: usize = 48;

    #[allow(clippy::too_many_arguments)]
    pub fn collect<H, Inspect, Parent, Cont>(
        root: H,
        focus: H,
        max_hops: usize,
        max_work: usize,
        max_probes: usize,
        mut inspect: Inspect,
        mut parent: Parent,
        mut should_continue: Cont,
    ) -> SurfaceFocusAnchorResult<H>
    where
        H: Clone + Eq + Hash,
        Inspect: FnMut(&H) -> WeightedSurfaceInspection,
        Parent: FnMut(&H) -> Option<H>,
        Cont: FnMut() -> bool,
    {
        let hop_cap = max_hops.min(Self::MAXIMUM_HOPS);
        let work_cap = max_work.min(Self::MAXIMUM_WORK);
        let probe_cap = max_probes.min(Self::MAXIMUM_PROBES);
        let mut work = 0usize;
        let mut probes = 0usize;
        let mut reversed: Vec<SurfaceFocusAnchor<H>> = Vec::new();
        let mut seen: HashSet<H> = HashSet::new();
        let mut current = focus.clone();

        let failed = |reason: SurfaceFocusPathReason, work: usize, probes: usize| {
            SurfaceFocusAnchorResult {
                plan: None,
                work,
                probes,
                reason: Some(reason),
            }
        };

        while reversed.len() < hop_cap {
            if work >= work_cap || probes >= probe_cap || !should_continue() {
                return failed(SurfaceFocusPathReason::Budget, work, probes);
            }
            if !seen.insert(current.clone()) {
                return failed(SurfaceFocusPathReason::Cycle, work, probes);
            }
            work += 1;
            probes += 1;
            let inspection = inspect(&current);
            if !should_continue() {
                return failed(SurfaceFocusPathReason::Budget, work, probes);
            }
            let metadata = match inspection {
                WeightedSurfaceInspection::Allowed(m) => m,
                WeightedSurfaceInspection::Pruned(_) => {
                    return failed(SurfaceFocusPathReason::Unavailable, work, probes);
                }
            };
            if metadata.child_count > 1_000_000 {
                return failed(SurfaceFocusPathReason::Unavailable, work, probes);
            }
            let Some(policy) = metadata
                .ax_role
                .as_deref()
                .and_then(WeightedSurfaceTraversal::role_policy)
            else {
                return failed(SurfaceFocusPathReason::Unavailable, work, probes);
            };
            if !reversed.is_empty() && policy.reads_text() {
                return failed(SurfaceFocusPathReason::Unavailable, work, probes);
            }
            let remaining_cost = policy.inspection_cost(metadata.child_count).saturating_sub(1);
            if remaining_cost > work_cap.saturating_sub(work) {
                return failed(SurfaceFocusPathReason::Budget, work, probes);
            }
            work += remaining_cost;
            reversed.push(SurfaceFocusAnchor {
                handle: current.clone(),
                metadata,
            });
            if current == root {
                reversed.reverse();
                let plan = SurfaceFocusAnchorPlan {
                    nodes: reversed,
                    root,
                    focus,
                    work,
                    probes,
                };
                return SurfaceFocusAnchorResult {
                    plan: Some(plan),
                    work,
                    probes,
                    reason: None,
                };
            }
            if reversed.len() >= hop_cap || work >= work_cap || !should_continue() {
                return failed(SurfaceFocusPathReason::Budget, work, probes);
            }
            work += 1;
            let next = parent(&current);
            if !should_continue() {
                return failed(SurfaceFocusPathReason::Budget, work, probes);
            }
            let Some(next_handle) = next else {
                return failed(SurfaceFocusPathReason::Unavailable, work, probes);
            };
            current = next_handle;
        }
        failed(SurfaceFocusPathReason::Budget, work, probes)
    }
}

#[derive(Debug, Clone)]
enum WeightedSurfaceWork<H> {
    Inspect {
        handle: H,
        parent: Option<H>,
        depth: usize,
        header_candidate: bool,
    },
    Text(usize),
    Children {
        index: usize,
        offset: usize,
    },
}

#[derive(Debug, Clone)]
struct WeightedSurfaceJob<H> {
    work: WeightedSurfaceWork<H>,
    priority: i32,
}

#[derive(Debug, Clone, Copy)]
struct PaneHeaderBand {
    parent_index: usize,
    min_y: f64,
    max_y: f64,
    max_depth: usize,
    max_probes: usize,
    max_text_hits: usize,
    probes_used: usize,
    text_hits: usize,
}

impl PaneHeaderBand {
    fn contains(&self, bounds: Option<SurfaceBounds>) -> bool {
        let Some(b) = bounds else {
            return false;
        };
        b.width > 0.0 && b.height > 0.0 && b.y >= self.min_y && (b.y + b.height) <= self.max_y
    }

    fn active(&self) -> bool {
        self.probes_used < self.max_probes && self.text_hits < self.max_text_hits
    }
}

struct WeightedSurfaceObservation<H> {
    handle: H,
    parent: Option<H>,
    metadata: WeightedSurfaceMetadata,
    depth: usize,
    focus_context: usize,
    composite_ancestors: usize,
    in_header_band: bool,
    text_read: Option<WeightedSurfaceTextRead>,
}

pub struct WeightedSurfaceTraversal;

impl WeightedSurfaceTraversal {
    pub fn role_policy(role: &str) -> Option<WeightedSurfaceRolePolicy> {
        match role {
            "AXTextField" | "AXTextArea" | "AXStaticText" => Some(WeightedSurfaceRolePolicy::Text),
            "AXWindow" | "AXGroup" | "AXScrollArea" | "AXSplitGroup" | "AXSheet"
            | "AXLayoutArea" => Some(WeightedSurfaceRolePolicy::Wrapper),
            "AXWebArea" | "AXDocument" | "AXList" | "AXTable" | "AXColumn" | "AXRow"
            | "AXCell" | "AXOutline" | "AXHeading" => Some(WeightedSurfaceRolePolicy::Semantic),
            "AXButton" | "AXToolbar" | "AXPopUpButton" | "AXComboBox" | "AXCheckBox"
            | "AXLink" | "AXTabGroup" | "AXTabButton" | "AXRadioGroup" | "AXRadioButton" => {
                Some(WeightedSurfaceRolePolicy::Composite)
            }
            _ => None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn run<H, Inspect, Children, ReadText, Cont, ContAfter>(
        root: H,
        limits: WeightedSurfaceTraversalLimits,
        preferred_roles: &HashSet<&str>,
        ignored_roles: &HashSet<&str>,
        ignored_subroles: &HashSet<&str>,
        collapse_empty_containers: bool,
        preparation_work: usize,
        preparation_probes: usize,
        focus_anchors: Option<&SurfaceFocusAnchorPlan<H>>,
        mut inspect: Inspect,
        mut children: Children,
        mut read_text: ReadText,
        mut should_continue: Cont,
        mut should_continue_after_work: ContAfter,
    ) -> WeightedSurfaceTraversalResult<H>
    where
        H: Clone + Eq + Hash,
        Inspect: FnMut(&H) -> WeightedSurfaceInspection,
        Children: FnMut(&H, usize, usize) -> WeightedSurfaceChildrenRead<H>,
        ReadText: FnMut(&H) -> Option<WeightedSurfaceTextRead>,
        Cont: FnMut() -> bool,
        ContAfter: FnMut() -> bool,
    {
        let mut reasons: Vec<WeightedSurfaceTraversalReason> = Vec::new();
        let mut counters = WeightedSurfaceTraversalCounters::default();
        let mut queue: Vec<WeightedSurfaceJob<H>> = Vec::new();
        let mut discovered: HashSet<H> = HashSet::new();
        let mut observations: Vec<WeightedSurfaceObservation<H>> = Vec::new();
        let mut priority_burst = 0usize;
        let mut observations_by_handle: HashMap<H, usize> = HashMap::new();
        let mut seeded: HashSet<H> = HashSet::new();
        let mut confirmed_seed_parents: HashSet<H> = HashSet::new();
        let mut composite_depth: HashMap<H, usize> = HashMap::new();
        let mut contexts: HashMap<H, usize> = HashMap::new();
        let mut frontiers: HashMap<usize, SurfaceChildFrontier> = HashMap::new();
        let mut header_band: Option<PaneHeaderBand> = None;

        let anchors = focus_anchors.filter(|plan| {
            plan.root == root
                && plan.nodes.first().map(|n| &n.handle) == Some(&root)
                && plan.nodes.last().map(|n| &n.handle) == Some(&plan.focus)
                && plan.nodes.len() <= limits.max_depth + 1
                && plan.nodes.len() <= limits.max_pending
                && plan.work <= limits.max_work
                && plan.probes <= limits.max_probes
                && plan.work == preparation_work
                && plan.probes == preparation_probes
        });
        let content_first = anchors.is_some();
        counters.work = preparation_work.min(limits.max_work);
        counters.probes = preparation_probes.min(limits.max_probes);

        let note = |reasons: &mut Vec<WeightedSurfaceTraversalReason>,
                    reason: WeightedSurfaceTraversalReason| {
            if !reasons.contains(&reason) {
                reasons.push(reason);
            }
        };

        let spend = |cost: usize,
                     counters: &mut WeightedSurfaceTraversalCounters,
                     reasons: &mut Vec<WeightedSurfaceTraversalReason>|
         -> bool {
            if cost > limits.max_work.saturating_sub(counters.work) {
                note(reasons, WeightedSurfaceTraversalReason::WorkBudget);
                return false;
            }
            counters.work += cost;
            true
        };

        let enqueue = |work: WeightedSurfaceWork<H>,
                       priority: i32,
                       queue: &mut Vec<WeightedSurfaceJob<H>>,
                       counters: &mut WeightedSurfaceTraversalCounters,
                       reasons: &mut Vec<WeightedSurfaceTraversalReason>|
         -> bool {
            if queue.len() >= limits.max_pending {
                note(reasons, WeightedSurfaceTraversalReason::PendingBudget);
                return false;
            }
            queue.push(WeightedSurfaceJob { work, priority });
            counters.peak_pending = counters.peak_pending.max(queue.len());
            true
        };

        let role_boost = |role: Option<&str>| -> i32 {
            if role.is_some_and(|r| preferred_roles.contains(r)) {
                40
            } else {
                0
            }
        };

        let page_priority = |metadata: &WeightedSurfaceMetadata| -> i32 {
            let base = if metadata.is_focused {
                70
            } else if metadata.child_count == 1 {
                60
            } else {
                30
            };
            base + role_boost(metadata.ax_role.as_deref())
        };

        let context_priority = |context: usize, fallback: i32| -> i32 {
            if context > 0 {
                80 + (fallback / 3).min(20)
            } else {
                fallback
            }
        };

        let child_page_priority =
            |observation: &WeightedSurfaceObservation<H>, continuation: bool| -> i32 {
                let fallback = (if continuation {
                    20
                } else {
                    page_priority(&observation.metadata)
                }) + role_boost(observation.metadata.ax_role.as_deref());
                if content_first {
                    let is_composite = observation
                        .metadata
                        .ax_role
                        .as_deref()
                        .and_then(Self::role_policy)
                        == Some(WeightedSurfaceRolePolicy::Composite);
                    SurfaceTextCoverage::priority(
                        observation.depth,
                        observation.focus_context > 0,
                        observation.composite_ancestors + usize::from(is_composite),
                        fallback,
                    )
                } else {
                    context_priority(observation.focus_context, fallback)
                }
            };

        if preparation_work > limits.max_work {
            note(&mut reasons, WeightedSurfaceTraversalReason::WorkBudget);
        }
        if preparation_probes > limits.max_probes {
            note(&mut reasons, WeightedSurfaceTraversalReason::ProbeBudget);
        }

        if limits.max_output_nodes == 0 {
            note(&mut reasons, WeightedSurfaceTraversalReason::OutputBudget);
        } else if let Some(plan) = anchors {
            for (depth, anchor) in plan.nodes.iter().enumerate() {
                let index = observations.len();
                observations.push(WeightedSurfaceObservation {
                    handle: anchor.handle.clone(),
                    parent: None,
                    metadata: anchor.metadata.clone(),
                    depth,
                    focus_context: plan.nodes.len(),
                    composite_ancestors: 0,
                    in_header_band: false,
                    text_read: None,
                });
                observations_by_handle.insert(anchor.handle.clone(), index);
                seeded.insert(anchor.handle.clone());
                discovered.insert(anchor.handle.clone());
                counters.max_depth = counters.max_depth.max(depth);
                counters.max_fanout = counters.max_fanout.max(anchor.metadata.child_count);
                counters.inspected_children += anchor.metadata.child_count;
            }

            // Detect the closest enclosing pane header band above the main content container
            // using DPI-normalized logical points (24..=120 pt header above >= 200 pt pane).
            if observations.len() >= 2 {
                for child_index in (1..observations.len()).rev() {
                    let parent_index = child_index - 1;
                    let parent = &observations[parent_index];
                    let child = &observations[child_index];
                    if parent.metadata.child_count < 2 {
                        continue;
                    }
                    let (Some(parent_bounds), Some(child_bounds)) =
                        (parent.metadata.bounds, child.metadata.bounds)
                    else {
                        continue;
                    };
                    if child_bounds.height < 200.0 {
                        continue;
                    }
                    let header_height = child_bounds.y - parent_bounds.y;
                    if (24.0..=120.0).contains(&header_height) {
                        header_band = Some(PaneHeaderBand {
                            parent_index,
                            min_y: parent_bounds.y - 4.0,
                            max_y: child_bounds.y + 8.0,
                            max_depth: parent.depth + 6,
                            max_probes: 12,
                            max_text_hits: 2,
                            probes_used: 0,
                            text_hits: 0,
                        });
                        break;
                    }
                }
            }

            counters.sampled_nodes = observations.len();
            for index in (0..observations.len()).rev() {
                let obs = &observations[index];
                let reads_text = obs
                    .metadata
                    .ax_role
                    .as_deref()
                    .and_then(Self::role_policy)
                    .is_some_and(WeightedSurfaceRolePolicy::reads_text);
                if reads_text {
                    let prio = if obs.metadata.is_focused {
                        13_000
                    } else {
                        12_000
                    };
                    let _ = enqueue(
                        WeightedSurfaceWork::Text(index),
                        prio,
                        &mut queue,
                        &mut counters,
                        &mut reasons,
                    );
                    if obs.metadata.child_count > 0 {
                        note(
                            &mut reasons,
                            WeightedSurfaceTraversalReason::InconsistentChildren,
                        );
                    }
                } else if obs.metadata.child_count > 0 {
                    if obs.depth == limits.max_depth {
                        note(&mut reasons, WeightedSurfaceTraversalReason::DepthBudget);
                    } else {
                        let prio = if header_band.is_some_and(|b| b.parent_index == index) {
                            11_600
                        } else {
                            child_page_priority(obs, false)
                        };
                        let _ = enqueue(
                            WeightedSurfaceWork::Children { index, offset: 0 },
                            prio,
                            &mut queue,
                            &mut counters,
                            &mut reasons,
                        );
                    }
                }
            }
        } else if enqueue(
            WeightedSurfaceWork::Inspect {
                handle: root.clone(),
                parent: None,
                depth: 0,
                header_candidate: false,
            },
            30,
            &mut queue,
            &mut counters,
            &mut reasons,
        ) {
            discovered.insert(root);
        }

        let effective_priority =
            |job: &WeightedSurfaceJob<H>, band: Option<PaneHeaderBand>| -> i32 {
                if let WeightedSurfaceWork::Inspect {
                    depth,
                    header_candidate: true,
                    ..
                } = &job.work
                {
                    if !band.is_some_and(|b| b.active()) {
                        return 8_000 + ((*depth).min(64) as i32) * 30;
                    }
                }
                job.priority
            };

        while !queue.is_empty() {
            if !should_continue() {
                note(&mut reasons, WeightedSurfaceTraversalReason::TimeBudget);
                break;
            }
            let mut selected = 0usize;
            if priority_burst < limits.max_priority_burst {
                let mut selected_priority = effective_priority(&queue[0], header_band);
                for (index, item) in queue.iter().enumerate().skip(1) {
                    let cand_priority = effective_priority(item, header_band);
                    if cand_priority > selected_priority {
                        selected = index;
                        selected_priority = cand_priority;
                    }
                }
            }
            priority_burst = if selected == 0 { 0 } else { priority_burst + 1 };
            let job = queue.remove(selected);

            match job.work {
                WeightedSurfaceWork::Inspect {
                    handle,
                    parent,
                    depth,
                    header_candidate,
                } => {
                    if depth > limits.max_depth {
                        note(&mut reasons, WeightedSurfaceTraversalReason::DepthBudget);
                        continue;
                    }
                    if counters.probes >= limits.max_probes {
                        note(&mut reasons, WeightedSurfaceTraversalReason::ProbeBudget);
                        continue;
                    }
                    if !spend(1, &mut counters, &mut reasons) {
                        continue;
                    }
                    counters.probes += 1;
                    let inspection = inspect(&handle);
                    if !should_continue_after_work() {
                        note(&mut reasons, WeightedSurfaceTraversalReason::TimeBudget);
                        continue;
                    }
                    let metadata = match inspection {
                        WeightedSurfaceInspection::Pruned(reason) => {
                            note(&mut reasons, reason);
                            continue;
                        }
                        WeightedSurfaceInspection::Allowed(m) => m,
                    };

                    let inside_header = if header_candidate {
                        if let Some(ref mut band) = header_band {
                            if band.active()
                                && depth <= band.max_depth
                                && metadata.ax_role.as_deref() != Some("AXToolbar")
                                && band.contains(metadata.bounds)
                            {
                                band.probes_used += 1;
                                true
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    } else {
                        false
                    };

                    if depth > 0
                        && !metadata.is_focused
                        && (metadata
                            .ax_role
                            .as_deref()
                            .is_some_and(|r| ignored_roles.contains(r))
                            || metadata
                                .subrole
                                .as_deref()
                                .is_some_and(|s| ignored_subroles.contains(s)))
                    {
                        note(&mut reasons, WeightedSurfaceTraversalReason::UnsupportedRole);
                        continue;
                    }

                    let Some(policy) = metadata
                        .ax_role
                        .as_deref()
                        .and_then(Self::role_policy)
                    else {
                        note(&mut reasons, WeightedSurfaceTraversalReason::UnsupportedRole);
                        continue;
                    };

                    if metadata.child_count > 1_000_000 {
                        note(
                            &mut reasons,
                            WeightedSurfaceTraversalReason::InvalidChildCount,
                        );
                        continue;
                    }

                    if depth > 0
                        && !metadata.is_focused
                        && metadata.is_enabled == Some(false)
                        && metadata.child_count == 0
                        && !policy.reads_text()
                        && metadata
                            .display_text
                            .as_deref()
                            .is_none_or(str::is_empty)
                    {
                        continue;
                    }

                    let extra_cost = policy.inspection_cost(metadata.child_count).saturating_sub(1);
                    if !spend(extra_cost, &mut counters, &mut reasons) {
                        continue;
                    }

                    if inside_header {
                        if let Some(ref dt) = metadata.display_text {
                            if !is_private_use_only_text(dt)
                                && dt.chars().any(|c| !c.is_whitespace())
                            {
                                if let Some(ref mut band) = header_band {
                                    band.text_hits += 1;
                                }
                            }
                        }
                    }

                    let index = observations.len();
                    let child_count = metadata.child_count;
                    let is_focused = metadata.is_focused;
                    let role_boost_val = role_boost(metadata.ax_role.as_deref());
                    observations.push(WeightedSurfaceObservation {
                        handle: handle.clone(),
                        parent,
                        metadata,
                        depth,
                        focus_context: contexts.get(&handle).copied().unwrap_or(0),
                        composite_ancestors: composite_depth.get(&handle).copied().unwrap_or(0),
                        in_header_band: inside_header,
                        text_read: None,
                    });
                    observations_by_handle.insert(handle, index);
                    counters.sampled_nodes = observations.len();
                    counters.max_depth = counters.max_depth.max(depth);
                    counters.max_fanout = counters.max_fanout.max(child_count);
                    counters.inspected_children += child_count;

                    if policy.reads_text() {
                        let text_prio = if inside_header {
                            12_500
                        } else if content_first {
                            (if is_focused { 13_000 } else { 12_000 }) + role_boost_val
                        } else {
                            (if is_focused { 130 } else { 120 }) + role_boost_val
                        };
                        let _ = enqueue(
                            WeightedSurfaceWork::Text(index),
                            text_prio,
                            &mut queue,
                            &mut counters,
                            &mut reasons,
                        );
                        if child_count > 0 {
                            note(
                                &mut reasons,
                                WeightedSurfaceTraversalReason::InconsistentChildren,
                            );
                        }
                    } else if child_count > 0 {
                        if depth == limits.max_depth {
                            note(&mut reasons, WeightedSurfaceTraversalReason::DepthBudget);
                        } else {
                            let children_prio = if inside_header
                                && header_band
                                    .is_some_and(|b| b.active() && depth < b.max_depth)
                            {
                                11_000 + (depth.min(48) as i32) * 10 + 5
                            } else {
                                child_page_priority(&observations[index], false)
                            };
                            let _ = enqueue(
                                WeightedSurfaceWork::Children { index, offset: 0 },
                                children_prio,
                                &mut queue,
                                &mut counters,
                                &mut reasons,
                            );
                        }
                    }
                }

                WeightedSurfaceWork::Text(index) => {
                    if !spend(2, &mut counters, &mut reasons) {
                        continue;
                    }
                    counters.text_reads += 1;
                    let value = read_text(&observations[index].handle);
                    if !should_continue_after_work() {
                        note(&mut reasons, WeightedSurfaceTraversalReason::TimeBudget);
                        continue;
                    }
                    let Some(val) = value else {
                        note(&mut reasons, WeightedSurfaceTraversalReason::ProviderRefused);
                        continue;
                    };
                    if val.text.is_none() {
                        note(&mut reasons, WeightedSurfaceTraversalReason::ProviderRefused);
                        continue;
                    }
                    if observations[index].in_header_band {
                        if let Some(ref rt) = val.text {
                            if !is_private_use_only_text(rt)
                                && rt.chars().any(|c| !c.is_whitespace())
                            {
                                if let Some(ref mut band) = header_band {
                                    band.text_hits += 1;
                                }
                            }
                        }
                    }
                    observations[index].text_read = Some(val);
                }

                WeightedSurfaceWork::Children { index, offset } => {
                    if counters.probes >= limits.max_probes {
                        note(&mut reasons, WeightedSurfaceTraversalReason::ProbeBudget);
                        continue;
                    }
                    let mut obs_child_count = observations[index].metadata.child_count;
                    let remaining = obs_child_count.saturating_sub(offset);
                    if remaining == 0 {
                        note(
                            &mut reasons,
                            WeightedSurfaceTraversalReason::InconsistentChildren,
                        );
                        continue;
                    }
                    let capacity = limits.max_pending.saturating_sub(queue.len());
                    if capacity == 0 {
                        note(&mut reasons, WeightedSurfaceTraversalReason::PendingBudget);
                        continue;
                    }
                    let slots = if capacity > 1 && remaining > 1 {
                        capacity - 1
                    } else {
                        capacity
                    };
                    let count = limits.page_size.min(remaining.min(slots));
                    let mut request_offset = offset;
                    let mut request_count = count;
                    let mut reverse_page = false;
                    let head_first_frontier = observations[index].in_header_band
                        || header_band.is_some_and(|b| b.parent_index == index);

                    if content_first {
                        let frontier = frontiers.entry(index).or_insert_with(|| {
                            SurfaceChildFrontier::new(obs_child_count, head_first_frontier)
                        });
                        let Some((off, cnt, rev)) = frontier.next(count) else {
                            note(
                                &mut reasons,
                                WeightedSurfaceTraversalReason::InconsistentChildren,
                            );
                            continue;
                        };
                        request_offset = off;
                        request_count = cnt;
                        reverse_page = rev;
                    }

                    if !spend(1, &mut counters, &mut reasons) {
                        continue;
                    }
                    counters.child_pages += 1;
                    let obs_handle = observations[index].handle.clone();
                    let mut page = children(&obs_handle, request_offset, request_count);
                    if !should_continue_after_work() {
                        note(&mut reasons, WeightedSurfaceTraversalReason::TimeBudget);
                        continue;
                    }
                    if let WeightedSurfaceChildrenRead::ResolvedCount(true_count) = page {
                        if offset != 0 {
                            note(
                                &mut reasons,
                                WeightedSurfaceTraversalReason::InconsistentChildren,
                            );
                            continue;
                        }
                        if true_count > 1_000_000 {
                            note(
                                &mut reasons,
                                WeightedSurfaceTraversalReason::InvalidChildCount,
                            );
                            continue;
                        }
                        counters.max_fanout = counters.max_fanout.max(true_count);
                        counters.inspected_children = counters
                            .inspected_children
                            .saturating_sub(obs_child_count)
                            .saturating_add(true_count);
                        observations[index].metadata.child_count = true_count;
                        obs_child_count = true_count;
                        frontiers.remove(&index);
                        if true_count == 0 {
                            continue;
                        }
                        let new_slots = if capacity > 1 && true_count > 1 {
                            capacity - 1
                        } else {
                            capacity
                        };
                        let new_count = limits.page_size.min(true_count.min(new_slots));
                        request_offset = 0;
                        request_count = new_count;
                        reverse_page = false;
                        if content_first {
                            let frontier = frontiers.entry(index).or_insert_with(|| {
                                SurfaceChildFrontier::new(true_count, head_first_frontier)
                            });
                            let Some((off, cnt, rev)) = frontier.next(new_count) else {
                                note(
                                    &mut reasons,
                                    WeightedSurfaceTraversalReason::InconsistentChildren,
                                );
                                continue;
                            };
                            request_offset = off;
                            request_count = cnt;
                            reverse_page = rev;
                        }
                        page = children(&obs_handle, request_offset, request_count);
                        if !should_continue_after_work() {
                            note(&mut reasons, WeightedSurfaceTraversalReason::TimeBudget);
                            continue;
                        }
                    }
                    let mut handles = match page {
                        WeightedSurfaceChildrenRead::Unavailable(reason) => {
                            note(&mut reasons, reason);
                            continue;
                        }
                        WeightedSurfaceChildrenRead::ResolvedCount(_) => {
                            note(
                                &mut reasons,
                                WeightedSurfaceTraversalReason::InconsistentChildren,
                            );
                            continue;
                        }
                        WeightedSurfaceChildrenRead::Values(vals) => vals,
                    };
                    if handles.len() > request_count {
                        note(
                            &mut reasons,
                            WeightedSurfaceTraversalReason::InconsistentChildren,
                        );
                        continue;
                    }
                    if handles.len() != request_count {
                        note(
                            &mut reasons,
                            WeightedSurfaceTraversalReason::InconsistentChildren,
                        );
                    }
                    let fetched_len = handles.len();
                    if reverse_page {
                        handles.reverse();
                    }

                    let obs_depth = observations[index].depth;
                    let obs_in_header = observations[index].in_header_band;
                    let obs_focus_context = observations[index].focus_context;
                    let obs_comp_anc = observations[index].composite_ancestors;
                    let obs_is_composite = observations[index]
                        .metadata
                        .ax_role
                        .as_deref()
                        .and_then(Self::role_policy)
                        == Some(WeightedSurfaceRolePolicy::Composite);
                    let obs_page_prio = page_priority(&observations[index].metadata);

                    let emit_header_candidate = if let Some(band) = header_band {
                        band.active()
                            && ((band.parent_index == index && offset == 0)
                                || (obs_in_header && obs_depth < band.max_depth))
                    } else {
                        false
                    };

                    for (child_pos, handle) in handles.into_iter().enumerate() {
                        if discovered.contains(&handle) {
                            if seeded.contains(&handle) {
                                if let (Some(&seeded_index), Some(plan)) =
                                    (observations_by_handle.get(&handle), anchors)
                                {
                                    if seeded_index > 0
                                        && plan.nodes[seeded_index - 1].handle == obs_handle
                                        && !confirmed_seed_parents.contains(&handle)
                                    {
                                        observations[seeded_index].parent =
                                            Some(obs_handle.clone());
                                        confirmed_seed_parents.insert(handle);
                                        continue;
                                    }
                                }
                            }
                            note(&mut reasons, WeightedSurfaceTraversalReason::RepeatedNode);
                            continue;
                        }

                        let comp = obs_comp_anc + usize::from(obs_is_composite);
                        let priority = if emit_header_candidate {
                            11_000 + ((obs_depth + 1).min(48) as i32) * 10
                                - (child_pos.min(9) as i32)
                        } else if content_first {
                            SurfaceTextCoverage::priority(
                                obs_depth + 1,
                                obs_focus_context > 0,
                                comp,
                                obs_page_prio,
                            )
                        } else {
                            context_priority(obs_focus_context, obs_page_prio)
                        };

                        if enqueue(
                            WeightedSurfaceWork::Inspect {
                                handle: handle.clone(),
                                parent: Some(obs_handle.clone()),
                                depth: obs_depth + 1,
                                header_candidate: emit_header_candidate,
                            },
                            priority,
                            &mut queue,
                            &mut counters,
                            &mut reasons,
                        ) {
                            discovered.insert(handle.clone());
                            contexts.insert(handle.clone(), obs_focus_context);
                            composite_depth.insert(handle, comp);
                        }
                    }

                    let next_offset = offset + fetched_len;
                    let has_remaining = if content_first {
                        frontiers.get(&index).is_some_and(|f| f.remaining() > 0)
                    } else {
                        next_offset < obs_child_count
                    };
                    if fetched_len == request_count && has_remaining {
                        let cont_prio = child_page_priority(&observations[index], true);
                        let _ = enqueue(
                            WeightedSurfaceWork::Children {
                                index,
                                offset: next_offset,
                            },
                            cont_prio,
                            &mut queue,
                            &mut counters,
                            &mut reasons,
                        );
                    }
                }
            }
        }

        if let Some(plan) = anchors {
            if plan
                .nodes
                .iter()
                .skip(1)
                .any(|n| !confirmed_seed_parents.contains(&n.handle))
            {
                note(
                    &mut reasons,
                    WeightedSurfaceTraversalReason::AnchorParentUnconfirmed,
                );
            }
        }

        let is_excluded_leaf = |obs: &WeightedSurfaceObservation<H>| -> bool {
            if obs.depth == 0 || obs.metadata.is_focused {
                return false;
            }
            if obs.metadata.ax_role.as_deref() == Some("AXStaticText") {
                if let Some(read_text) = obs.text_read.as_ref().and_then(|t| t.text.as_ref()) {
                    if is_private_use_only_text(read_text) {
                        return true;
                    }
                }
            }
            obs.metadata.is_enabled == Some(false)
                && obs.metadata.child_count == 0
                && obs
                    .text_read
                    .as_ref()
                    .and_then(|t| t.text.as_deref())
                    .is_none_or(str::is_empty)
                && obs
                    .metadata
                    .display_text
                    .as_deref()
                    .is_none_or(str::is_empty)
        };

        let is_collapsible_empty_wrapper = |obs: &WeightedSurfaceObservation<H>| -> bool {
            if !collapse_empty_containers || obs.depth == 0 || obs.metadata.is_focused {
                return false;
            }
            let is_wrapper = obs
                .metadata
                .ax_role
                .as_deref()
                .and_then(Self::role_policy)
                == Some(WeightedSurfaceRolePolicy::Wrapper);
            is_wrapper && obs.text_read.is_none() && obs.metadata.display_text.is_none()
        };

        let eligible_indices: Vec<usize> = (0..observations.len())
            .filter(|&i| !is_excluded_leaf(&observations[i]))
            .collect();
        let output_eligible_indices: Vec<usize> = if collapse_empty_containers {
            eligible_indices
                .into_iter()
                .filter(|&i| !is_collapsible_empty_wrapper(&observations[i]))
                .collect()
        } else {
            eligible_indices
        };

        let mut retained: HashSet<H> = HashSet::new();
        let by_handle: HashMap<H, usize> = observations
            .iter()
            .enumerate()
            .map(|(i, o)| (o.handle.clone(), i))
            .collect();

        let mut text_indices: Vec<usize> = output_eligible_indices
            .iter()
            .copied()
            .filter(|&i| {
                observations[i].text_read.is_some() || observations[i].metadata.display_text.is_some()
            })
            .collect();
        text_indices.sort_by(|&a, &b| {
            let left_text = observations[a]
                .text_read
                .as_ref()
                .and_then(|t| t.text.as_deref())
                .or(observations[a].metadata.display_text.as_deref());
            let right_text = observations[b]
                .text_read
                .as_ref()
                .and_then(|t| t.text.as_deref())
                .or(observations[b].metadata.display_text.as_deref());
            let lr = SurfaceTextCoverage::output_rank(
                left_text,
                observations[a].metadata.is_focused,
                observations[a].in_header_band,
            );
            let rr = SurfaceTextCoverage::output_rank(
                right_text,
                observations[b].metadata.is_focused,
                observations[b].in_header_band,
            );
            lr.cmp(&rr).then_with(|| a.cmp(&b))
        });

        for &index in &text_indices {
            if retained.len() >= limits.max_output_nodes {
                break;
            }
            retained.insert(observations[index].handle.clone());
        }

        let mut ancestors: Vec<H> = text_indices
            .iter()
            .filter(|&&i| retained.contains(&observations[i].handle))
            .filter_map(|&i| observations[i].parent.clone())
            .collect();
        let mut examined_ancestors: HashSet<H> = HashSet::new();
        while !ancestors.is_empty() && retained.len() < limits.max_output_nodes {
            let mut next = Vec::new();
            for handle in ancestors {
                if retained.len() >= limits.max_output_nodes {
                    break;
                }
                if !examined_ancestors.insert(handle.clone()) {
                    continue;
                }
                let Some(&index) = by_handle.get(&handle) else {
                    continue;
                };
                if !is_collapsible_empty_wrapper(&observations[index]) {
                    retained.insert(handle);
                }
                if let Some(ref parent) = observations[index].parent {
                    next.push(parent.clone());
                }
            }
            ancestors = next;
        }

        for &index in &output_eligible_indices {
            if retained.len() >= limits.max_output_nodes {
                break;
            }
            retained.insert(observations[index].handle.clone());
        }

        if retained.len() < output_eligible_indices.len() {
            note(&mut reasons, WeightedSurfaceTraversalReason::OutputBudget);
        }

        let mut nodes = Vec::with_capacity(retained.len());
        for obs in &observations {
            if !retained.contains(&obs.handle) {
                continue;
            }
            let mut parent_handle = obs.parent.clone();
            if collapse_empty_containers {
                while let Some(ref candidate) = parent_handle {
                    if retained.contains(candidate) {
                        break;
                    }
                    if let Some(&cand_idx) = by_handle.get(candidate) {
                        if is_collapsible_empty_wrapper(&observations[cand_idx]) {
                            parent_handle = observations[cand_idx].parent.clone();
                            continue;
                        }
                    }
                    break;
                }
            }
            let resolved_parent = parent_handle
                .as_ref()
                .filter(|p| retained.contains(*p))
                .cloned();
            if parent_handle.is_some() && resolved_parent.is_none() {
                note(&mut reasons, WeightedSurfaceTraversalReason::OutputBudget);
            }
            nodes.push(WeightedSurfaceSample {
                handle: obs.handle.clone(),
                parent: resolved_parent,
                metadata: obs.metadata.clone(),
                text_read: obs.text_read.clone(),
            });
        }

        let complete = reasons.is_empty() && queue.is_empty();
        WeightedSurfaceTraversalResult {
            nodes,
            reasons,
            complete,
            counters,
        }
    }
}

/// Stable `RuntimeId` key used to identify UIA elements across reads within a session epoch.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RuntimeIdKey(pub Vec<i32>);

impl RuntimeIdKey {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Bounded map translating UIA `RuntimeId` handles to stable UUIDs within one session epoch.
/// Capacity 192; resets on adapter change or overflow, pinning the focused node UUID.
#[derive(Debug, Clone)]
pub struct SurfaceNodeMap {
    entries: HashMap<RuntimeIdKey, String>,
    adapter_id: Option<String>,
    capacity: usize,
}

impl Default for SurfaceNodeMap {
    fn default() -> Self {
        Self::new()
    }
}

impl SurfaceNodeMap {
    pub const DEFAULT_CAPACITY: usize = 192;

    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            adapter_id: None,
            capacity: Self::DEFAULT_CAPACITY,
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            adapter_id: None,
            capacity: capacity.max(1),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn adapter_id(&self) -> Option<&str> {
        self.adapter_id.as_deref()
    }

    pub fn reset(&mut self) {
        self.entries.clear();
        self.adapter_id = None;
    }

    pub fn identifier(&mut self, handle: &RuntimeIdKey) -> Option<String> {
        if let Some(known) = self.entries.get(handle) {
            return Some(known.clone());
        }
        if self.entries.len() >= self.capacity {
            return None;
        }
        let id = generate_uuid_v4();
        self.entries.insert(handle.clone(), id.clone());
        Some(id)
    }

    /// Prepares the map for committing a batch of surface handles.
    /// Returns `true` if a reset occurred (caller MUST reset `SurfaceBaseline`).
    pub fn prepare_commit(
        &mut self,
        adapter_id: &str,
        handles: &[RuntimeIdKey],
        pin: Option<(&RuntimeIdKey, &str)>,
    ) -> bool {
        let mut unseen: HashSet<&RuntimeIdKey> = HashSet::new();
        for h in handles {
            if !self.entries.contains_key(h) {
                unseen.insert(h);
            }
        }
        let reset_needed = self.adapter_id.as_deref() != Some(adapter_id)
            || self.entries.len() + unseen.len() > self.capacity;
        if reset_needed {
            self.entries.clear();
            if let Some((pin_key, pin_id)) = pin {
                self.entries.insert(pin_key.clone(), pin_id.to_string());
            }
        }
        self.adapter_id = Some(adapter_id.to_string());
        reset_needed
    }
}

/// Ephemeral candidate surface capture prior to committing into `SurfaceNodeMap` + `SurfaceBaseline`.
#[derive(Debug, Clone)]
pub struct PendingSurfaceCapture {
    pub nodes: Vec<SurfaceNode>,
    pub truncated: bool,
    pub reasons: Vec<String>,
    pub complete: bool,
    pub geometry: Option<SurfaceGeometry>,
    pub adapter_id: String,
    pub references: Vec<(String, RuntimeIdKey)>,
}

impl PendingSurfaceCapture {
    pub fn selected_handles(&self) -> Vec<RuntimeIdKey> {
        self.references.iter().map(|(_, k)| k.clone()).collect()
    }

    /// Materializes ephemeral local node IDs into stable UUIDs from `node_id`.
    pub fn materialize_nodes<F>(&self, mut node_id: F) -> Option<Vec<SurfaceNode>>
    where
        F: FnMut(&RuntimeIdKey) -> Option<String>,
    {
        if self.nodes.len() > 96 || self.references.len() != self.nodes.len() {
            return None;
        }
        let mut seen_local: HashSet<&str> = HashSet::with_capacity(self.nodes.len());
        for (local_id, _) in &self.references {
            if !seen_local.insert(local_id.as_str()) {
                return None;
            }
        }
        for node in &self.nodes {
            if !seen_local.contains(node.id.as_str()) {
                return None;
            }
            if let Some(ref pid) = node.parent_id {
                if !seen_local.contains(pid.as_str()) {
                    return None;
                }
            }
        }

        let mut id_map: HashMap<&str, String> = HashMap::with_capacity(self.references.len());
        let mut unique_stable: HashSet<String> = HashSet::with_capacity(self.references.len());
        for (local_id, handle) in &self.references {
            let stable = node_id(handle)?;
            if !unique_stable.insert(stable.clone()) {
                return None;
            }
            id_map.insert(local_id.as_str(), stable);
        }

        let mut out = Vec::with_capacity(self.nodes.len());
        for node in &self.nodes {
            let stable_id = id_map.get(node.id.as_str())?.clone();
            let stable_parent = match node.parent_id.as_deref() {
                None => None,
                Some(p) => Some(id_map.get(p)?.clone()),
            };
            let mut materialized = node.clone();
            materialized.id = stable_id;
            materialized.parent_id = stable_parent;
            out.push(materialized);
        }
        Some(out)
    }
}
