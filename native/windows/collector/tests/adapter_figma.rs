//! Custom `FigmaAdapter` integration tests (4-zone Electron Design & Slides layout).

mod common;

use std::collections::HashMap;

use history_contract::utf16_len;
use collector_core::adapters::kernel::{
    KernelSurfaceContext, SurfaceCaptureOutcome, SurfaceCaptureRunner, SurfaceCapturedTree,
};
use collector_core::adapters::{
    AppAdapter, FigmaAdapter, SafeDisplayText, SurfaceHandle, FIGMA_ADAPTER,
};
use collector_core::policy::ReadBudget;
use collector_core::protocol_model::{SurfaceAbsoluteRect, SurfaceReadFailure};
use common::{allowlist_policy, assert_valid_forest, id, texts_of, FakeClock, MockNode, MockSurfaceBackend};
// ============================================================================
// Test 11: FigmaAdapter Four Zones from 8-Level Electron Shell & Noise Pruning
//          (macOS + Windows Electron titlebar / AI chrome / y >= window_height / is_offscreen)
// ============================================================================
#[test]
fn figma_adapter_extracts_four_zones_from_eight_level_electron_shell_and_prunes_noise() {
    let clock = FakeClock::new();
    let mut nodes = HashMap::new();

    // 8-level outer Electron shell: AXWindow(0) -> AXGroup(1..6) -> AXScrollArea(7) -> [WebArea #0(10), WebArea #1(20)]
    nodes.insert(
        0,
        MockNode::new("AXWindow")
            .children(vec![1])
            .window_title("Arco Design System – Figma")
            .bounds(0.0, 0.0, 1920.0, 1250.0),
    );
    for depth in 1..=6 {
        nodes.insert(depth, MockNode::new("AXGroup").children(vec![depth + 1]).parent(depth - 1));
    }
    nodes.insert(7, MockNode::new("AXScrollArea").children(vec![10, 20]).parent(6));

    // WebArea #0: Top Tab Bar [0, 0, 1920, 38] including macOS AND Windows titlebar chrome!
    nodes.insert(
        10,
        MockNode::new("AXWebArea")
            .children(vec![11])
            .parent(7)
            .display_text("Figma")
            .bounds(0.0, 0.0, 1920.0, 38.0)
            .label("Figma"),
    );
    nodes.insert(
        11,
        MockNode::new("AXTabGroup")
            .children(vec![12, 13, 14, 15, 16, 17, 18, 19, 25, 26])
            .parent(10)
            .label("Tab bar"),
    );
    nodes.insert(12, MockNode::new("AXRadioButton").parent(11).display_text("Arco Design System").bounds(80.0, 4.0, 180.0, 30.0).label("Arco Design System"));
    nodes.insert(13, MockNode::new("AXTabButton").parent(11).display_text("Mobile Checkout Flow").bounds(268.0, 4.0, 180.0, 30.0).label("Mobile Checkout Flow"));
    nodes.insert(14, MockNode::new("AXTabButton").parent(11).display_text("Close tab").bounds(240.0, 8.0, 16.0, 16.0).label("Close tab"));
    nodes.insert(15, MockNode::new("AXTabButton").parent(11).display_text("New file").bounds(456.0, 8.0, 24.0, 24.0).label("New file"));
    nodes.insert(16, MockNode::new("AXRadioButton").parent(11).display_text("Open tabs and recently closed items").bounds(488.0, 8.0, 24.0, 24.0).label("Open tabs and recently closed items"));
    // Windows Electron titlebar buttons MUST be pruned!
    nodes.insert(17, MockNode::new("AXTabButton").parent(11).display_text("Minimize").bounds(1780.0, 4.0, 32.0, 30.0).label("Minimize"));
    nodes.insert(18, MockNode::new("AXTabButton").parent(11).display_text("Maximize").bounds(1816.0, 4.0, 32.0, 30.0).label("Maximize"));
    nodes.insert(19, MockNode::new("AXTabButton").parent(11).display_text("Close").bounds(1852.0, 4.0, 32.0, 30.0).label("Close"));
    nodes.insert(25, MockNode::new("AXTabButton").parent(11).display_text("Menu").bounds(10.0, 4.0, 32.0, 30.0).label("Menu"));
    nodes.insert(26, MockNode::new("AXTabButton").parent(11).display_text("Restore").bounds(1816.0, 4.0, 32.0, 30.0).label("Restore"));

    // WebArea #1: Main Document [0, 38, 1920, 1212]
    let main_web_display = SafeDisplayText::compose(
        "AXWebArea",
        Some("Arco Design System – Figma"),
        None,
        Some("https://www.figma.com/design/abc123/Arco-Design-System"),
        256,
    )
    .unwrap();
    nodes.insert(
        20,
        MockNode::new("AXWebArea")
            .children(vec![21])
            .parent(7)
            .display_text(main_web_display.clone())
            .bounds(0.0, 38.0, 1920.0, 1212.0)
            .label("Arco Design System – Figma"),
    );
    nodes.insert(21, MockNode::new("AXGroup").children(vec![300, 100, 200, 90, 91]).parent(20));
    nodes.insert(90, MockNode::new("AXToolbar").children(vec![92]).parent(21).label("Editor"));
    nodes.insert(92, MockNode::new("AXButton").parent(90).display_text("Rectangle").label("Rectangle"));
    nodes.insert(91, MockNode::new("AXToolbar").children(vec![93]).parent(21).label("Help/zoom toolbar"));
    nodes.insert(93, MockNode::new("AXButton").parent(91).display_text("Zoom help").label("Zoom help"));

    // Zone 2: AXLandmarkMain
    nodes.insert(
        100,
        MockNode::new("AXGroup")
            .subrole("AXLandmarkMain")
            .children(vec![101])
            .parent(21)
            .bounds(240.0, 38.0, 1440.0, 1212.0)
            .label("Figma Design, 1 item selected"),
    );
    nodes.insert(101, MockNode::new("AXGroup").children(vec![102]).parent(100));
    nodes.insert(
        102,
        MockNode::new("AXGroup")
            .subrole("AXApplicationGroup")
            .children(vec![103, 104, 105, 106])
            .parent(101)
            .label("item-list-2nd-level, Design frame"),
    );
    nodes.insert(103, MockNode::new("AXStaticText").parent(102).text("Dimensions").reported_length(0));
    nodes.insert(104, MockNode::new("AXStaticText").parent(102).text("200 Fill × 32 Hug").reported_length(0));
    nodes.insert(105, MockNode::new("AXStaticText").parent(102).text("\u{EBB1}").reported_length(0));
    nodes.insert(
        106,
        MockNode::new("AXGroup")
            .subrole("AXApplicationGroup")
            .children(vec![107])
            .parent(102)
            .focused()
            .label("treenode/2nd-level, Component instance"),
    );
    nodes.insert(107, MockNode::new("AXStaticText").parent(106).text("176 Fill × 32 Hug").reported_length(0));

    // Zone 3: Right Sidebar (Windows UIA uses AXApplicationGroup for aria_role="region", macOS AXLandmarkRegion!)
    let right_noise = [
        "Apply variable",
        "Add fill",
        "Add stroke",
        "Add effect",
        "Add layout guide",
        "Add export settings",
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
    let mut right_children = vec![201, 202, 203, 204, 205, 206, 208, 209, 210, 211, 212];
    for idx in 0..right_noise.len() {
        right_children.push(250 + idx);
    }
    nodes.insert(
        200,
        MockNode::new("AXGroup")
            .subrole("AXApplicationGroup")
            .children(right_children)
            .parent(21)
            .bounds(1680.0, 38.0, 240.0, 1212.0)
            .label("Right sidebar"),
    );
    nodes.insert(201, MockNode::new("AXRadioButton").parent(200).display_text("Design").bounds(1690.0, 48.0, 60.0, 24.0).label("Design"));
    nodes.insert(202, MockNode::new("AXRadioButton").parent(200).display_text("Prototype").bounds(1756.0, 48.0, 72.0, 24.0).label("Prototype"));
    nodes.insert(203, MockNode::new("AXButton").parent(200).display_text("73%").bounds(1850.0, 48.0, 44.0, 24.0).label("73%"));
    nodes.insert(204, MockNode::new("AXHeading").parent(200).display_text("TreeNode").bounds(1690.0, 92.0, 180.0, 22.0).label("TreeNode"));
    nodes.insert(205, MockNode::new("AXStaticText").parent(200).text("From this file").reported_length(0).bounds(1690.0, 118.0, 120.0, 18.0));
    nodes.insert(206, MockNode::new("AXComboBox").children(vec![207]).parent(200).bounds(1690.0, 150.0, 180.0, 28.0).label("Level"));
    nodes.insert(207, MockNode::new("AXStaticText").parent(206).text("2nd-level").reported_length(0).bounds(1760.0, 154.0, 90.0, 20.0));
    nodes.insert(208, MockNode::new("AXCheckBox").parent(200).bounds(1690.0, 186.0, 120.0, 24.0).label("Show icon"));
    nodes.insert(209, MockNode::new("AXTextField").parent(200).text("200").bounds(1690.0, 218.0, 64.0, 24.0).label("Width"));
    nodes.insert(
        210,
        MockNode::new("AXButton")
            .parent(200)
            .display_text("Color Variable text/1 with value #1D2129 · 100%")
            .bounds(1690.0, 260.0, 210.0, 28.0)
            .label("Color Variable text/1 with value #1D2129 · 100%"),
    );
    nodes.insert(211, MockNode::new("AXStaticText").parent(200).text("Hidden zero-size text").reported_length(0).bounds(1690.0, 300.0, 0.0, 0.0));
    nodes.insert(212, MockNode::new("AXSlider").parent(200).bounds(1690.0, 320.0, 120.0, 16.0).label("Opacity slider"));
    for (idx, &noise) in right_noise.iter().enumerate() {
        nodes.insert(
            250 + idx,
            MockNode::new("AXButton")
                .parent(200)
                .display_text(noise)
                .bounds(1880.0, 100.0 + idx as f64 * 20.0, 24.0, 24.0)
                .label(noise),
        );
    }

    // Zone 4: Left Sidebar with Windows clipping (negative y, height<=1, y>=window_height, is_offscreen)
    nodes.insert(
        300,
        MockNode::new("AXGroup")
            .subrole("AXLandmarkRegion")
            .children(vec![301, 302, 303, 304, 305, 306, 308, 309, 310, 320])
            .parent(21)
            .bounds(0.0, 38.0, 240.0, 1212.0)
            .label("Left sidebar"),
    );
    nodes.insert(301, MockNode::new("AXToolbar").children(vec![307]).parent(300).bounds(0.0, 38.0, 240.0, 36.0).label("Navigation Bar"));
    nodes.insert(307, MockNode::new("AXButton").parent(301).display_text("Nav noise").label("Nav noise"));
    nodes.insert(302, MockNode::new("AXButton").parent(300).display_text("Minimize UI").bounds(200.0, 44.0, 24.0, 24.0).label("Minimize UI"));
    nodes.insert(303, MockNode::new("AXButton").parent(300).display_text("Collapse layers").bounds(170.0, 80.0, 24.0, 24.0).label("Collapse layers"));
    nodes.insert(304, MockNode::new("AXButton").parent(300).display_text("Find").bounds(140.0, 80.0, 24.0, 24.0).label("Find"));
    nodes.insert(305, MockNode::new("AXButton").parent(300).display_text("Add new page").bounds(200.0, 108.0, 24.0, 24.0).label("Add new page"));
    nodes.insert(306, MockNode::new("AXHeading").parent(300).display_text("Arco File Header").bounds(12.0, 52.0, 160.0, 24.0).label("Arco File Header"));
    nodes.insert(308, MockNode::new("AXButton").parent(300).display_text("Main menu").bounds(12.0, 44.0, 24.0, 24.0).label("Main menu"));
    nodes.insert(309, MockNode::new("AXButton").parent(300).display_text("New slide").bounds(12.0, 80.0, 24.0, 24.0).label("New slide"));
    nodes.insert(310, MockNode::new("AXTable").children(vec![311]).parent(300).bounds(0.0, 108.0, 240.0, 100.0));
    nodes.insert(311, MockNode::new("AXRow").parent(310).bounds(0.0, 112.0, 240.0, 28.0).label("Tree 树"));

    nodes.insert(
        320,
        MockNode::new("AXColumn")
            .children(vec![321, 322, 323, 324, 325, 326])
            .parent(300)
            .bounds(0.0, -200.0, 240.0, 1500.0),
    );
    nodes.insert(321, MockNode::new("AXRow").children(vec![331]).parent(320).bounds(0.0, -32.0, 240.0, 28.0));
    nodes.insert(331, MockNode::new("AXStaticText").parent(321).text("Offscreen Top Layer").reported_length(0));
    nodes.insert(322, MockNode::new("AXRow").children(vec![332]).parent(320).bounds(0.0, 220.0, 240.0, 1.0));
    nodes.insert(332, MockNode::new("AXStaticText").parent(322).text("Collapsed Virtual Placeholder").reported_length(0));
    nodes.insert(323, MockNode::new("AXRow").parent(320).bounds(0.0, 260.0, 240.0, 28.0).label("item-list-2nd-level"));
    nodes.insert(324, MockNode::new("AXRow").children(vec![334]).parent(320).bounds(0.0, 292.0, 240.0, 28.0));
    nodes.insert(334, MockNode::new("AXStaticText").parent(324).text("treenode/2nd-level").reported_length(0).bounds(24.0, 296.0, 180.0, 20.0));
    // Below window_height (y = 1260 >= 1250) & UIA IsOffscreen == true MUST be clipped without reading children!
    nodes.insert(325, MockNode::new("AXRow").children(vec![335]).parent(320).bounds(0.0, 1260.0, 240.0, 28.0));
    nodes.insert(335, MockNode::new("AXStaticText").parent(325).text("Below Viewport Row").reported_length(0));
    nodes.insert(326, MockNode::new("AXRow").children(vec![336]).parent(320).bounds(0.0, 340.0, 240.0, 28.0).offscreen());
    nodes.insert(336, MockNode::new("AXStaticText").parent(326).text("UIA Offscreen Row").reported_length(0));

    let mut backend = MockSurfaceBackend::new(nodes).with_window_rect(0.0, 0.0, 1920.0, 1250.0);
    let SurfaceCaptureOutcome::Success(tree) = SurfaceCaptureRunner::run(
        &FIGMA_ADAPTER,
        &id("figma.exe"),
        &allowlist_policy(&["figma.exe"]),
        "window",
        64,
        Some(SurfaceHandle(106)),
        ReadBudget::new(5_000, 150, 768, 32, 8_192),
        &clock,
        &mut backend,
    ) else {
        panic!("expected FigmaAdapter four-zone capture to succeed");
    };
    assert_eq!(tree.adapter_id, "figma");
    assert!(tree.geometry.is_some());
    assert_valid_forest(&tree);

    let texts = texts_of(&tree);
    assert!(texts.contains(&main_web_display.as_str()));
    assert!(texts.contains(&"Arco Design System"));
    assert!(texts.contains(&"Mobile Checkout Flow"));
    for tab_noise in ["Close tab", "New file", "Open tabs and recently closed items", "Minimize", "Maximize", "Close", "Menu", "Restore"] {
        assert!(!texts.contains(&tab_noise), "tab noise must be pruned: {tab_noise}");
    }

    assert!(texts.contains(&"Figma Design, 1 item selected"));
    assert!(texts.contains(&"item-list-2nd-level, Design frame"));
    assert!(texts.contains(&"200 Fill × 32 Hug"));
    assert!(texts.contains(&"treenode/2nd-level, Component instance"));
    assert!(texts.contains(&"176 Fill × 32 Hug"));
    assert!(!texts.contains(&"Dimensions"));
    assert!(!texts.contains(&"\u{EBB1}"));
    let focused: Vec<_> = tree.nodes.iter().filter(|n| n.focused == Some(true)).collect();
    assert_eq!(focused.len(), 1);
    assert_eq!(
        focused[0].text.as_deref(),
        Some("treenode/2nd-level, Component instance")
    );

    for right_keep in ["Design", "Prototype", "73%", "TreeNode", "From this file", "Level", "2nd-level", "Show icon", "200", "Color Variable text/1 with value #1D2129 · 100%"] {
        assert!(texts.contains(&right_keep), "missing right inspector item: {right_keep}");
    }
    assert!(!texts.contains(&"Hidden zero-size text"));
    assert!(!backend.text_reads.contains(&211));
    for noise in right_noise {
        assert!(!texts.contains(&noise), "right sidebar noise must be pruned: {noise}");
    }

    assert!(texts.contains(&"Arco File Header"));
    assert!(texts.contains(&"Tree 树"));
    assert!(texts.contains(&"item-list-2nd-level"));
    assert!(texts.contains(&"treenode/2nd-level"));
    for clipped in ["Offscreen Top Layer", "Collapsed Virtual Placeholder", "Below Viewport Row", "UIA Offscreen Row"] {
        assert!(!texts.contains(&clipped), "clipped row must not appear: {clipped}");
    }
    for skipped_id in [331, 332, 335, 336] {
        assert!(!backend.text_reads.contains(&skipped_id), "clipped child {skipped_id} must NEVER be text-read");
    }
    for left_noise in ["Minimize UI", "Collapse layers", "Find", "Add new page", "Navigation Bar", "Nav noise", "Main menu", "New slide", "Rectangle", "Zoom help"] {
        assert!(!texts.contains(&left_noise), "chrome noise must be pruned: {left_noise}");
    }
}

// ============================================================================
// Test 12: FigmaAdapter Blocks Protected Fields & Fails Closed on Sensitive Focus
// ============================================================================
#[test]
fn figma_adapter_blocks_protected_fields_and_fails_closed_on_sensitive_focus() {
    let clock = FakeClock::new();
    let mut nodes = HashMap::new();
    nodes.insert(0, MockNode::new("AXWindow").children(vec![1]).bounds(0.0, 0.0, 1440.0, 900.0));
    nodes.insert(1, MockNode::new("AXWebArea").children(vec![2, 3]).parent(0).bounds(0.0, 38.0, 1440.0, 862.0).label("Auth Mockup – Figma"));
    nodes.insert(2, MockNode::new("AXGroup").subrole("AXLandmarkMain").children(vec![10]).parent(1).label("Figma Design, 1 item selected"));
    nodes.insert(10, MockNode::new("AXGroup").subrole("AXApplicationGroup").parent(2).label("Login Card, Design frame"));
    nodes.insert(3, MockNode::new("AXGroup").subrole("AXLandmarkRegion").children(vec![20, 21, 22]).parent(1).bounds(1200.0, 38.0, 240.0, 862.0).label("Right sidebar"));
    nodes.insert(20, MockNode::new("AXSecureTextField").parent(3).text("hunter2").bounds(1210.0, 80.0, 180.0, 24.0).label("API Secret"));
    nodes.insert(21, MockNode::new("AXTextField").protected().parent(3).text("tok_live_secret").bounds(1210.0, 112.0, 180.0, 24.0).label("Protected Token"));
    nodes.insert(22, MockNode::new("AXStaticText").parent(3).text("Public Label").reported_length(0).bounds(1210.0, 144.0, 180.0, 20.0));

    let app = id("figma.exe");
    let policy = allowlist_policy(&["figma.exe"]);

    let mut mixed_backend = MockSurfaceBackend::new(nodes.clone()).with_window_rect(0.0, 0.0, 1440.0, 900.0);
    let SurfaceCaptureOutcome::Success(mixed_tree) = SurfaceCaptureRunner::run(
        &FIGMA_ADAPTER,
        &app,
        &policy,
        "window",
        48,
        None,
        ReadBudget::new(5_000, 150, 768, 32, 8_192),
        &clock,
        &mut mixed_backend,
    ) else {
        panic!("expected safe Figma siblings to succeed");
    };
    assert!(!mixed_backend.text_reads.contains(&20));
    assert!(!mixed_backend.text_reads.contains(&21));
    let t = texts_of(&mixed_tree);
    assert!(t.contains(&"Public Label"));
    for secret in ["hunter2", "API Secret", "tok_live_secret", "Protected Token"] {
        assert!(!t.contains(&secret));
    }

    // Focused protected field MUST abort the entire capture with SecurityExcluded (NO fallback!).
    nodes.get_mut(&20).unwrap().is_focused = true;
    let mut secret_focus_backend = MockSurfaceBackend::new(nodes).with_window_rect(0.0, 0.0, 1440.0, 900.0);
    let outcome = SurfaceCaptureRunner::run(
        &FIGMA_ADAPTER,
        &app,
        &policy,
        "window",
        48,
        Some(SurfaceHandle(20)),
        ReadBudget::new(5_000, 150, 768, 32, 8_192),
        &clock,
        &mut secret_focus_backend,
    );
    assert_eq!(
        outcome,
        SurfaceCaptureOutcome::Failure(SurfaceReadFailure::SecurityExcluded)
    );
    assert!(!secret_focus_backend.text_reads.contains(&20));
}

// ============================================================================
// Test 13: FigmaAdapter Falls Back to Weighted Traversal on Home/Recents Screen
// ============================================================================
#[test]
fn figma_adapter_falls_back_to_weighted_traversal_on_home_screen() {
    let clock = FakeClock::new();
    let mut home = HashMap::new();
    home.insert(0, MockNode::new("AXWindow").children(vec![1]).window_title("Recents – Figma").bounds(0.0, 0.0, 1440.0, 900.0));
    home.insert(1, MockNode::new("AXScrollArea").children(vec![2, 3]).parent(0));
    home.insert(2, MockNode::new("AXWebArea").parent(1).display_text("Figma").bounds(0.0, 0.0, 1440.0, 38.0).label("Figma"));
    home.insert(3, MockNode::new("AXWebArea").children(vec![4, 5]).parent(1).display_text("Recents – Figma").bounds(0.0, 38.0, 1440.0, 862.0).label("Recents – Figma"));
    home.insert(4, MockNode::new("AXHeading").parent(3).display_text("Recent files").label("Recent files"));
    home.insert(5, MockNode::new("AXStaticText").parent(3).text("Arco Design System").reported_length(0));

    let app = id("figma.exe");
    let policy = allowlist_policy(&["figma.exe"]);

    let mut direct_backend = MockSurfaceBackend::new(home.clone()).with_window_rect(0.0, 0.0, 1440.0, 900.0);
    let mut ctx = KernelSurfaceContext::new(
        app.clone(),
        &policy,
        FigmaAdapter.spec(),
        "window",
        48,
        SurfaceHandle(0),
        None,
        ReadBudget::new(5_000, 150, 768, 32, 8_192),
        &clock,
        &mut direct_backend,
    );
    ctx.set_initial_window_rect(SurfaceAbsoluteRect::new(0.0, 0.0, 1440.0, 900.0));
    assert!(FigmaAdapter.extract_surface(&mut ctx).is_none());

    let mut fallback_backend = MockSurfaceBackend::new(home).with_window_rect(0.0, 0.0, 1440.0, 900.0);
    let SurfaceCaptureOutcome::Success(tree) = SurfaceCaptureRunner::run(
        &FIGMA_ADAPTER,
        &app,
        &policy,
        "window",
        48,
        None,
        ReadBudget::new(5_000, 150, 768, 32, 8_192),
        &clock,
        &mut fallback_backend,
    ) else {
        panic!("expected weighted fallback on Figma Home screen");
    };
    assert_eq!(tree.adapter_id, "figma");
    let texts = texts_of(&tree);
    assert!(texts.contains(&"Recent files"));
    assert!(texts.contains(&"Arco Design System"));
}

// ============================================================================
// Test 14: FigmaAdapter Proportional Reservation & Text Budget Stay Bounded
// ============================================================================
#[test]
fn figma_adapter_proportional_reservation_and_text_budget_stay_bounded() {
    let clock = FakeClock::new();
    let mut nodes = HashMap::new();
    nodes.insert(0, MockNode::new("AXWindow").children(vec![1]).bounds(0.0, 0.0, 1440.0, 900.0));
    nodes.insert(1, MockNode::new("AXWebArea").children(vec![2, 3, 4]).parent(0).bounds(0.0, 38.0, 1440.0, 862.0).label("Big Canvas – Figma"));

    let canvas_children: Vec<usize> = (100..130).collect();
    nodes.insert(2, MockNode::new("AXGroup").subrole("AXLandmarkMain").children(canvas_children.clone()).parent(1).label("Figma Design, 30 items selected"));
    for nid in canvas_children {
        nodes.insert(nid, MockNode::new("AXGroup").subrole("AXApplicationGroup").parent(2).label(format!("Canvas Layer {nid}, Frame")));
    }

    let right_children: Vec<usize> = (200..215).collect();
    nodes.insert(3, MockNode::new("AXGroup").subrole("AXLandmarkRegion").children(right_children.clone()).parent(1).bounds(1200.0, 38.0, 240.0, 862.0).label("Right sidebar"));
    for nid in right_children {
        nodes.insert(
            nid,
            MockNode::new("AXStaticText")
                .parent(3)
                .text(format!("Inspector Prop {nid}"))
                .reported_length(0)
                .bounds(1210.0, 60.0 + (nid - 200) as f64 * 24.0, 180.0, 20.0),
        );
    }

    let left_children: Vec<usize> = (300..310).collect();
    nodes.insert(4, MockNode::new("AXGroup").subrole("AXLandmarkRegion").children(left_children.clone()).parent(1).bounds(0.0, 38.0, 240.0, 862.0).label("Left sidebar"));
    for nid in left_children {
        nodes.insert(
            nid,
            MockNode::new("AXRow")
                .parent(4)
                .bounds(0.0, 60.0 + (nid - 300) as f64 * 28.0, 240.0, 24.0)
                .label(format!("Sidebar Row {nid}")),
        );
    }

    let app = id("figma.exe");
    let policy = allowlist_policy(&["figma.exe"]);

    let mut backend = MockSurfaceBackend::new(nodes.clone()).with_window_rect(0.0, 0.0, 1440.0, 900.0);
    let SurfaceCaptureOutcome::Success(tree) = SurfaceCaptureRunner::run(
        &FIGMA_ADAPTER,
        &app,
        &policy,
        "window",
        32,
        None,
        ReadBudget::new(5_000, 150, 768, 32, 8_192),
        &clock,
        &mut backend,
    ) else {
        panic!("expected bounded Figma capture");
    };
    assert!(tree.nodes.len() <= 32);
    assert!(tree.reasons.iter().any(|r| r == "tree-output-budget"));
    assert_valid_forest(&tree);
    let texts = texts_of(&tree);
    assert!(texts.iter().any(|t| t.starts_with("Canvas Layer")));
    assert!(texts.iter().any(|t| t.starts_with("Inspector Prop")));
    assert!(texts.iter().any(|t| t.starts_with("Sidebar Row")));

    // Tight max_text_units = 120 must degrade gracefully with "text-budget" and NO budget poisoning.
    let mut tight_backend = MockSurfaceBackend::new(nodes).with_window_rect(0.0, 0.0, 1440.0, 900.0);
    let SurfaceCaptureOutcome::Success(tight_tree) = SurfaceCaptureRunner::run(
        &FIGMA_ADAPTER,
        &app,
        &policy,
        "window",
        32,
        None,
        ReadBudget::new(5_000, 150, 768, 32, 120),
        &clock,
        &mut tight_backend,
    ) else {
        panic!("tight max_text_units must degrade gracefully rather than abort");
    };
    let total_units: usize = tight_tree
        .nodes
        .iter()
        .filter_map(|n| n.text.as_deref())
        .map(utf16_len)
        .sum();
    assert!(total_units <= 120, "total_units={total_units}");
    assert!(tight_tree.reasons.iter().any(|r| r == "text-budget"));
}

// ============================================================================
// Test 15: FigmaAdapter Depth-8 File Tabs, Slides, Geometric Sidebars & Hidden Sidebars
// ============================================================================
#[test]
fn figma_adapter_captures_depth_eight_file_tabs_slides_windows_geo_sidebars_and_hidden_sidebars() {
    let clock = FakeClock::new();
    let mut nodes = HashMap::new();
    nodes.insert(0, MockNode::new("AXWindow").children(vec![1, 2]).bounds(0.0, 0.0, 1920.0, 1250.0));

    // Depth-8 file tabs under Tab Bar AXWebArea
    nodes.insert(1, MockNode::new("AXWebArea").children(vec![10]).parent(0).display_text("Figma").bounds(0.0, 0.0, 1920.0, 38.0).label("Figma"));
    nodes.insert(10, MockNode::new("AXGroup").children(vec![11]).parent(1).bounds(0.0, 0.0, 1920.0, 38.0));
    nodes.insert(11, MockNode::new("AXGroup").children(vec![12]).parent(10).bounds(0.0, 0.0, 1920.0, 38.0));
    nodes.insert(12, MockNode::new("AXGroup").children(vec![13]).parent(11).bounds(0.0, 0.0, 1920.0, 38.0));
    nodes.insert(13, MockNode::new("AXTabGroup").children(vec![14]).parent(12).bounds(0.0, 0.0, 1920.0, 38.0).label("Tab bar"));
    nodes.insert(14, MockNode::new("AXGroup").children(vec![15, 16]).parent(13).bounds(0.0, 0.0, 1920.0, 38.0));
    nodes.insert(15, MockNode::new("AXRadioButton").parent(14).display_text("Home").bounds(81.0, 0.0, 40.0, 38.0).label("Home"));
    nodes.insert(16, MockNode::new("AXGroup").children(vec![17]).parent(14).bounds(121.0, 0.0, 900.0, 38.0));
    nodes.insert(17, MockNode::new("AXGroup").children(vec![18, 19]).parent(16).bounds(121.0, 0.0, 900.0, 38.0));
    nodes.insert(18, MockNode::new("AXRadioButton").parent(17).display_text("Sketchpad").bounds(121.0, 0.0, 133.0, 38.0).label("Sketchpad"));
    nodes.insert(19, MockNode::new("AXRadioButton").parent(17).display_text("Slide Deck Demo").bounds(254.0, 0.0, 149.0, 38.0).label("Slide Deck Demo"));

    // Main Slides AXWebArea + unlabeled geometric right sidebar (Windows Electron fallback!)
    nodes.insert(
        2,
        MockNode::new("AXWebArea")
            .children(vec![30, 40])
            .parent(0)
            .display_text("Slide Deck Demo – Figma Slides (https://www.figma.com/slides/demo)")
            .bounds(0.0, 38.0, 1920.0, 1212.0)
            .label("Slide Deck Demo – Figma Slides"),
    );
    nodes.insert(
        30,
        MockNode::new("AXGroup")
            .subrole("AXLandmarkMain")
            .children(vec![31])
            .parent(2)
            .bounds(0.0, 38.0, 1680.0, 1212.0)
            .label("Figma Slides, 1 item selected"),
    );
    nodes.insert(
        31,
        MockNode::new("AXGroup")
            .subrole("AXApplicationGroup")
            .children(vec![32])
            .parent(30)
            .bounds(256.0, 135.0, 1407.0, 791.0)
            .label("Slide 6"),
    );
    nodes.insert(
        32,
        MockNode::new("AXHeading")
            .parent(31)
            .display_text("Architecture Overview")
            .bounds(350.0, 228.0, 600.0, 43.0)
            .label("Architecture Overview"),
    );
    // Notice: NO explicit "Right sidebar" label — resolved via Windows geometric fallback (x > 1920 - 320)!
    nodes.insert(
        40,
        MockNode::new("AXGroup")
            .children(vec![41, 42, 43, 44])
            .parent(2)
            .bounds(1680.0, 38.0, 240.0, 1212.0),
    );
    nodes.insert(41, MockNode::new("AXRadioButton").parent(40).display_text("Animate").bounds(1745.0, 86.0, 61.0, 24.0).label("Animate"));
    nodes.insert(42, MockNode::new("AXButton").parent(40).display_text("Align left").bounds(1688.0, 127.0, 30.0, 24.0).label("Align left"));
    nodes.insert(43, MockNode::new("AXPopUpButton").parent(40).display_text("Apply variable mode").bounds(1888.0, 127.0, 24.0, 24.0).label("Apply variable mode"));
    nodes.insert(44, MockNode::new("AXButton").parent(40).display_text("Edit template style").bounds(1880.0, 176.0, 24.0, 24.0).label("Edit template style"));

    let app = id("figma.exe");
    let policy = allowlist_policy(&["figma.exe"]);

    let mut backend = MockSurfaceBackend::new(nodes.clone()).with_window_rect(0.0, 0.0, 1920.0, 1250.0);
    let SurfaceCaptureOutcome::Success(tree) = SurfaceCaptureRunner::run(
        &FIGMA_ADAPTER,
        &app,
        &policy,
        "window",
        48,
        None,
        ReadBudget::new(5_000, 150, 768, 32, 8_192),
        &clock,
        &mut backend,
    ) else {
        panic!("expected Figma Slides capture to succeed");
    };
    assert_valid_forest(&tree);
    let texts = texts_of(&tree);
    assert!(texts.contains(&"Home"));
    assert!(texts.contains(&"Sketchpad"));
    assert!(texts.contains(&"Slide Deck Demo"));
    assert!(texts.contains(&"Figma Slides, 1 item selected"));
    assert!(texts.contains(&"Slide 6"));
    assert!(texts.contains(&"Architecture Overview"));
    assert!(texts.contains(&"Animate"));
    assert!(!texts.contains(&"Align left"));
    assert!(!texts.contains(&"Apply variable mode"));
    assert!(!texts.contains(&"Edit template style"));

    // Sidebar-hidden mode (Ctrl+\ / Cmd+\): no sidebars -> clean compact Tab Bar + Canvas snapshot!
    nodes.insert(
        2,
        MockNode::new("AXWebArea")
            .children(vec![30])
            .parent(0)
            .display_text("Slide Deck Demo – Figma Slides (https://www.figma.com/slides/demo)")
            .bounds(0.0, 38.0, 1920.0, 1212.0)
            .label("Slide Deck Demo – Figma Slides"),
    );
    nodes.get_mut(&30).unwrap().bounds = SurfaceAbsoluteRect::new(0.0, 38.0, 1920.0, 1212.0);
    let mut hidden_backend = MockSurfaceBackend::new(nodes).with_window_rect(0.0, 0.0, 1920.0, 1250.0);
    let SurfaceCaptureOutcome::Success(hidden_tree) = SurfaceCaptureRunner::run(
        &FIGMA_ADAPTER,
        &app,
        &policy,
        "window",
        48,
        None,
        ReadBudget::new(5_000, 150, 768, 32, 8_192),
        &clock,
        &mut hidden_backend,
    ) else {
        panic!("expected compact hidden-sidebar Figma snapshot");
    };
    assert_valid_forest(&hidden_tree);
    let ht = texts_of(&hidden_tree);
    assert!(ht.contains(&"Sketchpad"));
    assert!(ht.contains(&"Slide 6"));
    assert!(ht.contains(&"Architecture Overview"));
    assert!(!ht.contains(&"Animate"));
}

// ============================================================================
// Test 22: Live UIA 2-Child Probe Still Signals tree-output-budget in FigmaAdapter
// ============================================================================
#[test]
fn figma_live_two_child_probe_signals_tree_output_budget_on_truncated_container() {
    let clock = FakeClock::new();
    let app = id("figma.exe");
    let policy = allowlist_policy(&["figma.exe"]);

    let run_figma_with_canvas_items = |count: usize| -> SurfaceCapturedTree {
        let mut nodes = HashMap::new();
        nodes.insert(
            0,
            MockNode::new("AXWindow")
                .children(vec![1])
                .bounds(0.0, 0.0, 1440.0, 900.0),
        );
        nodes.insert(
            1,
            MockNode::new("AXWebArea")
                .parent(0)
                .children(vec![2])
                .display_text("Design File")
                .bounds(0.0, 40.0, 1440.0, 860.0),
        );
        let item_ids: Vec<usize> = (100..100 + count).collect();
        nodes.insert(
            2,
            MockNode::new("AXGroup")
                .parent(1)
                .subrole("AXLandmarkMain")
                .children(item_ids.clone())
                .bounds(240.0, 40.0, 920.0, 860.0),
        );
        for (i, &nid) in item_ids.iter().enumerate() {
            nodes.insert(
                nid,
                MockNode::new("AXStaticText")
                    .parent(2)
                    .text(format!("Layer {i}"))
                    .bounds(300.0, 100.0 + (i as f64) * 16.0, 200.0, 14.0),
            );
        }
        let mut backend = MockSurfaceBackend::new(nodes).with_window_rect(0.0, 0.0, 1440.0, 900.0);
        // Simulate live Windows UIA's 2-child initial probe where `child_count` is capped at 2!
        backend.cap_reported_child_count = Some(2);
        let SurfaceCaptureOutcome::Success(tree) = SurfaceCaptureRunner::run(
            &FIGMA_ADAPTER,
            &app,
            &policy,
            "window",
            64,
            None,
            ReadBudget::new(5_000, 150, 768, 32, 8_192),
            &clock,
            &mut backend,
        ) else {
            panic!("expected Figma capture to succeed for count={count}");
        };
        assert_valid_forest(&tree);
        tree
    };

    // 30 canvas items > page_limit (24): even with `child_count == 2`, `last_children_truncated()`
    // MUST signal `tree-output-budget`!
    let big_tree = run_figma_with_canvas_items(30);
    assert!(
        big_tree.reasons.iter().any(|r| r == "tree-output-budget"),
        "expected tree-output-budget when >24 live children exist, got {:?}",
        big_tree.reasons
    );

    // 5 canvas items <= page_limit (24): MUST NOT spuriously emit `tree-output-budget`!
    let small_tree = run_figma_with_canvas_items(5);
    assert!(
        !small_tree.reasons.iter().any(|r| r == "tree-output-budget"),
        "did not expect tree-output-budget for 5 items, got {:?}",
        small_tree.reasons
    );
}

// ============================================================================
// Test 23: Live Windows 11 3-AXWebArea Electron Shell (Empty Backdrop + Off-Left Badge)
// ============================================================================
#[test]
fn figma_skips_empty_electron_backdrop_web_area_and_selects_real_document() {
    let clock = FakeClock::new();
    let mut nodes = HashMap::new();

    // Exact Windows 11 Electron figma.exe 3-AXWebArea shell:
    // - Depth 0..7 outer shell wrappers (0 -> 1 -> ... -> 7)
    // - Depth 8: empty full-screen Electron backdrop AXWebArea (1920x1232, area=2,365,440, child_count=0, label=None)
    // - Depth 9: Top File Tab Bar AXWebArea (1920x38, y=6.5) + Real Main Document AXWebArea (1918x1193, y=44.5, area=2,288,174)
    nodes.insert(
        0,
        MockNode::new("AXWindow")
            .children(vec![1])
            .window_title("FloUNet 总结 – Figma Slides")
            .bounds(0.0, 0.0, 1920.0, 1232.0),
    );
    for depth in 1..=6 {
        nodes.insert(
            depth,
            MockNode::new("AXGroup")
                .children(vec![depth + 1])
                .parent(depth - 1)
                .bounds(0.0, 0.0, 1920.0, 1232.0),
        );
    }
    nodes.insert(
        7,
        MockNode::new("AXGroup")
            .children(vec![8, 9])
            .parent(6)
            .bounds(0.0, 0.0, 1920.0, 1232.0),
    );

    // Depth 8: Empty Electron backdrop AXWebArea (shallower AND larger than the real document!)
    nodes.insert(
        8,
        MockNode::new("AXWebArea")
            .parent(7)
            .bounds(0.0, 0.0, 1920.0, 1232.0),
    );

    // Depth 8 wrapper -> Depth 9 Tab Bar (10) and Main Document (20)
    nodes.insert(
        9,
        MockNode::new("AXGroup")
            .children(vec![10, 20])
            .parent(7)
            .bounds(0.0, 0.0, 1920.0, 1232.0),
    );

    // Depth 9 #1: Top File Tab Bar AXWebArea (1920x38, y=6.5)
    // Real Windows 11 Electron Figma wraps the 1920x38 tab strip inside a 0x0 CSS layout AXGroup.
    nodes.insert(
        10,
        MockNode::new("AXWebArea")
            .children(vec![40])
            .parent(9)
            .display_text("Figma (file:///C:/Users/test/AppData/Local/Figma/shell.html)")
            .bounds(0.0, 6.5, 1920.0, 38.0)
            .label("Figma"),
    );
    nodes.insert(
        40,
        MockNode::new("AXGroup")
            .children(vec![41])
            .parent(10)
            .bounds(6.5, 6.5, 0.0, 0.0),
    );
    nodes.insert(
        41,
        MockNode::new("AXGroup")
            .children(vec![11])
            .parent(40)
            .bounds(0.0, 6.5, 1920.0, 38.0),
    );
    nodes.insert(
        11,
        MockNode::new("AXTabGroup")
            .children(vec![12, 13, 14, 15, 16, 17, 18, 19, 42])
            .parent(41)
            .bounds(0.0, 6.5, 1920.0, 38.0)
            .label("Tab bar"),
    );
    nodes.insert(
        12,
        MockNode::new("AXRadioButton")
            .parent(11)
            .display_text("Home")
            .bounds(60.0, 8.0, 48.0, 34.0)
            .label("Home"),
    );
    nodes.insert(
        13,
        MockNode::new("AXTabButton")
            .parent(11)
            .display_text("FloUNet 总结")
            .bounds(116.0, 8.0, 180.0, 34.0)
            .label("FloUNet 总结"),
    );
    // Windows Electron titlebar & tab chrome noise MUST be pruned
    nodes.insert(14, MockNode::new("AXTabButton").parent(11).display_text("New file").bounds(304.0, 8.0, 28.0, 28.0).label("New file"));
    nodes.insert(15, MockNode::new("AXTabButton").parent(11).display_text("Menu").bounds(8.0, 8.0, 32.0, 30.0).label("Menu"));
    nodes.insert(16, MockNode::new("AXTabButton").parent(11).display_text("Minimize").bounds(1780.0, 8.0, 32.0, 30.0).label("Minimize"));
    nodes.insert(17, MockNode::new("AXTabButton").parent(11).display_text("Maximize").bounds(1816.0, 8.0, 32.0, 30.0).label("Maximize"));
    nodes.insert(18, MockNode::new("AXTabButton").parent(11).display_text("Restore").bounds(1816.0, 8.0, 32.0, 30.0).label("Restore"));
    nodes.insert(19, MockNode::new("AXTabButton").parent(11).display_text("Close").bounds(1852.0, 8.0, 32.0, 30.0).label("Close"));
    // Zero-size hidden leaf AXTabButton MUST still be pruned even while 0x0 wrapper AXGroup is traversed
    nodes.insert(
        42,
        MockNode::new("AXTabButton")
            .parent(11)
            .display_text("Hidden Zero-Size Tab")
            .bounds(0.0, 6.5, 0.0, 0.0)
            .label("Hidden Zero-Size Tab"),
    );

    // Depth 9 #2: Real Main Document AXWebArea (1918x1193, y=44.5)
    let main_web_display = SafeDisplayText::compose(
        "AXWebArea",
        Some("FloUNet 总结 – Figma Slides"),
        None,
        Some("https://www.figma.com/slides/flounet-demo/FloUNet"),
        256,
    )
    .unwrap();
    nodes.insert(
        20,
        MockNode::new("AXWebArea")
            .children(vec![21])
            .parent(9)
            .display_text(main_web_display.clone())
            .bounds(1.0, 44.5, 1918.0, 1193.0)
            .label("FloUNet 总结 – Figma Slides"),
    );
    // Deep DOM wrapper chain inside main_web_area so landmarks sit at depth 9 (> old MAX_LANDMARK_DEPTH=8)
    for idx in 21..=27 {
        nodes.insert(
            idx,
            MockNode::new("AXGroup")
                .children(vec![idx + 1])
                .parent(idx - 1)
                .bounds(1.0, 44.5, 1918.0, 1193.0),
        );
    }
    nodes.insert(
        28,
        MockNode::new("AXGroup")
            .children(vec![300, 100, 200])
            .parent(27)
            .bounds(1.0, 44.5, 1918.0, 1193.0),
    );

    // Zone 2: AXLandmarkMain with offscreen far-left dimension badge (x = -12371, width = 121) + visible slide
    nodes.insert(
        100,
        MockNode::new("AXGroup")
            .subrole("AXLandmarkMain")
            .children(vec![101])
            .parent(28)
            .bounds(240.0, 44.5, 1440.0, 1187.5)
            .label("Figma Slides, 1 item selected"),
    );
    nodes.insert(
        101,
        MockNode::new("AXGroup")
            .children(vec![102, 103, 105])
            .parent(100)
            .bounds(240.0, 44.5, 1440.0, 1187.5),
    );
    // Offscreen far-left dimension badge observed in live Windows 11 Figma Slides (rect.x + rect.width <= 0.0)
    nodes.insert(
        102,
        MockNode::new("AXStaticText")
            .parent(101)
            .text("1920 × 1080 offscreen badge")
            .reported_length(0)
            .bounds(-12371.0, 172.5, 121.0, 20.0),
    );
    nodes.insert(
        103,
        MockNode::new("AXGroup")
            .subrole("AXApplicationGroup")
            .children(vec![104])
            .parent(101)
            .bounds(-12371.0, 172.5, 121.0, 24.0)
            .label("Offscreen Left Dimension Badge"),
    );
    nodes.insert(
        104,
        MockNode::new("AXStaticText")
            .parent(103)
            .text("999 × 999")
            .reported_length(0)
            .bounds(-12371.0, 174.0, 121.0, 20.0),
    );
    // Active visible slide on canvas
    nodes.insert(
        105,
        MockNode::new("AXGroup")
            .subrole("AXApplicationGroup")
            .children(vec![106, 107])
            .parent(101)
            .bounds(260.0, 140.0, 1360.0, 765.0)
            .focused()
            .label("Slide 3"),
    );
    nodes.insert(
        106,
        MockNode::new("AXHeading")
            .parent(105)
            .display_text("FloUNet 模型结构总结")
            .bounds(340.0, 210.0, 620.0, 44.0)
            .label("FloUNet 模型结构总结"),
    );
    nodes.insert(
        107,
        MockNode::new("AXStaticText")
            .parent(105)
            .text("Skip-connection fusion")
            .reported_length(0)
            .bounds(340.0, 276.0, 420.0, 24.0),
    );

    // Zone 3: Right Inspector Sidebar with real properties + noise buttons
    nodes.insert(
        200,
        MockNode::new("AXGroup")
            .subrole("AXApplicationGroup")
            .children(vec![201, 202, 203, 204, 205, 206, 207, 208])
            .parent(28)
            .bounds(1680.0, 44.5, 240.0, 1187.5)
            .label("Right sidebar"),
    );
    nodes.insert(201, MockNode::new("AXRadioButton").parent(200).display_text("Slide").bounds(1690.0, 56.0, 56.0, 24.0).label("Slide"));
    nodes.insert(202, MockNode::new("AXRadioButton").parent(200).display_text("Animate").bounds(1752.0, 56.0, 68.0, 24.0).label("Animate"));
    nodes.insert(203, MockNode::new("AXStaticText").parent(200).text("16:9 Widescreen").reported_length(0).bounds(1690.0, 100.0, 160.0, 20.0));
    nodes.insert(204, MockNode::new("AXTextField").parent(200).text("#FFFFFF").bounds(1690.0, 136.0, 100.0, 24.0).label("Background"));
    // Right sidebar chrome noise MUST be pruned
    nodes.insert(205, MockNode::new("AXButton").parent(200).display_text("Share").bounds(1850.0, 56.0, 52.0, 24.0).label("Share"));
    nodes.insert(206, MockNode::new("AXButton").parent(200).display_text("Present").bounds(1800.0, 56.0, 48.0, 24.0).label("Present"));
    nodes.insert(207, MockNode::new("AXButton").parent(200).display_text("Start with an AI draft").bounds(1690.0, 180.0, 180.0, 28.0).label("Start with an AI draft"));
    nodes.insert(208, MockNode::new("AXButton").parent(200).display_text("Align left").bounds(1690.0, 216.0, 24.0, 24.0).label("Align left"));

    // Zone 4: Left Sidebar with visible slides + negative-y / below-viewport clipped slides + noise
    nodes.insert(
        300,
        MockNode::new("AXGroup")
            .subrole("AXLandmarkRegion")
            .children(vec![301, 302, 303, 304, 310])
            .parent(28)
            .bounds(0.0, 44.5, 240.0, 1187.5)
            .label("Left sidebar"),
    );
    nodes.insert(301, MockNode::new("AXButton").parent(300).display_text("Main menu").bounds(12.0, 52.0, 24.0, 24.0).label("Main menu"));
    nodes.insert(302, MockNode::new("AXButton").parent(300).display_text("New slide").bounds(44.0, 52.0, 24.0, 24.0).label("New slide"));
    nodes.insert(303, MockNode::new("AXButton").parent(300).display_text("Grid view").bounds(180.0, 52.0, 24.0, 24.0).label("Grid view"));
    nodes.insert(304, MockNode::new("AXButton").parent(300).display_text("Minimize UI").bounds(208.0, 52.0, 24.0, 24.0).label("Minimize UI"));
    nodes.insert(
        310,
        MockNode::new("AXColumn")
            .children(vec![311, 312, 313, 314])
            .parent(300)
            .bounds(0.0, -180.0, 240.0, 1600.0),
    );
    // Negative-y offscreen top slide MUST be clipped without reading text!
    nodes.insert(311, MockNode::new("AXRow").children(vec![321]).parent(310).bounds(0.0, -96.0, 240.0, 88.0));
    nodes.insert(321, MockNode::new("AXStaticText").parent(311).text("Slide 1 - Offscreen Top").reported_length(0));
    // Visible slides in viewport
    nodes.insert(312, MockNode::new("AXRow").parent(310).bounds(0.0, 110.0, 240.0, 88.0).label("Slide 2 - Overview"));
    nodes.insert(313, MockNode::new("AXRow").parent(310).bounds(0.0, 210.0, 240.0, 88.0).label("Slide 3 - FloUNet"));
    // Below-viewport slide MUST be clipped without reading text!
    nodes.insert(314, MockNode::new("AXRow").children(vec![324]).parent(310).bounds(0.0, 1240.0, 240.0, 88.0));
    nodes.insert(324, MockNode::new("AXStaticText").parent(314).text("Slide 9 - Below Viewport").reported_length(0));

    let app = id("figma.exe");
    let policy = allowlist_policy(&["figma.exe"]);

    // 1. Direct FigmaAdapter::extract_surface MUST return Some(...) selecting real document (20), NOT fallback!
    let mut direct_backend =
        MockSurfaceBackend::new(nodes.clone()).with_window_rect(0.0, 0.0, 1920.0, 1232.0);
    let mut direct_ctx = KernelSurfaceContext::new(
        app.clone(),
        &policy,
        FigmaAdapter.spec(),
        "window",
        64,
        SurfaceHandle(0),
        Some(SurfaceHandle(105)),
        ReadBudget::new(5_000, 150, 768, 32, 8_192),
        &clock,
        &mut direct_backend,
    );
    direct_ctx.set_initial_window_rect(SurfaceAbsoluteRect::new(0.0, 0.0, 1920.0, 1232.0));
    let custom_result = FigmaAdapter
        .extract_surface(&mut direct_ctx)
        .expect("FigmaAdapter must select real document AXWebArea rather than falling back");
    assert!(
        custom_result
            .nodes
            .iter()
            .any(|n| n.handle == SurfaceHandle(20)),
        "expected real document AXWebArea (20) in custom result"
    );
    assert!(
        !custom_result
            .nodes
            .iter()
            .any(|n| n.handle == SurfaceHandle(8)),
        "empty Electron backdrop AXWebArea (8) must not be emitted"
    );

    // 2. Full SurfaceCaptureRunner verification of all 4 zones, off-left pruning, noise pruning & slide clipping.
    let mut backend =
        MockSurfaceBackend::new(nodes.clone()).with_window_rect(0.0, 0.0, 1920.0, 1232.0);
    let SurfaceCaptureOutcome::Success(tree) = SurfaceCaptureRunner::run(
        &FIGMA_ADAPTER,
        &app,
        &policy,
        "window",
        64,
        Some(SurfaceHandle(105)),
        ReadBudget::new(5_000, 150, 768, 32, 8_192),
        &clock,
        &mut backend,
    ) else {
        panic!("expected FigmaAdapter 3-AXWebArea capture to succeed");
    };
    assert_eq!(tree.adapter_id, "figma");
    assert_valid_forest(&tree);

    let texts = texts_of(&tree);
    // Zone 1: Main document title + URL and clean file tabs (traversed through 0x0 wrapper AXGroup)
    assert!(texts.contains(&main_web_display.as_str()));
    assert!(texts.contains(&"Home"));
    assert!(texts.contains(&"FloUNet 总结"));
    assert!(
        !texts.contains(&"Hidden Zero-Size Tab"),
        "zero-size leaf AXTabButton must still be pruned"
    );
    for tab_noise in ["New file", "Menu", "Minimize", "Maximize", "Restore", "Close"] {
        assert!(
            !texts.contains(&tab_noise),
            "Windows titlebar/tab noise must be pruned: {tab_noise}"
        );
    }

    // Zone 2: Canvas landmark + visible slide (focused) with off-left x=-12371 badge pruned
    assert!(texts.contains(&"Figma Slides, 1 item selected"));
    assert!(texts.contains(&"Slide 3"));
    assert!(texts.contains(&"FloUNet 模型结构总结"));
    assert!(texts.contains(&"Skip-connection fusion"));
    assert!(!texts.contains(&"1920 × 1080 offscreen badge"));
    assert!(!texts.contains(&"Offscreen Left Dimension Badge"));
    assert!(!texts.contains(&"999 × 999"));
    assert!(
        !backend.text_reads.contains(&102),
        "off-left x=-12371 canvas badge must NEVER be text-read"
    );
    assert!(
        !backend.text_reads.contains(&104),
        "child of off-left x=-12371 canvas group must NEVER be text-read"
    );
    let focused: Vec<_> = tree.nodes.iter().filter(|n| n.focused == Some(true)).collect();
    assert_eq!(focused.len(), 1);
    assert_eq!(focused[0].text.as_deref(), Some("Slide 3"));

    // Zone 3: Right inspector properties preserved, chrome noise pruned
    for right_keep in ["Slide", "Animate", "16:9 Widescreen", "#FFFFFF"] {
        assert!(
            texts.contains(&right_keep),
            "missing right inspector item: {right_keep}"
        );
    }
    for right_noise in ["Share", "Present", "Start with an AI draft", "Align left"] {
        assert!(
            !texts.contains(&right_noise),
            "right sidebar noise must be pruned: {right_noise}"
        );
    }

    // Zone 4: Visible slides preserved, negative-y & below-viewport slides clipped, chrome pruned
    assert!(texts.contains(&"Slide 2 - Overview"));
    assert!(texts.contains(&"Slide 3 - FloUNet"));
    assert!(!texts.contains(&"Slide 1 - Offscreen Top"));
    assert!(!texts.contains(&"Slide 9 - Below Viewport"));
    assert!(
        !backend.text_reads.contains(&321),
        "negative-y clipped slide must NEVER be text-read"
    );
    assert!(
        !backend.text_reads.contains(&324),
        "below-viewport clipped slide must NEVER be text-read"
    );
    for left_noise in ["Main menu", "New slide", "Grid view", "Minimize UI"] {
        assert!(
            !texts.contains(&left_noise),
            "left sidebar noise must be pruned: {left_noise}"
        );
    }

    // 3. Even if the depth-8 Electron backdrop AXWebArea has dummy children and a label (no AXLandmarkMain),
    //    Step 2 tries ranked candidates in order and still selects real document AXWebArea (20)!
    nodes.insert(
        8,
        MockNode::new("AXWebArea")
            .children(vec![801])
            .parent(7)
            .display_text("Electron Overlay")
            .bounds(0.0, 0.0, 1920.0, 1232.0)
            .label("Electron Overlay"),
    );
    nodes.insert(
        801,
        MockNode::new("AXGroup")
            .parent(8)
            .bounds(0.0, 0.0, 1920.0, 1232.0)
            .label("Dummy overlay container"),
    );
    let mut overlay_backend =
        MockSurfaceBackend::new(nodes).with_window_rect(0.0, 0.0, 1920.0, 1232.0);
    let mut overlay_ctx = KernelSurfaceContext::new(
        app,
        &policy,
        FigmaAdapter.spec(),
        "window",
        64,
        SurfaceHandle(0),
        Some(SurfaceHandle(105)),
        ReadBudget::new(5_000, 150, 768, 32, 8_192),
        &clock,
        &mut overlay_backend,
    );
    overlay_ctx.set_initial_window_rect(SurfaceAbsoluteRect::new(0.0, 0.0, 1920.0, 1232.0));
    let overlay_result = FigmaAdapter
        .extract_surface(&mut overlay_ctx)
        .expect("FigmaAdapter must skip dummy populated overlay AXWebArea and select real document");
    assert!(
        overlay_result
            .nodes
            .iter()
            .any(|n| n.handle == SurfaceHandle(20)),
        "expected real document AXWebArea (20) after skipping overlay AXWebArea (8)"
    );
    assert!(
        !overlay_result
            .nodes
            .iter()
            .any(|n| n.handle == SurfaceHandle(8)),
        "dummy overlay AXWebArea (8) must not be emitted"
    );
}

// ============================================================================
// Test 30: [P2-6] FigmaAdapter Shallow Overlay, Negative-Y Tab Bar & Offscreen Tabs
// ============================================================================
#[test]
fn figma_adapter_handles_shallow_overlay_negative_y_tabbar_and_offscreen_background_tabs() {
    let clock = FakeClock::new();
    let app = id("figma.exe");
    let policy = allowlist_policy(&["figma.exe"]);

    // 1. Shallow depth-D non-canvas overlay AXWebArea + depth-D Tab Bar MUST NOT hide depth-(D+1) real document!
    {
        let mut nodes = HashMap::new();
        nodes.insert(0, MockNode::new("AXWindow").children(vec![1]).bounds(0.0, 0.0, 1920.0, 1200.0));
        // Depth 1 container holds: Depth-2 Tab Bar (10), Depth-2 populated labeled Overlay (11), Depth-2 wrapper (12)
        nodes.insert(1, MockNode::new("AXGroup").children(vec![10, 11, 12]).parent(0).bounds(0.0, 0.0, 1920.0, 1200.0));
        nodes.insert(
            10,
            MockNode::new("AXWebArea")
                .children(vec![100])
                .parent(1)
                .display_text("Figma")
                .bounds(0.0, 0.0, 1920.0, 38.0)
                .label("Figma"),
        );
        nodes.insert(100, MockNode::new("AXTabButton").parent(10).display_text("Real Doc Tab").bounds(80.0, 4.0, 160.0, 30.0).label("Real Doc Tab"));
        // Depth 2 populated labeled overlay WITHOUT AXLandmarkMain
        nodes.insert(
            11,
            MockNode::new("AXWebArea")
                .children(vec![110])
                .parent(1)
                .display_text("Toast Overlay")
                .bounds(0.0, 38.0, 1920.0, 1162.0)
                .label("Toast Overlay"),
        );
        nodes.insert(110, MockNode::new("AXGroup").parent(11).label("Toast container"));
        // Depth 2 wrapper -> Depth 3 REAL Figma Document AXWebArea
        nodes.insert(12, MockNode::new("AXGroup").children(vec![20]).parent(1).bounds(0.0, 38.0, 1920.0, 1162.0));
        nodes.insert(
            20,
            MockNode::new("AXWebArea")
                .children(vec![21])
                .parent(12)
                .display_text("Deep Design – Figma")
                .bounds(0.0, 38.0, 1920.0, 1162.0)
                .label("Deep Design – Figma"),
        );
        nodes.insert(21, MockNode::new("AXGroup").subrole("AXLandmarkMain").children(vec![22]).parent(20).bounds(0.0, 38.0, 1920.0, 1162.0).label("Figma Design, 1 item selected"));
        nodes.insert(22, MockNode::new("AXStaticText").parent(21).text("Deep Real Canvas").bounds(400.0, 200.0, 240.0, 24.0));

        let mut backend = MockSurfaceBackend::new(nodes).with_window_rect(0.0, 0.0, 1920.0, 1200.0);
        let SurfaceCaptureOutcome::Success(tree) = SurfaceCaptureRunner::run(
            &FIGMA_ADAPTER,
            &app,
            &policy,
            "window",
            48,
            None,
            ReadBudget::new(5_000, 150, 768, 32, 8_192),
            &clock,
            &mut backend,
        ) else {
            panic!("expected FigmaAdapter to discover depth-(D+1) document behind depth-D overlay");
        };
        let texts = texts_of(&tree);
        assert!(texts.contains(&"Deep Real Canvas"));
        assert!(texts.contains(&"Real Doc Tab"));
        assert!(!tree.handles.iter().any(|(_, idx)| *idx == 11));
        assert_valid_forest(&tree);
    }

    // 2. Negative-y offscreen AXWebArea (rect.y + rect.height <= 0) MUST NOT be mistaken for the top tab bar!
    {
        let mut nodes = HashMap::new();
        nodes.insert(0, MockNode::new("AXWindow").children(vec![10, 11, 20]).bounds(0.0, 0.0, 1920.0, 1200.0));
        // Offscreen negative-y strip listed FIRST with child_count > 0!
        nodes.insert(
            10,
            MockNode::new("AXWebArea")
                .children(vec![101])
                .parent(0)
                .display_text("Hidden Strip")
                .bounds(0.0, -200.0, 1920.0, 38.0)
                .label("Hidden Strip"),
        );
        nodes.insert(101, MockNode::new("AXTabButton").parent(10).display_text("Ghost Hidden Tab").bounds(80.0, -196.0, 160.0, 30.0).label("Ghost Hidden Tab"));
        // Real visible top tab bar listed SECOND
        nodes.insert(
            11,
            MockNode::new("AXWebArea")
                .children(vec![111])
                .parent(0)
                .display_text("Figma")
                .bounds(0.0, 6.5, 1920.0, 38.0)
                .label("Figma"),
        );
        nodes.insert(111, MockNode::new("AXTabButton").parent(11).display_text("Visible Real Tab").bounds(80.0, 10.0, 160.0, 30.0).label("Visible Real Tab"));
        // Real Main Document
        nodes.insert(
            20,
            MockNode::new("AXWebArea")
                .children(vec![21])
                .parent(0)
                .display_text("Active File – Figma")
                .bounds(0.0, 44.5, 1920.0, 1155.5)
                .label("Active File – Figma"),
        );
        nodes.insert(21, MockNode::new("AXGroup").subrole("AXLandmarkMain").children(vec![22]).parent(20).bounds(0.0, 44.5, 1920.0, 1155.5).label("Figma Design"));
        nodes.insert(22, MockNode::new("AXStaticText").parent(21).text("Canvas Content").bounds(400.0, 200.0, 240.0, 24.0));

        let mut backend = MockSurfaceBackend::new(nodes).with_window_rect(0.0, 0.0, 1920.0, 1200.0);
        let SurfaceCaptureOutcome::Success(tree) = SurfaceCaptureRunner::run(
            &FIGMA_ADAPTER,
            &app,
            &policy,
            "window",
            48,
            None,
            ReadBudget::new(5_000, 150, 768, 32, 8_192),
            &clock,
            &mut backend,
        ) else {
            panic!("expected FigmaAdapter to skip negative-y tab strip");
        };
        let texts = texts_of(&tree);
        assert!(texts.contains(&"Visible Real Tab"));
        assert!(!texts.contains(&"Ghost Hidden Tab"));
        assert!(texts.contains(&"Canvas Content"));
        assert_valid_forest(&tree);
    }

    // 3. On-screen active tab canvas MUST outrank a LARGER offscreen background tab canvas!
    {
        let mut nodes = HashMap::new();
        nodes.insert(0, MockNode::new("AXWindow").children(vec![10, 20]).bounds(0.0, 0.0, 1440.0, 900.0));
        // Background offscreen tab: LARGER area (2560x1400), has label + valid AXLandmarkMain, but is_offscreen = true!
        nodes.insert(
            10,
            MockNode::new("AXWebArea")
                .children(vec![11])
                .parent(0)
                .display_text("Background Huge Deck – Figma")
                .bounds(0.0, 38.0, 2560.0, 1400.0)
                .label("Background Huge Deck – Figma")
                .offscreen(),
        );
        nodes.insert(11, MockNode::new("AXGroup").subrole("AXLandmarkMain").children(vec![12]).parent(10).bounds(0.0, 38.0, 2560.0, 1400.0).label("Background Canvas"));
        nodes.insert(12, MockNode::new("AXStaticText").parent(11).text("Background Offscreen Slide").bounds(200.0, 200.0, 300.0, 24.0));

        // Active on-screen tab: SMALLER area (1440x862), is_offscreen = false!
        nodes.insert(
            20,
            MockNode::new("AXWebArea")
                .children(vec![21])
                .parent(0)
                .display_text("Active Design – Figma")
                .bounds(0.0, 38.0, 1440.0, 862.0)
                .label("Active Design – Figma"),
        );
        nodes.insert(21, MockNode::new("AXGroup").subrole("AXLandmarkMain").children(vec![22]).parent(20).bounds(0.0, 38.0, 1440.0, 862.0).label("Active Canvas"));
        nodes.insert(22, MockNode::new("AXStaticText").parent(21).text("Active Onscreen Frame").bounds(200.0, 200.0, 300.0, 24.0));

        let mut backend = MockSurfaceBackend::new(nodes).with_window_rect(0.0, 0.0, 1440.0, 900.0);
        let SurfaceCaptureOutcome::Success(tree) = SurfaceCaptureRunner::run(
            &FIGMA_ADAPTER,
            &app,
            &policy,
            "window",
            48,
            None,
            ReadBudget::new(5_000, 150, 768, 32, 8_192),
            &clock,
            &mut backend,
        ) else {
            panic!("expected FigmaAdapter to prefer on-screen active tab over larger offscreen tab");
        };
        let texts = texts_of(&tree);
        assert!(texts.contains(&"Active Onscreen Frame"));
        assert!(!texts.contains(&"Background Offscreen Slide"));
        assert_valid_forest(&tree);
    }
}
