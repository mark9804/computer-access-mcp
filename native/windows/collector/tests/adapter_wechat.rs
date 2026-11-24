//! Custom `WeChatAdapter` integration tests (Qt 4.x dotted AutomationId + Win32 DuiLib).

mod common;

use std::collections::HashMap;

use collector_core::adapters::kernel::{
    KernelSurfaceContext, SurfaceCaptureOutcome, SurfaceCaptureRunner,
};
use collector_core::adapters::wechat::matches_wechat_id;
use collector_core::adapters::{AppAdapter, SurfaceHandle, WeChatAdapter, WECHAT_ADAPTER};
use collector_core::policy::ReadBudget;
use common::{allowlist_policy, assert_valid_forest, id, texts_of, FakeClock, MockNode, MockSurfaceBackend};
// ============================================================================
// Test 6: WeChatAdapter (Qt 4.x + Dotted Windows Qt AutomationId + DuiLib AXRow)
// ============================================================================
#[test]
fn wechat_adapter_extracts_chat_pane_tail_and_skips_session_list_and_virtual_cells() {
    assert!(matches_wechat_id(Some("chat_message_list"), "chat_message_list"));
    assert!(matches_wechat_id(
        Some("MainWindow.centralWidget.splitter.chat_message_list"),
        "chat_message_list"
    ));
    assert!(!matches_wechat_id(
        Some("other_chat_message_list"),
        "chat_message_list"
    ));
    assert!(!matches_wechat_id(None, "chat_message_list"));

    let clock = FakeClock::new();

    // Run both exact Qt identifiers AND Windows dot-qualified Qt 4.x AutomationIds!
    for prefix in ["", "MainWindow.centralWidget.splitter."] {
        let q = |name: &str| format!("{prefix}{name}");
        let mut nodes = HashMap::new();
        nodes.insert(
            0,
            MockNode::new("AXWindow")
                .children(vec![1])
                .bounds(100.0, 200.0, 1000.0, 700.0),
        );
        nodes.insert(1, MockNode::new("AXGroup").children(vec![2]).parent(0));
        nodes.insert(
            2,
            MockNode::new("AXSplitGroup")
                .children(vec![3, 4, 5])
                .parent(1)
                .identifier(q("main_window_main_splitter_view")),
        );
        nodes.insert(
            3,
            MockNode::new("AXButton")
                .children(vec![30])
                .parent(2)
                .display_text("WeChat"),
        );
        nodes.insert(30, MockNode::new("AXStaticText").parent(3).text("Left nav noise"));
        nodes.insert(4, MockNode::new("AXButton").parent(2).display_text("Contacts"));
        nodes.insert(
            5,
            MockNode::new("AXSplitGroup")
                .children(vec![6, 7])
                .parent(2)
                .identifier(q("main_window_sub_splitter_view")),
        );

        let session_rows: Vec<usize> = (500..550).collect();
        nodes.insert(
            6,
            MockNode::new("AXList")
                .children(session_rows.clone())
                .parent(5)
                .identifier(q("session_list")),
        );
        for row_id in session_rows {
            nodes.insert(
                row_id,
                MockNode::new("AXStaticText")
                    .parent(6)
                    .text(format!("Session preview {row_id}")),
            );
        }

        nodes.insert(7, MockNode::new("AXGroup").children(vec![8]).parent(5));
        nodes.insert(8, MockNode::new("AXSplitGroup").children(vec![9, 12]).parent(7));
        nodes.insert(9, MockNode::new("AXGroup").children(vec![10]).parent(8));
        nodes.insert(
            10,
            MockNode::new("AXStaticText")
                .children(vec![11])
                .parent(9)
                .identifier(q("big_title_line_h_view")),
        );
        nodes.insert(
            11,
            MockNode::new("AXStaticText")
                .parent(10)
                .text("文件传输助手")
                .reported_length(0)
                .bounds(360.0, 220.0, 200.0, 28.0)
                .identifier(q("current_chat_name_label")),
        );
        nodes.insert(12, MockNode::new("AXSplitGroup").children(vec![13, 14]).parent(8));

        let message_ids: Vec<usize> = (1000..1120).collect();
        nodes.insert(
            13,
            MockNode::new("AXList")
                .children(message_ids)
                .parent(12)
                .bounds(340.0, 260.0, 640.0, 480.0)
                .identifier(q("chat_message_list")),
        );
        for offset in 0..120usize {
            let nid = 1000 + offset;
            if offset < 88 {
                nodes.insert(
                    nid,
                    MockNode::new("AXStaticText")
                        .parent(13)
                        .text(format!("Old msg {offset}"))
                        .reported_length(0)
                        .bounds(360.0, 270.0, 220.0, 24.0)
                        .identifier(q("chat_bubble_item_view")),
                );
            } else if offset < 92 {
                nodes.insert(
                    nid,
                    MockNode::new("AXStaticText")
                        .parent(13)
                        .text("")
                        .reported_length(0)
                        .bounds(100.0, 200.0, 0.0, 0.0)
                        .identifier(q("virtual_cell")),
                );
            } else if offset == 92 {
                nodes.insert(
                    nid,
                    MockNode::new("AXStaticText")
                        .parent(13)
                        .text("Hidden zero-size placeholder")
                        .reported_length(0)
                        .bounds(100.0, 200.0, 0.0, 0.0),
                );
            } else if offset == 93 {
                nodes.insert(
                    nid,
                    MockNode::new("AXStaticText")
                        .parent(13)
                        .text("14:20")
                        .reported_length(0)
                        .bounds(600.0, 280.0, 60.0, 16.0),
                );
            } else {
                nodes.insert(
                    nid,
                    MockNode::new("AXStaticText")
                        .parent(13)
                        .text(format!("Recent msg {offset}"))
                        .reported_length(0)
                        .bounds(360.0, 300.0 + (offset - 94) as f64 * 20.0, 260.0, 18.0)
                        .identifier(q("chat_bubble_item_view")),
                );
            }
        }
        nodes.insert(
            14,
            MockNode::new("AXTextArea")
                .parent(12)
                .text("Draft reply")
                .focused()
                .bounds(340.0, 760.0, 640.0, 120.0)
                .identifier(q("chat_input_field")),
        );

        let mut backend = MockSurfaceBackend::new(nodes).with_window_rect(100.0, 200.0, 1000.0, 700.0);
        let outcome = SurfaceCaptureRunner::run(
            &WECHAT_ADAPTER,
            &id("weixin.exe"),
            &allowlist_policy(&["weixin.exe"]),
            "window",
            48,
            Some(SurfaceHandle(14)),
            ReadBudget::new(5_000, 150, 768, 32, 8_192),
            &clock,
            &mut backend,
        );
        let SurfaceCaptureOutcome::Success(tree) = outcome else {
            panic!("expected WeChat extraction success (prefix={prefix:?}), got {outcome:?}");
        };
        assert_eq!(tree.adapter_id, "wechat");
        assert!(
            !backend.child_requests.iter().any(|r| r.0 == 6),
            "session_list children must NEVER be requested"
        );
        assert!(
            !backend.text_reads.contains(&30),
            "left nav button children must NEVER be read"
        );
        let list_pages: Vec<_> = backend.child_requests.iter().filter(|r| r.0 == 13).collect();
        assert_eq!(list_pages.len(), 1);
        assert_eq!(list_pages[0].1, 88);
        assert_eq!(list_pages[0].2, 32);
        for skipped in 1088..=1092 {
            assert!(
                !backend.text_reads.contains(&skipped),
                "virtual/zero-size cell {skipped} must NEVER be text-read"
            );
        }
        let texts = texts_of(&tree);
        assert_eq!(texts.first().copied(), Some("文件传输助手"));
        assert!(texts.contains(&"14:20"));
        assert!(texts.contains(&"Recent msg 94"));
        assert!(texts.contains(&"Recent msg 119"));
        assert!(!texts.contains(&"Old msg 87"));
        assert!(!texts.contains(&"Hidden zero-size placeholder"));
        assert!(!texts.iter().any(|t| t.starts_with("Session preview")));
        let p94 = texts.iter().position(|&t| t == "Recent msg 94").unwrap();
        let p119 = texts.iter().position(|&t| t == "Recent msg 119").unwrap();
        assert!(p94 < p119, "messages must stay in chronological order");
        let input = tree
            .nodes
            .iter()
            .find(|n| n.ax_role.as_deref() == Some("AXTextArea"))
            .expect("input node");
        assert_eq!(input.role, "editable");
        assert_eq!(input.text.as_deref(), Some("Draft reply"));
        assert_eq!(input.focused, Some(true));
        assert_eq!(tree.nodes.iter().filter(|n| n.focused == Some(true)).count(), 1);
        assert_valid_forest(&tree);
    }

    // Windows WeChat 3.x DuiLib variant (`ListItem`/`AXRow` holding message body directly in Name).
    let mut duilib = HashMap::new();
    duilib.insert(0, MockNode::new("AXWindow").children(vec![1, 2, 3]).bounds(0.0, 0.0, 900.0, 640.0));
    duilib.insert(1, MockNode::new("AXList").children(vec![10]).parent(0).label("会话"));
    duilib.insert(10, MockNode::new("AXRow").parent(1).label("Hidden session row"));
    duilib.insert(2, MockNode::new("AXList").children(vec![20, 21]).parent(0).label("消息"));
    duilib.insert(20, MockNode::new("AXRow").parent(2).label("Hello from WeChat 3.x").bounds(300.0, 100.0, 240.0, 24.0));
    duilib.insert(21, MockNode::new("AXRow").parent(2).label("Second bubble").bounds(300.0, 140.0, 240.0, 24.0));
    duilib.insert(3, MockNode::new("AXTextArea").parent(0).text("3.x draft").focused().bounds(300.0, 500.0, 560.0, 100.0));
    let mut duilib_backend = MockSurfaceBackend::new(duilib).with_window_rect(0.0, 0.0, 900.0, 640.0);
    let SurfaceCaptureOutcome::Success(duilib_tree) = SurfaceCaptureRunner::run(
        &WECHAT_ADAPTER,
        &id("wechat.exe"),
        &allowlist_policy(&["wechat.exe"]),
        "window",
        32,
        Some(SurfaceHandle(3)),
        ReadBudget::new(5_000, 150, 768, 32, 8_192),
        &clock,
        &mut duilib_backend,
    ) else {
        panic!("expected WeChat 3.x DuiLib extraction to succeed");
    };
    assert!(!duilib_backend.child_requests.iter().any(|r| r.0 == 1));
    let dt = texts_of(&duilib_tree);
    assert!(dt.contains(&"Hello from WeChat 3.x"));
    assert!(dt.contains(&"Second bubble"));
    assert!(dt.contains(&"3.x draft"));
    assert!(!dt.contains(&"Hidden session row"));
    assert_valid_forest(&duilib_tree);
}

// ============================================================================
// Test 7: WeChatAdapter Falls Back to Weighted Traversal When Identifiers Absent
// ============================================================================
#[test]
fn wechat_adapter_falls_back_to_weighted_traversal_when_identifiers_absent() {
    let clock = FakeClock::new();
    let mut login = HashMap::new();
    login.insert(0, MockNode::new("AXWindow").children(vec![1]));
    login.insert(1, MockNode::new("AXGroup").children(vec![2, 3]).parent(0));
    login.insert(
        2,
        MockNode::new("AXStaticText")
            .parent(1)
            .text("Scan QR code to log in")
            .reported_length(0),
    );
    login.insert(
        3,
        MockNode::new("AXButton")
            .parent(1)
            .display_text("Switch Account"),
    );

    let app = id("wechat.exe");
    let policy = allowlist_policy(&["wechat.exe"]);

    let mut direct_backend = MockSurfaceBackend::new(login.clone());
    let mut ctx = KernelSurfaceContext::new(
        app.clone(),
        &policy,
        WeChatAdapter.spec(),
        "window",
        48,
        SurfaceHandle(0),
        None,
        ReadBudget::new(5_000, 150, 768, 32, 8_192),
        &clock,
        &mut direct_backend,
    );
    assert!(WeChatAdapter.extract_surface(&mut ctx).is_none());

    let mut fallback_backend = MockSurfaceBackend::new(login);
    let SurfaceCaptureOutcome::Success(tree) = SurfaceCaptureRunner::run(
        &WECHAT_ADAPTER,
        &app,
        &policy,
        "window",
        48,
        None,
        ReadBudget::new(5_000, 150, 768, 32, 8_192),
        &clock,
        &mut fallback_backend,
    ) else {
        panic!("expected weighted traversal fallback on WeChat login screen");
    };
    assert_eq!(tree.adapter_id, "wechat");
    assert!(texts_of(&tree).contains(&"Scan QR code to log in"));
}
