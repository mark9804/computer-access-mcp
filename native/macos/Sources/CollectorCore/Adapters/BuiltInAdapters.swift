/// Registry list of all built-in application adapters shipped with `computer-history-collector`.
public enum BuiltInAdapters {
    public static let specialized: [any AppAdapter] = [
        VSCodeFamilyAdapter(),
        BrowserFamilyAdapter(),
        TerminalFamilyAdapter(),
        QQAdapter(),
        FeishuAdapter(),
        WeChatAdapter(),
        SlackAdapter(),
        TyporaAdapter(),
        FigmaAdapter(),
    ]

    public static let all: [any AppAdapter] = [GenericAdapter()] + specialized
}
