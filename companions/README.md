# Companion Bridges (`companions/`)

Reserved extension slot for optional, authenticated local bridges (browser extensions and IDE plugins) that supply structured context unavailable from OS accessibility APIs:

- **Browser Companion**: Exact tab URL, incognito/private window state, and reliable tab-to-window correlation.
- **Editor Companion**: Active workspace root, open file path, and explicit document save events.

All companion inputs must authenticate against the local daemon and pass the same application policy and epoch fencing as native Collector observations.
