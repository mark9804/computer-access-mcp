// Wire v1 protocol schema source of truth.
const integer = (minimum = 0, maximum = Number.MAX_SAFE_INTEGER) => ({ type: 'integer', minimum, maximum });
const string = (maxLength = 128, minLength = 1) => ({ type: 'string', minLength, maxLength, 'x-maxUtf16CodeUnits': maxLength });
const enumeration = (...values) => ({ type: 'string', enum: values });
const literal = value => ({ const: value });
const array = (items, maxItems = 64, minItems = 0) => ({ type: 'array', items, minItems, maxItems });
const ref = name => ({ $ref: `#/$defs/${name}` });
const object = (properties, optional = []) => ({
  type: 'object', properties,
  required: Object.keys(properties).filter(key => !optional.includes(key)),
  additionalProperties: false,
});
const union = (...names) => ({ oneOf: names.map(ref) });
const message = (type, properties, optional = []) => object({ protocolVersion: literal(1), type: literal(type), ...properties }, optional);
const boolean = { type: 'boolean' };

export const limits = Object.freeze({ maxFrameBytes: 65536, maxTextCodeUnits: 8192, maxDepth: 32, maxCollectionItems: 256 });
export const schema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: 'urn:computer-access-mcp:wire:1',
  title: 'Computer Access Wire v1',
  ...union('Hello', 'Configure', 'Configured', 'Control', 'State', 'Observation', 'ActionRequest', 'ActionReceipt', 'ProtocolFailure'),
  $defs: {
    TargetIdentity: object({
      deviceId: string(), osSessionId: string(), desktopId: string(),
      processId: integer(1, 2147483647), processStartTime: string(), applicationId: string(256),
      windowId: string(), windowGeneration: integer(),
    }),
    ApplicationTargetIdentity: object({
      deviceId: string(), osSessionId: string(), desktopId: string(),
      processId: integer(1, 2147483647), processStartTime: string(), applicationId: string(256),
    }),
    ResolvedTarget: object({ kind: literal('resolved'), identity: ref('TargetIdentity') }),
    ApplicationTarget: object({ kind: literal('application'), identity: ref('ApplicationTargetIdentity') }),
    UnresolvedTarget: object({ kind: literal('unresolved'), reason: enumeration('not-observed', 'focus-unavailable', 'policy-boundary', 'desktop-unavailable') }),
    TargetRef: union('ResolvedTarget', 'ApplicationTarget', 'UnresolvedTarget'),
    Stamp: object({ captureEpoch: integer(), foregroundGeneration: integer(), focusGeneration: integer(), policyRevision: integer() }),
    Capability: object({
      name: enumeration('text.snapshot', 'text.visible-range', 'text.marker', 'field.denylist', 'ax.enablement', 'surface.snapshot', 'selection.snapshot', 'input.text', 'input.activity', 'menu.action', 'text.set', 'pointer.click', 'key.chord', 'scroll', 'gesture.pinch', 'gesture.rotate', 'gesture.pan', 'gesture.swipe', 'contact.touch', 'contact.pen', 'view.zoom'),
      direction: enumeration('observe', 'act', 'verify'),
      scope: enumeration('app-local', 'authorized-desktop'),
      support: enumeration('supported', 'unsupported', 'unknown'),
      reason: string(256, 0),
    }),
    CapturePolicy: object({
      enabled: boolean, allowedApplicationIds: array(string(256), 64),
      applicationScope: { ...enumeration('allowlist', 'denylist'), default: 'allowlist' },
      excludedApplicationIds: array(string(256), 64),
      allowBrowserContent: { ...boolean, default: false },
      fieldSecurity: { ...enumeration('strict', 'denylist'), default: 'strict' },
      axCompatibility: { ...boolean, default: false },
      textMarkers: { ...boolean, default: false },
      captureScope: { ...enumeration('focused', 'region', 'window'), default: 'focused' },
      maxTreeNodes: { ...integer(1, 96), default: 64 },
      inputText: { ...boolean, default: false },
      selectionCapture: { ...boolean, default: false },
      // Additive opt-in: omission has the same disabled semantics as false.
      inputActivity: { ...boolean, default: false },
      menuActions: { ...boolean, default: false },
      textRange: { ...enumeration('prefix', 'visible'), default: 'prefix' },
      sampleIntervalMs: { ...integer(1000, 30000), default: 1000 },
      maxTextCodeUnits: integer(1, limits.maxTextCodeUnits), maxPending: integer(1, 64),
      debounceMs: integer(0, 2000), maxWaitMs: integer(1, 5000), readTimeoutMs: integer(1, 5000),
    }, ['applicationScope', 'excludedApplicationIds', 'allowBrowserContent', 'fieldSecurity', 'axCompatibility', 'textMarkers', 'captureScope', 'maxTreeNodes', 'inputText', 'selectionCapture', 'inputActivity', 'menuActions', 'textRange', 'sampleIntervalMs']),
    Hello: message('hello', { instanceId: string(), capabilities: array(ref('Capability')), maxFrameBytes: literal(limits.maxFrameBytes) }),
    Configure: message('configure', { requestId: string(), ownerId: string(), instanceId: string(), policyRevision: integer(1), policy: ref('CapturePolicy') }),
    Configured: message('configured', { requestId: string(), ownerId: string(), instanceId: string(), policyRevision: integer(1) }),
    Control: message('control', {
      requestId: string(), ownerId: string(), instanceId: string(), policyRevision: integer(1),
      command: enumeration('start', 'pause', 'resume', 'stop', 'heartbeat'), leaseDurationMs: integer(1, 30000),
    }),
    CaptureDiagnostics: object({
      axEnablement: enumeration('disabled', 'denied', 'already-enabled', 'enabled', 'unsupported', 'original-unknown', 'not-settable', 'write-failed'),
      axAttribute: enumeration('manual', 'enhanced', 'none'),
      observer: enumeration('unavailable', 'best-effort'),
    }),
    State: message('state', {
      requestId: string(), instanceId: string(), state: enumeration('unconfigured', 'ready', 'running', 'paused', 'stopped'),
      stamp: ref('Stamp'), reason: string(256, 0), captureDiagnostics: ref('CaptureDiagnostics'),
    }, ['captureDiagnostics']),
    Coverage: object({ status: enumeration('complete', 'partial', 'unknown'), truncated: boolean, missingReasons: array(string(128), 16) }),
    TextRange: object({ unit: literal('utf16'), start: integer(), length: integer(0, limits.maxTextCodeUnits) }),
    ContentGate: object({ secure: enumeration('safe', 'not-declared-sensitive', 'sensitive', 'unknown'), privateState: enumeration('normal', 'private', 'unknown', 'user-authorized'), policyRevision: integer(1) }),
    TextSnapshot: object({
      kind: literal('text.snapshot'), snapshotId: string(), editSessionId: string(), nodeId: string(),
      source: enumeration('fixture', 'ax.value', 'ax.range', 'ax.marker', 'uia.value', 'uia.text'),
      scope: enumeration('field', 'accessible-range'), valueState: enumeration('read', 'unavailable', 'redacted'),
      rangeBasis: { ...enumeration('prefix', 'visible'), default: 'prefix' },
      text: string(limits.maxTextCodeUnits, 0), range: ref('TextRange'), selection: ref('TextRange'), totalLength: integer(),
      composition: enumeration('composing', 'not-composing', 'unknown'),
      captureStartMs: integer(), captureEndMs: integer(), coverage: ref('Coverage'), gate: ref('ContentGate'),
    }, ['rangeBasis', 'text', 'range', 'selection', 'totalLength', 'gate']),
    TextChanged: object({ kind: literal('text.changed'), baseSnapshotId: string(), after: ref('TextSnapshot') }),
    InputActivityCounts: object({
      pointerReleases: integer(0, 256), dragSamples: integer(0, 256),
      scrollSamples: integer(0, 256), shortcutPresses: integer(0, 256),
    }),
    InputActivityGate: object({
      policyRevision: integer(1), secureInput: literal('inactive'),
      targetAttribution: literal('event-target-pid'), detail: literal('coarse-counts'),
    }),
    InputActivity: object({
      kind: literal('input.activity'), source: enumeration('cg.listen-only', 'win32.listen-only', 'fixture'), scope: literal('application'),
      intervalStartMs: integer(), intervalEndMs: integer(), counts: ref('InputActivityCounts'),
      gate: ref('InputActivityGate'), coverage: ref('Coverage'),
    }),
    MenuAction: object({
      kind: literal('menu.action'),
      source: enumeration('ax.menu', 'uia.menu', 'fixture'),
      scope: literal('menu-bar'),
      path: array(string(128, 1), 8, 2),
      observedAtMs: integer(),
      gate: ref('ContentGate'),
      secureInput: literal('inactive'),
      coverage: ref('Coverage'),
      effect: literal('unverified'),
    }),
    SurfaceBounds: object({ x: { type: 'number', minimum: -1000000, maximum: 1000000 }, y: { type: 'number', minimum: -1000000, maximum: 1000000 }, width: { type: 'number', minimum: 0, maximum: 1000000 }, height: { type: 'number', minimum: 0, maximum: 1000000 } }),
    SurfaceWindowSize: object({ width: { type: 'number', minimum: 0, maximum: 1000000 }, height: { type: 'number', minimum: 0, maximum: 1000000 } }),
    SurfaceGeometry: object({ coordinateSpace: literal('window-top-left-point'), windowSize: ref('SurfaceWindowSize'), observedAtMs: integer() }),
    SurfaceNode: object({ id: string(96), parentId: string(96), role: enumeration('text', 'editable', 'container', 'terminal', 'other'), text: string(limits.maxTextCodeUnits, 0), observedAtMs: integer(), bounds: ref('SurfaceBounds'), boundsObservedAtMs: integer(), axRole: string(64), focused: boolean }, ['parentId', 'text', 'bounds', 'boundsObservedAtMs', 'axRole', 'focused']),
    SurfaceChanges: object({ added: array(string(96), 96), updated: array(string(96), 96), removed: array(string(96), 96) }),
    SurfaceSnapshot: object({
      kind: literal('surface.snapshot'), snapshotId: string(), surfaceId: string(), revision: integer(1),
      source: enumeration('ax.tree', 'uia.tree', 'fixture'), scope: enumeration('region', 'window'), mode: enumeration('full', 'diff'),
      nodes: array(ref('SurfaceNode'), 96), changes: ref('SurfaceChanges'), baseRevision: integer(1), geometry: ref('SurfaceGeometry'),
      captureStartMs: integer(), captureEndMs: integer(), coverage: ref('Coverage'), gate: ref('ContentGate'), consistency: literal('non-atomic'),
    }, ['changes', 'baseRevision', 'geometry']),
    SelectionSnapshot: object({
      kind: literal('selection.snapshot'), snapshotId: string(), surfaceId: string(),
      source: enumeration('ax.range', 'ax.marker', 'uia.text', 'fixture'), scope: literal('selection'), text: string(limits.maxTextCodeUnits, 0),
      range: ref('TextRange'), captureStartMs: integer(), captureEndMs: integer(), coverage: ref('Coverage'), gate: ref('ContentGate'),
    }),
    InputText: object({
      kind: literal('input.text'), source: enumeration('cg.unicode', 'win32.unicode', 'fixture'), scope: literal('field'),
      eventKind: enumeration('text', 'return', 'shortcut'), text: string(2048, 0),
      modifiers: array(enumeration('command', 'control', 'option', 'shift'), 4),
      intervalStartMs: integer(), intervalEndMs: integer(), eventCount: integer(1, 256),
      surfaceId: string(), gate: ref('ContentGate'), secureInput: literal('inactive'), coverage: ref('Coverage'),
      effect: literal('unverified'),
    }),
    EvidenceRelation: object({ basis: literal('temporal-same-surface'), evidenceIds: array(string(240), 4, 1), effect: literal('unverified') }),
    // Closed metadata vocabulary only: never raw provider errors/roles or user text.
    GapDiagnostic: object({
      code: enumeration(
        'application-not-allowed', 'application-unavailable', 'browser-excluded', 'focused-field-unavailable', 'focused-role-not-text',
        'secure-field', 'field-security-unknown', 'visible-range-unavailable', 'text-read-unavailable', 'text-result-invalid', 'focus-changed',
        'invalid-sampling-policy', 'read-deadline', 'accessibility-denied', 'desktop-unavailable',
        'input-context-unverified', 'input-target-mismatch', 'input-role-not-editable', 'input-verification-timeout', 'input-field-security-unknown',
        'input-text-budget', 'input-text-backpressure', 'input-text-read-unavailable', 'input-policy-boundary', 'capture-authority-changed', 'worker-retirement-pending',
        'surface-not-started-budget', 'surface-call-budget', 'surface-time-budget', 'surface-anchor-unavailable', 'surface-boundary-unverified',
        'surface-boundary-mismatch', 'surface-boundary-ax-failed', 'surface-boundary-incomplete', 'surface-security-excluded', 'surface-provider-unavailable',
      ),
      role: enumeration('AXTextField', 'AXTextArea', 'AXStaticText', 'AXSecureTextField', 'AXMenuItem', 'AXMenu', 'AXWebArea', 'AXGroup', 'AXButton', 'other', 'unavailable'),
    }, ['role']),
    Gap: object({
      kind: literal('gap'),
      reason: enumeration('policy-boundary', 'stale', 'timeout', 'read-error', 'budget', 'backpressure', 'host-lost', 'desktop-unavailable', 'baseline-unavailable'),
      count: integer(1), diagnostic: ref('GapDiagnostic'), providerApplicationId: string(256),
    }, ['diagnostic', 'providerApplicationId']),
    ContextChanged: object({ kind: literal('context.changed'), reason: enumeration('application', 'window', 'focus', 'focus-unavailable') }),
    Observation: message('observation', {
      eventId: string(), instanceId: string(), seq: integer(1), eventTimeMs: integer(), monotonicMs: integer(),
      target: ref('TargetRef'), stamp: ref('Stamp'), actor: enumeration('unknown', 'user-estimated', 'agent'),
      relatedActionIds: array(string(), 16), relation: ref('EvidenceRelation'), payload: union('TextSnapshot', 'TextChanged', 'InputActivity', 'MenuAction', 'SurfaceSnapshot', 'SelectionSnapshot', 'InputText', 'Gap', 'ContextChanged'),
    }, ['relation']),
    Point: object({ x: { type: 'number', minimum: -1000000, maximum: 1000000 }, y: { type: 'number', minimum: -1000000, maximum: 1000000 }, space: enumeration('window-point', 'desktop-physical-pixel'), transformId: string() }),
    TextSet: object({ kind: literal('text.set'), text: string(limits.maxTextCodeUnits, 0) }),
    PointerClick: object({ kind: literal('pointer.click'), point: ref('Point'), button: enumeration('left', 'right', 'middle'), count: integer(1, 3) }),
    KeyChord: object({ kind: literal('key.chord'), keys: array(string(32), 8, 1) }),
    ViewZoom: object({ kind: literal('view.zoom'), subject: enumeration('page', 'canvas', 'viewport', 'system'), scale: { type: 'number', minimum: 0.01, maximum: 100 } }),
    ActionRequest: message('action.request', {
      requestId: string(), actionId: string(), target: ref('TargetIdentity'), stamp: ref('Stamp'),
      snapshotId: string(), backendId: string(), runtimeGeneration: integer(1), deadlineMs: integer(),
      sessionId: string(), agentId: string(), grantId: string(), leaseId: string(),
      mode: enumeration('background', 'foreground'), expectedCondition: string(256),
      action: union('TextSet', 'PointerClick', 'KeyChord', 'ViewZoom'),
    }),
    ActionReceipt: message('action.receipt', {
      requestId: string(), actionId: string(), dispatch: enumeration('not-dispatched', 'dispatched', 'partial', 'unknown'),
      effect: enumeration('confirmed', 'unverifiable', 'uncertain', 'refused'),
      startedMs: integer(), endedMs: integer(), route: string(), evidenceIds: array(string(), 32),
      reason: string(256, 0),
    }),
    ProtocolFailure: message('error', { requestId: string(), code: enumeration('invalid-message', 'unsupported-version', 'frame-too-large', 'permission-denied', 'stale', 'unsupported', 'unknown-capability'), retryable: literal(false) }),
  },
};
