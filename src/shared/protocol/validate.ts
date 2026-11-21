import schema from './wire.schema.json' with { type: 'json' };
import { LIMITS } from './generated.ts';
import type { CapturePolicy, ContentGate, Coverage, InputText, Observation, SelectionSnapshot, SurfaceSnapshot, TextRange, TextSnapshot, WireMessage } from './generated.ts';

type Schema = { $ref?: string; oneOf?: Schema[]; const?: unknown; enum?: unknown[]; type?: string; properties?: Record<string, Schema>; required?: string[]; additionalProperties?: boolean; items?: Schema; minItems?: number; maxItems?: number; minLength?: number; maxLength?: number; 'x-maxUtf16CodeUnits'?: number; minimum?: number; maximum?: number };
export class ProtocolError extends Error {
  readonly code: 'invalid-message' | 'unsupported-version' | 'frame-too-large';
  constructor(code: ProtocolError['code']) { super(code); this.name = 'ProtocolError'; this.code = code; }
}
function fail(): never { throw new ProtocolError('invalid-message'); }
const definitions = schema.$defs as unknown as Record<string, Schema>;
function validateNode(value: unknown, node: Schema, depth = 0): void {
  if (depth > LIMITS.maxDepth) fail();
  if (node.$ref) { const target = definitions[node.$ref.split('/').at(-1)!]; if (!target) fail(); validateNode(value, target, depth + 1); return; }
  if (node.oneOf) {
    let matches = 0;
    for (const branch of node.oneOf) { try { validateNode(value, branch, depth + 1); matches++; } catch (error) { if (!(error instanceof ProtocolError)) throw error; } }
    if (matches !== 1) fail(); return;
  }
  if ('const' in node && value !== node.const) fail();
  if (node.enum && !node.enum.includes(value)) fail();
  switch (node.type) {
    case 'object': {
      if (value === null || typeof value !== 'object' || Array.isArray(value)) fail();
      if (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) fail();
      const record = value as Record<string, unknown>;
      const properties = node.properties ?? {};
      for (const key of node.required ?? []) if (!Object.hasOwn(record, key)) fail();
      for (const key of Reflect.ownKeys(record)) {
        if (typeof key !== 'string' || !Object.hasOwn(properties, key)) fail();
        const descriptor = Object.getOwnPropertyDescriptor(record, key);
        if (!descriptor || !('value' in descriptor) || !descriptor.enumerable) fail();
        validateNode(descriptor.value, properties[key]!, depth + 1);
      }
      break;
    }
    case 'array':
      if (!Array.isArray(value) || value.length < (node.minItems ?? 0) || value.length > (node.maxItems ?? LIMITS.maxCollectionItems)) fail();
      if (Object.getPrototypeOf(value) !== Array.prototype || Reflect.ownKeys(value as unknown[]).length !== (value as unknown[]).length + 1) fail();
      for (let i = 0; i < (value as unknown[]).length; i++) {
        const descriptor = Object.getOwnPropertyDescriptor(value, String(i));
        if (!descriptor || !('value' in descriptor)) fail();
        validateNode(descriptor.value, node.items!, depth + 1);
      }
      break;
    case 'string':
      if (typeof value !== 'string') fail();
      // JSON Schema length counts code points; explicit wire extension also caps UTF-16 units.
      if (Array.from(value as string).length < (node.minLength ?? 0) || Array.from(value as string).length > (node.maxLength ?? LIMITS.maxTextCodeUnits)) fail();
      if (node['x-maxUtf16CodeUnits'] !== undefined && (value as string).length > node['x-maxUtf16CodeUnits']) fail();
      // JSON permits escaped lone surrogates; reject them to keep Swift/TS identical.
      if (!(value as string).isWellFormed()) fail();
      break;
    case 'integer': case 'number':
      if (typeof value !== 'number' || !Number.isFinite(value) || (node.type === 'integer' && !Number.isSafeInteger(value))) fail();
      if ((value as number) < (node.minimum ?? -Infinity) || (value as number) > (node.maximum ?? Infinity)) fail();
      break;
    case 'boolean': if (typeof value !== 'boolean') fail(); break;
  }
}
function validateCoverage(coverage: Coverage): void {
  if (coverage.status === 'complete' && (coverage.truncated || coverage.missingReasons.length > 0)) fail();
  if (coverage.status !== 'complete' && coverage.missingReasons.length === 0) fail();
}
function validateGate(gate: ContentGate | undefined, revision: number): void {
  // This declaration is not authorization: Host must independently check its policy.
  if (!gate || gate.policyRevision !== revision || !['safe', 'not-declared-sensitive'].includes(gate.secure) ||
      (gate.privateState !== 'normal' && gate.privateState !== 'user-authorized')) fail();
}
function validatePolicy(policy: CapturePolicy): void {
  if (policy.maxWaitMs < policy.debounceMs) fail();
  for (const ids of [policy.allowedApplicationIds, policy.excludedApplicationIds ?? []]) {
    if (ids.some(id => /^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$/.exec(id)?.[0] !== id) || new Set(ids.map(id => id.toLowerCase())).size !== ids.length) fail();
  }
  // Empty legacy lists remain representable. Exclusions win over overlapping allow entries in Host policy.
}
function validateRange(range: TextRange): void {
  if (range.length > Number.MAX_SAFE_INTEGER - range.start) fail();
}
function validateSurface(snapshot: SurfaceSnapshot): void {
  if (snapshot.captureEndMs < snapshot.captureStartMs) fail();
  validateCoverage(snapshot.coverage);
  const nodes = new Map(snapshot.nodes.map(node => [node.id, node]));
  if (nodes.size !== snapshot.nodes.length) fail();
  let textUnits = 0;
  if (snapshot.geometry && (snapshot.geometry.observedAtMs < snapshot.captureStartMs || snapshot.geometry.observedAtMs > snapshot.captureEndMs)) fail();
  if (snapshot.nodes.filter(node => node.focused === true).length > 1) fail();
  for (const node of snapshot.nodes) {
    if ((node.bounds === undefined) !== (node.boundsObservedAtMs === undefined)) fail();
    if (node.bounds !== undefined && snapshot.geometry === undefined) fail();
    if (node.boundsObservedAtMs !== undefined && (node.boundsObservedAtMs < snapshot.captureStartMs || node.boundsObservedAtMs > snapshot.captureEndMs)) fail();
    if (node.axRole !== undefined && /^AX[A-Za-z0-9]{1,62}$/.exec(node.axRole)?.[0] !== node.axRole) fail();
    textUnits += node.text?.length ?? 0;
    if (textUnits > LIMITS.maxTextCodeUnits || node.observedAtMs < snapshot.captureStartMs || node.observedAtMs > snapshot.captureEndMs) fail();
    // Iterative, bounded ancestry walk: no implicit parents from an older snapshot.
    const seen = new Set([node.id]);
    let parent = node.parentId;
    while (parent !== undefined) {
      if (seen.has(parent) || !nodes.has(parent)) fail();
      seen.add(parent);
      parent = nodes.get(parent)!.parentId;
    }
  }
  if (snapshot.mode === 'full') {
    if (snapshot.changes !== undefined || snapshot.baseRevision !== undefined) fail();
  } else {
    const changes = snapshot.changes;
    if (!changes || snapshot.baseRevision === undefined || snapshot.baseRevision >= snapshot.revision) fail();
    const ids = [...changes.added, ...changes.updated, ...changes.removed];
    if (new Set(ids).size !== ids.length || changes.added.some(id => !nodes.has(id)) || changes.updated.some(id => !nodes.has(id)) || changes.removed.some(id => nodes.has(id))) fail();
    if (snapshot.coverage.status !== 'complete' && changes.removed.length !== 0) fail();
  }
}
function validateSelection(snapshot: SelectionSnapshot): void {
  if (snapshot.captureEndMs < snapshot.captureStartMs || snapshot.range.length !== snapshot.text.length) fail();
  validateRange(snapshot.range);
  if (snapshot.coverage.status !== 'partial' || !snapshot.coverage.missingReasons.includes('selection-only')) fail();
}
function validateInputText(payload: InputText, message: Observation): void {
  if (payload.intervalEndMs < payload.intervalStartMs || payload.intervalEndMs - payload.intervalStartMs > 5000 || message.eventTimeMs !== payload.intervalEndMs) fail();
  if (new Set(payload.modifiers).size !== payload.modifiers.length) fail();
  const command = payload.modifiers.includes('command') || payload.modifiers.includes('control');
  if (payload.eventKind === 'text') {
    if (payload.text.length === 0 || command) fail();
  } else if (payload.text !== '' || (payload.eventKind === 'shortcut' && !command)) fail();
  if (payload.coverage.status !== 'partial' || !payload.coverage.missingReasons.includes('input-events-partial') || !payload.coverage.missingReasons.includes('effect-unverified')) fail();
}
function validateText(snapshot: TextSnapshot): void {
  const { coverage, range, selection } = snapshot;
  if (snapshot.captureEndMs < snapshot.captureStartMs) fail();
  validateCoverage(coverage);
  if (range) validateRange(range);
  if (selection) validateRange(selection);
  if (snapshot.valueState === 'read') {
    if (snapshot.text === undefined || range === undefined || range.length !== snapshot.text.length) fail();
    if (snapshot.totalLength !== undefined && range.start + range.length > snapshot.totalLength) fail();
    if (snapshot.scope === 'field' && coverage.status === 'complete' && (range.start !== 0 || snapshot.totalLength !== range.length)) fail();
  } else if (snapshot.text !== undefined || range !== undefined || selection !== undefined || coverage.status === 'complete') fail();
  if (selection && snapshot.totalLength !== undefined && selection.start + selection.length > snapshot.totalLength) fail();
  // Omitted basis keeps wire-v1's legacy accessible-range semantics unchanged.
  if (snapshot.rangeBasis === 'prefix' && range && range.start !== 0) fail();
  if (snapshot.rangeBasis === 'visible') {
    const totalLength = snapshot.totalLength;
    if ((snapshot.source !== 'fixture' && snapshot.source !== 'ax.range' && snapshot.source !== 'ax.marker') || snapshot.scope !== 'accessible-range' || snapshot.valueState !== 'read' ||
        range === undefined || totalLength === undefined || coverage.status !== 'partial' || !coverage.missingReasons.includes('visible-range-only')) fail();
    // Subtraction avoids accepting an imprecise sum near MAX_SAFE_INTEGER.
    if (range.start > totalLength || range.length > totalLength - range.start || (totalLength > 0 && range.length === 0)) fail();
    const end = range.start + range.length;
    if (!Number.isSafeInteger(end)) fail();
    if (selection && (selection.start < range.start || selection.start > end || selection.length > end - selection.start)) fail();
  }
}
export function validateMessage(value: unknown): WireMessage {
  if (value && typeof value === 'object') {
    const version = Object.getOwnPropertyDescriptor(value, 'protocolVersion');
    if (version && !('value' in version)) fail();
    if (version && version.value !== 1) throw new ProtocolError('unsupported-version');
  }
  validateNode(value, schema as unknown as Schema);
  const message = value as WireMessage;
  if (message.type === 'configure') validatePolicy(message.policy);
  if (message.type === 'observation') {
    const payload = message.payload;
    if (payload.kind === 'gap' && payload.providerApplicationId !== undefined
      && /^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$/.exec(payload.providerApplicationId)?.[0] !== payload.providerApplicationId) fail();
    const contentKind = payload.kind === 'text.snapshot' || payload.kind === 'text.changed' || payload.kind === 'surface.snapshot' || payload.kind === 'selection.snapshot' || payload.kind === 'input.text';
    if (message.relation && (!contentKind || new Set(message.relation.evidenceIds).size !== message.relation.evidenceIds.length || message.relation.evidenceIds.includes(message.eventId))) fail();
    // History existence/order/target checks for relation IDs belong to trusted Host admission.
    if (payload.kind === 'surface.snapshot' || payload.kind === 'selection.snapshot' || payload.kind === 'input.text') {
      if (message.target.kind !== 'resolved' || message.actor !== 'unknown' || message.relatedActionIds.length !== 0) fail();
      validateGate(payload.gate, message.stamp.policyRevision);
      if (payload.kind === 'surface.snapshot') validateSurface(payload);
      else if (payload.kind === 'selection.snapshot') validateSelection(payload);
      else validateInputText(payload, message);
    }
    // Application-only identities never stand in for a resolved text/window target.
    if (message.target.kind === 'application' && payload.kind !== 'input.activity') fail();
    if (payload.kind === 'input.activity') {
      if (message.target.kind !== 'application' || message.actor !== 'unknown' || message.relatedActionIds.length !== 0) fail();
      // Fixture sources carry exactly the same gate and coarse time/count limits.
      if (payload.gate.policyRevision !== message.stamp.policyRevision) fail();
      if (payload.intervalStartMs % 1000 !== 0 || payload.intervalEndMs !== payload.intervalStartMs + 1000 || message.eventTimeMs !== payload.intervalEndMs) fail();
      const { pointerReleases, dragSamples, scrollSamples, shortcutPresses } = payload.counts;
      const count = pointerReleases + dragSamples + scrollSamples + shortcutPresses;
      if (count < 1 || count > 256) fail();
      if (payload.coverage.status !== 'partial' || payload.coverage.missingReasons.length === 0) fail();
    }
    if (payload.kind === 'text.snapshot' || payload.kind === 'text.changed') {
      if (message.target.kind !== 'resolved') fail();
      const snapshot = payload.kind === 'text.changed' ? payload.after : payload;
      validateText(snapshot);
      if (snapshot.source !== 'fixture' || snapshot.gate !== undefined) validateGate(snapshot.gate, message.stamp.policyRevision);
      if (payload.kind === 'text.changed' && payload.baseSnapshotId === snapshot.snapshotId) fail();
    }
    if (message.actor === 'agent' && message.relatedActionIds.length === 0) fail();
  }
  if (message.type === 'action.receipt') {
    if (message.endedMs < message.startedMs) fail();
    if (message.effect === 'confirmed' && (message.evidenceIds.length === 0 || message.dispatch === 'not-dispatched' || message.dispatch === 'unknown')) fail();
    if (message.effect === 'refused' && message.dispatch !== 'not-dispatched') fail();
    if (message.dispatch === 'unknown' && message.effect !== 'uncertain') fail();
  }
  return message;
}
function validateDecodedShape(value: unknown, depth = 0): void {
  if (depth > LIMITS.maxDepth) fail();
  if (typeof value === 'string' && !value.isWellFormed()) fail();
  if (Array.isArray(value)) { for (const child of value) validateDecodedShape(child, depth + 1); }
  else if (value && typeof value === 'object') {
    for (const [key, child] of Object.entries(value)) { if (!key.isWellFormed()) fail(); validateDecodedShape(child, depth + 1); }
  }
}
export function decodeFrame(bytes: Uint8Array): WireMessage {
  if (bytes.byteLength > LIMITS.maxFrameBytes) throw new ProtocolError('frame-too-large');
  let value: unknown;
  try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes)); }
  catch { throw new ProtocolError('invalid-message'); }
  validateDecodedShape(value);
  return validateMessage(value);
}
export function encodeFrame(value: WireMessage): Uint8Array {
  validateMessage(value);
  const bytes = new TextEncoder().encode(JSON.stringify(value) + '\n');
  if (bytes.byteLength > LIMITS.maxFrameBytes) throw new ProtocolError('frame-too-large');
  return bytes;
}
// Hard-budget NDJSON framing; a partial unterminated frame cannot grow unbounded.
export class FrameDecoder {
  private readonly buffer = new Uint8Array(LIMITS.maxFrameBytes);
  private length = 0;
  push(chunk: Uint8Array): WireMessage[] {
    const messages: WireMessage[] = [];
    for (const byte of chunk) {
      if (this.length + 1 > LIMITS.maxFrameBytes) { this.length = 0; throw new ProtocolError('frame-too-large'); }
      if (byte === 10) { const complete = this.buffer.slice(0, this.length); this.length = 0; messages.push(decodeFrame(complete)); }
      else this.buffer[this.length++] = byte;
    }
    return messages;
  }
  finish(): void { if (this.length) { this.length = 0; fail(); } }
}
