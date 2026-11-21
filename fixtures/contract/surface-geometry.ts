import type { ContractCase } from './cases.ts';
import type { Observation, SurfaceSnapshot } from '../../src/shared/protocol/generated.ts';
import { surfaceObservation } from './multi-source.ts';

export function geometryObservation(): Observation & { payload: SurfaceSnapshot } {
  const record = surfaceObservation();
  record.payload.geometry = { coordinateSpace: 'window-top-left-point', windowSize: { width: 1000, height: 700 }, observedAtMs: 100 };
  Object.assign(record.payload.nodes[1]!, { bounds: { x: -12.5, y: 30.25, width: 300, height: 20 }, boundsObservedAtMs: 101, axRole: 'AXStaticText', focused: true });
  return record;
}
const valid = (name: string, edit: (record: ReturnType<typeof geometryObservation>) => void): ContractCase => {
  const value = geometryObservation(); edit(value); return { name: `layout-${name}`, valid: true, value };
};
const invalid = (name: string, edit: (record: ReturnType<typeof geometryObservation>) => void): ContractCase => ({ ...valid(name, edit), valid: false });
export const surfaceGeometryCases: ContractCase[] = [
  valid('relative-fraction-negative-coordinate', () => {}),
  valid('unknown-node-geometry', x => { delete x.payload.nodes[1]!.bounds; delete x.payload.nodes[1]!.boundsObservedAtMs; }),
  valid('zero-size-not-proof-of-invisibility', x => { x.payload.nodes[1]!.bounds!.height = 0; }),
  valid('window-size-zero', x => { x.payload.geometry!.windowSize.width = 0; }),
  valid('no-focus-metadata', x => { delete x.payload.nodes[1]!.focused; }),
  valid('explicitly-unfocused-window', x => { x.payload.scope = 'window'; for (const node of x.payload.nodes) node.focused = false; }),
  valid('explicitly-unfocused-window-without-geometry', x => { x.payload.scope = 'window'; delete x.payload.geometry; for (const node of x.payload.nodes) { node.focused = false; delete node.bounds; delete node.boundsObservedAtMs; } }),
  invalid('bounds-without-window-origin', x => { delete x.payload.geometry; }),
  invalid('bounds-without-observation-time', x => { delete x.payload.nodes[1]!.boundsObservedAtMs; }),
  invalid('bounds-time-without-bounds', x => { delete x.payload.nodes[1]!.bounds; }),
  invalid('bounds-stale-time', x => { x.payload.nodes[1]!.boundsObservedAtMs = 99; }),
  invalid('bounds-future-time', x => { x.payload.nodes[1]!.boundsObservedAtMs = 102; }),
  invalid('window-stale-time', x => { x.payload.geometry!.observedAtMs = 99; }),
  invalid('window-future-time', x => { x.payload.geometry!.observedAtMs = 102; }),
  invalid('negative-width', x => { x.payload.nodes[1]!.bounds!.width = -1; }),
  invalid('negative-window-height', x => { x.payload.geometry!.windowSize.height = -1; }),
  invalid('oversized-coordinate', x => { x.payload.nodes[1]!.bounds!.x = 1000001; }),
  invalid('oversized-window', x => { x.payload.geometry!.windowSize.width = 1000001; }),
  invalid('two-focused-nodes', x => { x.payload.nodes[0]!.focused = true; }),
  invalid('non-role-label', x => { x.payload.nodes[1]!.axRole = 'private arbitrary text'; }),
  invalid('newline-role', x => { x.payload.nodes[1]!.axRole = 'AXStaticText\n'; }),
  invalid('extra-desktop-origin', x => { Object.assign(x.payload.geometry!, { desktopX: -100 }); }),
  invalid('wrong-coordinate-space', x => { Object.assign(x.payload.geometry!, { coordinateSpace: 'desktop-pixel' }); }),
  invalid('boolean-coordinate', x => { Object.assign(x.payload.nodes[1]!.bounds!, { x: true }); }),
  invalid('null-bounds-not-omission', x => { Object.assign(x.payload.nodes[1]!, { bounds: null }); }),
];
