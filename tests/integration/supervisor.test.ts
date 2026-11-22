import test from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough, Writable } from 'node:stream';
import { createHash } from 'node:crypto';
import { chmod, mkdtemp, realpath, readFile, readdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { CollectorSupervisor } from '../../src/host/collectors/supervisor.ts';
import { minimalChildEnv } from '../../src/host/collectors/child-env.ts';
import type { SpawnManaged, SpawnSpec, ManagedProcess } from '../../src/host/collectors/process.ts';
import { FrameDecoder, encodeFrame } from '../../src/shared/protocol/validate.ts';
import type { CapturePolicy, Capability, Control, Gap, Observation, Stamp, TextSnapshot, WireMessage } from '../../src/shared/protocol/generated.ts';
import { observation, target } from '../../fixtures/contract/examples.ts';
import { granularGapDiagnostics } from '../../fixtures/contract/gap-diagnostics.ts';
import { menuAction } from '../../fixtures/contract/menu-action.ts';
import { SegmentStore } from '../../src/storage/segment-store.ts';
import { temporary } from './history-store-fixtures.ts';
import { visibleRangeSnapshot } from '../../fixtures/contract/text-range.ts';
import { surfaceObservation, selectionObservation, inputTextObservation } from '../../fixtures/contract/multi-source.ts';
import type { TestContext } from 'node:test';
import { activityObservation, activityIdentity } from './input-activity-fixtures.ts';
import { CollectorDebugTrace } from '../../src/host/collectors/debug-trace.ts';
import { CollectorDebugLog } from '../../src/host/collectors/debug-log.ts';
import type { DebugLogEntry } from '../../src/shared/ipc-types.ts';

const policy: CapturePolicy = { enabled: true, allowedApplicationIds: [target.applicationId], maxTextCodeUnits: 4096, maxPending: 4, debounceMs: 10, maxWaitMs: 30, readTimeoutMs: 50 };
async function setup(t: TestContext, options: {debugTrace?:boolean;onObservation?:(m:Observation,valid:()=>boolean)=>Promise<void>;wrongAck?:boolean;noHello?:boolean;unconfirmedExit?:boolean;exitOnStop?:boolean;allowFixture?:boolean;visibleCapability?:Capability['support']|false;visibleDirection?:Capability['direction'];multiSource?:boolean;diagnostics?:boolean;blockedCommand?:Control['command'];startReason?:string;pauseRunning?:boolean;pauseAfterCommand?:'start'|'resume';terminalAfterStartReply?:boolean;secureClearAfterCommand?:'start'|'resume';secureBlockAfterCommand?:'start'|'resume'; recoveryInStartBatch?: 'waiting' | 'resumed'} = {}) {
  const dir = await realpath(await mkdtemp(join(tmpdir(), 'dsh-supervisor-')));
  t.after(async () => { assert.ok(dir.startsWith(join(await realpath(tmpdir()), 'dsh-supervisor-'))); await rm(dir, { recursive: true, force: true }); });
  const binary = join(dir, 'fake-helper'); const content = 'synthetic managed process fixture'; await writeFile(binary, content, { mode: 0o700 }); await chmod(binary, 0o700);
  let output = new PassThrough(); let stderr = new PassThrough(); let decoder = new FrameDecoder();
  let instance = ''; let owner = ''; let revision = 1; let seq = 0; let terminated = 0; let stamp: Stamp = { captureEpoch: 1, foregroundGeneration: 1, focusGeneration: 1, policyRevision: revision };
  const send = (m:WireMessage) => output.write(encodeFrame(m));
  let state: 'ready'|'running'|'paused'|'stopped' = 'ready';
  const commands: Control['command'][] = []; const blockedReplies: WireMessage[] = []; const spawnSpecs: SpawnSpec[] = [];
  let resolveCurrentDone: (v:{exitCode:number|null;signal:NodeJS.Signals|null})=>void = () => {};
  const makeStdin = () => new Writable({write(chunk,_encoding,callback) {
    for (const message of decoder.push(chunk)) {
      if (message.type === 'configure') {
        revision = message.policyRevision; stamp.policyRevision = revision;
        send({protocolVersion:1,type:'configured',requestId:message.requestId,ownerId:options.wrongAck ? 'wrong' : owner,instanceId:instance,policyRevision:revision});
      } else if (message.type === 'control') {
        commands.push(message.command);
        if (message.command === 'start'||message.command==='resume') { state='running'; stamp={...stamp,captureEpoch:stamp.captureEpoch+1}; }
        if (message.command === 'start' && options.startReason || message.command === options.secureClearAfterCommand) state='paused';
        if (message.command === 'pause') { state=options.pauseRunning?'running':'paused'; stamp={...stamp,captureEpoch:stamp.captureEpoch+1}; }
        if (message.command === 'stop') state='stopped';
        const reply: WireMessage = {protocolVersion:1,type:'state',requestId:message.requestId,instanceId:instance,state,stamp:{...stamp},reason:message.command===options.secureClearAfterCommand?'secure-input-suppressed':message.command==='start'?options.startReason??'':message.command==='pause'&&!options.pauseRunning?'user-paused':'',...(options.diagnostics&&state==='running'?{captureDiagnostics:{axEnablement:'enabled' as const,axAttribute:'manual' as const,observer:'best-effort' as const}}:{})};
        if (message.command === options.blockedCommand) blockedReplies.push(reply);
        else if (message.command === 'start' && options.terminalAfterStartReply) {
          const last: WireMessage={protocolVersion:1,type:'state',requestId:'owner',instanceId:instance,state:'stopped',stamp:{...stamp,captureEpoch:stamp.captureEpoch+1},reason:'signal'};
          output.write(Buffer.concat([encodeFrame(reply),encodeFrame(last)]));
        }
        else if (message.command === 'start' && options.recoveryInStartBatch) {
          stamp = { ...stamp, captureEpoch: stamp.captureEpoch + 1 };
          state = 'paused';
          const batch: WireMessage[] = [reply, readRecoveryFrame(instance, stamp, 'paused', 'read-timeout-recovering')];
          if (options.recoveryInStartBatch === 'resumed') {
            state = 'running'; batch.push(readRecoveryFrame(instance, stamp, 'running', 'read-timeout-recovered'));
          }
          output.write(Buffer.concat(batch.map(m => encodeFrame(m))));
        }
        else if (message.command === options.secureBlockAfterCommand) {
          state='paused'; stamp={...stamp,captureEpoch:stamp.captureEpoch+1};
          const blocked: WireMessage={protocolVersion:1,type:'state',requestId:'secure-input',instanceId:instance,state,stamp:{...stamp},reason:'secure-input-suppressed'};
          output.write(Buffer.concat([encodeFrame(reply),encodeFrame(blocked)]));
        }
        else if (message.command === options.secureClearAfterCommand) {
          state='running'; stamp={...stamp,captureEpoch:stamp.captureEpoch+1};
          const cleared: WireMessage={protocolVersion:1,type:'state',requestId:'secure-input',instanceId:instance,state,stamp:{...stamp},reason:'secure-input-cleared'};
          output.write(Buffer.concat([encodeFrame(reply),encodeFrame(cleared)]));
        }
        else if (message.command === options.pauseAfterCommand) {
          state='paused';stamp={...stamp,captureEpoch:stamp.captureEpoch+1};
          const paused: WireMessage = {protocolVersion:1,type:'state',requestId:'native-lock',instanceId:instance,state,stamp:{...stamp},reason:'screen-locked'};
          output.write(Buffer.concat([encodeFrame(reply),encodeFrame(paused)]));
        } else send(reply);
      }
    } callback();
  }, final(callback) {
    if (options.exitOnStop && !options.unconfirmedExit) {
      resolveCurrentDone({ exitCode: 0, signal: null });
    }
    callback();
  }});
  let stdin = makeStdin();
  const spawn: SpawnManaged = spec => {
    spawnSpecs.push(spec);
    if (stdin.writableEnded) { output = new PassThrough(); stderr = new PassThrough(); decoder = new FrameDecoder(); stdin = makeStdin(); }
    let resolveDone: (v:{exitCode:number|null;signal:NodeJS.Signals|null})=>void = () => {};
    const done = new Promise<{exitCode:number|null;signal:NodeJS.Signals|null}>(resolve => { resolveDone = resolve; });
    resolveCurrentDone = resolveDone;
    instance = spec.argv[spec.argv.indexOf('--instance-id')+1]!; owner = spec.argv[spec.argv.indexOf('--owner-id')+1]!;
    const handle: ManagedProcess = {
      stdin,
      stdout:output,
      stderr,
      done,
      terminate(){terminated++; if(!options.unconfirmedExit)resolveDone({exitCode:0,signal:null});},
      async waitForExit(signal){
        if(options.unconfirmedExit)return false;
        if(!signal){await done;return true;}
        if(signal.aborted)return false;
        return new Promise<boolean>(resolve=>{
          const onAbort=()=>resolve(false);
          signal.addEventListener('abort',onAbort,{once:true});
          void done.then(()=>{signal.removeEventListener('abort',onAbort);resolve(true);});
        });
      },
    };
    const capabilities: Capability[] = [{name:'text.snapshot',direction:'observe',scope:'app-local',support:'supported',reason:''},{name:'input.activity',direction:'observe',scope:'authorized-desktop',support:'supported',reason:'synthetic-only'}];
    if (options.visibleCapability !== false) capabilities.push({name:'text.visible-range',direction:options.visibleDirection??'observe',scope:'app-local',support:options.visibleCapability??'supported',reason:'synthetic-only'});
    if (options.multiSource) for (const name of ['ax.enablement','text.marker','surface.snapshot','selection.snapshot','input.text','menu.action','field.denylist'] as const) capabilities.push({name,direction:'observe',support:'supported',scope:'app-local',reason:'synthetic-only'});
    if (!options.noHello) queueMicrotask(()=>send({protocolVersion:1,type:'hello',instanceId:instance,maxFrameBytes:65536,capabilities}));
    return handle;
  };
  const accepted: Observation[] = [];
  const debugLog = options.debugTrace ? new CollectorDebugLog(join(dir, 'synthetic-store'), true) : undefined;
  await debugLog?.prepare();
  t.after(() => debugLog?.close());
  const supervisor = new CollectorSupervisor({helperPath:binary,helperSha256:createHash('sha256').update(content).digest('hex'),cwd:dir,deviceId:target.deviceId,spawn,allowFixture:options.allowFixture??true,requestTimeoutMs:80,leaseDurationMs:150,debugTrace:options.debugTrace===true,...(debugLog?{debugLog}:{}),onObservation:options.onObservation??(async m=>{accepted.push(m);})});
  t.after(()=>supervisor.stop());
  function context() { stamp={...stamp,focusGeneration:stamp.focusGeneration+1};send({...observation(),instanceId:instance,eventId:`${instance}:${++seq}`,seq,stamp:{...stamp},payload:{kind:'context.changed',reason:'focus'}}); }
  function text(extra:Partial<Observation>={}) { const m:Observation={...observation(),instanceId:instance,eventId:`${instance}:${++seq}`,seq,stamp:{...stamp},...extra}; send(m); return m; }
  return {supervisor,accepted,context,text,send,commands,spawnSpecs,stderr,debugLog,releaseReplies(){for(const reply of blockedReplies.splice(0))send(reply);},get blockedReplies(){return blockedReplies.length;},get terminated(){return terminated;},get instance(){return instance;},get stamp(){return {...stamp};},activity(extra:Partial<Observation>={}){const value={...activityObservation(++seq,{...stamp},instance),...extra};send(value);return value;}};
}
const turn = () => new Promise<void>(resolve=>setImmediate(resolve));

test('not-declared-sensitive evidence requires explicit field policy and helper capability',async t=>{
  const missing=await setup(t);await assert.rejects(missing.supervisor.start({...policy,fieldSecurity:'denylist'}),/content-capability-unavailable/);
  for(const mode of ['strict','denylist'] as const){
    const h=await setup(t,{multiSource:true,allowFixture:false});await h.supervisor.start({...policy,fieldSecurity:mode});h.context();await turn();
    const base=observation();if(base.payload.kind!=='text.snapshot')throw Error('fixture');
    h.text({payload:{...base.payload,source:'ax.range',gate:{secure:'not-declared-sensitive',privateState:'normal',policyRevision:h.stamp.policyRevision}}});await turn();
    assert.equal(h.supervisor.status().accepted.text,mode==='denylist'?1:0);assert.equal(h.supervisor.status().state,'running');
  }
});
test('field blacklist policy gates every new content channel independently of fixture assertions',async t=>{
  for(const fieldSecurity of ['strict','denylist'] as const){
    const h=await setup(t,{multiSource:true,allowFixture:false});await h.supervisor.start({...policy,fieldSecurity,captureScope:'region',selectionCapture:true,inputText:true});h.context();await turn();
    for(const candidate of [surfaceObservation(),selectionObservation(),inputTextObservation()]){
      candidate.payload.gate.secure='not-declared-sensitive';candidate.payload.gate.policyRevision=h.stamp.policyRevision;
      h.text({eventTimeMs:candidate.eventTimeMs,payload:candidate.payload});await turn();
    }
    const status=h.supervisor.status();for(const value of [status.accepted.surface,status.accepted.selection,status.accepted.inputText])assert.equal(value,fieldSecurity==='denylist'?1:0);
  }
});
test('unfocused window surface is admitted without creating focused selection or input evidence',async t=>{
  const h=await setup(t,{multiSource:true,allowFixture:false});
  await h.supervisor.start({...policy,captureScope:'window',selectionCapture:true,inputText:true});h.context();await turn();
  const event=surfaceObservation();event.payload.scope='window';event.payload.source='ax.tree';
  for(const node of event.payload.nodes)node.focused=false;
  h.text({eventTimeMs:event.eventTimeMs,payload:event.payload});await turn();
  h.text({payload:{kind:'gap',reason:'read-error',count:1,diagnostic:{code:'focused-field-unavailable'}}});await turn();
  const status=h.supervisor.status();assert.equal(status.accepted.surface,1);assert.equal(status.accepted.text,0);
  assert.equal(status.accepted.selection,0);assert.equal(status.accepted.inputText,0);
  assert.ok(h.accepted.some(record=>record.payload.kind==='surface.snapshot'));
  assert.ok(h.accepted.some(record=>record.payload.kind==='gap'&&record.payload.diagnostic?.code==='focused-field-unavailable'));
});
test('capture diagnostics are fixed detached metadata and clear on explicit pause/stop',async t=>{
  const h=await setup(t,{diagnostics:true});await h.supervisor.start(policy);assert.equal(h.supervisor.status().captureDiagnostics?.axEnablement,'enabled');
  const status=h.supervisor.status();status.captureDiagnostics!.axEnablement='denied';assert.equal(h.supervisor.status().captureDiagnostics?.axEnablement,'enabled');
  await h.supervisor.pause();assert.equal(h.supervisor.status().captureDiagnostics,null);await h.supervisor.stop();assert.equal(h.supervisor.status().captureDiagnostics,null);
});
test('denylist never admits excluded applications even with a forged safe content gate',async t=>{
  const h=await setup(t);await h.supervisor.start({...policy,applicationScope:'denylist',allowedApplicationIds:[],allowBrowserContent:true});
  for(const applicationId of ['com.1password.1password','com.1password.safari.extension','com.apple.Safari']){
    const blocked={...target,applicationId};h.text({target:{kind:'resolved',identity:blocked},payload:{kind:'context.changed',reason:'focus'}});h.text({target:{kind:'resolved',identity:blocked}});
  }
  await turn();assert.equal(h.accepted.length,0);assert.equal(h.supervisor.status().state,'running');
});
test('new channels require explicit policy and actual helper capability before start',async t=>{
  const missing=await setup(t);await assert.rejects(missing.supervisor.start({...policy,inputText:true}),/content-capability-unavailable/);assert.equal(missing.accepted.length,0);
  const h=await setup(t,{multiSource:true});await h.supervisor.start({...policy,applicationScope:'denylist',allowedApplicationIds:[],inputText:true,selectionCapture:true,captureScope:'region'});h.context();await turn();
  const base=observation();const gate={secure:'safe' as const,privateState:'normal' as const,policyRevision:h.stamp.policyRevision};
  const payload={kind:'input.text' as const,source:'fixture' as const,scope:'field' as const,eventKind:'text' as const,text:'synthetic',modifiers:[],intervalStartMs:base.eventTimeMs,intervalEndMs:base.eventTimeMs,eventCount:1,surfaceId:'synthetic-surface',gate,secureInput:'inactive' as const,coverage:{status:'partial' as const,truncated:false,missingReasons:['input-events-partial','effect-unverified']},effect:'unverified' as const};
  h.text({payload});await turn();assert.equal(h.supervisor.status().accepted.inputText,1);assert.equal(h.supervisor.status().accepted.text,0);
  await h.supervisor.pause();h.text({payload});await turn();assert.equal(h.supervisor.status().accepted.inputText,1);
});
test('specific gap diagnostics count only committed still-authorized evidence and return detached status',async t=>{
  const h=await setup(t,{debugTrace:true});await h.supervisor.start(policy);
  h.text({target:{kind:'unresolved',reason:'policy-boundary'},payload:{kind:'gap',reason:'policy-boundary',count:1,diagnostic:{code:'focused-role-not-text',role:'AXMenuItem'}}});await turn();
  assert.deepEqual(h.supervisor.status().lastGapDiagnostic,{code:'focused-role-not-text',role:'AXMenuItem'});assert.equal(h.supervisor.status().accepted.gaps,1);
  const copy=h.supervisor.status();copy.lastGapDiagnostic!.code='secure-field';
  assert.equal(h.supervisor.status().lastGapDiagnostic!.code,'focused-role-not-text');
  await h.supervisor.pause();h.text({target:{kind:'unresolved',reason:'policy-boundary'},payload:{kind:'gap',reason:'policy-boundary',count:1,diagnostic:{code:'secure-field'}}});await turn();
  assert.equal(h.supervisor.status().lastGapDiagnostic!.code,'focused-role-not-text');assert.equal(h.supervisor.status().accepted.gaps,1);
});
test('failed or delayed gap commits cannot repopulate diagnostic state after pause',async t=>{
  let release!:()=>void;const blocked=new Promise<void>(resolve=>{release=resolve;});
  const h=await setup(t,{debugTrace:true,onObservation:async()=>{await blocked;}});await h.supervisor.start(policy);
  h.text({target:{kind:'unresolved',reason:'policy-boundary'},payload:{kind:'gap',reason:'policy-boundary',count:3,providerApplicationId:target.applicationId,diagnostic:{code:'focused-role-not-text',role:'AXMenuItem'}}});await turn();
  const paused=h.supervisor.pause();release();await paused;assert.equal(h.supervisor.status().lastGapDiagnostic,null);assert.equal(h.supervisor.status().accepted.gaps,0);
});

test('provider admission rejects excluded or disallowed browsers without leaking them to counters',async t=>{
  const h=await setup(t);await h.supervisor.start({...policy,applicationScope:'denylist',allowedApplicationIds:[],excludedApplicationIds:['test.excluded']});
  for(const id of ['com.1password.1password','com.apple.Safari','com.google.Chrome','test.excluded.child']){
    h.text({target:{kind:'unresolved',reason:'focus-unavailable'},payload:{kind:'gap',reason:'read-error',count:1,providerApplicationId:id}});await turn();
  }
  assert.equal(h.supervisor.status().accepted.gaps,0);assert.equal(h.accepted.length,0);
  h.text({target:{kind:'unresolved',reason:'focus-unavailable'},payload:{kind:'gap',reason:'read-error',count:2,providerApplicationId:'test.new-source'}});await turn();
  assert.equal(h.supervisor.status().accepted.gaps,1);assert.equal(h.supervisor.status().lastGapReason,'read-error');
});
test('storage-rejected provider gaps never enter committed counts',async t=>{
  const h=await setup(t,{onObservation:async()=>{throw Error('synthetic commit failure');}});await h.supervisor.start(policy);
  h.text({target:{kind:'unresolved',reason:'focus-unavailable'},payload:{kind:'gap',reason:'read-error',count:3,providerApplicationId:target.applicationId}});await turn();
  assert.equal(h.supervisor.status().reason,'storage-commit-failed');assert.equal(h.supervisor.status().accepted.gaps,0);
});
test('granular gaps survive native frame admission and encrypted SegmentStore reopen without changing legacy gaps',
  { skip: process.platform !== 'darwin' && process.platform !== 'win32', timeout: 15_000 }, async t => {
    const temp = await temporary();
    const opts = { root: temp.root, keyProvider: temp.provider, clock: () => 101 };
    let store: SegmentStore | undefined;
    try {
      const opened = await SegmentStore.open(opts); store = opened;
      const writes: Promise<void>[] = [];
      const h = await setup(t, { multiSource: true, allowFixture: false, onObservation: (message, isCurrent) => {
        const writing = opened.append(message, { generation: opened.generation, isCurrent });
        writes.push(writing); return writing;
      } });
      try {
        await h.supervisor.start({ ...policy, captureScope: 'window', inputText: true });
        const payloads: Gap[] = [
          ...granularGapDiagnostics.map(([code, reason], index): Gap => ({ kind: 'gap', reason, count: index + 1,
            providerApplicationId: target.applicationId, diagnostic: { code } })),
          { kind: 'gap', reason: 'stale', count: 1, providerApplicationId: target.applicationId, diagnostic: { code: 'input-context-unverified' } },
          { kind: 'gap', reason: 'read-error', count: 1, providerApplicationId: target.applicationId, diagnostic: { code: 'surface-boundary-unverified' } },
          { kind: 'gap', reason: 'stale', count: 1 },
        ];
        const signals: Observation[] = [];
        for (const payload of payloads) {
          signals.push(h.text({ target: { kind: 'unresolved', reason: 'focus-unavailable' }, payload }));
          await turn();
          assert.equal(writes.length, signals.length);
          await writes.at(-1);
          await turn();
          assert.equal(h.supervisor.status().accepted.gaps, signals.length);
        }
        const status = h.supervisor.status();
        assert.equal(status.accepted.inputText + status.accepted.surface + status.accepted.text, 0);
        await h.supervisor.stop();
        await opened.close();
        const reopened = await SegmentStore.open(opts); store = reopened;
        assert.deepEqual((await reopened.search({ kind: 'gap', limit: 20 })).records, signals);
        assert.equal(reopened.status().records, payloads.length);
      } finally { await h.supervisor.stop(); }
    } finally { await store?.close(); await temp.cleanup(); }
});

test('input activity is independently disabled by default and requires allowed application/device',async t=>{
  const off=await setup(t);await off.supervisor.start(policy);off.activity();await turn();assert.equal(off.accepted.length,0);
  const on=await setup(t);await on.supervisor.start({...policy,inputActivity:true});on.activity();on.activity({target:{kind:'application',identity:activityIdentity({deviceId:'other'})}});on.activity({target:{kind:'application',identity:activityIdentity({applicationId:'blocked.app'})}});await turn();
  assert.equal(on.accepted.length,1);assert.equal(on.supervisor.status().accepted.activity,1);assert.equal(on.supervisor.status().accepted.text,0);
});
test('application activity pins identity within an epoch even before a text boundary exists',async t=>{
  const h=await setup(t);await h.supervisor.start({...policy,inputActivity:true});h.activity();await turn();
  h.activity({target:{kind:'application',identity:activityIdentity({processStartTime:'reused-pid'})}});await turn();
  assert.equal(h.supervisor.status().state,'failed');assert.equal(h.supervisor.status().reason,'input-activity-identity-changed');assert.equal(h.accepted.length,1);
});
test('application activity retains first-event stamp across text reconciliation but not capture epoch boundaries',async t=>{
  let release!:()=>void;const blocked=new Promise<void>(resolve=>{release=resolve;});const valid:boolean[]=[];
  const h=await setup(t,{onObservation:async(m,current)=>{if(m.payload.kind==='input.activity'){await blocked;valid.push(current());}}});
  await h.supervisor.start({...policy,inputActivity:true});const stamp=h.stamp;h.activity();await turn();h.context();h.context();release();await turn();assert.deepEqual(valid,[true]);
  h.activity({stamp});await turn();assert.equal(h.supervisor.status().accepted.activity,2);
  const paused=h.supervisor.pause();h.activity({stamp});await paused;assert.ok(h.supervisor.status().dropped>=1);
});
test('old activity buffered after native application boundary never reaches persistence',async t=>{
  const h=await setup(t);await h.supervisor.start({...policy,inputActivity:true});const old=h.stamp;
  h.text({stamp:{...old,captureEpoch:old.captureEpoch+1},target:{kind:'unresolved',reason:'focus-unavailable'},payload:{kind:'context.changed',reason:'application'}});h.activity({stamp:old});await turn();
  assert.equal(h.accepted.filter(m=>m.payload.kind==='input.activity').length,0);
});
test('supervisor activation does not spawn; matching ACK and context precede ingestion',async t=>{
  const h=await setup(t);assert.equal(h.supervisor.status().state,'stopped');assert.equal(h.terminated,0);
  await h.supervisor.start(policy); h.context(); h.text(); await turn();
  assert.equal(h.supervisor.status().state,'running');assert.deepEqual(h.accepted.map(x=>x.payload.kind),['context.changed','text.snapshot']);assert.equal(h.supervisor.status().accepted.text,1);
  await h.supervisor.stop();assert.equal(h.supervisor.status().state,'stopped');assert.ok(h.terminated>=1);
});
test('unconfirmed process exit is failed and cannot launch a replacement',async t=>{
  const h=await setup(t,{unconfirmedExit:true});await h.supervisor.start(policy);const stopped=await h.supervisor.stop();
  assert.equal(stopped.state,'failed');assert.equal(stopped.reason,'helper-exit-unconfirmed');await assert.rejects(h.supervisor.start(policy),/start-not-available/);
});
test('concurrent stop shares one teardown instead of replaying control',async t=>{
  const h=await setup(t);await h.supervisor.start(policy);const first=h.supervisor.stop();const second=h.supervisor.stop();
  assert.equal(first,second);assert.equal((await first).state,'stopped');assert.equal(h.terminated,1);
});
test('wrong ACK never enables ingress and reaps child',async t=>{
  const h=await setup(t,{wrongAck:true});await assert.rejects(h.supervisor.start(policy));assert.equal(h.supervisor.status().state,'failed');assert.ok(h.terminated>=1);assert.equal(h.accepted.length,0);
});
test('missing hello fails bounded and never starts recording',async t=>{
  const h=await setup(t,{noHello:true});await assert.rejects(h.supervisor.start(policy));assert.equal(h.supervisor.status().state,'failed');assert.ok(h.terminated>=1);
});
test('untrusted actor and wrong target never reach sink',async t=>{
  const h=await setup(t);await h.supervisor.start(policy);h.context();h.text({actor:'agent',relatedActionIds:['invented']});h.text({target:{kind:'resolved',identity:{...target,deviceId:'other'}}});await turn();
  assert.equal(h.accepted.filter(m=>m.payload.kind==='text.snapshot').length,0);assert.equal(h.supervisor.status().dropped,2);
});
test('pause immediately fences a delayed sink and new snapshots',async t=>{
  let release:()=>void=()=>{};const blocked=new Promise<void>(resolve=>{release=resolve;});let allowed: boolean|undefined;
  const h=await setup(t,{onObservation:async(m,valid)=>{if(m.payload.kind==='text.snapshot'){await blocked;allowed=valid();}}});
  await h.supervisor.start(policy);h.context();h.text();await turn();const paused=h.supervisor.pause();h.text();release();await paused;
  assert.equal(allowed,false);assert.equal(h.supervisor.status().state,'paused');assert.ok(h.supervisor.status().dropped>=1);
});
test('native asynchronous lock state fences content without waiting on UI',async t=>{
  const h=await setup(t);await h.supervisor.start(policy);h.context();await turn();h.send({protocolVersion:1,type:'state',instanceId:h.instance,requestId:'native-lock',state:'paused',stamp:{...h.stamp,captureEpoch:h.stamp.captureEpoch+1},reason:'desktop-unavailable'});h.text();await turn();
  assert.equal(h.supervisor.status().state,'paused');assert.equal(h.supervisor.status().reason,'desktop-unavailable');assert.equal(h.accepted.filter(m=>m.payload.kind==='text.snapshot').length,0);
});

function readRecoveryFrame(instanceId: string, stamp: Stamp, state: 'running' | 'paused', reason: string): Extract<WireMessage, { type: 'state' }> {
  return { protocolVersion: 1, type: 'state', requestId: 'read-recovery', instanceId, state, stamp, reason };
}

test('exact native recovery boundary invalidates pending evidence and admits only a fresh epoch', async t => {
  let release!: () => void; const held = new Promise<void>(resolve => { release = resolve; });
  const accepted: Observation[] = [];
  const h = await setup(t, { multiSource: true, onObservation: async (m, current) => {
    if (m.payload.kind === 'text.snapshot' && m.seq === 2) await held;
    if (current()) accepted.push(m);
  } });
  try {
    await h.supervisor.start({ ...policy, inputText: true }); h.context(); const old = h.text(); await turn();
    const fresh = { ...h.stamp, captureEpoch: h.stamp.captureEpoch + 1, focusGeneration: h.stamp.focusGeneration + 1 };
    h.send(readRecoveryFrame(h.instance, fresh, 'paused', 'read-timeout-recovering'));
    assert.equal(h.supervisor.status().state, 'paused'); assert.equal(h.supervisor.status().reason, 'read-timeout-recovering');
    h.text({ stamp: fresh }); // Even a fresh-stamp frame is refused during the pause.
    h.send(readRecoveryFrame(h.instance, fresh, 'running', 'read-timeout-recovered'));
    h.text({ stamp: old.stamp });
    const gap = h.text({ stamp: fresh, target: { kind: 'unresolved', reason: 'policy-boundary' }, payload: { kind: 'gap', reason: 'timeout', count: 1, diagnostic: { code: 'read-deadline' } } });
    const resolved = { ...fresh, focusGeneration: fresh.focusGeneration + 1 };
    release(); await turn(); // Allow the native's gap to commit before the following resolved boundary.
    h.text({ stamp: resolved, payload: { kind: 'context.changed', reason: 'focus' } });
    const replacement = h.text({ stamp: resolved }); await turn();
    assert.equal(h.supervisor.status().state, 'running');
    assert.deepEqual(accepted.filter(m => m.payload.kind === 'text.snapshot').map(m => m.eventId), [replacement.eventId]);
    assert.ok(accepted.some(m => m.eventId === gap.eventId));
    assert.deepEqual(h.commands, ['start']);
  } finally { release(); }
});

test('recovery notices cannot bypass owner pause, another boundary, or exact epoch matching', async t => {
  for (const scenario of ['owner', 'lock', 'wrong-stamp', 'plain-desktop', 'unmatched'] as const) {
    const h = await setup(t, { multiSource: true, blockedCommand: 'pause' });
    await h.supervisor.start({ ...policy, inputText: true });
    const fresh = { ...h.stamp, captureEpoch: h.stamp.captureEpoch + 1 };
    if (scenario !== 'unmatched') h.send(readRecoveryFrame(h.instance, fresh, 'paused', 'read-timeout-recovering'));
    if (scenario === 'owner') {
      const pause = h.supervisor.pause();
      h.send(readRecoveryFrame(h.instance, fresh, 'running', 'read-timeout-recovered'));
      h.text({ stamp: fresh }); h.releaseReplies();
      assert.equal((await pause).reason, 'user-paused'); assert.equal(h.terminated, 0);
    } else {
      if (scenario === 'lock') h.send({ ...readRecoveryFrame(h.instance, { ...fresh, captureEpoch: fresh.captureEpoch + 1 }, 'paused', 'screen-locked'), requestId: 'desktop' });
      if (scenario === 'plain-desktop') h.send({ ...readRecoveryFrame(h.instance, fresh, 'running', 'desktop-unlocked'), requestId: 'desktop' });
      else h.send(readRecoveryFrame(h.instance, scenario === 'wrong-stamp' ? { ...fresh, focusGeneration: fresh.focusGeneration + 1 } : fresh, 'running', 'read-timeout-recovered'));
      assert.equal(h.supervisor.status().reason, 'unexpected-helper-response');
      assert.equal(h.supervisor.status().state, 'failed');
    }
    assert.equal(h.accepted.length, 0, scenario);
  }
});

test('actual state frames preserve retirement and input fault reasons without granting recovery or dropping the helper', async t => {
  for (const reason of ['worker-retirement-ack-failed', 'worker-retirement-exit-unconfirmed',
    'input-monitoring-required', 'input-monitoring-disabled', 'input-monitoring-unavailable', 'worker-retirement-unknown']) {
    const h = await setup(t, { multiSource: true });
    await h.supervisor.start({ ...policy, inputText: true });
    const fresh = { ...h.stamp, captureEpoch: h.stamp.captureEpoch + 1 };
    h.send({ ...readRecoveryFrame(h.instance, fresh, 'paused', reason), requestId: 'input' });
    h.text({ stamp: fresh }); await turn();
    assert.equal(h.supervisor.status().state, 'paused');
    assert.equal(h.supervisor.status().reason, reason === 'worker-retirement-unknown' ? 'desktop-unavailable' : reason);
    assert.equal(h.terminated, 0);
    assert.deepEqual(h.commands.filter(command => command !== 'heartbeat'), ['start']);
    assert.equal(h.accepted.length, 0);
    // A retirement failure is not a temporary privacy or read-recovery pause.
    h.send({ ...readRecoveryFrame(h.instance, fresh, 'running', 'secure-input-cleared'), requestId: 'secure-input' });
    assert.equal(h.supervisor.status().state, 'failed');
    assert.equal(h.supervisor.status().reason, 'unexpected-helper-response');
  }
});

test('startup refusal preserves Input Monitoring authorization failure after teardown', async t => {
  const h = await setup(t, { startReason: 'input-monitoring-required' });
  await assert.rejects(h.supervisor.start({ ...policy, inputActivity: true }), /^Error: input-monitoring-required$/);
  assert.equal(h.supervisor.status().state, 'failed');
  assert.equal(h.supervisor.status().reason, 'input-monitoring-required');
});

test('recovery terminal status is retained without a forced Host restart', async t => {
  const h = await setup(t, { multiSource: true }); await h.supervisor.start({ ...policy, inputText: true });
  const first = { ...h.stamp, captureEpoch: h.stamp.captureEpoch + 1 };
  h.send(readRecoveryFrame(h.instance, first, 'paused', 'read-timeout-recovering'));
  h.send(readRecoveryFrame(h.instance, { ...first, captureEpoch: first.captureEpoch + 1 }, 'paused', 'worker-exit-unconfirmed'));
  assert.equal(h.supervisor.status().state, 'paused'); assert.equal(h.supervisor.status().reason, 'worker-exit-unconfirmed');
  assert.equal(h.terminated, 0);
});

test('matched Start ACK remains authoritative across coalesced recovery frames', async t => {
  for (const scenario of ['waiting', 'resumed'] as const) {
    const h = await setup(t, { multiSource: true, recoveryInStartBatch: scenario });
    const status = await h.supervisor.start({ ...policy, inputText: true });
    assert.equal(status.state, scenario === 'waiting' ? 'paused' : 'running');
    if (scenario === 'waiting') {
      h.text(); await turn(); assert.deepEqual(h.accepted, []);
      h.send(readRecoveryFrame(h.instance, h.stamp, 'running', 'read-timeout-recovered'));
    }
    h.context(); const exact = h.text(); await turn();
    assert.ok(h.accepted.some(m => m.eventId === exact.eventId));
    assert.equal(h.supervisor.status().state, 'running');
  }
});

test('an owner Pause still receives its matching ACK when native safety cancels recovery', async t => {
  const h = await setup(t, { multiSource: true, blockedCommand: 'pause' });
  await h.supervisor.start({ ...policy, inputText: true });
  const fresh = { ...h.stamp, captureEpoch: h.stamp.captureEpoch + 1 };
  h.send(readRecoveryFrame(h.instance, fresh, 'paused', 'read-timeout-recovering'));
  const pending = h.supervisor.pause();
  h.send({ ...readRecoveryFrame(h.instance, fresh, 'paused', 'input-monitoring-required'), requestId: 'input' });
  h.releaseReplies();
  assert.equal((await pending).reason, 'user-paused'); assert.equal(h.terminated, 0);
});

test('native recovery terminal can race an explicit Resume without reopening ingress ahead of its ACK', async t => {
  const h = await setup(t, { multiSource: true, blockedCommand: 'resume' });
  await h.supervisor.start({ ...policy, inputText: true });
  // Simulate a terminal notice buffered before the later owner ACK.
  const first = { ...h.stamp, captureEpoch: h.stamp.captureEpoch + 1 };
  h.send(readRecoveryFrame(h.instance, first, 'paused', 'read-timeout-recovering'));
  const resume = h.supervisor.resume();
  const terminal = { ...first, captureEpoch: first.captureEpoch + 1 };
  h.send(readRecoveryFrame(h.instance, terminal, 'paused', 'read-timeout-unrecoverable'));
  assert.equal(h.supervisor.status().reason, 'read-timeout-unrecoverable');
  h.text({ stamp: terminal }); await turn(); assert.deepEqual(h.accepted, []);
  // The stale fixture ACK is correctly refused; it cannot clear either pause.
  h.releaseReplies(); await assert.rejects(resume, /resume-failed/);
  assert.equal(h.supervisor.status().state, 'paused'); assert.equal(h.terminated, 0);
});

test('successful explicit stop clears stale pause and native refusal reasons',async t=>{
  const h=await setup(t);await h.supervisor.start(policy);await h.supervisor.pause();
  assert.equal(h.supervisor.status().reason,'user-paused');
  assert.deepEqual({state:(await h.supervisor.stop()).state,reason:h.supervisor.status().reason},{state:'stopped',reason:''});
  const refused=await setup(t,{startReason:'permission-denied'});
  await assert.rejects(refused.supervisor.start(policy),/permission-denied/);
  assert.equal(refused.supervisor.status().reason,'permission-denied');
  assert.equal((await refused.supervisor.stop()).reason,'');
});

test('superseded waiting contexts do not consume slots at the hard limit', async t => {
  let release!: () => void;
  const held = new Promise<void>(resolve => { release = resolve; });
  const committed: number[] = [];
  const h = await setup(t, { onObservation: async (m, current) => {
    if (m.seq === 1) await held;
    if (current()) committed.push(m.seq);
  } });
  try {
    await h.supervisor.start({ ...policy, maxPending: 16, inputActivity: true });
    h.context(); await turn();
    const activity = h.activity(); // Unlike per-focus content, this stays authorized within the same capture epoch.
    for (let i = 0; i < 30; i++) { h.context(); assert.ok(h.supervisor.status().pending <= 16); }
    assert.equal(h.supervisor.status().state, 'running');
    release(); await turn();
    assert.deepEqual(committed, [activity.seq, 32]);
    assert.equal(h.supervisor.status().accepted.activity, 1);
    assert.equal(h.supervisor.status().pending, 0);
    assert.equal(h.supervisor.status().dropped, 29);
    assert.equal(h.terminated, 0);
  } finally { release(); }
});

test('current observations at the hard limit still fail closed and log bounded fault metadata', async t => {
  let release!: () => void;
  const held = new Promise<void>(resolve => { release = resolve; });
  let sinkCalls = 0, canCommit: (() => boolean) | undefined;
  const h = await setup(t, { debugTrace: true, onObservation: async (_m, current) => { sinkCalls++; canCommit = current; await held; } });
  try {
    await h.supervisor.start({ ...policy, maxPending: 16 });
    h.context(); await turn();
    const gap = () => h.text({ payload: { kind: 'gap', reason: 'stale', count: 1 } });
    for (let i = 0; i < 15; i++) gap();
    assert.equal(h.supervisor.status().pending, 16); assert.equal(canCommit?.(), true);
    gap();
    assert.equal(h.supervisor.status().reason, 'host-backpressure');
    assert.equal(h.supervisor.status().pending, 16); assert.equal(canCommit?.(), false);
    release(); await turn();
    assert.equal(sinkCalls, 1); assert.equal(h.supervisor.status().pending, 0);
    assert.equal(h.supervisor.status().accepted.gaps, 0); assert.equal(h.terminated, 1);
    await h.debugLog!.flush();
    const files = (await readdir(h.debugLog!.directory)).filter(name => name.endsWith('.jsonl'));
    const lines = (await Promise.all(files.map(name => readFile(join(h.debugLog!.directory, name), 'utf8')))).join('').trim().split('\n');
    const faults = lines.map(line => JSON.parse(line) as DebugLogEntry).filter(value => value.event === 'collector-fault');
    assert.equal(faults.length, 1); assert.equal(faults[0]?.detail?.reason, 'host-backpressure');
  } finally { release(); }
});

test('storage failure settling during stop is not reported as a successful stop',async t=>{
  let release!:()=>void;const block=new Promise<void>(resolve=>{release=resolve;});
  const h=await setup(t,{onObservation:async message=>{if(message.payload.kind==='text.snapshot'){await block;throw new Error('synthetic sink refusal');}}});
  await h.supervisor.start(policy);h.context();h.text();await turn();
  const stopping=h.supervisor.stop();release();const status=await stopping;
  assert.equal(status.state,'failed');assert.equal(status.reason,'storage-commit-failed');
});

test('terminal collector fault preserves its first cause through native teardown and late control replies', async t => {
  t.mock.timers.enable({apis:['setInterval']});
  const h=await setup(t,{debugTrace:true,blockedCommand:'heartbeat',onObservation:async m=>{
    if(m.payload.kind==='text.snapshot')throw new Error('SYNTHETIC_PRIVATE_SINK_FAILURE');
  }});
  await h.supervisor.start(policy);
  t.mock.timers.tick(50); assert.equal(h.blockedReplies,1);
  h.context();h.text();await turn();
  assert.equal(h.supervisor.status().reason,'storage-commit-failed');
  const state=(requestId:string,state: 'stopped'|'paused'|'running',reason:string)=>({protocolVersion:1 as const,type:'state' as const,requestId,instanceId:h.instance,state,stamp:{...h.stamp,captureEpoch:h.stamp.captureEpoch+1},reason});
  // Model the final state sent by a native helper after receiving SIGTERM.
  h.send(state('owner','stopped','signal'));
  h.releaseReplies(); // A heartbeat already rejected by the first fault must not re-fail or reopen it.
  h.send(state('secure-input','paused','secure-input-suppressed'));
  h.send(state('secure-input','running','secure-input-cleared'));
  h.text();await turn();
  const status=h.supervisor.status();
  assert.equal(status.state,'failed');assert.equal(status.reason,'storage-commit-failed');
  assert.equal(status.accepted.text,0);assert.equal(h.terminated,1);assert.ok(!h.commands.includes('resume'));
  await h.debugLog!.flush();
  const files=(await readdir(h.debugLog!.directory)).filter(name=>name.endsWith('.jsonl'));
  const jsonl=(await Promise.all(files.map(name=>readFile(join(h.debugLog!.directory,name),'utf8')))).join('');
  const faults=jsonl.trim().split('\n').map(line=>JSON.parse(line) as DebugLogEntry).filter(value=>value.event==='collector-fault');
  assert.deepEqual(faults.map(({detail})=>({reason:detail?.reason,phase:detail?.phase})),[{reason:'storage-commit-failed',phase:'running'}]);
  assert.equal(jsonl.includes('SYNTHETIC_PRIVATE_SINK_FAILURE'),false);
});

test('native terminal notices fail closed with the exact allowlisted first cause',async t=>{
  for(const scenario of [
    {id:'lease',reason:'lease-expired',expected:'helper-lease-expired'},
    {id:'owner',reason:'owner-eof',expected:'helper-owner-eof'},
    {id:'owner',reason:'parent-death',expected:'helper-parent-death'},
    {id:'owner',reason:'signal',expected:'helper-signaled'},
    {id:'owner',reason:'SYNTHETIC_PRIVATE_UNKNOWN_NATIVE_REASON',expected:'unexpected-helper-response'},
    {id:'SYNTHETIC_PRIVATE_UNKNOWN_ID',reason:'lease-expired',expected:'unexpected-helper-response'},
    {id:'lease',reason:'lease-expired',policyRevision:99,expected:'unexpected-helper-response'},
    {id:'lease',reason:'lease-expired',oldStamp:true,expected:'unexpected-helper-response'},
  ]) {
    const h=await setup(t);await h.supervisor.start(policy);h.context();await turn();
    const {id,reason,policyRevision=h.stamp.policyRevision,oldStamp,expected}=scenario;
    h.send({protocolVersion:1,type:'state',instanceId:h.instance,requestId:id,state:'stopped',stamp:{...h.stamp,policyRevision,captureEpoch:h.stamp.captureEpoch+(oldStamp?-1:1)},reason});
    h.text();await turn();const status=h.supervisor.status();
    assert.deepEqual([status.state,status.reason,status.accepted.text,h.terminated],['failed',expected,0,1]);
  }
});

test('lease expiry remains the first cause when an outstanding heartbeat is rejected',async t=>{
  t.mock.timers.enable({apis:['setInterval']});
  const h=await setup(t,{blockedCommand:'heartbeat'});await h.supervisor.start(policy);
  t.mock.timers.tick(50);assert.equal(h.blockedReplies,1);
  h.send({protocolVersion:1,type:'state',instanceId:h.instance,requestId:'lease',state:'stopped',stamp:{...h.stamp,captureEpoch:h.stamp.captureEpoch+1},reason:'lease-expired'});
  await turn();
  assert.deepEqual([h.supervisor.status().state,h.supervisor.status().reason,h.terminated],['failed','helper-lease-expired',1]);
});

test('a terminal frame after the Start ACK wins before its continuation and remains failed',async t=>{
  const h=await setup(t,{startReason:'permission-denied',terminalAfterStartReply:true});
  await assert.rejects(h.supervisor.start(policy),/helper-signaled/);
  assert.deepEqual([h.supervisor.status().state,h.supervisor.status().reason,h.accepted.length],['failed','helper-signaled',0]);
  assert.deepEqual(h.commands,['start']); // Do not wait on another ACK from a failing child.
  await h.supervisor.stop();
  assert.deepEqual([h.supervisor.status().state,h.supervisor.status().reason],['stopped','']);
});

test('stop fences an already-resolved pause continuation and its pending sink',async t=>{
  let release!:()=>void;const block=new Promise<void>(resolve=>{release=resolve;});
  const h=await setup(t,{onObservation:async message=>{if(message.payload.kind==='text.snapshot')await block;}});
  await h.supervisor.start(policy);h.context();h.text();await turn();
  const pausing=assert.rejects(h.supervisor.pause(),/pause-failed/);
  const stopping=h.supervisor.stop();release();await Promise.all([pausing,stopping]);
  assert.equal(h.supervisor.status().state,'stopped');assert.equal(h.supervisor.status().reason,'');assert.equal(h.terminated,1);
});

test('stop wins over a resolved resume ACK before its continuation',async t=>{
  const h=await setup(t);await h.supervisor.start(policy);await h.supervisor.pause();
  const resuming=assert.rejects(h.supervisor.resume(),/resume-failed/);
  await h.supervisor.stop();await resuming;
  assert.equal(h.supervisor.status().state,'stopped');assert.equal(h.supervisor.status().reason,'');
});

test('resume does not admit text until its running ACK and overlapping controls are refused',async t=>{
  const h=await setup(t,{blockedCommand:'resume'});await h.supervisor.start(policy);await h.supervisor.pause();
  const resuming=h.supervisor.resume();assert.equal(h.blockedReplies,1);
  await assert.rejects(h.supervisor.resume(),/resume-unavailable/);await assert.rejects(h.supervisor.pause(),/pause-unavailable/);
  h.context();h.text();await turn();assert.equal(h.accepted.length,0);assert.equal(h.supervisor.status().state,'paused');
  h.releaseReplies();await resuming;h.context();h.text();await turn();assert.equal(h.supervisor.status().accepted.text,1);
  assert.equal(h.commands.filter(command=>command==='resume').length,1);
});

test('native pause after a running ACK in the same frame batch wins over start and resume',async t=>{
  const starting=await setup(t,{pauseAfterCommand:'start'});
  await assert.rejects(starting.supervisor.start(policy),/screen-locked/);
  assert.equal(starting.supervisor.status().state,'failed');assert.equal(starting.supervisor.status().reason,'screen-locked');assert.ok(starting.terminated>=1);
  const resuming=await setup(t,{pauseAfterCommand:'resume'});await resuming.supervisor.start(policy);await resuming.supervisor.pause();
  await assert.rejects(resuming.supervisor.resume(),/resume-failed/);
  assert.equal(resuming.supervisor.status().state,'paused');assert.equal(resuming.supervisor.status().reason,'screen-locked');
  resuming.context();resuming.text();await turn();assert.equal(resuming.supervisor.status().accepted.text,0);
});

test('wrong pause acknowledgement fails closed instead of claiming a paused native collector',async t=>{
  const h=await setup(t,{pauseRunning:true});await h.supervisor.start(policy);
  await assert.rejects(h.supervisor.pause(),/pause-failed/);assert.equal(h.supervisor.status().state,'failed');assert.equal(h.supervisor.status().reason,'pause-failed');
});

test('visible policy requires an explicitly supported observation capability',async t=>{
  for(const visibleCapability of [false,'unsupported','unknown'] as const){
    const h=await setup(t,{visibleCapability});await assert.rejects(h.supervisor.start({...policy,textRange:'visible'}),/text-visible-range-unavailable/);
    assert.equal(h.supervisor.status().reason,'text-visible-range-unavailable');assert.equal(h.commands.includes('start'),false);
  }
  const wrongDirection=await setup(t,{visibleDirection:'act'});
  await assert.rejects(wrongDirection.supervisor.start({...policy,textRange:'visible'}),/text-visible-range-unavailable/);
  const legacy=await setup(t,{visibleCapability:false});await legacy.supervisor.start(policy);assert.equal(legacy.supervisor.status().state,'running');
});

test('secure input pause reasons survive native state and heartbeat without restarting', async t => {
  for (const reason of ['secure-input-active', 'secure-input-indicated']) {
    const h = await setup(t); await h.supervisor.start(policy);
    h.send({ protocolVersion: 1, type: 'state', requestId: 'input', instanceId: h.instance, state: 'paused', stamp: h.stamp, reason });
    await turn(); assert.equal(h.supervisor.status().state, 'paused'); assert.equal(h.supervisor.status().reason, reason);
    h.context(); h.text(); await turn(); assert.equal(h.supervisor.status().accepted.text, 0);
    assert.equal(h.commands.filter(command => command === 'start').length, 1); assert.equal(h.commands.includes('resume'), false);
  }
});

test('secure input is an owned temporary fence that automatically clears but cannot override owner pause', async t => {
  const h = await setup(t, { startReason: 'secure-input-suppressed' });
  const started = await h.supervisor.start(policy);
  assert.equal(started.state, 'paused'); assert.equal(started.reason, 'secure-input-suppressed'); assert.equal(h.terminated, 0);
  h.context(); h.text(); await turn(); assert.equal(h.supervisor.status().accepted.text, 0);
  const cleared = () => h.send({ protocolVersion: 1, type: 'state', requestId: 'secure-input', instanceId: h.instance, state: 'running', stamp: h.stamp, reason: 'secure-input-cleared' });
  cleared(); h.context(); h.text(); await turn(); assert.equal(h.supervisor.status().state, 'running'); assert.equal(h.supervisor.status().accepted.text, 1);
  h.send({ protocolVersion: 1, type: 'state', requestId: 'secure-input', instanceId: h.instance, state: 'paused', stamp: h.stamp, reason: 'secure-input-suppressed' });
  await turn(); await h.supervisor.pause(); cleared(); h.context(); h.text(); await turn();
  assert.equal(h.supervisor.status().state, 'failed', 'A forged cleared frame after owner Pause must fail closed, never reopen ingress'); assert.equal(h.supervisor.status().accepted.text, 1);
  assert.equal(h.commands.includes('resume'), false);
});

test('suppressed control ACK and automatic clear in one pipe batch defer ingress until the owning continuation', async t => {
  for (const command of ['start', 'resume'] as const) {
    const h = await setup(t, { secureClearAfterCommand: command });
    if (command === 'resume') { await h.supervisor.start(policy); await h.supervisor.pause(); }
    const result = command === 'start' ? await h.supervisor.start(policy) : await h.supervisor.resume();
    assert.equal(result.state, 'running'); assert.equal(result.reason, ''); assert.equal(h.terminated, 0);
    h.context(); h.text(); await turn(); assert.equal(h.supervisor.status().accepted.text, 1);
  }
});

test('a new secure interval after the running ACK keeps the owned helper instead of cancelling activation', async t => {
  for (const command of ['start', 'resume'] as const) {
    const h = await setup(t, { secureBlockAfterCommand: command });
    if (command === 'resume') { await h.supervisor.start(policy); await h.supervisor.pause(); }
    const result = command === 'start' ? await h.supervisor.start(policy) : await h.supervisor.resume();
    assert.equal(result.state, 'paused'); assert.equal(result.reason, 'secure-input-suppressed'); assert.equal(h.terminated, 0);
    h.context(); h.text(); await turn(); assert.equal(h.supervisor.status().accepted.text, 0);
    h.send({protocolVersion:1,type:'state',requestId:'secure-input',instanceId:h.instance,state:'running',stamp:h.stamp,reason:'secure-input-cleared'});
    await turn(); assert.equal(h.supervisor.status().state, 'running');
  }
});

test('development trace survives fragmented stderr, noise, pause and stop without becoming content or a fault',async t=>{
  const h=await setup(t,{debugTrace:true});await h.supervisor.start(policy);
  const secret='SYNTHETIC_PRIVATE_NEVER_COPY';
  const entry={version:1,code:'worker-retire-timeout',pid:12,timeMs:100,monotonicMs:90,file:'Worker.swift',line:99,
    numbers:{childPid:13,remainingMs:-1,waitStatus:70<<8,text:secret},flags:{retiring:true},stack:['0xabcd',secret],imageBase:'0x1000',text:secret};
  const line=Buffer.from(JSON.stringify(entry)+'\n');h.stderr.write(line.subarray(0,70));h.stderr.write(line.subarray(70));
  h.stderr.write(Buffer.alloc(70000,120));h.stderr.write('\n');
  for(let i=0;i<20;i++)h.stderr.write(JSON.stringify({...entry,timeMs:101+i})+'\n');
  h.context();h.text();await turn();
  assert.equal(h.supervisor.status().state,'running');assert.equal(h.supervisor.status().accepted.text,1);
  await h.supervisor.pause();
  await h.supervisor.stop();
  await h.debugLog!.flush();
  const files=(await readdir(h.debugLog!.directory)).filter(name=>name.endsWith('.jsonl'));
  const lines=(await Promise.all(files.map(name=>readFile(join(h.debugLog!.directory,name),'utf8')))).join('');
  const saved=lines.trim().split('\n').map(line=>JSON.parse(line) as DebugLogEntry);
  assert.equal(saved.filter(value=>value.event==='worker-retire-timeout').length,21);
  assert.ok(saved.some(value=>value.event==='collection-start'));
  assert.ok(saved.some(value=>value.event==='helper-exit'&&value.detail?.exitCode===0));
  assert.equal(lines.includes(secret),false);
});
test('trace parser resynchronizes after oversized lines and never interprets their tail as a new record',()=>{
  const entries: DebugLogEntry[] = [];
  const log=new CollectorDebugTrace(true, { onEntry: e => entries.push(e) });
  const entry={version:1,code:'worker-eof',pid:1,timeMs:1,monotonicMs:1,file:'Worker.swift',line:1,numbers:{waitStatus:9},flags:{}};
  log.push(Buffer.alloc(4097,120));log.push(Buffer.from(JSON.stringify(entry)+'\n'));
  assert.equal(entries.length,0);
  log.push(Buffer.from([0xff,10]));log.push(Buffer.from(JSON.stringify(entry)+'\n'));
  assert.equal(entries.length,1);assert.equal(entries[0]!.detail?.waitStatus,9);
  const disabledEntries: DebugLogEntry[] = [];
  const disabled=new CollectorDebugTrace(false, { onEntry: e => disabledEntries.push(e) });
  disabled.push(Buffer.from(JSON.stringify(entry)+'\n'));assert.equal(disabledEntries.length,0);
});

test('prefix policy rejects visible and legacy nonzero ranges before fixture authorization',async t=>{
  const h=await setup(t);await h.supervisor.start(policy);h.context();
  h.text({payload:visibleRangeSnapshot()});
  const legacy=visibleRangeSnapshot();delete legacy.rangeBasis;h.text({payload:legacy});
  h.text();await turn();assert.equal(h.supervisor.status().accepted.text,1);assert.equal(h.supervisor.status().dropped,2);
});

test('visible policy admits only explicitly visible partial snapshots and no prefix fallback',async t=>{
  const h=await setup(t);await h.supervisor.start({...policy,textRange:'visible',sampleIntervalMs:1000});h.context();
  h.text();const legacy=visibleRangeSnapshot();delete legacy.rangeBasis;h.text({payload:legacy});
  h.text({payload:visibleRangeSnapshot()});await turn();
  assert.equal(h.supervisor.status().accepted.text,1);assert.equal(h.supervisor.status().dropped,2);
  const accepted=h.accepted.find(message=>message.payload.kind==='text.snapshot')?.payload as TextSnapshot;
  assert.equal(accepted.rangeBasis,'visible');assert.equal(accepted.range?.start,10);assert.equal(accepted.coverage.status,'partial');
});

test('real-source visible evidence retains the normal gate and fixture cannot bypass production policy',{skip:process.platform!=='darwin'&&process.platform!=='win32'},async t=>{
  const h=await setup(t,{allowFixture:false});await h.supervisor.start({...policy,textRange:'visible'});h.context();
  h.text({payload:visibleRangeSnapshot()});
  const native={...visibleRangeSnapshot(),source:'ax.range' as const,gate:{secure:'safe' as const,privateState:'normal' as const,policyRevision:1}};
  h.text({payload:native});await turn();assert.equal(h.supervisor.status().accepted.text,1);assert.equal(h.supervisor.status().dropped,1);
});

test('Windows uia and win32 sources are authorized in production mode while fixture sources remain refused', { skip: process.platform !== 'darwin' && process.platform !== 'win32' }, async t => {
  const h = await setup(t, { multiSource: true, allowFixture: false });
  await h.supervisor.start({
    ...policy,
    maxPending: 16,
    captureScope: 'window',
    textRange: 'visible',
    selectionCapture: true,
    inputText: true,
    inputActivity: true,
    menuActions: true,
  });
  h.context();
  await turn();

  const gate = { secure: 'safe' as const, privateState: 'normal' as const, policyRevision: h.stamp.policyRevision };

  const uiaSurface = surfaceObservation();
  uiaSurface.payload.source = 'uia.tree';
  uiaSurface.payload.scope = 'window';
  uiaSurface.payload.gate = gate;
  h.text({ eventTimeMs: uiaSurface.eventTimeMs, payload: uiaSurface.payload });

  const uiaVisible = { ...visibleRangeSnapshot(), source: 'uia.text' as const, gate };
  h.text({ payload: uiaVisible });

  const uiaSelection = selectionObservation();
  uiaSelection.payload.source = 'uia.text';
  uiaSelection.payload.gate = gate;
  h.text({ eventTimeMs: uiaSelection.eventTimeMs, payload: uiaSelection.payload });

  const winInputText = inputTextObservation();
  winInputText.payload.source = 'win32.unicode';
  winInputText.payload.gate = gate;
  h.text({ eventTimeMs: winInputText.eventTimeMs, payload: winInputText.payload });

  const winActivity = h.activity();
  // First send fixture activity (must be rejected when allowFixture: false) and then win32.listen-only.
  assert.equal(winActivity.payload.kind, 'input.activity');
  h.activity({
    payload: {
      ...winActivity.payload,
      source: 'win32.listen-only',
    },
  });

  const fixtureMenu = menuAction('fixture', ['File', 'Save']);
  h.text({
    target: fixtureMenu.target,
    eventTimeMs: fixtureMenu.eventTimeMs,
    payload: { ...fixtureMenu.payload, gate },
  });
  const uiaMenu = menuAction('uia.menu', ['File', 'Save']);
  h.text({
    target: uiaMenu.target,
    eventTimeMs: uiaMenu.eventTimeMs,
    payload: { ...uiaMenu.payload, gate },
  });

  await turn();
  const status = h.supervisor.status();
  assert.equal(status.state, 'running');
  assert.equal(status.accepted.surface, 1);
  assert.equal(status.accepted.text, 1);
  assert.equal(status.accepted.selection, 1);
  assert.equal(status.accepted.inputText, 1);
  assert.equal(status.accepted.activity, 1);
  assert.equal(status.accepted.menu, 1);
  assert.equal(status.dropped, 2);
});

test('minimalChildEnv filters Windows environment variables without forwarding parent secrets and stays minimal on POSIX', async t => {
  const parentEnv: NodeJS.ProcessEnv = {
    SystemRoot: 'C:\\Windows',
    windir: 'C:\\Windows',
    SystemDrive: 'C:',
    ComSpec: 'C:\\Windows\\System32\\cmd.exe',
    Path: 'C:\\Windows\\System32',
    TEMP: 'C:\\Temp',
    TMP: 'C:\\Temp',
    USERPROFILE: 'C:\\Users\\tester',
    LOCALAPPDATA: 'C:\\Users\\tester\\AppData\\Local',
    APPDATA: 'C:\\Users\\tester\\AppData\\Roaming',
    PATHEXT: '.COM;.EXE',
    SECRET_API_KEY: 'never-forward-me',
    COMPUTER_ACCESS_ADMIN_TOKEN: 'admin-secret',
  };

  const winEnv = minimalChildEnv({ COMPUTER_ACCESS_DEBUG: '1' }, 'win32', parentEnv);
  assert.deepEqual(winEnv, {
    SystemRoot: 'C:\\Windows',
    WINDIR: 'C:\\Windows',
    SystemDrive: 'C:',
    ComSpec: 'C:\\Windows\\System32\\cmd.exe',
    PATH: 'C:\\Windows\\System32',
    TEMP: 'C:\\Temp',
    TMP: 'C:\\Temp',
    USERPROFILE: 'C:\\Users\\tester',
    LOCALAPPDATA: 'C:\\Users\\tester\\AppData\\Local',
    APPDATA: 'C:\\Users\\tester\\AppData\\Roaming',
    PATHEXT: '.COM;.EXE',
    COMPUTER_ACCESS_DEBUG: '1',
  });
  assert.equal('Path' in winEnv, false);
  assert.equal('SECRET_API_KEY' in winEnv, false);
  assert.equal('COMPUTER_ACCESS_ADMIN_TOKEN' in winEnv, false);

  const posixEnv = minimalChildEnv({ COMPUTER_ACCESS_DEBUG: '1' }, 'darwin', parentEnv);
  assert.deepEqual(posixEnv, { COMPUTER_ACCESS_DEBUG: '1' });

  const secretKey = 'CAMCP_TEST_UNEXPECTED_SECRET_ENV';
  process.env[secretKey] = 'top-secret-value';
  t.after(() => {
    delete process.env[secretKey];
  });
  const h = await setup(t, { debugTrace: true });
  await h.supervisor.start(policy);
  const spawnedEnv = h.spawnSpecs[0]?.env ?? {};
  assert.equal(spawnedEnv[secretKey], undefined);
  assert.equal(spawnedEnv.COMPUTER_ACCESS_DEBUG, '1');
  assert.equal(spawnedEnv.DSH_COMPUTER_ACCESS_DEBUG, '1');
  if (process.platform === 'win32') {
    assert.ok(typeof spawnedEnv.SystemRoot === 'string' && spawnedEnv.SystemRoot.length > 0);
  }
});

test('stopOwned waits briefly for clean Windows collector exit before falling back to terminate', { skip: process.platform !== 'win32' }, async t => {
  const clean = await setup(t, { exitOnStop: true });
  await clean.supervisor.start(policy);
  const stoppedClean = await clean.supervisor.stop();
  assert.equal(stoppedClean.state, 'stopped');
  assert.equal(clean.terminated, 0);

  const hung = await setup(t, { exitOnStop: false });
  await hung.supervisor.start(policy);
  const stoppedHung = await hung.supervisor.stop();
  assert.equal(stoppedHung.state, 'stopped');
  assert.equal(hung.terminated, 1);
});
