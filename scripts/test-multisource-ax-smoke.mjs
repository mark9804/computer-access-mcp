import { mkdtemp, realpath, rm } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

// Explicit real-AX synthetic-only P1-P4 test. Never user History or Keychain.
const mode=process.argv[3];
if(process.argv.length!==4||process.argv[2]!=='--authorized-synthetic-ax'||!['surface','selection','input','excluded','diff','combined','field-denylist','field-strict','field-protected','field-slow-tree'].includes(mode)){
  console.error(JSON.stringify({ok:false,failure:'explicit-synthetic-authorization-required'}));process.exit(64);
}
const root=dirname(dirname(fileURLToPath(import.meta.url))),runFile=promisify(execFile);
const fieldCase=mode.startsWith('field-');const negativeField=mode==='field-strict'||mode==='field-protected';const preparation=mode==='field-slow-tree'?'slow-tree':mode==='field-protected'?'protected':fieldCase?'unmarked':'plain';
const appId='com.dsh.computer-access.fixture',deviceId='synthetic-multisource';
const check=(condition,code)=>{if(!condition)throw new Error(code);};
// Do not echo provider stderr, frame bodies or arbitrary exception messages.
const collectorReasons=new Set(['input-monitoring-required','input-monitoring-disabled','input-monitoring-unavailable','permission-denied','desktop-unavailable','content-capability-unavailable','helper-protocol-error','helper-exited','storage-commit-failed','user-paused']);
const own=new Set(['fixture-preparation-failed','fixture-input-failed','non-fixture-evidence','missing-new-evidence','excluded-produced-evidence','pause-produced-evidence','store-reopen-mismatch','owned-helper-exit-unconfirmed','unsafe-cleanup','cleanup-failed','observation-failed']);
let parent,temp,key,store,supervisor,timer,failure,result,finish,observed=false;
const diagnostics={};const committedKinds={};let relations=0;let readFailure;const inputParts=new Map();const inputIds=new Set();let excludedNamed=0;let inputVerified=false,relationVerified=false;
try{
  const [{SegmentStore},{MemoryKeyProvider},{CollectorSupervisor},{spawnLocal},{verifyNativeBinary},{EvidenceCorrelator}]=await Promise.all([import('../dist/storage/segment-store.js'),import('../dist/storage/key-provider.js'),import('../dist/host/collectors/supervisor.js'),import('../dist/host/collectors/local-process.js'),import('../dist/host/service/binaries.js'),import('../dist/host/collectors/evidence-correlator.js')]);
  const correlator=new EvidenceCorrelator();
  const binary=await verifyNativeBinary(join(root,'native-bin/computer-access-collector'),'computer-access-collector');
  parent=await realpath(tmpdir());temp=await realpath(await mkdtemp(join(parent,'dsh-p4-synthetic-')));key=randomBytes(32);
  const options={root:join(temp,'data'),keyProvider:new MemoryKeyProvider(key)};store=await SegmentStore.open(options);
  try{const prepared=await runFile('swift',['scripts/prepare-fixture-smoke.swift',preparation],{cwd:root,timeout:10000,maxBuffer:4096,killSignal:'SIGKILL'});check(prepared.stdout.trim()===`fixture-prepared-${preparation}`,'fixture-preparation-failed');}catch{throw new Error('fixture-preparation-failed');}
  if(mode==='selection')try{await runFile('swift',['scripts/input-fixture-smoke.swift','--authorized-synthetic-input','selection'],{cwd:root,timeout:10000,maxBuffer:4096,killSignal:'SIGKILL'});}catch(error){diagnostics.fixtureInputCode=Number.isInteger(error?.code)?error.code:'unknown';throw new Error('fixture-input-failed');}
  const ready=new Promise(resolve=>{finish=resolve;});
  supervisor=new CollectorSupervisor({helperPath:binary.path,helperSha256:binary.sha256,cwd:temp,deviceId,spawn:spawnLocal,
    async onObservation(record,isCurrent){try{
      check(record.target.kind==='unresolved'||record.target.identity.applicationId===appId,'non-fixture-evidence');
      const related=correlator.preview(record);await store.append(related,{generation:store.generation,isCurrent});if(isCurrent())correlator.commit(related);
      const p=record.payload;committedKinds[p.kind]=(committedKinds[p.kind]??0)+1;if(related.relation)relations++;
      if(record.target.kind!=='unresolved')excludedNamed++;
      if(p.kind==='gap'){const code=p.diagnostic?.code??p.reason;diagnostics[code]=(diagnostics[code]??0)+1;}
      if(['field-denylist','field-slow-tree'].includes(mode)&&p.kind==='text.snapshot'&&p.text?.includes('FIELD-POLICY-SYNTHETIC')&&p.gate?.secure==='not-declared-sensitive'){
        if(mode==='field-slow-tree'){diagnostics.captureElapsedMs=p.captureEndMs-p.captureStartMs;if(diagnostics.captureElapsedMs<800||diagnostics.captureElapsedMs>=1500)return;}
        observed=true;finish(true);
      }
      if(mode==='diff'&&p.kind==='surface.snapshot'&&p.mode==='diff'&&p.coverage.status==='complete'&&p.nodes.some(node=>node.text?.includes('合成测试'))){observed=true;finish(true);}
      if(mode==='surface'&&p.kind==='surface.snapshot'&&p.nodes.some(node=>node.text?.includes('合成测试'))){observed=true;finish(true);}
      if(mode==='selection'&&p.kind==='selection.snapshot'&&p.text==='你好'){observed=true;finish(true);}
      if((mode==='input'||mode==='combined')&&p.kind==='input.text'&&p.source==='cg.unicode'&&p.eventKind==='text'){
        const identity=JSON.stringify([record.instanceId,record.target,record.stamp,p.surfaceId]);const combined=(inputParts.get(identity)??'')+p.text;inputParts.set(identity,combined.slice(-256));
        inputIds.add(record.eventId);if(combined.includes('P4-SYNTHETIC')){inputVerified=true;if(mode==='input'){observed=true;finish(true);}}
      }
      if(mode==='combined'&&p.kind==='surface.snapshot'&&inputVerified&&related.relation?.evidenceIds.some(id=>inputIds.has(id))){relationVerified=true;observed=true;finish(true);}
    }catch{readFailure='observation-failed';finish(false);throw new Error(readFailure);}}
  });
  await supervisor.start({enabled:true,fieldSecurity:fieldCase&&mode!=='field-strict'?'denylist':'strict',allowedApplicationIds:[appId],applicationScope:'allowlist',excludedApplicationIds:mode==='excluded'?[appId]:[],allowBrowserContent:false,
    axCompatibility:mode==='excluded',textMarkers:mode==='excluded',captureScope:mode==='surface'||mode==='excluded'?'window':mode==='diff'||mode==='combined'||fieldCase?'region':'focused',maxTreeNodes:64,selectionCapture:fieldCase||['selection','combined','excluded'].includes(mode),inputText:['input','combined','excluded'].includes(mode),inputActivity:mode==='excluded',
    textRange:'prefix',sampleIntervalMs:1000,maxTextCodeUnits:2048,maxPending:16,debounceMs:150,maxWaitMs:500,readTimeoutMs:mode==='field-slow-tree'?1500:2500});
  if(mode==='input'||mode==='combined'){
    // Let the worker establish its exact field identity and passive listener.
    await new Promise(resolve=>setTimeout(resolve,1800));
    try{await runFile('swift',['scripts/input-fixture-smoke.swift','--authorized-synthetic-input','input'],{cwd:root,timeout:10000,maxBuffer:4096,killSignal:'SIGKILL'});}catch(error){diagnostics.fixtureInputCode=Number.isInteger(error?.code)?error.code:'unknown';throw new Error('fixture-input-failed');}
  }
  timer=setTimeout(()=>finish(mode==='excluded'||negativeField),mode==='excluded'||negativeField?5000:18000);
  check(await ready&&!readFailure,'missing-new-evidence');clearTimeout(timer);timer=undefined;
  const before=store.status();
  if(mode==='excluded')check(excludedNamed===0&&before.counts.text===0&&before.counts.surface===0&&before.counts.selection===0&&before.counts.inputText===0&&before.counts.activity===0,'excluded-produced-evidence');
  if(negativeField)check(before.counts.text===0&&before.counts.surface===0&&before.counts.selection===0&&before.counts.inputText===0&&(diagnostics[mode==='field-strict'?'field-security-unknown':'secure-field']??0)>0,'excluded-produced-evidence');
  await supervisor.pause();const paused=store.status().records;await new Promise(resolve=>setTimeout(resolve,1250));check(store.status().records===paused,'pause-produced-evidence');
  check((await supervisor.stop()).state==='stopped','owned-helper-exit-unconfirmed');await store.close();store=await SegmentStore.open(options);
  const query=await store.search({kind:mode==='surface'||mode==='diff'?'surface':mode==='selection'?'selection':mode==='input'?'input':'all',limit:100});
  check(mode==='excluded'?query.records.every(record=>record.target.kind==='unresolved'&&record.payload.kind==='gap'):negativeField?query.records.every(record=>['context.changed','gap'].includes(record.payload.kind)):query.records.length>0,'store-reopen-mismatch');
  result={ok:true,mode,records:before.records,textRecords:before.counts.text,surfaceRecords:before.counts.surface,selectionRecords:before.counts.selection,inputTextRecords:before.counts.inputText,
    observationVerified:observed,...(mode==='combined'?{relationVerified}:{}),diagnostics,pausedAndStopped:true,reopened:true,existingHistoryRead:false,keychainAccess:false,modelShared:false,syntheticOnly:true};
}catch(error){failure=own.has(error?.message)?error.message:collectorReasons.has(error?.message)?error.message:'synthetic-p4-failed';
  diagnostics.committedKinds=committedKinds;diagnostics.relations=relations;diagnostics.inputVerified=inputVerified;
  const state=supervisor?.status();if(state){diagnostics.collectorState=['starting','running','paused','stopped','failed'].includes(state.state)?state.state:'unknown';diagnostics.collectorReason=collectorReasons.has(state.reason)?state.reason:'other';diagnostics.received=state.received;diagnostics.dropped=state.dropped;}
}
finally{
  if(timer)clearTimeout(timer);let cleaned=false;
  try{const stopped=await supervisor?.stop();check(!stopped||stopped.state==='stopped','owned-helper-exit-unconfirmed');await store?.close();cleaned=true;}catch{failure='owned-helper-exit-unconfirmed';}
  key?.fill(0);
  if(temp&&cleaned)try{check(resolve(temp)===temp&&dirname(temp)===parent&&temp.startsWith(join(parent,'dsh-p4-synthetic-'))&&await realpath(temp)===temp,'unsafe-cleanup');await rm(temp,{recursive:true,force:false});}catch{failure='cleanup-failed';}
}
if(failure){console.error(JSON.stringify({ok:false,mode,failure,diagnostics,existingHistoryRead:false,keychainAccess:false}));process.exitCode=1;}else console.log(JSON.stringify(result,null,2));
