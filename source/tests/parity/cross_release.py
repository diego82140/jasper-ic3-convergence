#!/usr/bin/env python3
"""Finite cross-release information parity, not universal solver equivalence.

Compare complete decoded record fields and literal diagnostic lines. Only the
listed execution identities, reviewed hook addresses and measured durations are
normalized. Missing fields/events/payload bytes fail: no field intersection.
Each input archive must first pass the normal strict, complete streaming reader.
Native baseline/preload controls use the worker's unchanged main and solver.
"""
import argparse, collections, gzip, hashlib, json, math, re, subprocess, sys
from pathlib import Path
from native_client import run_worker, digest, WORKER_SHA, FAMILIES, decode, expected_results

ROOT=Path(__file__).resolve().parents[3]
RELEASES={
 'prerelease':('jasper_2026.0920260826065032',WORKER_SHA),
 'production':('jasper_2026.09','b3e7723c4335266b1cd1436277111d54ee7802944b8b4f7d6eaacaa28b7c84b4'),
 'production-p001':('jasper_2026.09p001','e1b53cf546e048df0f9996646afba34b0faf7b38095b22ed700a507b64cf4e7b'),
}
# These are tested run metadata, never cube/name/query/frame content.
IDENTITIES={'pid','tid','capture'}
DERIVED_IDENTITIES={'chain','worker_sha256'}
DURATIONS={'wall_ns','cpu_ns','thread_cpu_ns','process_cpu_ns','elapsed',
           'emission_wall_ns_lower_bound'}
POINTERS={'circuit_address','queue_address','manager_address','short_queue_address','long_queue_address','native_address','return_slot','stack_pointer','list_node','seq','actual_jip','bound_jip','actual_circuit','bound_circuit','epoch_circuit'}
CODE_ADDRESSES={'native_entry','native_site','callsite','native_callsite','canonical_entry','resolved_entry'}
FIELDS=re.compile(r'(\w+)=([^ ]*)')
REQUIRED_PHASES={'run_contract','model','cube_definition','cube_chunk','cube_definition_end',
 'signal','signal_name_chunk','signal_name_end','predecessor_cubes','relative_begin','relative_end',
 'query_context','query_conclusion','sat_begin','sat_end','frames_begin','frame_chunk','frames_end',
 'queues_begin','queue_member','queue_end','queues_end','obligation_dequeue','queue_membership_remove',
 'native_validation_begin','native_validation_stage','native_validation_end','run_seal'}

def parsed_rows(lines):
    """Only an observer hash-table delta batch is unordered; native tuples stay ordered."""
    batch=[];batch_key=None
    def ordered(items):
        if not items:return []
        # Event ordinals still occupy exactly the same contiguous interval.
        first=int(items[0]['event'])
        if [int(r['event']) for r in items]!=list(range(first,first+len(items))):
            raise ValueError('Noncontiguous removal batch')
        items.sort(key=lambda r:int(r['obligation_id']))
        for i,row in enumerate(items):row['event']=str(first+i)
        return items
    for line in lines:
        if not line.startswith('IC3_STATS '):continue
        if not line.endswith('\n'):raise ValueError('Unterminated canonical record')
        tokens=line.removesuffix('\n')[len('IC3_STATS '):].split(' ')
        if any(re.fullmatch(r'[A-Za-z_]\w*=[^ \t\r\n]*',t) is None for t in tokens):
            raise ValueError('Malformed or unconsumed record bytes')
        items=[t.split('=',1) for t in tokens]
        if len(items)!=len(dict(items)):raise ValueError('Duplicate field in record')
        row=dict(items)
        boundary=('capture','pid','tid','run','model_epoch','ctx_rev','op_id','snapshot','operation','cause')
        key=tuple(row[k] for k in boundary) if row['phase']=='queue_membership_remove' and all(k in row for k in boundary) else None
        if key is not None:key+=(row.get('epoch'),)
        if batch and key!=batch_key:
            yield from ordered(batch);batch=[]
        if key is not None:batch.append(row);batch_key=key
        else:yield row
    yield from ordered(batch)

def hook_names(profile):
    counts=collections.Counter();out={}
    for line in profile.read_text().splitlines():
        if not line.startswith('hook '):continue
        p=line.split();kind=p[1];counts[kind]+=1
        out[int(p[2],16)]=kind+':'+str(counts[kind])
    return out

def normalize(lines,profile):
    hooks=hook_names(profile);pointers={};result=[];next_pointer=0
    identities={key:{} for key in IDENTITIES}
    profile_sha=next((line.split()[1] for line in profile.read_text().splitlines() if line.startswith('sha256 ')),None)
    for row in parsed_rows(lines):
        if row['phase']=='collector_diagnostic' and not row.get('capture'):
            raise ValueError('Producer diagnostic has no canonical capture binding')
        worker=(row.get('capture'),row.get('pid'))
        retired=[]
        if row['phase']=='obligation_destroy':retired.append(row.get('native_address'))
        for key,value in list(row.items()):
            if key in IDENTITIES:
                mapping=identities[key]
                scope=() if key=='capture' else (worker[:1] if key=='pid' else worker)
                row[key]=mapping.setdefault((scope,value),key+':'+str(len(mapping)+1))
            elif key=='worker_sha256':
                if profile_sha is None or value!=profile_sha:raise ValueError('Worker identity differs from the exact selected profile')
                row[key]='<selected-worker>'
            elif key=='chain':
                # The full original chain is independently checked by strict_ingest.
                if not re.fullmatch('[0-9a-f]{64}',value):raise ValueError('Invalid chain digest')
                row[key]='<independently-verified-chain>'
            elif key in DURATIONS:
                number=float(value)
                if not math.isfinite(number) or number<0:raise ValueError('Invalid duration '+key)
                row[key]='<duration>'
            elif key in POINTERS:
                # Membership loss does not establish allocation death. Preserve
                # aliases conservatively until a native destructor is observed.
                if value!='0':
                    identity=(worker,value)
                    if identity not in pointers:
                        next_pointer+=1;pointers[identity]='address:'+str(next_pointer)
                    row[key]=pointers[identity]
            elif key in CODE_ADDRESSES:
                address=int(value,16)
                if address not in hooks:raise ValueError('Unreviewed native code address '+key+'='+value)
                row[key]=hooks[address]
        result.append(row)
        for address in retired:pointers.pop((worker,address),None)
    if not result:raise ValueError('No canonical records')
    return result

def comparison(reference,candidate):
    for i,(a,b) in enumerate(zip(reference,candidate)):
        if a!=b:
            return dict(pass_=False,index=i,reference=a,candidate=b,
                        missing_fields=sorted(a.keys()-b.keys()),extra_fields=sorted(b.keys()-a.keys()))
    return dict(pass_=len(reference)==len(candidate),reference_records=len(reference),candidate_records=len(candidate))

def load_capture(path,sha,*,observer_graph=False):
    records=[];displays=[];diagnostic_pids=set();canonical_pids=set()
    for p in sorted(path.glob('events-*.log*')):
        pending={}
        with (gzip.open(p,'rb') if p.suffix=='.gz' else p.open('rb')) as f:
            while raw:=f.readline():
                if raw.startswith(b'[JIPSTATS] '):
                    # Producer diagnostics are a separate declared channel,
                    # not raw display payloads or canonical engine events.
                    m=re.fullmatch(rb'\[JIPSTATS\] pid=(\d+) backend=events (.*)\n',raw)
                    if not m:raise ValueError('Malformed producer diagnostic')
                    body=m[2].decode('ascii')
                    if body.startswith('attached '):kind='attached';body=body[len('attached '):]
                    elif body.startswith('summary '):kind='summary';body=body[len('summary '):]
                    elif body.startswith('native_IC3_reports_redirected='):kind='native_reports'
                    else:raise ValueError('Unreviewed producer diagnostic')
                    line='IC3_STATS phase=collector_diagnostic diagnostic='+kind+' pid='+m[1].decode()+' '+body+'\n'
                    diagnostic=next(parsed_rows([line]))
                    diagnostic_pids.add(diagnostic['pid'])
                    if kind=='attached':
                        if diagnostic.pop('sha256')!=sha:raise ValueError('Diagnostic worker identity mismatch')
                        diagnostic['worker_sha256']=sha
                    records.append('IC3_STATS '+' '.join(k+'='+v for k,v in diagnostic.items())+'\n')
                    continue
                if not raw.startswith(b'IC3_STATS '):raise ValueError('Unframed or unreviewed capture bytes')
                line=raw.decode('ascii');row=next(parsed_rows([line]));records.append(line)
                if row['phase']=='collector_diagnostic':raise ValueError('Canonical phase collides with reserved diagnostic channel')
                canonical_pids.add(row.get('pid'))
                key=tuple(row.get(k) for k in ('capture','pid','tid','run','parity_sequence'))
                if row['phase']=='parity_record':
                    if key in pending:raise ValueError('Duplicate diagnostic header')
                    pending[key]=row
                elif row['phase']=='parity_record_end':
                    header=pending.pop(key);n=int(row['bytes'])
                    if row['complete']!='1' or not 0<=n<=16*1024*1024 or int(header['bytes'])!=n:raise ValueError('Invalid diagnostic extent')
                    body=f.read(n+1)
                    if len(body)!=n+1 or body[-1:]!=b'\n' or hashlib.sha256(body[:-1]).hexdigest()!=header['sha256']:raise ValueError('Truncated or changed diagnostic bytes')
                    if header['family'] not in FAMILIES or not body.startswith(header['family'].encode('ascii')+b' '):raise ValueError('Unreviewed diagnostic family')
                    displays.append(body[:-1])
        if pending:raise ValueError('Missing diagnostic end')
    if not diagnostic_pids<=canonical_pids:raise ValueError('Diagnostic process does not own a canonical stream')
    # Bind diagnostic process IDs to the unique canonical capture in this
    # archive before applying the same identity mapping to both channels.
    scopes={}
    parsed=list(parsed_rows(records))
    for row in parsed:
        if row['phase']!='collector_diagnostic' and 'pid' in row and 'capture' in row:
            scopes.setdefault(row['pid'],set()).add(row['capture'])
    for row in parsed:
        if row['phase']=='collector_diagnostic':
            candidates=scopes.get(row['pid'],set())
            if len(candidates)!=1:raise ValueError('Missing or ambiguous diagnostic capture association')
            row['capture']=next(iter(candidates))
    if observer_graph:
        from observer_equivalence import project
        parsed,_=project(parsed,POINTERS)
    normalized=normalize(('IC3_STATS '+' '.join(k+'='+v for k,v in row.items())+'\n' for row in parsed),ROOT/'profiles'/(sha+'.events'))
    diagnostics=[r for r in normalized if r['phase']=='collector_diagnostic']
    return [r for r in normalized if r['phase']!='collector_diagnostic'],displays,diagnostics

def strict_ingest(path):
    index=path/'parity-index.sqlite'
    command=[sys.executable,'-I',str(ROOT/'tools/telemetry_db.py'),'ingest',str(path),str(index)]
    with (path/'reader.stdout').open('w') as out,(path/'reader.stderr').open('w') as err:
        r=subprocess.run(command,stdout=out,stderr=err)
    if r.returncode:raise ValueError('Strict reconstruction failed: '+str(path))
    result=json.loads((path/'reader.stdout').read_text())
    if not result['complete']:raise ValueError('Incomplete capture: '+str(path))
    for p in (index,Path(str(index)+'.integrity.json')):p.unlink()
    return result

def validate_case(case,sha,model_sha,engine,shared,library_sha):
    """The same acceptance checks apply to fresh and reused native controls."""
    expected=expected_results(model_sha,shared);accepted=[]
    for mode,preload in (('plain',False),('capture',True)):
        directory=case/mode
        result=json.loads((directory/'RESULT.json').read_text());invocation=json.loads((directory/'INVOCATION.json').read_text())
        required={'status':'PASS','exit':0,'engine':engine,'preload':preload,'model_sha256':model_sha,'worker_unchanged':True,
                  'original_main':True,'original_solver':True,'receive_eof':True,'receiver_joined':True,
                  'protocol_buffer_empty':True,'expected_sequence_verified':True}
        if any(type(result.get(k)) is not type(v) or result[k]!=v for k,v in required.items()):raise ValueError('Unqualified native result: '+str(directory))
        identity={'worker_sha256':sha,'model_sha256':model_sha,'library_sha256':library_sha,'engine':engine,'preload':preload,'sink':'disk','original_main':True,'original_solver':True}
        if any(type(invocation.get(k)) is not type(v) or invocation[k]!=v for k,v in identity.items()):raise ValueError('Native invocation identity differs: '+str(directory))
        _,verdicts,_,_=decode((directory/'native-response.bin').read_bytes())
        if not verdicts or verdicts!=expected or result.get('verdicts')!=verdicts:raise ValueError('Native result sequence differs from model contract: '+str(directory))
        accepted.append(result)
    return accepted

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--models',type=Path,required=True,help='Pinned five-model directory with model.bs per model')
    parser.add_argument('--compare-only',action='store_true')
    parser.add_argument('--resume',action='store_true',help='Reuse only completed, identity-matching captures; never overwrite partial cases')
    parser.add_argument('--observer-graph',action='store_true',help='Candidate scoped observer graph view; writes a separate report and never replaces the strict raw-history gate')
    args=parser.parse_args()
    args.output.mkdir(parents=True,exist_ok=args.compare_only or args.resume)
    models={'shared':(ROOT/'source/tests/worker_protocol/model.bs',True)}
    for name in ('xy','and_predecessor','composite_property','delayed_bug'):
        models[name]=(args.models/name/'model.bs',False)
    report={'publication_allowed':False,'feature_closure':'OPEN','scope':'finite five-model M/M4 cross-release information parity; universal equivalence NOT claimed',
            'normalization':dict(identities=sorted(IDENTITIES),derived_identities=sorted(DERIVED_IDENTITIES),durations=sorted(DURATIONS),pointers=sorted(POINTERS),code_addresses=sorted(CODE_ADDRESSES)),
            'library_sha256':digest(ROOT/'libjipstats.so'),'models':{n:digest(p) for n,(p,s) in models.items()},'cases':[]}
    report['comparison_view']='observer_graph' if args.observer_graph else 'strict_raw_history'
    if args.observer_graph:
        report.update(scope='finite emitted observer graph equivalence under checked reference fences; not physical-history or native allocation-lifetime equivalence',
                      native_lifetime_certified=False,independent_review_pending=True,
                      strict_raw_history_gate='separate INFORMATION-PARITY.json retained; not replaced by this view')
    failures=[];phase_inventory={key:set() for key in RELEASES};display_inventory={key:set() for key in RELEASES}
    for name,(model,shared) in models.items():
        for engine in ('M','M4'):
            reference=None;reference_display=None;reference_verdicts=None;reference_diagnostics=None
            for label,(release,sha) in RELEASES.items():
                case=args.output/name/engine/label;runtime=Path('/projects/external_ip/cadence')/release
                completed=(case/'plain/RESULT.json').is_file() and (case/'capture/RESULT.json').is_file()
                if not args.compare_only and not(args.resume and completed):
                    case.mkdir(parents=True,exist_ok=args.resume)
                    worker=runtime/'Linux64/bin/jg_proof'
                    plain=run_worker(worker,runtime,ROOT,model,case/'plain',engine,False,shared,timeout=900,worker_sha=sha,sink='disk')
                    hooked=run_worker(worker,runtime,ROOT,model,case/'capture',engine,True,shared,timeout=900,worker_sha=sha,sink='disk')
                    if plain['verdicts']!=hooked['verdicts']:raise ValueError('Instrumentation changed native verdicts')
                else:
                    plain=json.loads((case/'plain/RESULT.json').read_text());hooked=json.loads((case/'capture/RESULT.json').read_text())
                    if plain['verdicts']!=hooked['verdicts']:raise ValueError('Native control mismatch')
                plain,hooked=validate_case(case,sha,report['models'][name],engine,shared,report['library_sha256'])
                strict_ingest(case/'capture')
                invocation=json.loads((case/'capture/INVOCATION.json').read_text())
                if invocation['library_sha256']!=report['library_sha256'] or invocation['model_sha256']!=report['models'][name] or invocation['worker_sha256']!=sha or invocation['engine']!=engine:
                    raise ValueError('Capture component/model identity mismatch')
                rows,display,diagnostics=load_capture(case/'capture',sha,observer_graph=args.observer_graph)
                phase_inventory[label].update(x['phase'] for x in rows)
                display_inventory[label].update(x.split(b' ',1)[0].decode('ascii') for x in display)
                item=dict(model=name,engine=engine,release=label,records=len(rows),display_records=len(display),verdicts=hooked['verdicts'])
                if reference is None:
                    reference=rows;reference_display=display;reference_verdicts=hooked['verdicts'];reference_diagnostics=diagnostics
                else:
                    item['records_comparison']=comparison(reference,rows)
                    item['displays_equal']=reference_display==display
                    item['native_verdicts_equal']=reference_verdicts==hooked['verdicts']
                    item['diagnostics_comparison']=comparison(reference_diagnostics,diagnostics)
                    if not item['records_comparison']['pass_'] or not item['displays_equal'] or not item['native_verdicts_equal'] or not item['diagnostics_comparison']['pass_']:failures.append(item)
                report['cases'].append(item)
                print(name,engine,label,len(rows),'records',flush=True)
    report['phases']={k:sorted(v) for k,v in phase_inventory.items()}
    report['all_phase_inventories_equal']=all(v==phase_inventory['prerelease'] for v in phase_inventory.values())
    report['required_content_exercised']=all(REQUIRED_PHASES<=v for v in phase_inventory.values()) and all(set(FAMILIES)==v for v in display_inventory.values())
    report['display_families']={k:sorted(v) for k,v in display_inventory.items()}
    report['unordered_observer_batch']='queue_membership_remove only; preserve every member, field and duplicate; native frame/queue tuples are never sorted'
    # Negative controls prove that the comparator detects missing information.
    mutated=[dict(r) for r in reference];mutated[0].pop(next(k for k in mutated[0] if k!='phase'))
    report['missing_field_detected']=not comparison(reference,mutated)['pass_']
    report['missing_event_detected']=not comparison(reference,reference[1:])['pass_']
    cube=next((i for i,r in enumerate(reference) if r['phase']=='cube_chunk'),None)
    if cube is None:raise ValueError('No literal payload exercised')
    mutated=[dict(r) for r in reference];mutated[cube]['values']='DELIBERATE_PAYLOAD_MUTATION'
    report['changed_payload_detected']=not comparison(reference,mutated)['pass_']
    report['failures']=failures
    accepted=not failures and report['all_phase_inventories_equal'] and report['required_content_exercised'] and all(report[k] for k in ('missing_field_detected','missing_event_detected','changed_payload_detected'))
    report['status']=('PASS_FINITE_OBSERVER_GRAPH' if args.observer_graph else 'PASS') if accepted else 'FAIL'
    report_name='OBSERVER-GRAPH-PARITY.json' if args.observer_graph else 'INFORMATION-PARITY.json'
    (args.output/report_name).write_text(json.dumps(report,indent=2)+'\n')
    raise SystemExit(0 if accepted else 1)

if __name__=='__main__':main()
