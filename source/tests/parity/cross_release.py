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
from native_client import run_worker, digest, WORKER_SHA, FAMILIES

ROOT=Path(__file__).resolve().parents[3]
RELEASES={
 'prerelease':('jasper_2026.0920260826065032',WORKER_SHA),
 'production':('jasper_2026.09','b3e7723c4335266b1cd1436277111d54ee7802944b8b4f7d6eaacaa28b7c84b4'),
 'production-p001':('jasper_2026.09p001','e1b53cf546e048df0f9996646afba34b0faf7b38095b22ed700a507b64cf4e7b'),
}
# These are tested run metadata, never cube/name/query/frame content.
IDENTITIES={'pid','tid','capture','chain','worker_sha256'}
DURATIONS={'wall_ns','cpu_ns','thread_cpu_ns','process_cpu_ns','elapsed',
           'emission_wall_ns_lower_bound'}
POINTERS={'circuit_address','queue_address','native_address','return_slot','stack_pointer','list_node','seq','actual_jip','bound_jip','actual_circuit','bound_circuit','epoch_circuit'}
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
        items.sort(key=lambda r:int(r['obligation_id']))
        for i,row in enumerate(items):row['event']=str(first+i)
        return items
    for line in lines:
        if not line.startswith('IC3_STATS '):continue
        items=FIELDS.findall(line.rstrip())
        if len(items)!=len(dict(items)):raise ValueError('Duplicate field in record')
        row=dict(items)
        key=tuple(row.get(k) for k in ('run','snapshot','operation','cause')) if row['phase']=='queue_membership_remove' else None
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
    for row in parsed_rows(lines):
        if row.get('phase')=='run_contract':pointers.clear();next_pointer=0
        retired=[]
        if row['phase'] in ('obligation_dequeue','queue_membership_remove'):retired.append(row.get('list_node'))
        if row['phase']=='obligation_destroy':retired.append(row.get('native_address'))
        for key,value in list(row.items()):
            if key in IDENTITIES:row[key]='<'+key+'>'
            elif key in DURATIONS:
                number=float(value)
                if not math.isfinite(number) or number<0:raise ValueError('Invalid duration '+key)
                row[key]='<duration>'
            elif key in POINTERS:
                # Preserve live aliasing. Allocators may reuse an address after
                # the native queue removal / obligation destruction boundary.
                if value!='0':
                    if value not in pointers:
                        next_pointer+=1;pointers[value]='address:'+str(next_pointer)
                    row[key]=pointers[value]
            elif key in CODE_ADDRESSES:
                address=int(value,16)
                if address not in hooks:raise ValueError('Unreviewed native code address '+key+'='+value)
                row[key]=hooks[address]
        result.append(row)
        for address in retired:pointers.pop(address,None)
    if not result:raise ValueError('No canonical records')
    return result

def comparison(reference,candidate):
    for i,(a,b) in enumerate(zip(reference,candidate)):
        if a!=b:
            return dict(pass_=False,index=i,reference=a,candidate=b,
                        missing_fields=sorted(a.keys()-b.keys()),extra_fields=sorted(b.keys()-a.keys()))
    return dict(pass_=len(reference)==len(candidate),reference_records=len(reference),candidate_records=len(candidate))

def load_capture(path,sha):
    records=[];displays=[]
    for p in sorted(path.glob('events-*.log*')):
        with (gzip.open(p,'rt') if p.suffix=='.gz' else p.open()) as f:
            for line in f:
                if line.startswith('IC3_STATS '):records.append(line)
                elif line.startswith(('IC3_CTI ','IC3_VALIDATION ','IC3_OBLIGATION_')):displays.append(line.rstrip())
    return normalize(records,ROOT/'profiles'/(sha+'.events')),displays

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

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--models',type=Path,required=True,help='Pinned five-model directory with model.bs per model')
    parser.add_argument('--compare-only',action='store_true')
    args=parser.parse_args()
    args.output.mkdir(parents=True,exist_ok=args.compare_only)
    models={'shared':(ROOT/'source/tests/worker_protocol/model.bs',True)}
    for name in ('xy','and_predecessor','composite_property','delayed_bug'):
        models[name]=(args.models/name/'model.bs',False)
    report={'scope':'finite five-model M/M4 cross-release information parity; universal equivalence NOT claimed',
            'normalization':dict(identities=sorted(IDENTITIES),durations=sorted(DURATIONS),pointers=sorted(POINTERS),code_addresses=sorted(CODE_ADDRESSES)),
            'library_sha256':digest(ROOT/'libjipstats.so'),'models':{n:digest(p) for n,(p,s) in models.items()},'cases':[]}
    failures=[];phase_inventory={key:set() for key in RELEASES};display_inventory={key:set() for key in RELEASES}
    for name,(model,shared) in models.items():
        for engine in ('M','M4'):
            reference=None;reference_display=None;reference_verdicts=None
            for label,(release,sha) in RELEASES.items():
                case=args.output/name/engine/label;runtime=Path('/projects/external_ip/cadence')/release
                if not args.compare_only:
                    case.mkdir(parents=True)
                    worker=runtime/'Linux64/bin/jg_proof'
                    plain=run_worker(worker,runtime,ROOT,model,case/'plain',engine,False,shared,worker_sha=sha,sink='disk')
                    hooked=run_worker(worker,runtime,ROOT,model,case/'capture',engine,True,shared,worker_sha=sha,sink='disk')
                    if plain['verdicts']!=hooked['verdicts']:raise ValueError('Instrumentation changed native verdicts')
                else:
                    plain=json.loads((case/'plain/RESULT.json').read_text());hooked=json.loads((case/'capture/RESULT.json').read_text())
                    if plain['verdicts']!=hooked['verdicts']:raise ValueError('Native control mismatch')
                strict_ingest(case/'capture')
                invocation=json.loads((case/'capture/INVOCATION.json').read_text())
                if invocation['library_sha256']!=report['library_sha256'] or invocation['model_sha256']!=report['models'][name] or invocation['worker_sha256']!=sha:
                    raise ValueError('Capture component/model identity mismatch')
                rows,display=load_capture(case/'capture',sha)
                phase_inventory[label].update(x['phase'] for x in rows)
                display_inventory[label].update(x.split(' ',1)[0] for x in display)
                item=dict(model=name,engine=engine,release=label,records=len(rows),display_records=len(display),verdicts=hooked['verdicts'])
                if reference is None:
                    reference=rows;reference_display=display;reference_verdicts=hooked['verdicts']
                else:
                    item['records_comparison']=comparison(reference,rows)
                    item['displays_equal']=reference_display==display
                    item['native_verdicts_equal']=reference_verdicts==hooked['verdicts']
                    if not item['records_comparison']['pass_'] or not item['displays_equal'] or not item['native_verdicts_equal']:failures.append(item)
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
    report['status']='PASS' if not failures and report['all_phase_inventories_equal'] and report['required_content_exercised'] and all(report[k] for k in ('missing_field_detected','missing_event_detected','changed_payload_detected')) else 'FAIL'
    (args.output/'INFORMATION-PARITY.json').write_text(json.dumps(report,indent=2)+'\n')
    raise SystemExit(0 if report['status']=='PASS' else 1)

if __name__=='__main__':main()
