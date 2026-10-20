#!/usr/bin/env python3
"""Adversarial semantic tests against a real, measured worker capture.
Mutations are re-chained when stated, to test semantics independently of hashes.
No mock data is represented as a native proof.
"""
from pathlib import Path
import argparse,importlib.util,collections,hashlib,json,re,subprocess,tempfile
S=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('a',S/'analysis.py');a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)

def rows_after_rechain(rows):
    out=[];tips={};counts=collections.Counter();finals={}
    for row in rows:
        text=row.rsplit(' chain=',1)[0];r=dict(re.findall(r'(\w+)=([^ ]*)',text));key=(r['capture'],r['pid'],r['tid'],r['run'])
        counts[key]+=1;n=counts[key];text=re.sub(r'\bevent=\d+',f'event={n}',text)
        if r['phase']=='final':finals[key]=n
        if r['phase']=='run_seal':
            text=re.sub(r'events_before_seal=\d+',f'events_before_seal={n-1}',text)
            text=re.sub(r'final_event=\d+',f'final_event={finals[key]}',text)
        h=hashlib.sha256(bytes.fromhex(tips.get(key,'0'*64))+text.encode()).hexdigest();tips[key]=h
        out.append(text+' chain='+h)
    return out

def main():
    p=argparse.ArgumentParser();p.add_argument('capture',type=Path);p.add_argument('manifest',type=Path);p.add_argument('--output',type=Path,required=True);args=p.parse_args()
    args.output.mkdir(parents=True,exist_ok=False);rows=args.capture.read_text().splitlines();tests=[]
    def test(name,lines,expected='rejected',rechain=True,manifest=False,frozen=False):
        if rechain:lines=rows_after_rechain(lines)
        path=args.output/(name+'.log');path.write_text('\n'.join(lines)+'\n')
        error=None
        try:
            r=a.analyse_records(path,False,[args.manifest] if manifest else None);got='complete' if r['complete'] else 'incomplete'
        except (ValueError,KeyError) as e:got='rejected';error=str(e)
        if got!=expected:raise AssertionError((name,expected,got,error))
        item={'test':name,'result':got,'expected':expected,'recomputed_hashes':rechain,'reason':error,'status':'PASS'}
        if frozen:
            cmd=[str(S.parent/'jipstats'),'--analyse',str(path),'--output',str(args.output/(name+'.json'))]
            if manifest:cmd+=['--manifest',str(args.manifest)]
            run=subprocess.run(cmd,capture_output=True,text=True,timeout=25)
            want=0 if expected=='complete' else 2
            if run.returncode!=want:raise AssertionError((name,run.returncode,run.stderr))
            (args.output/(name+'.console.txt')).write_text(run.stdout+run.stderr);item['standalone_exit']=run.returncode
        tests.append(item)
        # Preserve compact reproductions for forged final-only and key cases, not
        # dozens of full 10MB copies: changed inputs are deterministically regenerated.
        if name not in ('final_only','unmodified') and not frozen:path.unlink()
    def alter(phase,field,value,predicate=lambda r:True):
        new=rows[:]
        for i,line in enumerate(new):
            r=dict(re.findall(r'(\w+)=([^ ]*)',line))
            if r['phase']==phase and predicate(r):
                v=value(r) if callable(value) else value
                new[i]=re.sub(r'\b'+field+r'=[^ ]*',field+'='+str(v),line);return new
        raise AssertionError('No matching phase '+phase)
    test('unmodified',rows,'complete',False,True,True)
    test('mirror_duplicate',rows+rows,'complete',False)
    test('final_only',[next(l for l in rows if 'phase=final ' in l)],frozen=True)
    test('forged_solver_counter',alter('final','solver_calls','999999'),frozen=True)
    test('self_parent',alter('obligation','parent_id',lambda r:r['obligation_id']),frozen=True)
    test('undefined_parent',alter('obligation','parent_id','999999'))
    test('wrong_relative_parent',alter('sat_end','relative_query','99999'))
    test('unknown_solver_result',alter('sat_end','result','MAGIC_UNSAT'))
    test('raw_result_disagrees',alter('sat_end','result_raw','99999',lambda r:r['result']=='sat'))
    test('wrong_query_frame',alter('relative_end','frame','99999'))
    test('wrong_formula_class',alter('query_context','query_class','relative_induction',lambda r:r['query_class']=='predecessor_exclusion'))
    test('wrong_parent_kind',alter('query_context','parent_kind','push',lambda r:r['parent_kind']!='push'))
    test('forged_global_lemma',alter('query_conclusion','promote_to_global_lemma','1'),frozen=True)
    test('forged_initialization_check',alter('query_conclusion','initialization_validated','1'))
    test('context_closed_claim',alter('run_contract','context_formula_closed','1'))
    test('missing_semantic_query',[l for l in rows if 'phase=query_context ' not in l])
    test('missing_conclusions',[l for l in rows if 'phase=query_conclusion ' not in l])
    test('wrong_operation_parent',alter('operation_enter','parent_operation','99999'))
    test('incomplete_snapshot',alter('frames_end','complete','0'))
    test('false_native_crosscheck',alter('native_final_check','match','0'))
    test('changed_cube_without_hash_update',alter('cube_chunk','values',lambda r:'00000001'+(','+r['values'].split(',',1)[1] if ',' in r['values'] else '')))
    test('changed_name_original_chain',alter('signal_name_chunk','utf8_hex',lambda r:('00'+r['utf8_hex'][2:])),rechain=False)
    test('changed_name_original_manifest',alter('signal_name_chunk','utf8_hex',lambda r:('00'+r['utf8_hex'][2:])),manifest=True)
    test('missing_whole_final_run',[l for l in rows if ' run=4 ' not in l],manifest=True,frozen=True)
    test('truncated_seal',rows[:-1],'incomplete',False)
    complete=a.analyse_records(args.capture,True,[args.manifest]);native_phases=complete['phases']
    assert sum(len(r['solver_queries']) for r in complete['runs'].values())==native_phases['sat_begin']
    assert sum(len(r['relative_queries']) for r in complete['runs'].values())==native_phases['relative_begin']
    assert sum(len(r['frame_history']) for r in complete['runs'].values())==native_phases['frames_end']
    assert sum(len(r['queue_history']) for r in complete['runs'].values())==native_phases['queues_end']
    assert sum(len(r['operations']) for r in complete['runs'].values())==native_phases['operation_enter']
    for r in complete['runs'].values():
        assert r['independently_certified_global_lemmas']==0
        assert (r['final']['result']=='valid')==r['native_reported_fixpoint']
        for candidate in r['diagnosis']['top_investigations']:
            assert candidate['candidate']['status']=='UNVALIDATED' and not candidate['candidate']['automatic_assumption_permitted']
            assert candidate['estimated_speedup'] is None
    tests.append({'test':'all_joined_queries_checkpoints_lifecycles_retained_no_proof_promotion','status':'PASS'})
    report={'status':'PASS','tests':tests,'counts':native_phases,'authenticated':False,
            'scope':'real-capture reconstruction and adversarial analysis, not a proof of arbitrary engine instrumentation'}
    (args.output/'SEMANTIC-TESTS.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS',len(tests),'tests')
if __name__=='__main__':main()
