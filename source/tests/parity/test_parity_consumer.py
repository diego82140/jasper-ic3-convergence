#!/usr/bin/env python3
"""Consumer integrity and false-parity rejection checks on the actual native log."""
from pathlib import Path
import argparse,copy,hashlib,importlib.util,io,json,os,re,subprocess,sys
from suite import records,compare
S=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(S))
spec=importlib.util.spec_from_file_location('consumer',S/'analysis.py');a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
sys.path.insert(0,str(S.parent/'rebuilt/test-deps/pyelftools-0.32'))
spec=importlib.util.spec_from_file_location('launcher',S/'jipstats.py');j=importlib.util.module_from_spec(spec);spec.loader.exec_module(j)
sys.path.insert(0,str(S/'tests'));from test_semantic_analysis import rows_after_rechain

def main():
 p=argparse.ArgumentParser();p.add_argument('--suite',type=Path,required=True);p.add_argument('--output',type=Path,required=True);args=p.parse_args();args.output.mkdir(parents=True,exist_ok=False)
 case=args.suite/'shared/M';capture=case/'preload/IC3-STATS.log';manifest=next((case/'preload').glob('worker-*.manifest.json'))
 result=a.analyse_records(capture,True,[manifest]);assert result['complete'] and result['session_complete']
 reconstructed=[x['raw'] for run in result['runs'].values() for x in run['native_dollar_diagnostics']]
 raw=(case/'preload/DOLLAR-DIAGNOSTICS.log').read_text().splitlines();assert reconstructed==raw
 oracle=records(case/'stats.log');event=records(capture);diag=records(case/'preload/DOLLAR-DIAGNOSTICS.log')
 tests=[{'test':'all native parity bytes retained exactly in structured analysis','status':'PASS','records':len(raw)}]
 # Each corruption must lose the PASS, not be hidden by intersection/projection.
 def damage(name,changed):
  report=compare(oracle,event,changed);assert not report['pass'],name;tests.append({'test':name,'status':'PASS','corruption_rejected':True})
 damage('drop CTI family',[r for r in diag if r['family']!='IC3_CTI'])
 damage('drop validation family',[r for r in diag if r['family']!='IC3_VALIDATION'])
 damage('drop obligation focus',[r for r in diag if r['family']!='IC3_OBLIGATION_FOCUS'])
 for field in ('active_property','target_state','state','target_fingerprint','source_target_state','sample'):
  mutated=copy.deepcopy(diag)
  row=next(r for r in mutated if r['family']=='IC3_CTI')
  row['raw']=re.sub(r'\b'+field+r'=(?:"[^"]*"|[^ ]+)',field+'="CORRUPT"',row['raw'])
  damage('change CTI '+field,mutated)
 mutated=copy.deepcopy(oracle);scalar=next(r for r in mutated if r['family']=='IC3_STATS');scalar['fields']['unimplemented_baseline_field']='1'
 assert not compare(mutated,event,diag)['pass'];tests.append({'test':'new baseline scalar is not silently dropped','status':'PASS'})
 mutated=copy.deepcopy(oracle);next(r for r in mutated if r['family']=='IC3_STATS')['fields']['phase']='unimplemented_phase'
 try:compare(mutated,event,diag);raise AssertionError('Unknown baseline phase silently ignored')
 except ValueError as exc:assert 'Unmapped actual Dollar statistics phase' in str(exc)
 tests.append({'test':'unknown baseline record phase is rejected','status':'PASS'})
 lines=capture.read_text().splitlines()
 def check_log(name,mutated,match):
  # Recompute the ordinary event chain; the independent native payload hash and
  # structural constraints must still detect this corruption.
  path=args.output/(name+'.log');path.write_text('\n'.join(rows_after_rechain(mutated))+'\n')
  try:a.analyse_records(path);raise AssertionError('Invalid log accepted '+name)
  except ValueError as exc:
   assert match in str(exc),(name,exc);tests.append({'test':name,'status':'PASS','reason':str(exc)})
  path.unlink()
 changed=lines[:];i=next(i for i,l in enumerate(changed) if 'phase=parity_record_chunk ' in l)
 changed[i]=re.sub(r'utf8_hex=([0-9a-f]{2})',lambda m:'utf8_hex='+('00' if m[1]!='00' else 'ff'),changed[i],count=1)
 check_log('tamper_named_CTIs_after_rechaining',changed,'digest mismatch')
 changed=lines[:];i=next(i for i,l in enumerate(changed) if 'phase=parity_record_chunk ' in l);changed[i]=re.sub(r'offset=\d+','offset=1',changed[i])
 check_log('skip_native_payload_byte',changed,'gap/overlap')
 # Finished logs with a missing end must not be called complete, even if hashes
 # are rewritten (there is no authentication claim).
 changed=[l for l in lines if 'phase=parity_record_end ' not in l]
 check_log('remove_parity_record_completion',changed,'sequence/overlap')
 # Exact named-state payloads must be visible in the customer live mirror.
 out=io.StringIO();folder=args.output/'live';folder.mkdir();(folder/'events-1-1.log').write_text('\n'.join(raw)+'\n')
 live=j.LiveStatistics(folder,'native',out);live.pump();live.pump()
 assert live.parity_records==len(raw) and live.records==0
 for row in raw:assert '[jipstats live native] '+row+'\n' in out.getvalue()
 tests.append({'test':'live mirror displays native CTI validation and focus once each','status':'PASS','displayed':live.parity_records})
 # Exercise actual frozen no-Python analyzer on the fundamental x/y example.
 xy=args.suite/'xy/M/preload';outfile=args.output/'xy-analysis.json';brief=args.output/'xy-llm-brief.json'
 run=subprocess.run([str(S.parent/'jipstats'),'--analyse',str(xy/'IC3-STATS.log'),'--manifest',str(next(xy.glob('worker-*.manifest.json'))),'--details','--output',str(outfile),'--llm-brief',str(brief)],env={'PATH':'/nonexistent','HOME':str(args.output)},capture_output=True,text=True,timeout=30)
 assert run.returncode==0,run.stderr
 b=json.loads(brief.read_text());cti=[c for v in b['runs'].values() for c in v['named_predecessor_ctis']]
 assert len(cti)==1 and cti[0]['fields']['active_property']=='~x' and cti[0]['fields']['state']=='y' and cti[0]['fields']['target_state']=='y'
 tests.append({'test':'prebuilt analyzer LLM packet has actual ~x/y/y fields','status':'PASS'})
 (args.output/'PARITY-CONSUMER-TESTS.json').write_text(json.dumps({'status':'PASS','tests':tests,'count':len(tests),'authentication_claimed':False},indent=2)+'\n')
 print('PASS',len(tests),'parity consumer and negative-comparator checks')
if __name__=='__main__':main()
