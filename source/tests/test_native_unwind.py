"""Actual Gum/C++ exception regressions. This worker is not Jasper."""
from pathlib import Path
import gzip,hashlib,importlib.util,json,os,re,subprocess,sys,tempfile
SOURCE=Path(__file__).resolve().parents[1]
BUILD=Path(os.environ.get('JIPSTATS_TEST_BUILD',str(SOURCE.parent/'rebuilt'))).resolve()
sys.path.insert(0,str(BUILD/'test-deps/pyelftools-0.32'))
from elftools.elf.elffile import ELFFile
worker=BUILD/'marker-free-worker';library=BUILD/'libjipstats.so'
profile=(BUILD/'marker-free.events').read_text()
with worker.open('rb') as f:
 elf=ELFFile(f)
 symbol=next(s for s in elf.get_section_by_name('.symtab').iter_symbols() if s.name.startswith('_Z13fixture_probe'))
 address=int(symbol['st_value'])
 segment=next(s for s in elf.iter_segments() if s['p_type']=='PT_LOAD' and s['p_vaddr']<=address< s['p_vaddr']+s['p_filesz'])
 f.seek(segment['p_offset']+address-segment['p_vaddr']);guard=f.read(16).hex()
profile+=f'hook trace {address:x} 0 1 -1 -1 -1 0 {guard}\n'
spec=importlib.util.spec_from_file_location('telemetry',SOURCE.parent/'tools/telemetry_db.py')
telemetry=importlib.util.module_from_spec(spec);spec.loader.exec_module(telemetry)
results=[]
with tempfile.TemporaryDirectory(prefix='jipstats-native-unwind-') as tmp:
 tmp=Path(tmp)
 for mode in ('entry','probe','ancestor','generalize','recursive','tail','two_runs','recursive_throw','selfcatch','second_throw','longjmp'):
  out=tmp/mode;out.mkdir();p=out/'profile.events';p.write_text(profile)
  env=dict(os.environ,FIXTURE_UNWIND=mode)
  env.pop('LD_PRELOAD',None)
  baseline=subprocess.run([str(worker)],env=env,capture_output=True,check=True,timeout=30)
  env.update(LD_PRELOAD=str(library),JIPSTATS_PROFILE=str(p),JIPSTATS_IMAGE=str(worker),
             JIPSTATS_EVIDENCE_DIR=str(out),JIPSTATS_SINK='disk',JIPSTATS_COMPRESSION='gzip')
  observed=subprocess.run([str(worker)],env=env,capture_output=True,check=True,timeout=30)
  assert observed.stdout==baseline.stdout,(mode,observed.stdout,baseline.stdout)
  data=b''.join(gzip.open(p,'rb').read() for p in sorted(out.glob('events-*.log.gz')))
  rows=[telemetry.fields(line.rstrip(b'\n')) for line in data.splitlines() if line.startswith(b'IC3_STATS ')]
  live={};counts={};returned=aborted=0
  for r in rows:
   phase=r['phase']
   if phase=='invocation_begin':
    counts.setdefault(r['run'],[0,0,0])[0]+=1
    token=r['activation'];assert token not in live
    parent=r['parent_activation'];assert parent=='0' or parent in live
    live[token]=(r['hook'],r['operation'])
   elif phase in ('invocation_return','invocation_abort'):
    assert live.pop(r['activation'])==(r['hook'],r['operation'])
    if phase=='invocation_abort':aborted+=1;assert r['native_return_observed']=='0'
    else:returned+=1;assert r['native_return_observed']=='1'
    counts[r['run']][2 if phase=='invocation_abort' else 1]+=1
  assert not live
  starts={(r['run'],r['query']):r for r in rows if r['phase']=='relative_begin'}
  ends={(r['run'],r['query']):r for r in rows if r['phase']=='relative_end'}
  aborts={(r['run'],r['query']):r for r in rows if r['phase']=='query_abort'}
  expected_aborts=2 if mode in ('recursive_throw','second_throw') else 1
  assert len(aborts)==expected_aborts and not(set(ends)&set(aborts)) and set(starts)==set(ends)|set(aborts)
  aborted_query=max(aborts,key=lambda k:int(aborts[k]['event']));assert starts[aborted_query]['frame'] in ('3','5','7')
  assert all('result' not in r and 'result_raw' not in r and r['native_return_observed']=='0' for r in aborts.values())
  assert 'result' not in aborts[aborted_query] and 'result_raw' not in aborts[aborted_query]
  driver=next(r for r in rows if r['phase']=='invocation_begin' and r['hook']=='run')
  if mode=='probe':
   probe=next(r for r in rows if r['phase']=='block_begin' and r.get('boundary')=='native_cexAttempt')
   assert probe['op_id']==driver['operation'],('probe retained abandoned operation',probe)
  if mode not in ('ancestor','longjmp'):
   after=[r for r in rows if r['phase']=='sat_begin' and int(r['event'])>int(aborts[aborted_query]['event'])]
   assert after and after[0]['relative_query']=='0',('driver inherited aborted query',mode,after[:1])
  if mode=='longjmp':
   after=[r for r in rows if r['phase']=='sat_begin' and int(r['event'])>int(aborts[aborted_query]['event'])]
   assert after and all(r['relative_query']=='0' or int(starts[(r['run'],r['relative_query'])]['event'])>int(aborts[aborted_query]['event']) for r in after)
  if mode=='recursive':
   assert len(starts)==6 and len(ends)==5
   assert any(r['frame']=='4' for r in ends.values())
  if mode=='tail':
   assert sum(r['phase']=='invocation_begin' and r['hook']=='relative' for r in rows)==len(starts)
   assert any(r['phase']=='listener_alias' and r['distinct_native_call']=='0' for r in rows)
  if mode=='generalize':assert any(r['phase']=='operation_abort' and r['kind']=='generalize' for r in rows)
  for seal in (r for r in rows if r['phase']=='run_seal'):
   assert seal['capture_status']==('incomplete' if mode=='longjmp' else 'complete') and seal['activation_live']=='0'
   assert (int(seal['observer_errors'])>0 or int(seal['native_unwind_runtime_fault'])>0)==(mode=='longjmp'),(mode,seal)
   assert seal['native_unwind_return_restore']=='1'
   began,ended,unwound=counts[seal['run']]
   assert int(seal['activation_returns'])==ended and int(seal['activation_aborts'])==unwound
   assert int(seal['activation_begins'])==began==ended+unwound
  manifest=json.loads(next(out.glob('worker-*.manifest.json')).read_text())
  assert manifest['process_closed']
  if mode=='longjmp':
   assert not all(r['sealed'] for r in manifest['runs'])
   try:telemetry.ingest(out,tmp/(mode+'.db'),allow_incomplete=True)
   except ValueError as e:assert 'observer' in str(e)
   else:raise AssertionError('Lost nonlocal scope coverage must fail closed')
   indexed={'records':len(rows),'complete':False}
  else:
   assert all(r['sealed'] for r in manifest['runs'])
   indexed=telemetry.ingest(out,tmp/(mode+'.db'));assert indexed['complete']
  results.append({'mode':mode,'status':'PASS','native_stdout_unchanged':True,'relative_queries':len(starts),
                  'relative_returns':len(ends),'explicit_query_aborts':len(aborts),'invocation_aborts':aborted,
                  'strict_records':indexed['records'],'fixture_not_jasper':True})
print(json.dumps(results,indent=2))
