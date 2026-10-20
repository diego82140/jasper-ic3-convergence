#!/usr/bin/env python3
"""Executable ABI/injection regressions; fixture results are not Jasper proofs."""
from pathlib import Path
import json,subprocess,os,re,hashlib,tempfile,sys
W=Path(__file__).resolve().parents[1]
B=Path(os.environ.get('JIPSTATS_TEST_BUILD',str(W.parent/'rebuilt'))).resolve()
worker=B/'marker-free-worker';lib=B/'libjipstats.so';profile=B/'marker-free.events'
(B/'evidence').mkdir(exist_ok=True)
assert b'IC3_STATS' not in worker.read_bytes()
base=subprocess.run([str(worker)],capture_output=True,text=True,check=True).stdout
results=[]
with tempfile.TemporaryDirectory(prefix='jipstats-events-tests-') as tmp:
 tmp=Path(tmp)
 def test(name,profile_text=None,extra=None):
  out=tmp/name;out.mkdir();p=out/'worker.events';p.write_text(profile.read_text() if profile_text is None else profile_text)
  env=dict(os.environ);env.pop('LD_PRELOAD',None)
  env.update(LD_PRELOAD=str(lib),JIPSTATS_PROFILE=str(p),JIPSTATS_IMAGE=str(worker),JIPSTATS_EVIDENCE_DIR=str(out))
  if extra:env.update(extra)
  run=subprocess.run([str(worker)],env=env,capture_output=True,text=True,timeout=10)
  assert run.returncode==0,(name,run.stderr)
  native=''.join(line for line in run.stdout.splitlines(keepends=True) if not line.startswith('IC3_STATS '))
  assert native==base,(name,native)
  rows=[dict(re.findall(r'(\w+)=([^ ]+)',l)) for l in run.stdout.splitlines() if l.startswith('IC3_STATS ')]
  return rows,run
 rows,run=test('normal')
 for field in ('relative','sat'):
  begin=[r for r in rows if r['phase']==field+'_begin'];end=[r for r in rows if r['phase']==field+'_end']
  assert len(begin)==len(end)==6
  keys=lambda rr:{(r['run'],r.get('call',r.get('query'))) for r in rr}
  assert keys(begin)==keys(end)
  assert [r['result'] for r in end].count('sat')==2
  assert [r['result'] for r in end].count('unsat')==2
 results.append({'test':'zero-marker generation, typed results and balanced pairs','status':'PASS'})
 assert all(r['encoding']=='chunked_raw_jip_formula_u32' and r['truncated']=='0' for r in rows if r['phase']=='cube')
 definitions={};payloads={}
 for r in rows:
  if r['phase']=='cube_definition':definitions[(r['run'],r['cube_id'])]=r;payloads[(r['run'],r['cube_id'])]=[]
  elif r['phase']=='cube_chunk':
   key=(r['run'],r['cube_id']);assert int(r['offset'])==len(payloads[key]);payloads[key]+=r['values'].split(',')
  elif r['phase']=='cube_definition_end':
   key=(r['run'],r['cube_id']);assert r['complete']=='1' and len(payloads[key])==int(r['literals'])
   expected=hashlib.sha256(definitions[key]['domain'].encode()+b'\0'+int(r['literals']).to_bytes(4,'little')+b''.join(int(x,16).to_bytes(4,'little') for x in payloads[key])).hexdigest()
   assert expected==definitions[key]['sha256']
 assert any(len(values)==257 for values in payloads.values())
 assert any(len(values)==256 for values in payloads.values())
 results.append({'test':'complete 257-literal cubes and 256-literal generalized cubes independently reconstructed and SHA256 checked','status':'PASS'})
 finals=[r for r in rows if r['phase']=='final'];assert len(finals)==2
 assert [f['result'] for f in finals]==['valid','cex']
 assert all(f['relative_calls']=='3' and f['solver_calls']=='3' and f['generalize_calls']=='1' and f['obligation_process_calls']=='1' and f['obligations_created']=='1' for f in finals)
 results.append({'test':'instance lifecycle and own independent counters','status':'PASS'})
 assert all(f['read_failures']=='0' and f['callback_failures']=='0' and f['lost']=='0' for f in finals)
 results.append({'test':'original data/results preserved and no telemetry failures','status':'PASS'})
 text=profile.read_text();rows,run=test('wrong_hash',re.sub(r'sha256 [0-9a-f]+','sha256 '+'0'*64,text))
 assert not rows and 'image_hash_mismatch' in run.stderr
 results.append({'test':'wrong fingerprint does not attach','status':'PASS'})
 changed=text.splitlines();i=next(i for i,l in enumerate(changed) if l.startswith('hook '));x=changed[i].split();x[-1]='00'*16;changed[i]=' '.join(x)
 rows,run=test('wrong_instruction','\n'.join(changed)+'\n');assert not rows and 'instruction_guard_mismatch' in run.stderr
 results.append({'test':'instruction guards checked before any hook installation','status':'PASS'})
 rows,run=test('old_logger_profile','JIPSTATS_SITES 1\n');assert not rows and 'profile_rejected' in run.stderr
 results.append({'test':'legacy log-forwarding profile not used as event injection','status':'PASS'})
 rows,run=test('capped_records',extra={'JIPSTATS_MAX_RECORDS':'5'})
 finals=[r for r in rows if r['phase']=='final'];assert len(finals)==2 and all(int(f['lost'])>0 for f in finals)
 results.append({'test':'record cap explicit, final retained, original behavior unchanged','status':'PASS'})
 rows,run=test('invalid_callback',text.replace('callback 0 2','callback 900000 2'))
 assert not rows and 'callback_failures=' in run.stderr
 results.append({'test':'invalid memory reads do not fault or change target results','status':'PASS'})
 # Freshly strip the fixture. Automatic blind ABI inference must reject it;
 # a profile qualified from the original fixture can be producer-pinned again.
 stripped=tmp/'worker-stripped';subprocess.run(['strip','-o',str(stripped),str(worker)],check=True)
 assert b'IC3_STATS' not in stripped.read_bytes()
 results.append({'test':'fixture has no marker strings before or after strip','status':'PASS'})
report={'status':'PASS','scope':'marker-free compiled fixture, not native Jasper proof',
 'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'binary_sha256':hashlib.sha256(worker.read_bytes()).hexdigest(),
 'tests':results}
(B/'evidence/FIXTURE-TESTS.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
