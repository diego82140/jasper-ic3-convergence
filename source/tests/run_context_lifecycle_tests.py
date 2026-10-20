#!/usr/bin/env python3
"""Exercise observer lifecycle with fake native layouts; never a Jasper proof.

Compile context_lifecycle_fixture.c against the packaged Gum SDK first, then
pass the binary and a fresh evidence directory. Retain causal captures/receipts.
"""
import argparse,datetime,gzip,hashlib,json,os,sqlite3,subprocess,sys
from pathlib import Path

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('binary',type=Path);p.add_argument('evidence',type=Path);a=p.parse_args()
 a.evidence.mkdir(parents=True,exist_ok=False)
 repo=Path(__file__).resolve().parents[2]
 env={k:v for k,v in os.environ.items() if k not in ('LD_PRELOAD','JIPSTATS_PROFILE','JIPSTATS_IMAGE')}
 modes=['positive','ambiguous','missing_validation','resumed_search','validation_abort','validation_outcomes','validation_nested_abort','validation_gum_abort','validation_outer_abort','validation_late_return']
 cases=[]
 for mode in modes:
  capture=a.evidence/mode;capture.mkdir();env['JIPSTATS_EVIDENCE_DIR']=str(capture)
  fixture=subprocess.run([str(a.binary.resolve())]+([] if mode=='positive' else [mode]),env=env,capture_output=True,text=True)
  assert fixture.returncode==0,(mode,fixture.stderr)
  allowed=mode in ('missing_validation','validation_gum_abort')
  reject=mode in ('ambiguous','resumed_search','validation_outer_abort','validation_late_return')
  command=[sys.executable,str(repo/'tools/telemetry_db.py'),'ingest',str(capture),str(capture/'index.db')]
  if allowed:command.append('--allow-incomplete')
  reader=subprocess.run(command,capture_output=True,text=True)
  row=dict(mode=mode,fixture_rc=fixture.returncode,fixture_stderr=fixture.stderr,reader_rc=reader.returncode,reader_stdout=reader.stdout,reader_stderr=reader.stderr)
  cases.append(row)
  assert (reader.returncode!=0)==reject,(mode,row)
  if not reject:
   receipt=json.loads(reader.stdout);assert receipt['complete']==(not allowed),(mode,receipt)
   with sqlite3.connect(capture/'index.db') as db:
    row['run_counts']=db.execute('SELECT count(*),sum(sealed),sum(complete) FROM runs').fetchone()
    row['terminal_counts']=dict(db.execute("SELECT phase,count(*) FROM events WHERE phase IN ('final','run_abort_seal','native_validation_abort','native_validation_missing') GROUP BY phase"))
   lines=[]
   for path in capture.glob('events-*.log.gz'):
    with gzip.open(path,'rb') as f:
     for line in f:
      if b'phase=native_validation_' in line:lines.append(line.decode())
   (capture/'validation-boundaries.txt').write_text(''.join(lines))
   if mode=='validation_abort':
    assert row['terminal_counts'].get('native_validation_abort')==1
    assert 'phase=native_validation_end ' not in ''.join(lines)
    assert 'result_raw=5 result=limit_or_unknown' in ''.join(lines)
   if mode=='validation_outcomes':
    ends=[line for line in lines if 'phase=native_validation_end ' in line]
    assert len(ends)==6
    assert [line.split(' outcome=')[1].split()[0] for line in ends]==['refuted_local','pass','pass','inconclusive','inconclusive','inconclusive']
   if mode=='validation_nested_abort':assert row['terminal_counts'].get('native_validation_abort',0)==0
  print(json.dumps(row))
 result=dict(utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),scope='fake-layout fixtures; NOT Jasper qualification or proof certificates',cases=cases,source_sha256={name:hashlib.sha256((repo/name).read_bytes()).hexdigest() for name in ['source/src/events.c','source/src/activations.h','source/src/parity.h','source/tests/context_lifecycle_fixture.c','tools/telemetry_db.py']},binary_sha256=hashlib.sha256(a.binary.read_bytes()).hexdigest())
 (a.evidence/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n')

if __name__=='__main__':main()
