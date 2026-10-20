#!/usr/bin/env python3
"""Independent telemetry integrity tests using a real captured native stream.
Usage: python3 tests/test_reconstruction.py /path/to/IC3-STATS.log
Not a Jasper proof; proves the log parser rejects the listed corruptions.
"""
from pathlib import Path
import importlib.util,json,sys,tempfile
source=Path(__file__).resolve().parents[1]/'analysis.py'
spec=importlib.util.spec_from_file_location('capture_analysis',source)
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
lines=Path(sys.argv[1]).read_text().splitlines()
results=[]
with tempfile.TemporaryDirectory(prefix='jipstats-reconstruction-') as td:
 def check(name,rows,expected):
  path=Path(td)/'input.log';path.write_text('\n'.join(rows)+'\n')
  try:
   report=a.analyse_records(path)
   outcome='complete' if report['complete'] else 'incomplete'
  except (ValueError,KeyError):outcome='rejected'
  if outcome!=expected:raise AssertionError((name,outcome,expected))
  results.append({'test':name,'status':'PASS','outcome':outcome})
 check('actual complete worker stream',lines,'complete')
 check('identical native and live-mirror duplication',lines+lines,'complete')
 check('empty input',[],'rejected')
 check('lost middle event',lines[:20]+lines[21:],'rejected')
 check('truncated last run',lines[:-1],'incomplete')
 rows=lines[:];i=next(i for i,s in enumerate(rows) if 'phase=cube_chunk ' in s)
 start=rows[i].index('values=')+7;old=rows[i][start:start+8]
 rows[i]=rows[i][:start]+format(int(old,16)^8,'08x')+rows[i][start+8:]
 check('changed cube payload',rows,'rejected')
 rows=lines[:];i=next(i for i,s in enumerate(rows) if 'phase=native_final_check ' in s)
 rows[i]=rows[i].replace('match=1','match=0');check('native final count mismatch',rows,'rejected')
 rows=lines[:];i=next(i for i,s in enumerate(rows) if 'phase=final ' in s)
 rows[i]=rows[i].replace('lost=0','lost=1');check('reported data loss',rows,'rejected')
 rows=lines[:];i=next(i for i,s in enumerate(rows) if 'phase=obligation ' in s)
 import re
 rows[i]=re.sub(r'parent_id=\d+', 'parent_id=999999999',rows[i]);check('undefined obligation parent',rows,'rejected')
 rows=lines[:];i=next(i for i,s in enumerate(rows) if 'phase=frames_end ' in s)
 rows[i]=rows[i].replace('complete=1','complete=0');check('incomplete frame snapshot',rows,'rejected')
 rows=lines[:];i=next(i for i,s in enumerate(rows) if 'phase=queues_end ' in s)
 rows[i]=rows[i].replace('complete=1','complete=0');check('incomplete queue snapshot',rows,'rejected')
 rows=lines[:];i=next(i for i,s in enumerate(rows) if 'phase=signal_name_chunk ' in s)
 rows[i]=rows[i].replace('offset=0','offset=1');check('retained-name chunk gap',rows,'rejected')
 rows=lines[:];rows.append(rows[20]+' corrupt=1');check('contradictory duplicate event',rows,'rejected')
 print(json.dumps({'status':'PASS','tests':results,'scope':'Native-stream reconstruction validation, not proof-engine replacement'},indent=2))
