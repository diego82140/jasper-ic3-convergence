#!/usr/bin/env python3
"""Optional producer tests; dependencies taken from bundled source archive."""
from pathlib import Path
import importlib.util, os, subprocess, sys, tarfile
S=Path(__file__).resolve().parents[1]
B=Path(os.environ.get('JIPSTATS_TEST_BUILD',str(S.parent/'rebuilt'))).resolve()
B.mkdir(parents=True,exist_ok=True)
deps=B/'test-deps';deps.mkdir(exist_ok=True)
a=S.parent/'third_party/python-sources/pyelftools-0.32.tar.gz'
with tarfile.open(a) as t:
 for m in t:
  p=Path(m.name)
  if p.is_absolute() or '..' in p.parts or m.issym() or m.islnk():raise RuntimeError('Unsafe third-party archive')
 t.extractall(deps)
sys.path[:0]=[str(S),str(deps/'pyelftools-0.32')]
from prepare import derive
worker=B/'marker-free-worker'
subprocess.run(['g++','-std=c++17','-O0','-g','-fno-inline','-no-pie',str(S/'tests/marker_free_fixture.cpp'),'-o',str(worker)],check=True)
if b'IC3_STATS' in worker.read_bytes():raise RuntimeError('Fixture must not contain telemetry markers')
text,meta=derive(worker)
(B/'marker-free.events').write_text(text)
import json
(B/'marker-free-profile.json').write_text(json.dumps(meta,indent=2)+'\n')
env=dict(os.environ);env['JIPSTATS_TEST_BUILD']=str(B)
subprocess.run([sys.executable,'-S',str(S/'tests/check_events.py')],env=env,check=True)
