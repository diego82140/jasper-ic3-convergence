#!/usr/bin/env python3
"""Behavioral archive checks against a native qualification capture."""
import gzip,importlib.util,shutil,tempfile,sqlite3,sys
from pathlib import Path
root=Path(__file__).resolve().parents[1]
s=importlib.util.spec_from_file_location('db',root/'tools/telemetry_db.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
source=Path(sys.argv[1])
with tempfile.TemporaryDirectory() as d:
    d=Path(d);good=m.ingest(source,d/'good.db');assert good['records']>0
    db=sqlite3.connect(d/'good.db')
    assert db.execute('SELECT count(*) FROM payloads WHERE complete=0').fetchone()[0]==0
    # Event removal and byte damage must both fail before a verified archive is published.
    for case in ('gap','damage','manifest'):
        target=d/case;shutil.copytree(source,target)
        if case=='manifest':
            next(target.glob('worker-*.manifest.json')).unlink()
        else:
            p=next(target.glob('events-*.log*'));lines=(gzip.open(p,'rb').read() if p.suffix=='.gz' else p.read_bytes()).splitlines(keepends=True)
            i=next(i for i,l in enumerate(lines) if l.startswith(b'IC3_STATS ') and b' event=2 ' in l)
            if case=='gap':del lines[i]
            else:lines[i]=lines[i].replace(b' event=2 ',b' event=9 ')
            
            if p.suffix=='.gz':
                with gzip.open(p,'wb') as f:f.write(b''.join(lines))
            else:p.write_bytes(b''.join(lines))
        try:m.ingest(target,d/(case+'.db'))
        except ValueError:pass
        else:raise AssertionError('corruption accepted: '+case)
print('PASS: native payload hashes, missing event, damaged event, missing manifest')
