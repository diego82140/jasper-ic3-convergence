#!/usr/bin/env python3
"""Verify closed-capture compression is byte-preserving and active logs are rejected."""
import contextlib,gzip,importlib.util,io,json,tempfile
from pathlib import Path
root=Path(__file__).resolve().parents[1]
s=importlib.util.spec_from_file_location('pack',root/'tools/archive_pack.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
with tempfile.TemporaryDirectory() as d:
    p=Path(d);source=p/'events-12-12.log';data=(b'complete record\n'*10000)+bytes(range(256));source.write_bytes(data)
    manifest=p/'worker-12.manifest.json';manifest.write_text(json.dumps({'process_closed':False}))
    try:m.pack(p,True)
    except ValueError:pass
    else:raise AssertionError('active capture accepted')
    assert source.read_bytes()==data and not (p/'events-12-12.log.gz').exists()
    manifest.write_text(json.dumps({'process_closed':True}))
    with contextlib.redirect_stdout(io.StringIO()):m.pack(p,True)
    archive=p/'events-12-12.log.gz'
    assert not source.exists() and gzip.open(archive,'rb').read()==data
    original=archive.read_bytes();manifest.write_text(json.dumps({'process_closed':False}))
    try:m.compact(p)
    except ValueError:pass
    else:raise AssertionError('active gzip capture accepted')
    assert archive.read_bytes()==original
    manifest.write_text(json.dumps({'process_closed':True}))
    with contextlib.redirect_stdout(io.StringIO()):m.compact(p)
    assert archive.stat().st_size<len(original) and gzip.open(archive,'rb').read()==data
    compacted=archive.read_bytes()
    with contextlib.redirect_stdout(io.StringIO()):m.compact(p)
    assert archive.read_bytes()==compacted  # no expansion/rewrite of an already smaller archive
print('PASS: raw and gzip exact byte round trips; active captures rejected; compaction never expands archive')
