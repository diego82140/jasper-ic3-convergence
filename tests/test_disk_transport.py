#!/usr/bin/env python3
"""Marker-free compiled ABI fixture: transport behavior, not Jasper evidence."""
import gzip,os,subprocess,tempfile,json,sys,importlib.util,shutil
from pathlib import Path
root=Path(__file__).resolve().parents[1];build=Path(os.environ.get('JIPSTATS_TEST_BUILD',str(root/'rebuilt')))
with tempfile.TemporaryDirectory() as d:
    d=Path(d);env=dict(os.environ)
    env.update(LD_PRELOAD=str(build/'libjipstats.so'),JIPSTATS_PROFILE=str(build/'marker-free.events'),JIPSTATS_IMAGE=str(build/'marker-free-worker'),JIPSTATS_EVIDENCE_DIR=str(d),JIPSTATS_SINK='disk')
    base=subprocess.run([str(build/'marker-free-worker')],capture_output=True,check=True)
    run=subprocess.run([str(build/'marker-free-worker')],env=env,capture_output=True,check=True)
    assert run.stdout==base.stdout,'instrumentation reached the original callback'
    logs=list(d.glob('events-*.log'));assert logs
    data=b''.join(p.read_bytes() for p in logs)
    assert b'IC3_STATS phase=cube_chunk' in data and b'truncated=0' in data
    manifests=list(d.glob('worker-*.manifest.json'));assert len(manifests)==1
    m=json.loads(manifests[0].read_text());assert not m['dropped_records'] and m['process_closed']
    compressed=d/'compressed';compressed.mkdir();env.update(JIPSTATS_EVIDENCE_DIR=str(compressed),JIPSTATS_COMPRESSION='gzip')
    run=subprocess.run([str(build/'marker-free-worker')],env=env,capture_output=True,check=True)
    assert run.stdout==base.stdout
    compressed_logs=list(compressed.glob('events-*.log.gz'));assert compressed_logs
    decoded=b''.join(gzip.open(p,'rb').read() for p in compressed_logs)
    assert b'IC3_STATS phase=cube_definition_end' in decoded and b'truncated=0' in decoded
    assert sum(p.stat().st_size for p in compressed_logs)<len(decoded)//2
    # A clean early process exit must attest the captured unsealed tail too.
    early=d/'early';early.mkdir();env.update(JIPSTATS_EVIDENCE_DIR=str(early),FIXTURE_EARLY_EXIT='1')
    subprocess.run([str(build/'marker-free-worker')],env=env,capture_output=True,check=True)
    manifest=json.loads(next(early.glob('worker-*.manifest.json')).read_text())
    assert manifest['process_closed'] and manifest['ledger_tail_on_each_record']
    assert manifest['runs'][0]['events']>0 and not manifest['runs'][0]['sealed']
    spec=importlib.util.spec_from_file_location('telemetry',root/'tools/telemetry_db.py');db=importlib.util.module_from_spec(spec);spec.loader.exec_module(db)
    indexed=db.ingest(early,d/'early.db',True);assert indexed['integrity']=='incomplete_diagnostic'
    p=next(early.glob('events-*.log.gz'));lines=gzip.open(p,'rb').readlines()
    last=max(i for i,line in enumerate(lines) if line.startswith(b'IC3_STATS '))
    del lines[last]
    with gzip.open(p,'wb') as out:out.writelines(lines)
    try:db.ingest(early,d/'truncated-tail.db',True)
    except ValueError as e:assert 'manifest tail mismatch' in str(e),str(e)
    else:raise AssertionError('valid-chain prefix with a missing tail was accepted')
    env.pop('FIXTURE_EARLY_EXIT')
    # Cancellation immediately after final bypasses context-tail retirement.
    # The checkpoint is readable, but the unsealed tail is never complete.
    aborted=d/'sealed-abort';aborted.mkdir();env.update(JIPSTATS_EVIDENCE_DIR=str(aborted),FIXTURE_ABORT_AFTER_SEAL='1')
    subprocess.run([str(build/'marker-free-worker')],env=env,capture_output=True,check=True)
    manifest=json.loads(next(aborted.glob('worker-*.manifest.json')).read_text())
    assert not manifest['process_closed'] and not manifest['runs'][0]['sealed']
    sealed=gzip.open(next(aborted.glob('events-*.log.gz')),'rb').read()
    assert b'phase=native_tail_begin ' in sealed and b'phase=run_seal ' not in sealed and b'phase=cube_definition_end ' in sealed
    assert sum(line.startswith(b'IC3_STATS ') for line in sealed.splitlines())==manifest['runs'][0]['events']
    env.pop('FIXTURE_ABORT_AFTER_SEAL')
    mixed=d/'mixed';mixed.mkdir()
    for source in (compressed,aborted):
        for p in source.iterdir():shutil.copy2(p,mixed/p.name)
    try:db.ingest(mixed,d/'all-workers.db')
    except ValueError as e:assert 'worker closure unattested' in str(e),str(e)
    else:raise AssertionError('unclosed worker was accepted by default')
    try:db.ingest(mixed,d/'unsealed-snapshot.db',True)
    except ValueError as e:assert 'worker closure unattested' in str(e) and 'fully sealed' in str(e),str(e)
    else:raise AssertionError('unclosed unsealed tail was accepted as a diagnostic snapshot')
    selected=db.ingest(mixed,d/'closed-workers.db',True,True)
    assert selected['selection']=='closed_workers_only' and not selected['complete']
    assert len(selected['excluded_worker_files'])==1 and selected['records']>0
    assert len(list(mixed.glob('events-*.log.gz')))==2 # original unclosed worker preserved
    broken=d/'bad-gzip';shutil.copytree(compressed,broken)
    p=next(broken.glob('events-*.log.gz'));p.write_bytes(p.read_bytes()[:-8])
    try:db.ingest(broken,d/'bad-gzip.db',True)
    except ValueError as e:assert 'incomplete or invalid archive stream' in str(e) and p.name in str(e),str(e)
    else:raise AssertionError('truncated gzip accepted')
    # Reject a sink that cannot be opened; never claim a completed capture.
    bad=d/'absent';env['JIPSTATS_EVIDENCE_DIR']=str(bad)
    failed=subprocess.run([str(build/'marker-free-worker')],env=env,capture_output=True)
    assert failed.returncode==74 and b'disk capture failed' in failed.stderr
print('PASS: callback bypass, complete cube chunks, closed/unsealed tails, readable cancelled checkpoint rejected, removed-tail rejection, disk failure')
