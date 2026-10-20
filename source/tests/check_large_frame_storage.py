from pathlib import Path
import datetime,gzip,hashlib,importlib.util,json,os,sqlite3,struct,subprocess,time
import argparse
p=argparse.ArgumentParser(description='Check every ordered raw frame tuple against the independent native-layout fixture oracle; NOT a Jasper proof.')
p.add_argument('binary',type=Path);p.add_argument('evidence',type=Path)
a=p.parse_args();repo=Path(__file__).resolve().parents[2];out=a.evidence.resolve();out.mkdir(exist_ok=False);binary=a.binary.resolve()
spec=importlib.util.spec_from_file_location('telemetry',repo/'tools/telemetry_db.py');t=importlib.util.module_from_spec(spec);spec.loader.exec_module(t)
env={k:val for k,val in os.environ.items() if k not in ('LD_PRELOAD','JIPSTATS_PROFILE','JIPSTATS_IMAGE','JIPSTATS_MAX_RECORDS')};env['JIPSTATS_EVIDENCE_DIR']=str(out)
p=subprocess.run(['/usr/bin/time','-f','%M %e %U %S','-o',str(out/'producer-time.txt'),str(binary),'compact','wide',str(out/'oracle.bin')],env=env,capture_output=True)
(out/'producer.stderr').write_bytes(p.stderr);assert p.returncode==0,p.stderr
started=time.monotonic();receipt=t.ingest(out,out/'index.db');assert receipt['complete']
ingest_seconds=time.monotonic()-started
with sqlite3.connect(out/'index.db') as db:
 db.execute('PRAGMA cache_size=-8192');db.execute('PRAGMA mmap_size=0')
 t.verify_index(out/'index.db');stable=t.verify_sources(db)
 key=db.execute('SELECT run FROM runs').fetchone()[0]
 raw={ident:struct.unpack('<I',data)[0] for ident,data in db.execute("SELECT id,data FROM chunks WHERE kind='cube' AND offset=0")}
 distinct=db.execute('SELECT count(*) FROM frame_chunks').fetchone()[0];assert distinct>16384,distinct
 adds=db.execute("SELECT count(*) FROM events WHERE phase='frame_membership_add'").fetchone()[0];assert adds==1096,adds
 frames=[];total=0;oracle_hash=hashlib.sha256();all_members=iter(t.snapshot_members(db,key,1))
 with (out/'oracle.bin').open('rb') as f:
  header=f.read(20);oracle_hash.update(header);epoch,snapshot,count=struct.unpack('<QQI',header)
  assert snapshot==1 and count==4
  for _ in range(count):
   header=f.read(8);oracle_hash.update(header);frame,members=struct.unpack('<iI',header)
   observed=0
   for ignored in range(members):
    member=next(all_members);assert member['frame']==frame
    expected=f.read(8);assert len(expected)==8
    oracle_hash.update(expected)
    actual=struct.pack('<II',raw[member['cube_id']],member['packed'])
    assert actual==expected and member['index']==observed,(frame,observed)
    observed+=1
   assert observed==members,(frame,observed,members)
   frames.append(dict(frame=frame,members=members,all_ordered_raw_tuples_match=True));total+=observed
  assert not f.read(1);assert next(all_members,None) is None
 t.verify_stable_sources(stable);t.verify_index(out/'index.db')
result=dict(utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),batch_selector='snapshot_members/--all-frames',scope='fake native-layout producer fixture, NOT Jasper or target certificate',producer_source_sha256=hashlib.sha256((repo/'source/src/events.c').read_bytes()).hexdigest(),producer_binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),fixture_source_sha256=hashlib.sha256((repo/'source/tests/frame_storage_fixture.c').read_bytes()).hexdigest(),producer_resource_receipt=(out/'producer-time.txt').read_text().strip(),reader=receipt,reader_seconds=ingest_seconds,distinct_chunk_definitions=distinct,chunk_cache_limit=16384,frames=frames,total_members_checked=total,ordered_oracle_sha256=oracle_hash.hexdigest(),ordered_oracle_bytes=(out/'oracle.bin').stat().st_size,membership_add_records=adds,compressed_canonical_bytes=sum(p.stat().st_size for p in out.glob('events-*.log.gz')),index_bytes=(out/'index.db').stat().st_size,result='PASS single snapshot exceeds native chunk-cache limit, full order/duplicates/flags including negative level preserved')
(out/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n')
# The independent tuple oracle and offset index are reconstructible artifacts.
for p in [out/'oracle.bin',out/'index.db',t.index_receipt_path(out/'index.db')]:
 digest=hashlib.sha256()
 with p.open('rb') as f:
  for block in iter(lambda:f.read(1024*1024),b''):digest.update(block)
 result.setdefault('removed_reconstructible_artifacts',[]).append(dict(path=str(p),bytes=p.stat().st_size,sha256=digest.hexdigest()))
 p.unlink()
(out/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:result[k] for k in ['distinct_chunk_definitions','total_members_checked','compressed_canonical_bytes','producer_resource_receipt','result']}))
