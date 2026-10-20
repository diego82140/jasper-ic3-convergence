"""Reference selection must find pairs/transformations and preserve empty snapshots."""
import importlib.util,sqlite3,unittest,subprocess,sys,tempfile,gzip,hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=importlib.util.spec_from_file_location('telemetry',ROOT/'tools/telemetry_db.py');db=importlib.util.module_from_spec(s);s.loader.exec_module(db)
class Queries(unittest.TestCase):
 def setUp(self):
  self.con=sqlite3.connect(':memory:');self.con.executescript(db.SCHEMA)
 def tearDown(self):self.con.close()
 def test_every_reference_role_matches_once(self):
  rows=[{'source_cube_id':'7','predecessor_cube_id':'9'},{'cube_id':'10'},
        {'before_cube_id':'7','after_cube_id':'11'},{'source_cube_id':'7','predecessor_cube_id':'7'}]
  for event,row in enumerate(rows,1):
   self.con.execute('INSERT INTO events(run,event,phase) VALUES(1,?,?)',(event,'test'))
   db.index_cube_refs(self.con,1,event,row)
  query='SELECT e.event FROM events e WHERE '+db.cube_filter(self.con)+' ORDER BY e.event'
  self.assertEqual(list(self.con.execute(query,(7,))),[(1,),(3,),(4,)])
  self.assertEqual(list(self.con.execute(query,(9,))),[(1,)])
  self.assertEqual(self.con.execute('SELECT count(*) FROM cube_refs WHERE cube=7').fetchone()[0],4)
 def test_explicit_worker_scope_avoids_copying_without_hiding_selected_errors(self):
  with tempfile.TemporaryDirectory() as d:
   d=Path(d);capture=d/'capture';capture.mkdir()
   for pid in (1,2):
    tip=bytes(32);lines=[]
    phases=['run_contract','final','run_seal final_event=2 events_before_seal=2 capture_status=complete'] if pid==1 else ['run_contract','capture_error operation=circuit_pointer complete=0']
    for event,phase in enumerate(phases,1):
     body=f'IC3_STATS schema=2 capture=c pid={pid} tid={pid} run=1 event={event} phase={phase}'.encode()
     tip=hashlib.sha256(tip+body).digest();lines.append(body+b' chain='+tip.hex().encode()+b'\n')
    (capture/f'events-{pid}-{pid}.log').write_bytes(b''.join(lines))
    (capture/f'worker-{pid}.manifest.json').write_text(json.dumps(dict(schema=2,scope='one_worker_process',process_closed=True,runs=[dict(key=f'c:{pid}:{pid}:1',events=len(phases),sealed=pid==1,tip=tip.hex())])))
   original={p:p.read_bytes() for p in capture.iterdir()}
   with self.assertRaisesRegex(ValueError,'requires --allow-incomplete'):db.ingest(capture,d/'requires.db',workers=[1])
   with self.assertRaisesRegex(ValueError,'unavailable'):db.ingest(capture,d/'missing.db',allow_incomplete=True,workers=[3])
   with self.assertRaisesRegex(ValueError,'capture failure'):db.ingest(capture,d/'all.db',allow_incomplete=True)
   r=db.ingest(capture,d/'subset.db',allow_incomplete=True,workers=[1])
   self.assertFalse(r['complete']);self.assertEqual(r['selection'],'explicit_workers');self.assertEqual(r['selected_worker_pids'],[1])
   self.assertEqual(len(r['excluded_worker_files']),1)
   con=sqlite3.connect(d/'subset.db');paths=[p for p, in con.execute('SELECT path FROM files')];con.close()
   self.assertTrue(paths and all(Path(p).parent==capture for p in paths))
   db.verify_index(d/'subset.db')
   with self.assertRaisesRegex(ValueError,'capture failure'):db.ingest(capture,d/'selected-bad.db',allow_incomplete=True,workers=[2])
   self.assertFalse(db.index_receipt_path(d/'selected-bad.db').exists())
   self.assertTrue(all(p.read_bytes()==data for p,data in original.items()))
 def test_old_index_requires_explicit_reingest_for_cube_queries(self):
  self.con.execute('DROP TABLE cube_refs')
  with self.assertRaisesRegex(ValueError,'re-ingest'):db.cube_filter(self.con)
 def test_terminal_incomplete_seal_remains_diagnostic_and_checks_manifest_tail(self):
  with tempfile.TemporaryDirectory() as d:
   d=Path(d);capture=d/'capture';capture.mkdir();tip=bytes(32);lines=[]
   phases=['run_contract','final','run_seal final_event=2 events_before_seal=2 capture_status=incomplete']
   for event,phase in enumerate(phases,1):
    body=f'IC3_STATS schema=2 capture=c pid=1 tid=1 run=1 event={event} phase={phase}'.encode()
    tip=hashlib.sha256(tip+body).digest();lines.append(body+b' chain='+tip.hex().encode()+b'\n')
   (capture/'events-1-1.log').write_bytes(b''.join(lines))
   manifest={'schema':2,'scope':'one_worker_process','process_closed':True,'ledger_tail_on_each_record':True,
             'runs':[{'key':'c:1:1:1','events':3,'sealed':False,'tip':tip.hex()}],
             'dropped_records':0,'ledger_failures':0}
   path=capture/'worker-1.manifest.json';path.write_text(json.dumps(manifest))
   with self.assertRaisesRegex(ValueError,'incomplete or unsealed'):db.ingest(capture,d/'strict.db')
   result=db.ingest(capture,d/'diagnostic.db',allow_incomplete=True)
   self.assertFalse(result['complete']);self.assertEqual(result['integrity'],'incomplete_diagnostic')
   con=sqlite3.connect(d/'diagnostic.db')
   self.assertEqual(con.execute('SELECT sealed,complete FROM runs').fetchone(),(1,0));con.close()
   db.verify_index(d/'diagnostic.db')
   manifest['runs'][0]['tip']='0'*64;path.write_text(json.dumps(manifest))
   with self.assertRaisesRegex(ValueError,'manifest tail mismatch'):db.ingest(capture,d/'bad-tail.db',allow_incomplete=True)
 def test_empty_final_snapshot_does_not_hide_earlier_context(self):
  for event,phase,snapshot in [(1,'frame_member',1),(2,'frames_end',1),(3,'frames_end',2),(4,'frame_member',3)]:
   self.con.execute('INSERT INTO events(run,event,phase,snapshot) VALUES(1,?,?,?)',(event,phase,snapshot))
  r=db.frame_summary(self.con,1)
  self.assertEqual(r['last_closed_frame_snapshot'],2)
  self.assertEqual(r['last_closed_frame_members'],0)
  self.assertEqual(r['last_nonempty_closed_frame_snapshot'],1) # open snapshot 3 is excluded
  self.assertIsNone(db.frame_summary(self.con,2)['last_closed_frame_snapshot'])
 def test_cli_requires_cube_scope_and_rejects_unknown_runs(self):
  with tempfile.TemporaryDirectory() as d:
   index=Path(d)/'i.db';con=sqlite3.connect(index);con.executescript(db.SCHEMA)
   con.execute("INSERT INTO metadata VALUES('integrity','incomplete_diagnostic')");con.commit();con.close();db.write_index_receipt(index)
   for args,expected in [(['export','--cube','7'],'requires --run'),(['export','--run','typo'],'run unavailable'),(['native-display','--run','typo'],'run unavailable')]:
    run=subprocess.run([sys.executable,str(ROOT/'tools/telemetry_db.py'),args[0],str(index),*args[1:]],capture_output=True,text=True)
    self.assertEqual(run.returncode,1);self.assertEqual(run.stdout,'');self.assertIn(expected,run.stderr)
 def test_changed_gzip_sources_fail_contextually_for_exports_and_display(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'events-1-1.log.gz';line=b'NATIVE_IC3_REPORT capture=c pid=1 tid=1 run=1 text=IC3_CTI projection\n'
   with gzip.open(p,'wb') as f:f.write(line*10000)
   index=Path(d)/'i.db';con=sqlite3.connect(index);con.executescript(db.SCHEMA)
   con.execute("INSERT INTO metadata VALUES('integrity','incomplete_diagnostic')")
   con.execute("INSERT INTO runs(run,event,tip) VALUES('c:1:1:1',10000,'')")
   con.execute('INSERT INTO files VALUES(1,?,?,?)',(str(p),len(line)*10000,hashlib.sha256(line*10000).hexdigest()))
   for i in range(10000):con.execute("INSERT INTO events(run,event,phase,source,offset,length) VALUES(1,?,'test',1,?,?)",(i+1,i*len(line),len(line)))
   con.commit();con.close();db.write_index_receipt(index);p.write_bytes(p.read_bytes()[:-8])
   for command in ['export','native-display']:
    run=subprocess.run([sys.executable,str(ROOT/'tools/telemetry_db.py'),command,str(index)],capture_output=True,text=True)
    self.assertEqual(run.returncode,1);self.assertIn(str(p),run.stderr);self.assertIn('partial output',run.stderr);self.assertNotIn('Traceback',run.stderr)
    self.assertEqual(run.stdout,'') # verification precedes publication
   # A modified source with a valid new gzip CRC also must fail, including
   # cached-payload and summary paths. A trailer check alone misses this case.
   with gzip.open(p,'wb') as f:f.write(line.replace(b'projection',b'corruption')*10000)
   for command in ['export','native-display','summary']:
    run=subprocess.run([sys.executable,str(ROOT/'tools/telemetry_db.py'),command,str(index)],capture_output=True,text=True)
    self.assertEqual(run.returncode,1);self.assertEqual(run.stdout,'');self.assertIn('changed since ingestion',run.stderr)
   # Different compressed bytes are legitimate when all decoded bytes match.
   with gzip.open(p,'wb',compresslevel=1) as f:f.write(line*10000)
   run=subprocess.run([sys.executable,str(ROOT/'tools/telemetry_db.py'),'export',str(index)],capture_output=True)
   self.assertEqual(run.returncode,0);self.assertEqual(run.stdout,line*10000)
 def test_malformed_manifests_name_the_source(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'worker-1.manifest.json'
   for text in ['[]','{"runs":','{"schema":2,"scope":"one_worker_process","runs":[null]}']:
    p.write_text(text)
    with self.assertRaisesRegex(ValueError,str(p)):db.read_manifest(p)
 def test_index_changes_and_source_races_are_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'i.db';p.write_bytes(b'original index');db.write_index_receipt(p);db.verify_index(p)
   p.write_bytes(b'modified index')
   with self.assertRaisesRegex(ValueError,'index changed'):db.verify_index(p)
   source=Path(d)/'events.log';source.write_bytes(b'old');st=source.stat()
   signatures={str(source):db.source_signature(st)};source.write_bytes(b'new longer')
   with self.assertRaisesRegex(ValueError,'source changed during query'):db.verify_stable_sources(signatures)
if __name__=='__main__':unittest.main()
