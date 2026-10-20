"""Lossless compact frames, malformed semantics and complete reference queries."""
import importlib.util,hashlib,json,sqlite3,struct,tempfile,unittest,copy,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=importlib.util.spec_from_file_location('telemetry',ROOT/'tools/telemetry_db.py');db=importlib.util.module_from_spec(s);s.loader.exec_module(db)
class FrameCodec(unittest.TestCase):
 def records(self):
  data=struct.pack('<QI',1,0xffffffff)+struct.pack('<QI',1,0x40000000)+struct.pack('<QI',2,0x80000000)
  chunk_sha=hashlib.sha256(b'jipstats-frame-chunk-v1\0'+struct.pack('<I',3)+data).hexdigest()
  frame_sha=hashlib.sha256(b'jipstats-frame-tuples-v1\0'+struct.pack('<QiQ',1,0,3)+data).hexdigest()
  empty_sha=hashlib.sha256(b'jipstats-frame-tuples-v1\0'+struct.pack('<QiQ',1,-1,0)).hexdigest()
  rows=[dict(phase='run_contract',model_epoch=0,frame_encoding='tuple_chunks_v1'),dict(phase='model_epoch_begin')]
  for ident in (1,2):
   raw=struct.pack('<I',ident*8+2);digest=hashlib.sha256(b'jip_formula\0'+struct.pack('<I',1)+raw).hexdigest()
   rows.extend([dict(phase='cube_definition',cube_id=ident,literals=1,domain='jip_formula',sha256=digest,model_qualified=1),dict(phase='cube_chunk',cube_id=ident,offset=0,count=1,values=raw.hex()),dict(phase='cube_definition_end',cube_id=ident,literals=1,complete=1)])
   # values fields represent a u32 hexadecimal integer, not little-endian bytes.
   rows[-2]['values']=f'{ident*8+2:08x}'
  rows.append(dict(phase='frame_end',depth=3))
  rows.append(dict(phase='frame_chunk',chunk_id=1,members=3,sha256=chunk_sha,tuples_hex=data.hex(),complete=1,encoding='cube_u64_packed_u32_le'))
  for snapshot in (1,2):
   rows.extend([dict(phase='frames_begin',snapshot=snapshot,frontier_count=1),dict(phase='frame',snapshot=snapshot,frame=0,cubes=3),dict(phase='frame_chunk_ref',snapshot=snapshot,frame=0,offset=0,chunk_id=1,members=3),dict(phase='frame_manifest_end',snapshot=snapshot,frame=0,cubes=3,refs=1,sha256=frame_sha,complete=1),dict(phase='frame',snapshot=snapshot,frame=-1,cubes=0),dict(phase='frame_manifest_end',snapshot=snapshot,frame=-1,cubes=0,refs=0,sha256=empty_sha,complete=1),dict(phase='frames_end',snapshot=snapshot,members=3,complete=1)])
  rows.extend([dict(phase='final'),dict(phase='run_seal',capture_status='complete',final_event=len(rows)+1,events_before_seal=len(rows)+1)])
  return rows
 def capture(self,d,rows):
  d.mkdir();tip=bytes(32);lines=[]
  for event,r in enumerate(rows,1):
   record=dict(schema=3,capture='c',pid=1,tid=1,run=1,event=event,model_epoch=1);record.update(r)
   body=b'IC3_STATS '+b' '.join(f'{k}={v}'.encode() for k,v in record.items());tip=hashlib.sha256(tip+body).digest();lines.append(body+b' chain='+tip.hex().encode()+b'\n')
  (d/'events-1-1.log').write_bytes(b''.join(lines))
  (d/'worker-1.manifest.json').write_text(json.dumps(dict(schema=2,scope='one_worker_process',process_closed=True,runs=[dict(key='c:1:1:1',events=len(rows),sealed=True,tip=tip.hex())])))
 def test_exact_duplicates_flags_signed_levels_and_all_referencing_snapshots(self):
  with tempfile.TemporaryDirectory() as tmp:
   tmp=Path(tmp);self.capture(tmp/'good',self.records());self.assertTrue(db.ingest(tmp/'good',tmp/'i.db')['complete'])
   con=sqlite3.connect(tmp/'i.db')
   for snap in (1,2):
    members=list(db.frame_members(con,'c:1:1:1',snap,0))
    self.assertEqual([(m['cube_id'],m['max_level'],m['validated']) for m in members],[(1,-1,1),(1,-1073741824,0),(2,0,1)])
    self.assertEqual(list(db.frame_members(con,'c:1:1:1',snap,-1)),[])
    self.assertEqual(list(db.frame_members(con,'c:1:1:1',snap,0,1,1))[0]['index'],1)
   selected=list(con.execute('SELECT e.phase,e.snapshot FROM events e WHERE '+db.cube_filter(con)+' ORDER BY e.event',(2,)))
   self.assertIn(('frame_chunk',None),selected);self.assertIn(('frame_chunk_ref',1),selected);self.assertIn(('frame_chunk_ref',2),selected)
   self.assertEqual(db.frame_summary(con,1)['last_closed_frame_members'],3);con.close()
 def atomic_records(self):
  rows=self.records();result=[]
  ends={(r['snapshot'],r['frame']):r for r in rows if r['phase']=='frame_manifest_end'}
  for r in rows:
   if r['phase']=='run_contract':r['frame_encoding']='tuple_chunks_v2'
   if r['phase']=='frame':
    end=ends[(r['snapshot'],r['frame'])];r.update(ref_chunk=1 if r['cubes'] else 0,sha256=end['sha256'],complete=1)
   if r['phase'] not in ('frame_chunk_ref','frame_manifest_end'):result.append(r)
  result[-1]['final_event']=len(result)-1;result[-1]['events_before_seal']=len(result)-1
  return result
 def legacy_records(self):
  rows=[]
  for r in self.records():
   r=copy.deepcopy(r);r['schema']=2
   if r['phase']=='run_contract':r['frame_encoding']='members_v1'
   if r['phase']=='frame_chunk':continue
   if r['phase']=='frame_chunk_ref':
    for i,(cube,level,valid) in enumerate([(1,-1,1),(1,-1073741824,0),(2,0,1)]):
     rows.append(dict(phase='frame_member',snapshot=r['snapshot'],frame=r['frame'],index=i,cube_id=cube,max_level=level,validated=valid))
    continue
   if r['phase']=='frame_manifest_end':continue
   rows.append(r)
  for row in rows:row['schema']=2
  rows[-1]['final_event']=len(rows)-1;rows[-1]['events_before_seal']=len(rows)-1
  return rows
 def test_whole_snapshot_modern_and_legacy_preserve_order_duplicates_empty_frames(self):
  with tempfile.TemporaryDirectory() as tmp:
   tmp=Path(tmp)
   for name,rows in [('chunks',self.records()),('atomic',self.atomic_records()),('legacy',self.legacy_records())]:
    self.capture(tmp/name,rows);index=tmp/(name+'.db');db.ingest(tmp/name,index)
    with sqlite3.connect(index) as con:
     expected=list(db.frame_members(con,'c:1:1:1',2,0))+list(db.frame_members(con,'c:1:1:1',2,-1))
     self.assertEqual(list(db.snapshot_members(con,'c:1:1:1',2)),expected)
     with self.assertRaises(ValueError):list(db.snapshot_members(con,'c:1:1:1',99))
    result=subprocess.run([sys.executable,str(ROOT/'tools/telemetry_db.py'),'frame-members',str(index),'c:1:1:1','2','--all-frames'],capture_output=True)
    self.assertEqual(result.returncode,0,result.stderr)
    self.assertEqual([json.loads(x) for x in result.stdout.splitlines()],expected)
 def test_whole_snapshot_checks_closure_and_cli_selection(self):
  with tempfile.TemporaryDirectory() as tmp:
   tmp=Path(tmp);self.capture(tmp/'good',self.records());index=tmp/'i.db';db.ingest(tmp/'good',index)
   for suffix,message in [([],'select exactly'),(['0','--all-frames'],'select exactly'),(['--all-frames','--offset','1'],'uncapped'),(['--all-frames','--limit','1'],'uncapped')]:
    result=subprocess.run([sys.executable,str(ROOT/'tools/telemetry_db.py'),'frame-members',str(index),'c:1:1:1','2',*suffix],capture_output=True)
    self.assertNotEqual(result.returncode,0);self.assertEqual(result.stdout,b'');self.assertIn(message.encode(),result.stderr)
   with sqlite3.connect(index) as con:
    con.execute('UPDATE frame_snapshots SET closed=0 WHERE snapshot=2')
    with self.assertRaisesRegex(ValueError,'incomplete'):list(db.snapshot_members(con,'c:1:1:1',2))
   # The public batch command must retain the existing index-integrity guard.
   result=subprocess.run([sys.executable,str(ROOT/'tools/telemetry_db.py'),'frame-members',str(index),'c:1:1:1','2','--all-frames'],capture_output=True)
   self.assertNotEqual(result.returncode,0);self.assertEqual(result.stdout,b'')
   with sqlite3.connect(':memory:') as con:
    with self.assertRaisesRegex(ValueError,'re-ingest'):list(db.snapshot_members(con,'c:1:1:1',1))
 def test_whole_snapshot_multiple_frontiers_invariant_order_and_cleanup_scope(self):
  with tempfile.TemporaryDirectory() as tmp:
   tmp=Path(tmp)
   for name,source in [('chunks',self.records()),('atomic',self.atomic_records()),('legacy',self.legacy_records())]:
    rows=[]
    for r in source:
     if r.get('snapshot') is not None:continue
     if r['phase'] in ('final','run_seal'):continue
     rows.append(copy.deepcopy(r))
    codec=rows[0]['frame_encoding'];schema=rows[0].get('schema',3)
    rows.append(dict(phase='final',schema=schema));final=len(rows)
    rows[0].update(completion_tail_tracking=1,activation_tracking=1)
    rows.append(dict(phase='native_tail_begin',schema=schema,native_final_event=final,native_verdict_already_observed=1,proof_frontier=0))
    rows.append(dict(phase='frames_begin',snapshot=3,frontier_count=3,schema=schema))
    chunk=next((r for r in source if r['phase']=='frame_chunk'),None)
    for frame in (0,1,2,-1):
     template_frame=-1 if frame==1 else 0
     selected=[copy.deepcopy(r) for r in source if r.get('snapshot')==2 and r.get('frame')==template_frame]
     for r in selected:
      r.update(snapshot=3,frame=frame,schema=schema)
      if r['phase'] in ('frame','frame_manifest_end') and 'sha256' in r:
       payload=b'' if frame==1 else bytes.fromhex(chunk['tuples_hex'])
       r['sha256']=hashlib.sha256(b'jipstats-frame-tuples-v1\0'+struct.pack('<QiQ',1,frame,0 if frame==1 else 3)+payload).hexdigest()
      rows.append(r)
    rows.append(dict(phase='frames_end',snapshot=3,members=9,complete=1,schema=schema))
    rows.append(dict(phase='run_seal',capture_status='complete',schema=schema,final_event=final,events_before_seal=len(rows),activation_begins=0,activation_returns=0,activation_aborts=0,activation_live=0,observer_errors=0))
    self.capture(tmp/name,rows);index=tmp/(name+'.db');db.ingest(tmp/name,index)
    with sqlite3.connect(index) as con:
     members=list(db.snapshot_members(con,'c:1:1:1',3))
     self.assertEqual([m['frame'] for m in members],[0]*3+[2]*3+[-1]*3)
     self.assertTrue(all(m['native_phase']=='post_final_cleanup' for m in members))
 def test_atomic_sparse_frames_are_complete_with_full_tuple_flags(self):
  with tempfile.TemporaryDirectory() as tmp:
   tmp=Path(tmp);self.capture(tmp/'atomic',self.atomic_records());self.assertTrue(db.ingest(tmp/'atomic',tmp/'i.db')['complete'])
   con=sqlite3.connect(tmp/'i.db')
   members=list(db.frame_members(con,'c:1:1:1',2,0))
   self.assertEqual([r['packed'] for r in members],[0xffffffff,0x40000000,0x80000000])
   self.assertTrue(all(r['encoding']=='tuple_chunks_v2' for r in members))
   self.assertEqual(list(db.frame_members(con,'c:1:1:1',2,-1)),[])
   query='SELECT e.phase,e.snapshot FROM events e WHERE '+db.cube_filter(con,1)
   self.assertIn(('frame',2),list(con.execute(query,(2,))));con.close()
 def test_atomic_semantic_corruption_fails_before_receipt(self):
  with tempfile.TemporaryDirectory() as tmp:
   tmp=Path(tmp)
   for case,frame,field,value in [('future',0,'ref_chunk',2),('count',0,'cubes',4),('empty',-1,'ref_chunk',1),('hash',0,'sha256','0'*64),('empty_hash',-1,'sha256','0'*64),('closure',0,'complete',0)]:
    rows=self.atomic_records();next(r for r in rows if r['phase']=='frame' and r['frame']==frame)[field]=value;self.capture(tmp/case,rows)
    with self.subTest(case=case),self.assertRaises(ValueError):db.ingest(tmp/case,tmp/(case+'.db'))
    self.assertFalse(db.index_receipt_path(tmp/(case+'.db')).exists())
   for missing in ('ref_chunk','sha256'):
    rows=self.atomic_records();del next(r for r in rows if r['phase']=='frame')[missing]
    self.capture(tmp/missing,rows)
    with self.subTest(missing=missing),self.assertRaisesRegex(ValueError,'atomic frame missing'):db.ingest(tmp/missing,tmp/(missing+'.db'))
    self.assertFalse(db.index_receipt_path(tmp/(missing+'.db')).exists())
 def test_rechained_semantic_corruption_still_rejected(self):
  cases={
   'future':('frame_chunk_ref','chunk_id',2),
   'order':('frame_chunk_ref','offset',1),
   'ref_count':('frame_chunk_ref','members',2),
   'frame_count':('frame_manifest_end','cubes',2),
   'frame_hash':('frame_manifest_end','sha256','0'*64),
   'chunk_hash':('frame_chunk','sha256','0'*64),
   'chunk_bytes':('frame_chunk','tuples_hex',struct.pack('<QI',1,0).hex()),
   'cube_future':('frame_chunk','tuples_hex',(struct.pack('<QI',9,0)*3).hex()),
   'missing_close':('frame_manifest_end','complete',0),
   'epoch':('frame_chunk_ref','model_epoch',2),
   'old_reader_contract':('run_contract','schema',2),
   'unknown_codec':('run_contract','frame_encoding','sampled'),
   'duplicate_frame':('frame','frame',-1),
   'snapshot_members':('frames_end','members',2),
  }
  with tempfile.TemporaryDirectory() as tmp:
   tmp=Path(tmp)
   for case,(phase,field,value) in cases.items():
    rows=self.records();next(r for r in rows if r['phase']==phase)[field]=value
    if case=='cube_future':
     data=bytes.fromhex(next(r for r in rows if r['phase']=='frame_chunk')['tuples_hex']);next(r for r in rows if r['phase']=='frame_chunk')['sha256']=hashlib.sha256(b'jipstats-frame-chunk-v1\0'+struct.pack('<I',3)+data).hexdigest()
    self.capture(tmp/case,rows)
    with self.subTest(case=case),self.assertRaises((ValueError,sqlite3.Error)):db.ingest(tmp/case,tmp/(case+'.db'))
    self.assertFalse(db.index_receipt_path(tmp/(case+'.db')).exists())
 def test_cross_epoch_reference_rejects_even_with_valid_chain_and_complete_definitions(self):
  rows=self.records();at=next(i for i,r in enumerate(rows) if r['phase']=='frames_begin' and r['snapshot']==2)
  rows.insert(at,dict(phase='model_epoch_begin',model_epoch=2))
  for r in rows[at+1:]:r['model_epoch']=2
  rows[-1]['final_event']+=1;rows[-1]['events_before_seal']+=1
  with tempfile.TemporaryDirectory() as tmp:
   tmp=Path(tmp);self.capture(tmp/'cross',rows)
   with self.assertRaisesRegex(ValueError,'cross-epoch'):db.ingest(tmp/'cross',tmp/'bad.db')
 def aborted_records(self):
  rows=self.records()[:-2];rows[0].update(activation_tracking=1,abort_terminal_tracking=1)
  rows.insert(2,dict(phase='invocation_begin',activation=1,parent_activation=0,hook='run',operation=1,gum_depth=0,run_generation=1))
  rows.append(dict(phase='invocation_abort',activation=1,hook='run',operation=1,gum_depth=0,native_return_observed=0))
  abort=len(rows)
  rows.append(dict(phase='run_abort_seal',abort_event=abort,native_final_observed=0,terminal_kind='native_aborted_attempt',final_event=0,events_before_seal=abort,capture_status='complete',activation_begins=1,activation_returns=0,activation_aborts=1,activation_live=0,observer_errors=0))
  return rows
 def test_aborted_attempt_closes_transport_without_native_verdict(self):
  with tempfile.TemporaryDirectory() as tmp:
   tmp=Path(tmp);self.capture(tmp/'aborted',self.aborted_records());r=db.ingest(tmp/'aborted',tmp/'i.db')
   self.assertTrue(r['complete']);self.assertFalse(r['proof_certificate'])
   con=sqlite3.connect(tmp/'i.db');self.assertEqual(con.execute('SELECT final,sealed,complete FROM runs').fetchone(),(0,1,1));con.close()
 def test_abort_terminal_requires_actual_abort_and_cannot_invent_final(self):
  with tempfile.TemporaryDirectory() as tmp:
   tmp=Path(tmp)
   for case,phase,field,value in [('contract','run_contract','abort_terminal_tracking',0),('abort','run_abort_seal','abort_event',1),('verdict','run_abort_seal','native_final_observed',1),('result','run_abort_seal','result','valid'),('scope','invocation_abort','hook','push')]:
    rows=self.aborted_records();next(r for r in rows if r['phase']==phase)[field]=value;self.capture(tmp/case,rows)
    with self.subTest(case=case),self.assertRaises(ValueError):db.ingest(tmp/case,tmp/(case+'.db'))
    self.assertFalse(db.index_receipt_path(tmp/(case+'.db')).exists())
 def tail_records(self):
  rows=self.records()[:-1]
  rows[0].update(activation_tracking=1,completion_tail_tracking=1)
  final=len(rows)
  rows.append(dict(phase='native_tail_begin',native_final_event=final,native_verdict_already_observed=1,proof_frontier=0))
  cleanup=copy.deepcopy([r for r in rows if r.get('snapshot')==2])
  for r in cleanup:r['snapshot']=3
  rows.extend(cleanup)
  rows.append(dict(phase='run_seal',final_event=final,events_before_seal=len(rows),capture_status='complete',activation_begins=0,activation_returns=0,activation_aborts=0,activation_live=0,observer_errors=0))
  return rows
 def test_post_final_cleanup_preserved_and_excluded_from_search_frontier(self):
  with tempfile.TemporaryDirectory() as tmp:
   tmp=Path(tmp);self.capture(tmp/'tail',self.tail_records());self.assertTrue(db.ingest(tmp/'tail',tmp/'i.db')['complete'])
   con=sqlite3.connect(tmp/'i.db');self.assertEqual(db.frame_summary(con,1)['last_closed_frame_snapshot'],2)
   members=list(db.frame_members(con,'c:1:1:1',3,0))
   self.assertEqual([m['packed'] for m in members],[0xffffffff,0x40000000,0x80000000])
   self.assertTrue(all(m['native_phase']=='post_final_cleanup' for m in members))
   self.assertTrue(all(m['native_phase']=='search' for m in db.frame_members(con,'c:1:1:1',2,0)))
   con.close()
 def test_legacy_member_exports_label_search_and_cleanup(self):
  rows=[]
  for r in self.tail_records():
   if r['phase'] in ('frame_chunk','frame_chunk_ref','frame_manifest_end'):continue
   r=copy.deepcopy(r);r['schema']=2
   if r['phase']=='run_contract':r['frame_encoding']='members_v1'
   rows.append(r)
   if r['phase']=='frame' and r['cubes']:
    for i,(cube,level,valid) in enumerate(((1,-1,1),(1,-1073741824,0),(2,0,1))):
     rows.append(dict(schema=2,phase='frame_member',snapshot=r['snapshot'],frame=0,index=i,cube_id=cube,max_level=level,validated=valid))
  final=next(i+1 for i,r in enumerate(rows) if r['phase']=='final')
  next(r for r in rows if r['phase']=='native_tail_begin')['native_final_event']=final
  rows[-1].update(final_event=final,events_before_seal=len(rows)-1)
  with tempfile.TemporaryDirectory() as tmp:
   tmp=Path(tmp);self.capture(tmp/'legacy',rows);self.assertTrue(db.ingest(tmp/'legacy',tmp/'i.db')['complete'])
   con=sqlite3.connect(tmp/'i.db')
   for snap,phase in ((2,'search'),(3,'post_final_cleanup')):
    members=list(db.frame_members(con,'c:1:1:1',snap,0))
    self.assertEqual([m['packed'] for m in members],[0xffffffff,0x40000000,0x80000000])
    self.assertEqual([m['native_phase'] for m in members],[phase]*3)
   con.close()
 def test_tail_marker_requires_final_contract_and_search_scope(self):
  with tempfile.TemporaryDirectory() as tmp:
   tmp=Path(tmp)
   for case,phase,field,value in [('contract','run_contract','completion_tail_tracking',0),('final','native_tail_begin','native_final_event',1),('proof','native_tail_begin','proof_frontier',1)]:
    rows=self.tail_records();next(r for r in rows if r['phase']==phase)[field]=value;self.capture(tmp/case,rows)
    with self.subTest(case=case),self.assertRaises(ValueError):db.ingest(tmp/case,tmp/(case+'.db'))
    self.assertFalse(db.index_receipt_path(tmp/(case+'.db')).exists())
 def test_process_binding_loss_rejects_individually_complete_runs(self):
  with tempfile.TemporaryDirectory() as tmp:
   tmp=Path(tmp)
   for case in ('unbound_hook_calls','ambiguous_seq_bindings'):
    d=tmp/case;self.capture(d,self.records());p=d/'worker-1.manifest.json';m=json.loads(p.read_text());m[case]=1;p.write_text(json.dumps(m))
    with self.subTest(case=case),self.assertRaises(ValueError):db.ingest(d,tmp/(case+'.db'),allow_incomplete=True)
    self.assertFalse(db.index_receipt_path(tmp/(case+'.db')).exists())
 def test_resumed_search_cannot_be_hidden_as_post_final_cleanup(self):
  with tempfile.TemporaryDirectory() as tmp:
   tmp=Path(tmp)
   for phase in ('relative_begin','run_begin','sat_begin','final','native_tail_begin'):
    rows=self.tail_records();rows.insert(-1,dict(phase=phase));rows[-1]['events_before_seal']+=1;self.capture(tmp/phase,rows)
    with self.subTest(phase=phase),self.assertRaises(ValueError):db.ingest(tmp/phase,tmp/(phase+'.db'))
    self.assertFalse(db.index_receipt_path(tmp/(phase+'.db')).exists())
if __name__=='__main__':unittest.main()
