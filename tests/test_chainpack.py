"""Original-byte, offset and integrity oracles for post-close derived hashes."""
import contextlib,gzip,hashlib,importlib.util,io,json,random,sqlite3,subprocess,sys,tempfile,unittest
from unittest import mock
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
reader=load('chainpack_reader',ROOT/'tools/telemetry_db.py')
packer=load('chainpack_packer',ROOT/'tools/archive_pack.py')
fixture=load('frame_fixture',ROOT/'tests/test_frame_codec.py')

def original_lines():
 tips={};events={};result=[]
 # Independent construction with overlapping generations and raw display data.
 for run,phase in [(1,'run_contract'),(2,'run_contract'),(1,'final'),(2,'run_abort_seal'),(1,'run_seal')]:
  events[run]=events.get(run,0)+1
  body=f'IC3_STATS phase={phase} capture=c pid=1 tid=1 run={run} event={events[run]}'.encode()
  tips[run]=hashlib.sha256(tips.get(run,bytes(32))+body).digest()
  result.append(body+b' chain='+tips[run].hex().encode()+b'\n')
  result.append(b'NATIVE_IC3_REPORT text=all bytes retained \xff\t\x00\n')
 return b''.join(result)

class Chainpack(unittest.TestCase):
 def test_caller_errors_are_not_misclassified_as_archive_failures(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);plain=root/'ordinary.log';plain.write_bytes(b'healthy\n')
   for path in (plain,self.write(root,self.packed(original_lines()))):
    with self.assertRaisesRegex(ValueError,'^caller failure$'):
     with reader.archive_open(path) as stream:raise ValueError('caller failure')
 def packed(self,data):
  out=io.BytesIO();receipt=reader.chainpack_encode(io.BytesIO(data),out)
  self.assertEqual(receipt['sha256'],hashlib.sha256(data).hexdigest())
  self.assertEqual(receipt['decoded_bytes'],len(data))
  return out.getvalue()
 def write(self,root,data):
  path=root/'events-1-1.log.chainpack.gz';path.write_bytes(gzip.compress(data,mtime=0));return path
 def test_exact_bytes_random_seeks_and_buffered_offsets(self):
  data=original_lines();packed=self.packed(data)
  with tempfile.TemporaryDirectory() as directory:
   path=self.write(Path(directory),packed)
   with reader.archive_open(path) as stream:
    self.assertEqual(stream.read(),data)
    rng=random.Random(98273)
    for _ in range(100):
     at=rng.randrange(len(data)+1);length=rng.randrange(120)
     self.assertEqual(stream.seek(at),at);self.assertEqual(stream.tell(),at)
     self.assertEqual(stream.read(length),data[at:at+length])
     self.assertEqual(stream.tell(),min(at+length,len(data)))
    self.assertEqual(stream.seek(-35,io.SEEK_END),len(data)-35)
    self.assertEqual(stream.read(7),data[-35:-28])
    self.assertEqual(stream.seek(-3,io.SEEK_CUR),len(data)-31)
    self.assertEqual(stream.read(),data[-31:])
    with self.assertRaises(ValueError):stream.seek(-1)
    stream.seek(0);self.assertEqual(list(stream),data.splitlines(keepends=True))
 def test_corruption_missing_footer_tags_and_trailing_data_reject(self):
  data=self.packed(original_lines());lines=data.splitlines(keepends=True)
  mutations=[data.replace(b'phase=final',b'phase=finaX'),b''.join(lines[:-1]),data+b'Rextra\n',data.replace(b'JIPSTATS_CHAINPACK 1',b'JIPSTATS_CHAINPACK 9'),data.replace(b'event=2',b'event=5',1),data.replace(b'CIC3_STATS',b'RIC3_STATS',1),data.replace(b'CIC3_STATS',b'XIC3_STATS',1),data.replace(b'"records":5',b'"records":4'),data[:-1],data.replace(b'capture=c',b'capture=c capture=x',1)]
  with tempfile.TemporaryDirectory() as directory:
   for broken in mutations:
    path=self.write(Path(directory),broken)
    with self.assertRaisesRegex(ValueError,str(path)):
     with reader.archive_open(path) as stream:stream.read()
   path=self.write(Path(directory),data);compressed=bytearray(path.read_bytes());compressed[-8]^=1;path.write_bytes(compressed)
   with self.assertRaisesRegex(ValueError,'invalid archive'):
    with reader.archive_open(path) as stream:stream.read()
 def test_encoder_rejects_original_chain_and_unsealed_or_partial_data(self):
  data=original_lines()
  for broken in [data.replace(b'phase=final',b'phase=finaX'),b''.join(data.splitlines(keepends=True)[:2]),data[:-1]]:
   with self.assertRaises(ValueError):self.packed(broken)
  with self.assertRaises(ValueError):self.packed(b'R'+b'x'*reader.CHAINPACK_MAX_LINE+b'\n')
 def native_capture(self,root,records=None):
  case=fixture.FrameCodec();case.capture(root,case.records() if records is None else records)
  path=root/'events-1-1.log';data=path.read_bytes()+b'NATIVE_IC3_REPORT capture=c pid=1 tid=1 run=1 text=IC3_STATS keep this report\n'
  archive=path.with_suffix('.log.gz');archive.write_bytes(gzip.compress(data,mtime=0));path.unlink();return archive,data
 def test_strict_migration_query_equivalence_and_disposable_index(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);source,data=self.native_capture(root/'capture');index=root/'before.db'
   reader.ingest(root/'capture',index)
   def command(index,*args):
    command_name,*tail=args
    result=subprocess.run([sys.executable,str(ROOT/'tools/telemetry_db.py'),command_name,str(index),*tail],capture_output=True)
    self.assertEqual(result.returncode,0,result.stderr);return result.stdout
   selectors=[('export',),('export','--cube','1','--run','c:1:1:1'),('payload','c:1:1:1','cube','1'),('frame-members','c:1:1:1','2','--all-frames'),('frame-members','c:1:1:1','1','0'),('native-display',),('cube-ids','c:1:1:1','--domain','jip_formula')]
   before={args:command(index,*args) for args in selectors}
   with contextlib.redirect_stdout(io.StringIO()) as log:packer.chainpack(root/'capture',index)
   receipt=json.loads(log.getvalue());self.assertTrue(receipt['replaced']);self.assertFalse(source.exists())
   with reader.archive_open(Path(receipt['archive'])) as stream:self.assertEqual(stream.read(),data)
   after=root/'after.db';self.assertTrue(reader.ingest(root/'capture',after)['complete'])
   for args in selectors:self.assertEqual(command(after,*args),before[args])
   with sqlite3.connect(after) as db:
    row=db.execute('SELECT bytes,sha256 FROM files WHERE path LIKE "%events-%"').fetchone()
    self.assertEqual(row,(len(data),hashlib.sha256(data).hexdigest()))
   result=subprocess.run([sys.executable,str(ROOT/'tools/telemetry_db.py'),'summary',str(index)],capture_output=True)
   self.assertNotEqual(result.returncode,0)
 def test_unclosed_manifest_and_changed_index_or_source_reject(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);source,data=self.native_capture(root/'capture');index=root/'i.db';reader.ingest(root/'capture',index)
   manifest=root/'capture/worker-1.manifest.json';saved=manifest.read_bytes();m=json.loads(saved);m['process_closed']=False;manifest.write_text(json.dumps(m))
   with self.assertRaises(ValueError):packer.chainpack(root/'capture',index)
   manifest.write_bytes(saved);source.write_bytes(gzip.compress(data+b'changed\n',mtime=0))
   with self.assertRaises(ValueError):packer.chainpack(root/'capture',index)
   self.assertTrue(source.exists());self.assertEqual(list((root/'capture').glob('*.chainpack.gz')),[])
 def test_stale_complete_index_cannot_omit_new_worker(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);source,data=self.native_capture(root/'capture');index=root/'i.db';reader.ingest(root/'capture',index)
   (root/'capture/events-2-2.log.gz').write_bytes(gzip.compress(data,mtime=0))
   with self.assertRaisesRegex(ValueError,'entire current capture'):packer.chainpack(root/'capture',index)
   self.assertTrue(source.exists());self.assertEqual(list((root/'capture').glob('*.chainpack.gz')),[])
 def test_large_raw_seek_readinto_and_pinned_file_descriptor(self):
  data=original_lines()+b'NATIVE report raw payload\n'*30000
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);path=self.write(root,self.packed(data))
   with reader.ChainpackStream(path) as stream:
    scratch=bytearray(70000);self.assertEqual(stream.readinto(scratch),len(scratch));self.assertEqual(bytes(scratch),data[:len(scratch)])
    stream.seek(0);self.assertEqual(stream.readline(13),data[:13]);stream.seek(-55,io.SEEK_END);self.assertEqual(stream.read(),data[-55:])
    replacement=root/'replacement.gz';replacement.write_bytes(gzip.compress(self.packed(b'different raw bytes\n'),mtime=0));replacement.replace(path)
    stream.seek(0);self.assertEqual(stream.read(),data)
   with reader.archive_open(path) as stream:self.assertEqual(stream.read(),b'different raw bytes\n')
   path=self.write(root,self.packed(data))
   with reader.archive_open(path) as stream:
    rng=random.Random(1732)
    for _ in range(100):
     offset=rng.randrange(len(data));stream.seek(offset);self.assertEqual(stream.peek(19)[:19],data[offset:offset+19]);self.assertEqual(stream.read(321),data[offset:offset+321])
 def test_exact_supported_line_boundaries(self):
  raw=b'x'*(reader.CHAINPACK_MAX_LINE-1)+b'\n'
  prefix=b'IC3_STATS phase=run_contract capture=c pid=1 tid=1 run=1 event=1 padding='
  body=prefix+b'a'*(reader.CHAINPACK_MAX_LINE-len(prefix)-len(b' chain=')-64-1)
  tip=hashlib.sha256(bytes(32)+body).digest();first=body+b' chain='+tip.hex().encode()+b'\n'
  end=b'IC3_STATS phase=run_abort_seal capture=c pid=1 tid=1 run=1 event=2'
  tip=hashlib.sha256(tip+end).digest();data=raw+first+end+b' chain='+tip.hex().encode()+b'\n'
  self.assertEqual(len(first),reader.CHAINPACK_MAX_LINE)
  with tempfile.TemporaryDirectory() as directory:
   path=self.write(Path(directory),self.packed(data))
   with reader.archive_open(path) as stream:self.assertEqual(stream.read(),data)
 def test_crash_leftovers_and_multiple_encodings_reject_explicitly(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);source,data=self.native_capture(root/'capture')
   leftover=root/'capture/events-1-1.log.chainpack.gz.new';leftover.write_bytes(b'not a canonical source\n')
   with self.assertRaisesRegex(ValueError,'unsupported worker archive'):reader.ingest(root/'capture',root/'bad.db')
   leftover.unlink();duplicate=root/'capture/events-1-1.log.chainpack.gz';duplicate.write_bytes(gzip.compress(self.packed(data),mtime=0))
   with self.assertRaisesRegex(ValueError,'multiple encodings'):reader.ingest(root/'capture',root/'bad2.db')
   duplicate.unlink();hidden=root/'capture/.events-1-1.log.chainpack.gz.new';hidden.write_bytes(b'ignored unpublished bytes\n')
   self.assertTrue(reader.ingest(root/'capture',root/'good.db')['complete'])
 def test_raw_source_default_strict_index_and_preserved_permissions(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);source,data=self.native_capture(root/'capture');plain=source.with_suffix('');plain.write_bytes(data);plain.chmod(0o640);source.unlink()
   with contextlib.redirect_stdout(io.StringIO()) as log:packer.chainpack(root/'capture')
   receipt=json.loads(log.getvalue());self.assertTrue(receipt['replaced']);target=Path(receipt['archive'])
   self.assertEqual(target.stat().st_mode&0o777,0o640);self.assertFalse(plain.exists())
   self.assertEqual(target.stat().st_gid,root.stat().st_gid)
   self.assertTrue(reader.ingest(root/'capture',root/'after.db')['complete'])
 def test_atomic_and_legacy_frame_members_match_original_after_packing(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);case=fixture.FrameCodec()
   for label,records in [('atomic',case.atomic_records()),('legacy',case.legacy_records())]:
    capture=root/label;self.native_capture(capture,records);before=root/(label+'-before.db');reader.ingest(capture,before)
    with sqlite3.connect(before) as db:expected=list(reader.snapshot_members(db,'c:1:1:1',2))
    with contextlib.redirect_stdout(io.StringIO()):packer.chainpack(capture,before)
    after=root/(label+'-after.db');self.assertTrue(reader.ingest(capture,after)['complete'])
    with sqlite3.connect(after) as db:self.assertEqual(list(reader.snapshot_members(db,'c:1:1:1',2)),expected)
 def test_larger_codec_keeps_original_and_valid_index(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);source,data=self.native_capture(root/'capture');rng=random.Random(12)
   data+=b'NATIVE_IC3_REPORT text='+rng.randbytes(400000).hex().encode()+b'\n'
   source.write_bytes(gzip.compress(data,compresslevel=9,mtime=0));expected=source.read_bytes();index=root/'i.db';reader.ingest(root/'capture',index)
   with contextlib.redirect_stdout(io.StringIO()) as log:packer.chainpack(root/'capture',index,level=1)
   receipt=json.loads(log.getvalue());self.assertFalse(receipt['replaced']);self.assertEqual(source.read_bytes(),expected)
   with sqlite3.connect(index) as db:reader.verify_sources(db)
 def test_foreign_incomplete_selected_and_tampered_indexes_reject(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);source,data=self.native_capture(root/'capture');index=root/'i.db';reader.ingest(root/'capture',index)
   other,_=self.native_capture(root/'other')
   with self.assertRaisesRegex(ValueError,'entire current capture'):packer.chainpack(root/'other',index)
   for key,value in [('selection','explicit_workers'),('selection','closed_workers_only'),('integrity','incomplete_diagnostic')]:
    saved=index.read_bytes();receipt=reader.index_receipt_path(index);saved_receipt=receipt.read_bytes()
    with sqlite3.connect(index) as db:db.execute('UPDATE metadata SET value=? WHERE key=?',(value,key))
    receipt.unlink();reader.write_index_receipt(index)
    with self.assertRaisesRegex(ValueError,'complete strict index'):packer.chainpack(root/'capture',index)
    index.write_bytes(saved);receipt.write_bytes(saved_receipt)
   index.write_bytes(index.read_bytes()+b'tampered')
   with self.assertRaisesRegex(ValueError,'index changed'):packer.chainpack(root/'capture',index)
   self.assertTrue(source.exists());self.assertTrue(other.exists())
 def test_compressed_truncation_appended_members_and_footer_types(self):
  data=self.packed(original_lines())
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory)
   for bad in [data.replace(b'"records":5',b'"records":5.0'),data.replace(b'"records":5',b'"extra":0,"records":5')]:
    path=self.write(root,bad)
    with self.assertRaisesRegex(ValueError,'chainpack'):
     with reader.archive_open(path) as stream:stream.read()
   path=self.write(root,data);original=path.read_bytes()
   for broken in [original[:-4],original+gzip.compress(b'Rextra\n',mtime=0)]:
    path.write_bytes(broken)
    with self.assertRaisesRegex(ValueError,'invalid archive'):
     with reader.archive_open(path) as stream:stream.read()
 def test_original_changes_after_index_verification_retain_source(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);source,data=self.native_capture(root/'capture');index=root/'i.db';reader.ingest(root/'capture',index)
   module=packer.reader_module();encode=module.chainpack_encode
   def changed(stream,destination):
    source.write_bytes(gzip.compress(data+b'late change\n',mtime=0));return encode(stream,destination)
   with mock.patch.object(packer,'reader_module',return_value=module),mock.patch.object(module,'chainpack_encode',side_effect=changed):
    with self.assertRaises(ValueError):packer.chainpack(root/'capture',index)
   self.assertTrue(source.exists());self.assertEqual(list((root/'capture').glob('*.chainpack.gz')),[])
 def test_active_run_bound_and_noncanonical_chain_hex_reject(self):
  data=original_lines();first=data.splitlines(keepends=True)[0];body,chain=first[:-1].rsplit(b' chain=',1)
  for declared in (chain.upper(),chain[:32]):
   with self.assertRaisesRegex(ValueError,'hash-chain'):self.packed(data.replace(first,body+b' chain='+declared+b'\n',1))
  lines=[]
  for run in range(1,4):
   body=f'IC3_STATS phase=run_contract capture=c pid=1 tid=1 run={run} event=1'.encode();tip=hashlib.sha256(bytes(32)+body).hexdigest().encode();lines.append(body+b' chain='+tip+b'\n')
  with mock.patch.object(reader,'CHAINPACK_MAX_LIVE',2):
   with self.assertRaisesRegex(ValueError,'too many active'):self.packed(b''.join(lines))

if __name__=='__main__':unittest.main()
