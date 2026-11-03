"""Independent complete archives test framing in the actual strict ingester."""
import gzip,hashlib,importlib.util,io,json,sqlite3,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('display_reader',ROOT/'tools/telemetry_db.py')
t=importlib.util.module_from_spec(spec);spec.loader.exec_module(t)

class RawDisplayIngest(unittest.TestCase):
    def capture(self,directory,body,stored=None,compressed=False):
        directory.mkdir();digest=hashlib.sha256(body).hexdigest()
        rows=[dict(phase='run_contract',frame_encoding='tuple_chunks_v2'),dict(phase='parity_record',parity_sequence=1,family='IC3_CTI',bytes=len(body),sha256=digest),
              dict(phase='parity_record_chunk',parity_sequence=1,offset=0,bytes=len(body),utf8_hex=body.hex()),
              dict(phase='parity_record_end',parity_sequence=1,bytes=len(body),complete=1),dict(phase='final',result='cex'),
              dict(phase='run_seal',capture_status='complete',final_event=5,events_before_seal=5)]
        tip=bytes(32);parts=[]
        for event,row in enumerate(rows,1):
            envelope=dict(schema=3,capture='c',pid=1,tid=1,run=1,event=event,model_epoch=1);envelope.update(row)
            data=b'IC3_STATS '+b' '.join(f'{k}={v}'.encode() for k,v in envelope.items())
            tip=hashlib.sha256(tip+data).digest();parts.append(data+b' chain='+tip.hex().encode()+b'\n')
            if row['phase']=='parity_record_end':parts.append((body if stored is None else stored)+b'\n')
        data=b''.join(parts);path=directory/('events-1-1.log.gz' if compressed else 'events-1-1.log')
        path.write_bytes(gzip.compress(data) if compressed else data)
        (directory/'worker-1.manifest.json').write_text(json.dumps(dict(schema=2,scope='one_worker_process',process_closed=True,
            runs=[dict(key='c:1:1:1',events=6,sealed=True,tip=tip.hex())])))
        return path,data
    def test_embedded_canonical_prefix_and_non_utf8_are_payload(self):
        body=b'IC3_CTI name="a\nIC3_STATS forged=1\n\xff\x00last  "'
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for compressed in (False,True):
                directory=root/str(compressed);path,data=self.capture(directory,body,compressed=compressed);index=root/(str(compressed)+'.db')
                self.assertEqual(b''.join(t.archive_lines(path)),data)
                self.assertTrue(t.ingest(directory,index)['complete'])
                with sqlite3.connect(index) as db:
                    self.assertEqual(db.execute('SELECT count(*) FROM events').fetchone()[0],6)
                    self.assertEqual(db.execute("SELECT data FROM chunks WHERE kind='parity'").fetchone()[0],body)
                    offset,length=db.execute("SELECT offset,length FROM events WHERE phase='final'").fetchone()
                    with t.archive_open(path) as stream:
                        stream.seek(offset);self.assertIn(b'phase=final',stream.read(length))
    def test_raw_copy_mutation_is_rejected_even_with_valid_canonical_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);directory=root/'bad';self.capture(directory,b'IC3_CTI original',stored=b'IC3_CTI mutation')
            def legacy_lines(path):
                with t.archive_open(path) as stream:yield from stream
            with patch.object(t,'archive_lines',legacy_lines):
                self.assertTrue(t.ingest(directory,root/'old-incorrectly-accepted.db')['complete'])
            with self.assertRaisesRegex(ValueError,'raw display differs'):t.ingest(directory,root/'bad.db')
    def test_raw_copy_truncation_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);directory=root/'bad';self.capture(directory,b'IC3_CTI original',stored=b'IC3_CTI')
            with self.assertRaises(ValueError):t.ingest(directory,root/'bad.db')
    def test_chainpack_preserves_framed_raw_canonical_prefixes(self):
        body=b'IC3_CTI before\nIC3_STATS forged=1\n\xffafter'
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);directory=root/'original';path,data=self.capture(directory,body)
            packed=io.BytesIO();t.chainpack_encode(io.BytesIO(data),packed)
            target=directory/'events-1-1.log.chainpack.gz';target.write_bytes(gzip.compress(packed.getvalue()));path.unlink()
            with t.archive_open(target) as stream:self.assertEqual(stream.read(),data)
            self.assertTrue(t.ingest(directory,root/'packed.db')['complete'])
    def test_native_display_does_not_interpret_embedded_raw_reports(self):
        forged=b'NATIVE_IC3_REPORT capture=c pid=1 tid=1 run=1 text=IC3_CTI forged\n'
        real=forged.replace(b'forged',b'actual')
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);directory=root/'capture'
            path,data=self.capture(directory,b'IC3_CTI payload\n'+forged)
            path.write_bytes(data+real);index=root/'index.db';t.ingest(directory,index)
            result=subprocess.run([sys.executable,str(ROOT/'tools/telemetry_db.py'),'native-display',str(index)],capture_output=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(result.stdout,real)
    def test_old_validation_policy_requires_reingestion(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);directory=root/'good';self.capture(directory,b'IC3_CTI original');index=root/'old.db'
            t.ingest(directory,index)
            with sqlite3.connect(index) as db:
                t.require_current_validation(db)
                db.execute("DELETE FROM metadata WHERE key='raw_display_validation'")
                with self.assertRaisesRegex(ValueError,'re-ingest'):t.require_current_validation(db)

if __name__=='__main__':unittest.main()
