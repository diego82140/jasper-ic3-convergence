"""Fresh/reuse acceptance binds both controls to bytes and model expectations."""
import json,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'source/tests/parity'))
import cross_release as p

class NativeAcceptance(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.case=Path(self.tmp.name)
        self.sha=p.RELEASES['production'][1];self.model='366058887187e7957fd1a76fca2adef293db47431166967a7afb76ab79b8e119';self.library='d'*64
        self.expected=p.expected_results(self.model,False)
        for mode,preload in [('plain',False),('capture',True)]:
            directory=self.case/mode;directory.mkdir()
            result=dict(status='PASS',exit=0,engine='M',preload=preload,model_sha256=self.model,worker_unchanged=True,original_main=True,
                original_solver=True,receive_eof=True,receiver_joined=True,protocol_buffer_empty=True,expected_sequence_verified=True,verdicts=self.expected)
            invocation=dict(worker_sha256=self.sha,model_sha256=self.model,library_sha256=self.library,engine='M',preload=preload,sink='disk',original_main=True,original_solver=True)
            (directory/'RESULT.json').write_text(json.dumps(result));(directory/'INVOCATION.json').write_text(json.dumps(invocation))
            # Exact qualified decoder header: valid, one target, target zero.
            (directory/'native-response.bin').write_bytes(b'\x02\x06\x01\x00\n')
    def validate(self):return p.validate_case(self.case,self.sha,self.model,'M',False,self.library)
    def change(self,path,**updates):
        data=json.loads(path.read_text());data.update(updates);path.write_text(json.dumps(data))
    def test_valid_controls_are_accepted(self):self.assertEqual(len(self.validate()),2)
    def test_failed_or_wrong_baseline_and_empty_outcomes_are_rejected(self):
        path=self.case/'plain/RESULT.json';original=path.read_bytes()
        for updates in [dict(status='FAIL'),dict(exit=17),dict(verdicts=[]),dict(receive_eof=False),dict(preload=True)]:
            path.write_bytes(original);self.change(path,**updates)
            with self.assertRaises(ValueError):self.validate()
    def test_wrong_plain_identity_is_rejected(self):
        path=self.case/'plain/INVOCATION.json';self.change(path,worker_sha256='0'*64)
        with self.assertRaises(ValueError):self.validate()
    def test_raw_sequence_is_redecoded_and_late_duplicates_rejected(self):
        path=self.case/'capture/native-response.bin';path.write_bytes(path.read_bytes()*2)
        with self.assertRaises(ValueError):self.validate()
    def test_empty_or_partial_wire_cannot_authenticate_json(self):
        path=self.case/'capture/native-response.bin'
        for data in (b'\x02\x02\x00\n',b'\x02\x06\x01\x00'):
            path.write_bytes(data)
            with self.assertRaises(ValueError):self.validate()

if __name__=='__main__':unittest.main()
