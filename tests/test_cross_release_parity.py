"""Sensitivity and representation tests for the information-parity comparator."""
import hashlib,importlib.util,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'source/tests/parity'))
spec=importlib.util.spec_from_file_location('cross_release',ROOT/'source/tests/parity/cross_release.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)

class CrossReleaseParity(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.profile=Path(self.temp.name)/'profile.events'
        self.profile.write_text('hook relative aa 0 1 2 3 4 -1 9090\n')
    def normalize(self,*rows):return p.normalize(['IC3_STATS '+r+'\n' for r in rows],self.profile)
    def test_missing_field_event_and_payload_change_are_rejected(self):
        a=self.normalize('phase=cube_chunk event=1 run=1 values=00000002 count=1')
        for b in (self.normalize('phase=cube_chunk event=1 run=1 count=1'),[],self.normalize('phase=cube_chunk event=1 run=1 values=00000003 count=1')):
            self.assertFalse(p.comparison(a,b)['pass_'])
    def test_durations_identities_and_code_roles(self):
        a=self.normalize('phase=sat_begin event=1 run=1 pid=1 wall_ns=4 native_entry=aa')
        b=self.normalize('phase=sat_begin event=1 run=1 pid=2 wall_ns=7 native_entry=aa')
        self.assertTrue(p.comparison(a,b)['pass_'])
        for value in ('-1','nan','inf'):
            with self.assertRaises(ValueError):self.normalize('phase=sat_end run=1 event=1 elapsed='+value)
        with self.assertRaises(ValueError):self.normalize('phase=sat_begin event=1 run=1 native_entry=bb')
    def test_only_hash_table_removal_batches_are_unordered(self):
        common='capture=c pid=1 tid=2 model_epoch=1 ctx_rev=1 op_id=7 run=1 snapshot=3 operation=7 cause=fixture '
        a=self.normalize('phase=queue_membership_remove event=1 '+common+'obligation_id=22 list_node=aaa',
                         'phase=queue_membership_remove event=2 '+common+'obligation_id=11 list_node=bbb')
        b=self.normalize('phase=queue_membership_remove event=1 '+common+'obligation_id=11 list_node=ccc',
                         'phase=queue_membership_remove event=2 '+common+'obligation_id=22 list_node=ddd')
        self.assertTrue(p.comparison(a,b)['pass_'])
        c=self.normalize('phase=queue_member event=1 run=1 obligation_id=22','phase=queue_member event=2 run=1 obligation_id=11')
        d=self.normalize('phase=queue_member event=1 run=1 obligation_id=11','phase=queue_member event=2 run=1 obligation_id=22')
        self.assertFalse(p.comparison(c,d)['pass_'])
        self.assertFalse(p.comparison(a,b[:-1])['pass_'])
    def test_queue_removal_does_not_establish_allocation_death(self):
        a=self.normalize('phase=obligation_dequeue event=1 run=1 obligation_id=1 list_node=aaa',
                         'phase=obligation_dequeue event=2 run=1 obligation_id=2 list_node=aaa')
        b=self.normalize('phase=obligation_dequeue event=1 run=1 obligation_id=1 list_node=bbb',
                         'phase=obligation_dequeue event=2 run=1 obligation_id=2 list_node=ccc')
        self.assertFalse(p.comparison(a,b)['pass_'])
        c=self.normalize('phase=model_context event=1 run=1 actual_jip=aaa bound_jip=aaa')
        d=self.normalize('phase=model_context event=1 run=1 actual_jip=bbb bound_jip=ccc')
        self.assertFalse(p.comparison(c,d)['pass_'])
    def test_namespace_splits_are_not_erased_by_normalization(self):
        reference=self.normalize('phase=sat_begin event=1 run=1 pid=10 tid=11 capture=old',
                                 'phase=sat_end event=2 run=1 pid=10 tid=11 capture=old')
        equivalent=self.normalize('phase=sat_begin event=1 run=1 pid=20 tid=21 capture=new',
                                  'phase=sat_end event=2 run=1 pid=20 tid=21 capture=new')
        split=self.normalize('phase=sat_begin event=1 run=1 pid=20 tid=21 capture=new',
                             'phase=sat_end event=2 run=1 pid=20 tid=22 capture=new')
        self.assertTrue(p.comparison(reference,equivalent)['pass_'])
        self.assertFalse(p.comparison(reference,split)['pass_'])
    def test_worker_digest_must_match_selected_profile(self):
        sha='a'*64;self.profile.write_text('sha256 '+sha+'\n')
        self.normalize('phase=model event=1 run=1 worker_sha256='+sha)
        with self.assertRaises(ValueError):self.normalize('phase=model event=1 run=1 worker_sha256='+'b'*64)
    def test_malformed_bytes_and_gaps_cannot_be_normalized_away(self):
        for line in ('IC3_STATS phase=x event=1 garbage\n','IC3_STATS phase=x phase=y\n','IC3_STATS phase=x'):
            with self.assertRaises(ValueError):list(p.parsed_rows([line]))
        rows=['phase=queue_membership_remove event='+str(i)+' capture=c pid=1 tid=2 model_epoch=1 ctx_rev=1 op_id=1 run=1 snapshot=1 operation=1 cause=x obligation_id=1' for i in (1,3)]
        with self.assertRaises(ValueError):self.normalize(*rows)
    def test_another_run_does_not_reset_live_aliases(self):
        a=self.normalize('phase=model_context event=1 run=1 actual_jip=aaa',
                         'phase=run_contract event=1 run=2',
                         'phase=model_context event=2 run=1 actual_jip=aaa')
        b=self.normalize('phase=model_context event=1 run=1 actual_jip=bbb',
                         'phase=run_contract event=1 run=2',
                         'phase=model_context event=2 run=1 actual_jip=ccc')
        self.assertFalse(p.comparison(a,b)['pass_'])
    def test_diagnostic_extent_preserves_newlines_non_utf8_and_spaces(self):
        root=Path(self.temp.name);(root/'profiles').mkdir();(root/'profiles/test.events').write_text('')
        old=p.ROOT;p.ROOT=root;self.addCleanup(setattr,p,'ROOT',old)
        body=b'IC3_CTI name="a\nIC3_STATS forged=1\n\xff" tail=1  '
        header='IC3_STATS phase=parity_record run=1 event=1 parity_sequence=1 family=IC3_CTI bytes='+str(len(body))+' sha256='+hashlib.sha256(body).hexdigest()+'\n'
        end='IC3_STATS phase=parity_record_end run=1 event=2 parity_sequence=1 bytes='+str(len(body))+' complete=1\n'
        path=root/'events-test.log';path.write_bytes((header+end).encode()+body+b'\n')
        self.assertEqual(p.load_capture(root,'test')[1],[body])
        path.write_bytes((header+end).encode()+body[:-1]+b'!\n')
        with self.assertRaises(ValueError):p.load_capture(root,'test')
    def test_producer_diagnostics_require_exact_worker_and_process(self):
        root=Path(self.temp.name);(root/'profiles').mkdir();sha='a'*64
        (root/'profiles'/(sha+'.events')).write_text('sha256 '+sha+'\n')
        old=p.ROOT;p.ROOT=root;self.addCleanup(setattr,p,'ROOT',old)
        record='IC3_STATS phase=model event=1 run=1 pid=9 capture=owned worker_sha256='+sha+'\n'
        header='[JIPSTATS] pid=9 backend=events attached sha256='+sha+' hooks=60\n'
        path=root/'events-test.log';path.write_text(header+record)
        self.assertEqual(p.load_capture(root,sha)[2][0]['worker_sha256'],'<selected-worker>')
        for bad in (header.replace(sha,'b'*64)+record,header.replace('pid=9','pid=8')+record,'unframed data\n'+record):
            path.write_text(bad)
            with self.assertRaises(ValueError):p.load_capture(root,sha)

if __name__=='__main__':unittest.main()
