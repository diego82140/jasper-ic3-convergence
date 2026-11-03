"""Sensitivity and representation tests for the information-parity comparator."""
import importlib.util,sys,tempfile,unittest
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
    def normalize(self,*rows):return p.normalize(['IC3_STATS '+r for r in rows],self.profile)
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
        common='run=1 snapshot=3 operation=7 cause=fixture '
        a=self.normalize('phase=queue_membership_remove event=1 '+common+'obligation_id=22 list_node=aaa',
                         'phase=queue_membership_remove event=2 '+common+'obligation_id=11 list_node=bbb')
        b=self.normalize('phase=queue_membership_remove event=1 '+common+'obligation_id=11 list_node=ccc',
                         'phase=queue_membership_remove event=2 '+common+'obligation_id=22 list_node=ddd')
        self.assertTrue(p.comparison(a,b)['pass_'])
        c=self.normalize('phase=queue_member event=1 run=1 obligation_id=22','phase=queue_member event=2 run=1 obligation_id=11')
        d=self.normalize('phase=queue_member event=1 run=1 obligation_id=11','phase=queue_member event=2 run=1 obligation_id=22')
        self.assertFalse(p.comparison(c,d)['pass_'])
        self.assertFalse(p.comparison(a,b[:-1])['pass_'])
    def test_pointer_reuse_after_retirement_and_live_aliasing(self):
        a=self.normalize('phase=obligation_dequeue event=1 run=1 obligation_id=1 list_node=aaa',
                         'phase=obligation_dequeue event=2 run=1 obligation_id=2 list_node=aaa')
        b=self.normalize('phase=obligation_dequeue event=1 run=1 obligation_id=1 list_node=bbb',
                         'phase=obligation_dequeue event=2 run=1 obligation_id=2 list_node=ccc')
        self.assertTrue(p.comparison(a,b)['pass_'])
        c=self.normalize('phase=model_context event=1 run=1 actual_jip=aaa bound_jip=aaa')
        d=self.normalize('phase=model_context event=1 run=1 actual_jip=bbb bound_jip=ccc')
        self.assertFalse(p.comparison(c,d)['pass_'])

if __name__=='__main__':unittest.main()
