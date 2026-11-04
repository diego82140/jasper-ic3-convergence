"""Prevent a common-mode deletion relative to the frozen original v2 source."""
import copy,json,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'source/tests/parity'))
from literal_contract import inventory,missing_sites

class LegacyLiteralContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.baseline=json.loads((ROOT/'source/tests/parity/legacy_literal_contract.json').read_text())
        cls.current=inventory(ROOT)
    def test_every_old_literal_emit_site_and_field_is_preserved(self):
        self.assertEqual(missing_sites(self.baseline,self.current),[])
    def test_a_shared_event_or_field_deletion_cannot_pass(self):
        changed=copy.deepcopy(self.current);changed['sites']=[]
        self.assertTrue(missing_sites(self.baseline,changed))
        site=next(s for s in self.baseline['sites'] if 'result_raw' in s['fields'])
        changed=copy.deepcopy(self.current)
        for candidate in changed['sites']:
            if candidate['phases']==site['phases'] and 'result_raw' in candidate['fields']:candidate['fields'].remove('result_raw')
        self.assertTrue(missing_sites(self.baseline,changed))

if __name__=='__main__':unittest.main()
