"""The pinned native recording must advance on results, not timer spacing."""
import json,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'source/tests/parity'))
from native_client import send_commands,settings

class NativeCommandOrder(unittest.TestCase):
    def test_every_shared_result_precedes_the_next_command(self):
        recording=json.loads((ROOT/'source/tests/worker_protocol/job-commands.json').read_text())
        chunks=[b'\x00',settings('M')]+[bytes.fromhex(s) for s in recording['commands_after_strategy'][:-1]]
        wire=[];completed=[];pending=[None]
        class Connection:
            def sendall(self,payload):
                if pending[0] is not None:raise AssertionError('Next command raced the unfinished proof')
                index=len(wire);wire.append(payload)
                if index in (2,4,6,8):pending[0]=index//2
        def await_verdict(wanted):
            self.assertEqual(pending[0],wanted);completed.append(wanted);pending[0]=None
        send_commands(Connection(),chunks,True,await_verdict)
        self.assertEqual(wire,chunks);self.assertEqual(completed,[1,2,3,4])
    def test_changed_recording_does_not_guess_proof_positions(self):
        with self.assertRaises(ValueError):send_commands(None,[b'x'],True,lambda n:None)

if __name__=='__main__':unittest.main()
