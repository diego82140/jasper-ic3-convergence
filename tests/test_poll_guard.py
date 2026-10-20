import importlib.util,json,subprocess,sys,unittest
from pathlib import Path
hook=Path(__file__).resolve().parents[1]/'hooks/poll_guard.py'
s=importlib.util.spec_from_file_location('guard',hook);g=importlib.util.module_from_spec(s);s.loader.exec_module(g)
# Exact background watcher observed as convergenceClaude42's final tool call.
OBSERVED='N=/formal_shared/diego1/.foo/validation/restart-pagewalk-20261007/runs/component-decomp-original; for i in $(seq 1 120); do grep -q "^LEVEL r1 ACCEPTED\\|^LEVEL r1 REJECTED\\|DECOMP STOP" $N/out/receipts.txt 2>/dev/null && break; [ -e $N/run/native-exit.txt ] && break; sleep 15; done; date -u +%FT%TZ; head -40 $N/out/receipts.txt'
class Guard(unittest.TestCase):
 def check(self,cmd,background=False):return g.reason({'tool_name':'Bash','tool_input':{'command':cmd,'run_in_background':background}})
 def test_foreground_poll_blocks(self):
  self.assertIsNotNone(self.check('for i in {1..100}; do squeue -j 123; sleep 10; done'))
  self.assertIsNotNone(self.check('sleep 170; tail -n 10 runs/a/iter.report'))
 def test_observed_background_watcher_blocks(self):
  for background in (True,False):
   message=self.check(OBSERVED,background)
   self.assertIsNotNone(message)
   self.assertIn('run_in_background',message);self.assertIn('checkpoint',message)
 def test_background_slurm_loops_and_follow_block(self):
  for cmd in ['while squeue -j 123; do sleep 5; done','until sacct -j 123 -n -o State | grep -q COMPLETED; do sleep 30; done','sleep 600; cat runs/a/capture.log','tail --pid=123 -f /dev/null','P=$(pgrep -f "telemetry_db.py ingest"); for p in $P; do tail --pid=$p -f /dev/null; done']:
   self.assertIsNotNone(self.check(cmd,True),cmd)
 def test_native_and_nonblocking_work_allowed(self):
  for background in (False,True):
   for cmd in ['squeue -j 123; tail -n 10 runs/a/jg.log','sacct -j 123 -n -o State','head -40 runs/a/out/receipts.txt','sbatch proof.sh','slurm/submit.sh batch run/proof_graph.tcl','srun --overlap -j 123 python3 rss_monitor.py','python3 tools/telemetry_db.py ingest RUN/telemetry index','setsid bash -c "slurm/submit.sh batch g.tcl; echo $? > native-exit.txt" &','cat > worker.sh <<EOF\nwhile squeue; do sleep 5; done\nEOF','sleep 120; make test','while true; do ps -o rss= -p 123 >> rss.log; sleep 5; done','tail -n 5 ingest.out']:
    self.assertIsNone(self.check(cmd,background),(cmd,background))
 def test_foreground_pid_follow_wait_blocks(self):
  self.assertIsNotNone(self.check('P=$(pgrep -f "telemetry_db.py ingest"); for p in $P; do tail --pid=$p -f /dev/null; done'))
  self.assertIsNotNone(self.check('tail -f --pid=123 /dev/null'))
  self.assertIsNotNone(self.check('P=$(pgrep -f "python3 .*telemetry_db.py ingest"); for p in $P; do tail --pid=$p -f /dev/null; done'))
  self.assertIsNotNone(self.check('python3 tools/telemetry_db.py ingest source index & tail --pid=$! -f /dev/null'))
  self.assertIsNone(self.check('tail -n 5 ingest.out'))
 def test_hook_process_exit_codes(self):
  def run(request):return subprocess.run([sys.executable,str(hook)],input=json.dumps(request),capture_output=True,text=True)
  denied=run({'tool_name':'Bash','tool_input':{'command':OBSERVED,'run_in_background':True}})
  self.assertEqual(denied.returncode,2);self.assertIn('durable continuation',denied.stderr);self.assertEqual(denied.stdout,'')
  for request in [{'tool_name':'Bash','tool_input':{'command':'squeue -j 123','run_in_background':True}},{'tool_name':'Bash','tool_input':{'command':'sbatch proof.sh'}},{'tool_name':'Read','tool_input':{'file_path':'x'}}]:
   allowed=run(request)
   self.assertEqual((allowed.returncode,allowed.stdout,allowed.stderr),(0,'',''),request)
if __name__=='__main__':unittest.main()
