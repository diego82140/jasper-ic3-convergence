#!/usr/bin/env python3
import os,sys,tempfile,io,subprocess,time,unittest,json,importlib.util
from pathlib import Path
from unittest.mock import patch
PKG=Path(os.environ.get('JIPSTATS_LIVE_TEST_PACKAGE',str(Path(__file__).resolve().parents[2])));sys.path.insert(0,str(PKG/'source'))
spec=importlib.util.spec_from_file_location('live_test_launcher',PKG/'source/jipstats.py');j=importlib.util.module_from_spec(spec);spec.loader.exec_module(j)
ROW='IC3_STATS phase=sat_end origin=preload backend=events run=1 event=1 pid=42 tid=42 call=1 result=sat\n'
class LiveTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.d=Path(self.tmp.name);self.out=io.StringIO();self.live=j.LiveStatistics(self.d,'test',self.out)
 def tearDown(self):self.tmp.cleanup()
 def test_only_real_event_rows_displayed(self):
  (self.d/'events-1-1.log').write_text('[JIPSTATS] attached\nIC3_STATS not_the_own_producer\n'+ROW)
  self.live.pump();self.assertEqual(self.live.records,1);self.assertEqual(self.out.getvalue(),'[jipstats live test] '+ROW)
 def test_partial_lines_wait_and_not_duplicated(self):
  f=self.d/'events-1-1.log';f.write_text(ROW[:-2]);self.live.pump();self.assertEqual(self.live.records,0)
  with f.open('a') as t:t.write(ROW[-2:])
  self.live.pump();self.live.pump();self.assertEqual(self.live.records,1)
 def test_all_events_remain_visible(self):
  (self.d/'events-1-1.log').write_text(ROW*1000);self.live.pump();self.assertEqual(self.live.records,1000)
 def test_no_symlink_followed(self):
  f=self.d/'other';f.write_text(ROW);(self.d/'events-1-1.log').symlink_to(f)
  self.live.pump();self.assertEqual(self.live.records,0);self.assertTrue(self.live.failed)
 def test_live_before_child_exit(self):
  f=self.d/'events-1-1.log'
  p=subprocess.Popen([sys.executable,'-S','-c','from pathlib import Path;import time;Path('+repr(str(f))+').write_text('+repr(ROW)+');time.sleep(1)'])
  deadline=time.monotonic()+.7
  while not self.live.records and time.monotonic()<deadline:time.sleep(.02);self.live.pump()
  self.assertEqual(self.live.records,1);self.assertIsNone(p.poll());p.wait(timeout=3)
 def test_exit_status_preserved(self):
  p=subprocess.Popen([sys.executable,'-S','-c','raise SystemExit(7)'])
  code,result=j.wait_with_live_statistics(p,None,'test',timeout=3);self.assertEqual(code,7);self.assertEqual(result['records_displayed'],0)
 def test_timeout_does_not_claim_pass(self):
  p=subprocess.Popen([sys.executable,'-S','-c','import time;time.sleep(5)'])
  try:
   with self.assertRaises(subprocess.TimeoutExpired):j.wait_with_live_statistics(p,None,'test',timeout=.1)
  finally:p.terminate();p.wait()
 def test_launcher_live_flag_preserves_jasper_args(self):
  options,value,args,msg=j.parse_options(['--live','/tool','-batch','-tcl','project.tcl'])
  self.assertTrue(options['live']);self.assertEqual(value,'/tool');self.assertEqual(args,['-batch','-tcl','project.tcl'])
 def test_live_flag_is_not_given_to_jasper(self):
  options,value,args,msg=j.parse_options(['--live','--check','/tool'])
  self.assertTrue(options['live']);self.assertTrue(options['check']);self.assertEqual(args,[])
 def test_native_console_validation_still_separate(self):
  text=(PKG/'source/jipstats.py').read_text()
  self.assertIn("rows=[line[line.index('IC3_STATS '):] for line in text.splitlines()",text)
  self.assertIn("force=options['check']",text)
 @unittest.skipUnless(os.environ.get('JIPSTATS_LIVE_TEST_TARGET'), 'Set JIPSTATS_LIVE_TEST_TARGET to the exact target install or worker')
 def test_exact_worker_frozen_no_python_path(self):
  p=subprocess.run([str(PKG/'jipstats'),'--discover-only',os.environ['JIPSTATS_LIVE_TEST_TARGET']],env={'HOME':str(self.d),'PATH':'/nonexistent','XDG_CACHE_HOME':str(self.d/'cache')},capture_output=True,text=True,timeout=30)
  self.assertEqual(p.returncode,0,p.stderr);self.assertIn('Profile available',p.stdout)
 def test_os_opt_in_preserves_project_args(self):
  options,value,args,msg=j.parse_options(['--allow-unsupported-os','--live','/tool','-batch'])
  self.assertTrue(options['allow_unsupported_os']);self.assertEqual(args,['-batch'])
 def test_current_version(self):
  p=subprocess.run([str(PKG/'jipstats'),'--version'],capture_output=True,text=True)
  self.assertEqual(p.stdout.strip(),'jipstats 1.5.0')
if __name__=='__main__':unittest.main(verbosity=2)
