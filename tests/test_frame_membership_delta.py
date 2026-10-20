"""Exercise native C set deltas against independently written ordered tuples."""
from pathlib import Path
import gzip,importlib.util,os,struct,subprocess,tempfile,unittest
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('telemetry',ROOT/'tools/telemetry_db.py');t=importlib.util.module_from_spec(spec);spec.loader.exec_module(t)
class MembershipDelta(unittest.TestCase):
 def test_duplicates_frames_remove_readd_epoch_and_failed_scan_retry(self):
  with tempfile.TemporaryDirectory() as temporary:
   tmp=Path(temporary);binary=tmp/'fixture'
   command=['gcc','-D_GNU_SOURCE','-std=gnu11','-O2','-I'+str(ROOT/'third_party/frida-gum'),'-include',str(ROOT/'source/src/compat.h'),str(ROOT/'source/tests/frame_storage_fixture.c'),str(ROOT/'source/src/compat.c'),str(ROOT/'source/src/launchpropagate.c'),str(ROOT/'third_party/frida-gum/libfrida-gum.a'),'-Wl,--wrap=stat64','-ldl','-lrt','-pthread','-lresolv','-lm','-lz','-o',str(binary)]
   subprocess.run(command,check=True,capture_output=True)
   for mode in ['short','retry']:
    with self.subTest(mode=mode):
     out=tmp/mode;out.mkdir();oracle=out/'oracle.bin'
     env={key:value for key,value in os.environ.items() if not key.startswith('JIPSTATS_') and key!='LD_PRELOAD'};env['JIPSTATS_EVIDENCE_DIR']=str(out)
     subprocess.run([str(binary),'compact',mode,str(oracle)],env=env,check=True,capture_output=True)
     expected={};previous={};occurrences={}
     with oracle.open('rb') as f:
      while header:=f.read(20):
       epoch,snapshot,frames=struct.unpack('<QQI',header);current=set();count=0
       for _ in range(frames):
        frame,members=struct.unpack('<iI',f.read(8))
        for _ in range(members):
         raw,packed=struct.unpack('<II',f.read(8));current.add((frame,raw));count+=1
       prior=previous.get(epoch,set());expected[(epoch,snapshot)]=(current-prior,prior-current);previous[epoch]=current;occurrences[(epoch,snapshot)]=count
     definitions={};adds={};removes={};closed={};failed=[];all_adds=[]
     for path in out.glob('events-*.log.gz'):
      with gzip.open(path,'rb') as f:
       for line in f:
        r=t.fields(line.rstrip(b'\n'));phase=r['phase'];epoch=int(r['model_epoch'])
        if phase=='cube_chunk':definitions[(epoch,int(r['cube_id']))]=int(r['values'],16)
        if phase in ('frame_membership_add','frame_membership_remove'):
         key=(epoch,int(r['snapshot']));member=(int(r['frame']),definitions[(epoch,int(r['cube_id']))])
         target=adds if phase=='frame_membership_add' else removes;target.setdefault(key,[]).append(member)
         if phase=='frame_membership_add':all_adds.append((key,member))
        if phase=='frames_end':
         key=(epoch,int(r['snapshot']));closed[key]=int(r['members']) if r['complete']=='1' else None
         if r['complete']!='1':failed.append(key)
     self.assertTrue(failed if mode=='retry' else not failed)
     for key,(new,removed) in expected.items():
      self.assertEqual(closed[key],occurrences[key]);self.assertEqual(set(adds.get(key,[])),new);self.assertEqual(len(adds.get(key,[])),len(new))
      self.assertEqual(set(removes.get(key,[])),removed);self.assertEqual(len(removes.get(key,[])),len(removed))
     first=min(expected);self.assertLess(len(adds[first]),occurrences[first])
     # cube900 is both an ordinary frontier member and an engine invariant.
     self.assertIn((0,(900<<3)|2),adds[first]);self.assertIn((-1,(900<<3)|2),adds[first])
     if mode=='retry':
      provisional=(0,0xabcdef02);self.assertIn(provisional,adds[failed[0]])
      self.assertTrue(any(provisional in adds.get(key,[]) for key in expected if key>failed[0]))
