"""Native collector regression and a deliberately failing old-predicate mutation."""
import gzip,os,shutil,subprocess,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

class QueueMembership(unittest.TestCase):
    def test_recycled_node_removes_old_obligation_and_old_predicate_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            temp=Path(temp)
            for mutation in (False,True):
                src=temp/('old' if mutation else 'fixed');shutil.copytree(ROOT/'source/src',src)
                if mutation:
                    p=src/'details.h';s=p.read_text();old='g_hash_table_lookup(nodes,node)!=po'
                    self.assertEqual(s.count(old),1);p.write_text(s.replace(old,'!g_hash_table_contains(nodes,node)'))
                binary=src/'fixture'
                cmd=['gcc','-D_GNU_SOURCE','-std=gnu11','-O2','-I'+str(ROOT/'third_party/frida-gum'),
                     '-include',str(src/'compat.h'),'-DQUEUE_PRODUCER_FILE="'+str(src/'events.c')+'"',
                     str(ROOT/'source/tests/queue_membership_fixture.c'),str(src/'compat.c'),str(src/'launchpropagate.c'),
                     str(ROOT/'third_party/frida-gum/libfrida-gum.a'),'-Wl,--wrap=stat64','-ldl','-lrt','-pthread','-lresolv','-lm','-lz','-o',str(binary)]
                subprocess.run(cmd,check=True,capture_output=True)
                out=src/'capture';out.mkdir()
                env={k:v for k,v in os.environ.items() if not k.startswith(('JIPSTATS_','LD_PRELOAD'))}
                env['JIPSTATS_EVIDENCE_DIR']=str(out)
                result=subprocess.run([str(binary)],env=env,capture_output=True)
                if mutation:
                    self.assertEqual(result.returncode,3);self.assertIn(b'recycled list node',result.stderr)
                else:
                    self.assertEqual(result.returncode,0,result.stderr)
                    observed=[]
                    for p in out.glob('events-*.log.gz'):
                        with gzip.open(p,'rt') as f:
                            for line in f:
                                if 'phase=queue_membership_remove ' in line:
                                    fields=dict(item.split('=',1) for item in line.split()[1:])
                                    observed.append((int(fields['snapshot']),int(fields['obligation_id'])))
                    self.assertEqual(observed,[(1,11),(2,22),(3,33)])

if __name__=='__main__':unittest.main()
