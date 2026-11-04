"""Exercise real collector state, including a forced digest-key collision."""
import os,resource,shutil,subprocess,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

class PayloadConsistency(unittest.TestCase):
    def test_actual_collector_does_not_reuse_incomplete_or_different_payload(self):
        with tempfile.TemporaryDirectory() as temp:
            for mutation in ('fixed','hash_only','incomplete_reuse','stale_obligation','unguarded_unhook','duplicate_node'):
                with self.subTest(mutation=mutation):
                    out=Path(temp)/mutation;out.mkdir();src=out/'src';shutil.copytree(ROOT/'source/src',src)
                    p=src/'details.h';text=p.read_text()
                    if mutation=='hash_only':text=text.replace('&&!memcmp(known->values,captured->values,bytes)','')
                    if mutation=='incomplete_reuse':text=text.replace('known&&known->complete&&known->count','known&&known->count')
                    if mutation=='stale_obligation':
                        anchor='uint64_t id=full_cube(s,cube);struct po_definition*pa=reserve_po(s,parent);'
                        self.assertEqual(text.count(anchor),1)
                        text=text.replace(anchor,'if(po->defined&&po->flags==flags&&po->cex_size==path&&po->cube==cube&&po->parent==parent)break;\n  '+anchor)
                    if mutation=='duplicate_node':
                        text=text.replace('if(g_hash_table_contains(nodes,(gpointer)node)){detail_error(s,"queue_duplicate_physical_node");complete=false;break;}','')
                    if mutation=='unguarded_unhook':
                        original=text;start=text.index('/* A cached membership does not certify the current node payload. */')
                        end=text.index('emit(s,"obligation_dequeue"',start);text=text[:start]+text[end:]
                        self.assertNotEqual(text,original)
                    elif mutation!='fixed':self.assertNotEqual(text,p.read_text())
                    p.write_text(text);binary=out/'fixture'
                    subprocess.run(['gcc','-D_GNU_SOURCE','-std=gnu11','-O2',
                        '-I'+str(ROOT/'third_party/frida-gum'),'-include',str(src/'compat.h'),
                        '-DPAYLOAD_PRODUCER_FILE="'+str(src/'events.c')+'"',
                        str(ROOT/'source/tests/payload_consistency_fixture.c'),str(src/'compat.c'),
                        str(src/'launchpropagate.c'),str(ROOT/'third_party/frida-gum/libfrida-gum.a'),
                        '-Wl,--wrap=stat64','-ldl','-lrt','-pthread','-lresolv','-lm','-lz','-o',str(binary)],
                        check=True,capture_output=True)
                    capture=out/'capture';capture.mkdir()
                    env={k:v for k,v in os.environ.items() if not k.startswith(('JIPSTATS_','LD_PRELOAD'))}
                    env['JIPSTATS_EVIDENCE_DIR']=str(capture)
                    result=subprocess.run([str(binary)],env=env,capture_output=True,timeout=60,
                        preexec_fn=lambda:resource.setrlimit(resource.RLIMIT_CORE,(0,0)))
                    if mutation=='fixed':
                        self.assertEqual(result.returncode,0,result.stderr)
                        self.assertIn(b'PASS exact cube/frame cache',result.stdout)
                    else:self.assertEqual(result.returncode,-6,result.stderr)

if __name__=='__main__':unittest.main()
