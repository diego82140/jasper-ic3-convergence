#!/usr/bin/env python3
"""Run actual target functions with explicitly controlled ABI fixtures.

NOT native Jasper prove. Replaces process main ONLY with a separate test DSO.
The shipped libjipstats.so remains unchanged. Never use this harness in a user
proof session. A full corresponding Jasper installation is needed for --check.
"""
from pathlib import Path
import argparse,hashlib,json,os,re,subprocess,tempfile
from build_b5006df1 import build

HERE=Path(__file__).resolve().parent
PACKAGE=HERE.parents[1]
HASH='b5006df1ff1ab23d9effd5eec464b1962a0905da1880aaa8fae574a4a9a81604'
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('worker',type=Path)
    p.add_argument('--runtime-lib',type=Path,required=True,help='Producer test dependencies and ld-linux-x86-64.so.2')
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--cc',default='gcc')
    a=p.parse_args();worker=a.worker.resolve();r=a.runtime_lib.resolve();out=a.output.resolve()
    if sha(worker)!=HASH:raise RuntimeError('Unqualified worker for this test harness')
    out.mkdir(parents=True,exist_ok=False)
    native=PACKAGE/'libjipstats.so';probe=out/'target-abi-probe.so'
    cmd=[a.cc,'-shared','-fPIC','-O2','-g','-Wall','-Wextra','-Werror',str(HERE/'target_b5006df1_abi_probe.c'),
         '-o',str(probe),'-Wl,--no-as-needed',str(r/'libdl.so.2'),'-Wl,--as-needed']
    result=subprocess.run(cmd,capture_output=True,text=True)
    (out/'build.log').write_text(' '.join(cmd)+'\n'+result.stdout+result.stderr)
    result.check_returncode()
    profile=build(worker,out/'profiles')
    text=profile.read_text()
    bad_hash=out/'bad-hash.events';bad_hash.write_text(text.replace(HASH,'0'*64))
    rows=text.splitlines();i=next(i for i,l in enumerate(rows) if l.startswith('hook '))
    fields=rows[i].split();fields[-1]='00'*24;rows[i]=' '.join(fields)
    bad_guard=out/'bad-guard.events';bad_guard.write_text('\n'.join(rows)+'\n')
    results={};baseline=None
    for name,prof,injected,expected in [('baseline',profile,False,0),('preload',profile,True,201),
                                       ('rejected_hash',bad_hash,True,0),('rejected_instruction',bad_guard,True,0)]:
        d=out/name;d.mkdir()
        env={k:v for k,v in os.environ.items() if not k.startswith('JIPSTATS_') and k not in ('LD_PRELOAD','EXPECT_PRELOAD')}
        env.update(JIPSTATS_PROFILE=str(prof),JIPSTATS_IMAGE=str(worker),JIPSTATS_EVIDENCE_DIR=str(d))
        if expected:env['EXPECT_PRELOAD']='1'
        libraries=str(probe)+(':'+str(native) if injected else '')
        cmd=[str(r/'ld-linux-x86-64.so.2'),'--preload',libraries,'--library-path',str(r),str(worker)]
        completed=subprocess.run(cmd,env=env,capture_output=True,text=True,timeout=20)
        body=completed.stdout+'\n'+completed.stderr
        (d/'console.log').write_text(body)
        if completed.returncode:raise RuntimeError(name+' exited '+str(completed.returncode))
        assert 'TARGET_ABI_PROBE_PASS calls=32 records='+str(expected)+' failures=0' in body
        actual=[line for line in completed.stdout.splitlines() if line.startswith('ABI_RESULT ')]
        assert len(actual)==32
        if baseline is None:baseline=actual
        else:assert actual==baseline,'Native results changed'
        event_rows=[dict(re.findall(r'(\w+)=([^ ]+)',l)) for l in completed.stdout.splitlines() if l.startswith('IC3_STATS ')]
        assert len(event_rows)==expected
        if expected:
            assert 'hooks=17 producer_strings_required=0 debug_selector_modified=0' in body
            for kind,key in [('relative','query'),('sat','call')]:
                begin=[x for x in event_rows if x['phase']==kind+'_begin']
                end=[x for x in event_rows if x['phase']==kind+'_end']
                assert len(begin)==len(end)==32
                assert {x[key] for x in begin}=={x[key] for x in end}
                assert sum(x['result']=='sat' for x in end)==8
                assert sum(x['result']=='unsat' for x in end)==16
                assert sum(x['result'].startswith('limit') for x in end)==8
            final=next(x for x in event_rows if x['phase']=='final')
            for field,want in [('relative_calls','32'),('solver_calls','32'),('generalize_calls','2'),('depth','6'),('obligations_created','37'),
                               ('lost','0'),('read_failures','0'),('callback_failures','0')]:
                assert final[field]==want,(field,final)
            assert any(x['phase']=='cube' and x.get('values')=='00000010' for x in event_rows)
            assert all('origin' in x and x['origin']=='preload' for x in event_rows)
        if name=='rejected_hash':assert 'image_hash_mismatch' in body
        if name=='rejected_instruction':assert 'instruction_guard_mismatch' in body
        assert sha(worker)==HASH,'Installed worker changed'
        results[name]={'exit':completed.returncode,'cases':32,'generated_records':len(event_rows),'native_result_equivalence':'PASS','log_sha256':sha(d/'console.log')}
    report={'validation_scope':'ACTUAL_TARGET_FUNCTIONS_WITH_CONTROLLED_ABI_FIXTURES_NOT_NATIVE_PROVE',
            'worker_sha256':HASH,'library_sha256':sha(native),'worker_unchanged':True,
            'old_statistics_marker_count':worker.read_bytes().count(b'IC3_STATS'),
            'native_M_M4_proofs_tested':False,'cases':results,
            'limitations':['Controlled downstream solver returns, not SAT proof outcomes.',
                           'Original target Bullet JIP report bridge is exercised; downstream session transport is a fixture.',
                           '17 hooks attach; six event-hooked functions are exercised by these fixtures.'],
            'result':'PASS'}
    (out/'TARGET-ABI-TESTS.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
if __name__=='__main__':main()
