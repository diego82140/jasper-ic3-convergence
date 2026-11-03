#!/usr/bin/env python3
"""Compare fresh prior full-data producer against each updated agent view.

No pointer-allocation equivalence, event-count proxy or empty sidecar comparison.
Only strict, complete archives and exact ordered semantic streams are accepted.
"""
import argparse,gzip,json,resource,sys,tempfile,time
from pathlib import Path
from agent_cti_parity import reader,export_view,compare_streams,VIEW_STREAMS,digest,must,MODELS,RELEASES
from native_client import decode,expected_results,WORKER_SHA
OLD_LIBRARY='fa90623cc659b079d6f32d3a5ffd13bfd796b5c35d08d33a9af5d5e43e6bcb9b'
STREAMS=VIEW_STREAMS

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--baseline',type=Path,required=True);p.add_argument('--updated-views',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(exist_ok=False);start=time.monotonic()
 base=json.loads((a.baseline/'RESULTS.json').read_text());must(base['original_library_sha256']==OLD_LIBRARY and base['worker_sha256']==WORKER_SHA,'baseline source identity mismatch')
 prior=json.loads((a.updated_views/'CTI-AGENT-PARITY.json').read_text());must(prior['status']=='PASS_FINITE_CTI_AGENT_PARITY','updated agent views have no accepted earlier comparison');must(prior['reader_sha256']==digest(reader.__file__),'updated views used different reader')
 cases=[];failures=[]
 with tempfile.TemporaryDirectory(prefix='jipstats-full-agent-parity-') as tmp:
  tmp=Path(tmp)
  for model in MODELS:
   for engine in ('M','M4'):
    source=a.baseline/model/engine;result=json.loads((source/'RESULT.json').read_text());invocation=json.loads((source/'INVOCATION.json').read_text());must(invocation['library_sha256']==OLD_LIBRARY and invocation['worker_sha256']==WORKER_SHA and invocation['engine']==engine and invocation['sink']=='disk','baseline native invocation mismatch')
    must(result['status']=='PASS' and result['exit']==0 and result['original_main'] is True and result['original_solver'] is True and result['receive_eof'] is True and result['receiver_joined'] is True and result['protocol_buffer_empty'] is True,'baseline native completion unqualified')
    _,verdicts,_,_=decode((source/'native-response.bin').read_bytes());must(verdicts==expected_results(invocation['model_sha256'],model=='shared')==result['verdicts'],'baseline native verdict mismatch')
    target=a.output/model/engine;target.mkdir(parents=True);index=tmp/f'{model}-{engine}.db';integrity=reader.ingest(source,index);must(integrity['complete'],'baseline archive incomplete');view=export_view(index,target/'producer1613');index.unlink();Path(str(index)+'.integrity.json').unlink()
    expected_quip=str(int(engine=='M'));must(view['native_configuration'] and all(r['quip_mode']==expected_quip for r in view['native_configuration']),'baseline effective native M/M4 configuration differs')
    reference=next(c for c in prior['cases'] if c['model']==model and c['engine']==engine);compared={}
    for release in RELEASES:
     directory=a.updated_views/model/engine/release;metadata=reference['releases'][release]['agent_view'];r={}
     for name in STREAMS:
      path=directory/name;must(digest(path)==metadata['streams'][name]['sha256'],'updated exported view changed after comparison')
      r[name]=compare_streams(target/'producer1613'/name,path)
     must(view['native_configuration']==metadata['native_configuration'],'baseline native configuration fields differ')
     compared[release]=r
     if not all(v['pass_'] for v in r.values()):failures.append(model+'/'+engine+'/'+release)
    row=dict(model=model,engine=engine,model_sha256=invocation['model_sha256'],baseline_native_invocation_sha256=digest(source/'INVOCATION.json'),baseline_result_sha256=digest(source/'RESULT.json'),baseline_integrity=integrity,baseline_agent_view=view,comparisons=compared);cases.append(row);(target/'RESULT.json').write_text(json.dumps(row,indent=2)+'\n');print(model,engine,'complete CTI comparisons',all(x['pass_'] for z in compared.values() for x in z.values()),flush=True)
 report=dict(status='FAIL' if failures else 'PASS_FINITE_COMPLETE_AGENT_PARITY',cases=cases,failures=failures,old_library_sha256=OLD_LIBRARY,new_library_sha256=digest(Path(reader.__file__).parents[1]/'libjipstats.so'),reader_sha256=digest(reader.__file__),exporter_sha256=digest(Path(__file__).with_name('agent_cti_parity.py')),driver_sha256=digest(__file__),prior_report_sha256=digest(a.updated_views/'CTI-AGENT-PARITY.json'),max_analysis_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,wall_seconds=time.monotonic()-start,scope='Finite exact complete decoded cube/query/frame and predecessor-pair semantics against fresh producer1.6.13; not a universal all-design/solver equivalence theorem or proof certificate')
 (a.output/'COMPLETE-AGENT-PARITY.json').write_text(json.dumps(report,indent=2)+'\n');print(report['status'],failures,flush=True);return int(bool(failures))
if __name__=='__main__':raise SystemExit(main())
