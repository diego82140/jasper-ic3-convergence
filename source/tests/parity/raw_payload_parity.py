#!/usr/bin/env python3
"""Supplement strict archive/decoded-view checks with direct ordered raw words.

Hash-only equality is not this comparison: every actual literal word is compared,
including the SAT domain that the state-bit decoder correctly leaves unqualified.
Inputs must already have passed the main strict complete-archive comparison.
"""
import argparse,gzip,json,resource,tempfile,time
from pathlib import Path
from agent_cti_parity import reader,canonical,compare_streams,digest,must,MODELS,RELEASES

def export_words(source,target,legacy=False):
 paths=[source/'IC3-STATS.log'] if legacy else list(reader.canonical_logs(source));runs={};pending={};counts={'cubes':0,'words':0,'jip_formula_words':0,'sat_literal_raw_words':0}
 with gzip.open(target,'wb') as out:
  for p in paths:
   lines=p.open('rb') if legacy else reader.archive_lines(p)
   try:
    for raw in lines:
     if isinstance(raw,reader.FramedDisplay) or not raw.startswith(b'IC3_STATS '):continue
     r=reader.fields(raw.rstrip(b'\n'));phase=r['phase'];key=tuple(r[k] for k in ('capture','pid','tid','run'));rn=runs.setdefault(key,len(runs)+1)
     if phase=='cube_definition':
      k=(key,r['cube_id']);must(k not in pending,'overlapping cube definition');pending[k]=[r['domain'],int(r['literals']),0]
      out.write(canonical(dict(kind='cube',run=rn,cube=int(r['cube_id']),domain=r['domain'],literals=int(r['literals']))));counts['cubes']+=1
     elif phase=='cube_chunk':
      k=(key,r['cube_id']);must(k in pending,'chunk without definition');domain,total,at=pending[k];vs=r['values'].split(',') if r['values'] else []
      must(int(r['offset'])==at and len(vs)==int(r['count']),'raw payload chunk extent differs')
      for word in vs:
       must(len(word)==8 and 0<=int(word,16)<2**32,'invalid u32 literal')
       out.write(canonical(dict(kind='literal',run=rn,cube=int(r['cube_id']),index=at,raw=word.lower())));at+=1;counts['words']+=1
       key_count=domain+'_words'
       if key_count in counts:counts[key_count]+=1
      pending[k][2]=at
     elif phase=='cube_definition_end':
      k=(key,r['cube_id']);must(k in pending,'end without definition');_,total,at=pending.pop(k);must(r['complete']=='1' and at==total==int(r['literals']),'incomplete raw payload')
      out.write(canonical(dict(kind='cube_end',run=rn,cube=int(r['cube_id']),complete=True)))
   finally:
    if legacy:lines.close()
 must(not pending,'unfinished cube definition');return counts

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(exist_ok=False);prior=json.load(open(a.root/'results-r3/CTI-AGENT-PARITY.json'));full=json.load(open(a.root/'complete-results-r3/COMPLETE-AGENT-PARITY.json'));must(prior['status']=='PASS_FINITE_CTI_AGENT_PARITY' and full['status']=='PASS_FINITE_COMPLETE_AGENT_PARITY','strict prior comparisons not accepted');start=time.monotonic();cases=[];failed=[]
 for model in MODELS:
  for engine in ('M','M4'):
   d=a.output/model/engine;d.mkdir(parents=True);sources={'legacy15':Path('/formal_shared/diego1/jipstats-linux-x86_64/evidence/results-1.5.0/parity')/model/engine/'preload','old1613':a.root/'producer-1.6.13'/model/engine}
   sources.update({n:Path('/projects/diego1/jasper-202609-validation/information-parity-r7')/model/engine/n/'capture' for n in RELEASES});counts={}
   for name,source in sources.items():counts[name]=export_words(source,d/(name+'.jsonl.gz'),name=='legacy15')
   comparisons={}
   for n in ['old1613',*RELEASES]:
    comparisons[n]=compare_streams(d/'legacy15.jsonl.gz',d/(n+'.jsonl.gz'))
    if not comparisons[n]['pass_']:failed.append(model+'/'+engine+'/'+n)
   cases.append(dict(model=model,engine=engine,counts=counts,comparisons=comparisons));print(model,engine,'raw words',counts['legacy15']['words'],'equal',all(v['pass_'] for v in comparisons.values()),flush=True)
 report=dict(status='FAIL' if failed else 'PASS_DIRECT_ORDERED_RAW_WORD_PARITY',cases=cases,failures=failed,scope='every captured cube header/domain/complete raw u32 literal/order/duplicate, across legacy1.5,fresh1.6.13 and three updated September builds; no hash-only payload comparison; no interpretation of unqualified SAT atoms',prior_report_sha256=digest(a.root/'results-r3/CTI-AGENT-PARITY.json'),full_report_sha256=digest(a.root/'complete-results-r3/COMPLETE-AGENT-PARITY.json'),script_sha256=digest(__file__),reader_sha256=digest(reader.__file__),wall_seconds=time.monotonic()-start,max_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
 (a.output/'RAW-PAYLOAD-PARITY.json').write_text(json.dumps(report,indent=2)+'\n');print(report['status'],flush=True);return int(bool(failed))
if __name__=='__main__':raise SystemExit(main())
