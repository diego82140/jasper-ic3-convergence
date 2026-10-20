#!/usr/bin/env python3
"""Actual Dollar-oracle vs unchanged marker-free worker differential regression.
Every non-timing baseline field must be present and equal; additional plugin
records are allowed only without deleting/reordering baseline information.
Raw CTI/validation/lens/queue/focus lines must match byte for byte (prefix removed).
This is finite executable evidence for pinned builds, not universal equivalence.
"""
from pathlib import Path
import argparse,collections,hashlib,json,os,re,subprocess,sys,time
from native_client import run_worker,digest,FAMILIES,WORKER_SHA
from models import MODELS
BASELINE_DOLLAR='4b6288c1c3501f2343c27fbea45e009fcb645077b13324cd2cf7a2f2c2dc091b'
STAT_PHASES=('block_begin','block_sample','push_begin','push_end','final','sat_begin','sat_end')

def records(path):
 result=[]
 for no,line in enumerate(Path(path).read_text(errors='strict').splitlines(),1):
  match=re.search(r'\b(IC3_[A-Z_]+) ',line)
  if not match:continue
  family=match[1];raw=line[match.start():]
  result.append({'family':family,'raw':raw,'line':no,'fields':dict(re.findall(r'(\w+)=([^ ]+)',raw))})
 return result

def compare(oracle,plugin_events,plugin_families):
 results=[];allbase=oracle;eventdata=plugin_events
 familyset=set(x['family'] for x in allbase)
 unexpected=familyset-set(FAMILIES)-{'IC3_STATS'}
 if unexpected:raise ValueError('Unmapped actual Dollar diagnostic families: '+str(unexpected))
 unknown_phases={r['fields'].get('phase') for r in allbase if r['family']=='IC3_STATS'}-set(STAT_PHASES)
 if unknown_phases:raise ValueError('Unmapped actual Dollar statistics phase: '+str(unknown_phases))
 for family in FAMILIES:
  a=[r['raw'] for r in allbase if r['family']==family]
  b=[r['raw'] for r in plugin_families if r['family']==family]
  equal=a==b
  results.append({'family':family,'comparison':'exact_ordered_record_text','baseline_records':len(a),'plugin_records':len(b),'pass':equal,'first_mismatch':next(({'index':i,'dollar':x,'plugin':y} for i,(x,y) in enumerate(zip(a,b)) if x!=y),None)})
 for phase in STAT_PHASES:
  a=[r for r in allbase if r['family']=='IC3_STATS' and r['fields'].get('phase')==phase]
  if not a:continue
  b=[r for r in eventdata if r['fields'].get('phase')==phase and (not phase.startswith('sat_') or r['fields'].get('relative_query')!='0')]
  # Record-specific required fields: no use of intersection that could silently
  # erase baseline fields. Extra observer fields are not required to be absent.
  def project(row,keys,is_plugin):
   d={}
   for key in keys:
    if key=='elapsed':continue
    lookup='sat_calls' if is_plugin and key=='call' and phase.startswith('sat_') else key
    val=row['fields'].get(lookup)
    if val is None:return None
    if key=='sat_percent':val=f'{float(val):.1f}'
    if key=='result' and val=='limit_or_unknown':val='limit'
    d[key]=val
   return d
  j=0;matched=[];failure=None
  for i,ref in enumerate(a):
   keys=set(ref['fields']);wanted=project(ref,keys,False);start=j
   while j<len(b) and project(b[j],keys,True)!=wanted:j+=1
   if j==len(b):
    failure={'baseline_index':i,'baseline_line':ref['line'],'wanted':wanted,'first_candidate':project(b[start],keys,True) if start<len(b) else None};break
   if 'elapsed' in ref['fields']:
    if float(b[j]['fields']['elapsed'])<0 or float(ref['fields']['elapsed'])<0:raise ValueError('Negative duration')
    if 'process_cpu_ns' in b[j]['fields'] and abs(float(b[j]['fields']['elapsed'])-int(b[j]['fields']['process_cpu_ns'])/1e9)>1e-9:raise ValueError('Duration units disagree')
   matched.append({'baseline_line':ref['line'],'plugin_line':b[j]['line'],'fields_checked':len(keys)-('elapsed' in keys)});j+=1
  results.append({'family':'IC3_STATS','phase':phase,'comparison':'all_baseline_non_timing_fields_ordered_subsequence','baseline_records':len(a),'plugin_records_projected':len(b),'pass':failure is None,'matched_records':len(matched),'matched_fields':sum(x['fields_checked'] for x in matched),'extra_plugin_records':len(b)-len(a),'elapsed_comparison':'both nonnegative with checked units, not numeric equality across executions' if phase=='sat_end' else None,'first_mismatch':failure,'line_mapping':matched})
 return {'pass':all(x['pass'] for x in results),'families':results}

def call(argv,cwd,log,timeout=45):
 start=time.monotonic();r=subprocess.run([str(x) for x in argv],cwd=cwd,env={'PATH':os.environ.get('PATH','/usr/bin:/bin'),'HOME':str(cwd),'LANG':'C'},capture_output=True,text=True,timeout=timeout)
 Path(log).write_text(r.stdout+r.stderr)
 if r.returncode:raise RuntimeError('Command failed '+str(argv)+' exit '+str(r.returncode)+' log '+str(log))
 return {'argv':[str(x) for x in argv],'exit':r.returncode,'seconds':time.monotonic()-start,'log_sha256':digest(log)}

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for arg in ('worker','runtime','package','output'):p.add_argument('--'+arg,type=Path,required=True)
 a=p.parse_args()
 for arg in ('worker','runtime','package','output'):setattr(a,arg,getattr(a,arg).resolve())
 if digest(a.worker)!=WORKER_SHA or digest(a.runtime/'proofengine/dollar/dollar.bin')!=BASELINE_DOLLAR:raise ValueError('Different baseline builds: regenerate qualification, do not reuse PASS')
 a.output.mkdir(parents=True,exist_ok=False)
 pkgsha=digest(a.package/'libjipstats.so');dollar=a.runtime/'dollar';bsutil=a.runtime/'bin/jg_bsutil'
 models={'shared':(a.package/'source/tests/worker_protocol/model.bs',True)};generation=[]
 for name,src in MODELS.items():
  d=a.output/'models'/name;d.mkdir(parents=True);smv=d/'model.smv';smv.write_text(src)
  generation.append(call([dollar,'-M','-jipIcStats','-dumpbs','-nosimplify','-noreduce','-noTrivCheck','-time','20','-smv',smv],d,d/'generation.log'))
  dump=Path(str(smv)+'.dump.0.bs');model=d/'model.bs'
  if not dump.is_file():raise RuntimeError('Expected generated netlist absent')
  generation.append(call([bsutil,'-c','-o',model,dump],d,d/'conversion.log'))
  models[name]=(model,False)
 reports=[];failures=[]
 for name,(model,shared) in models.items():
  for engine in ('M','M4'):
   d=a.output/name/engine;d.mkdir(parents=True)
   oracle={};calls=[]
   for mode in ('stats','noise'):
    cmd=[dollar,'-'+engine,'-jipIcStats','-nosimplify','-noreduce','-noTrivCheck','-time','30']
    if mode=='noise':cmd+=['-jipVerbose','3']
    cmd+=['-bs',model]
    calls.append(call(cmd,d,d/(mode+'.log')));oracle[mode]=records(d/(mode+'.log'))
   baseline=run_worker(a.worker,a.runtime,a.package,model,d/'baseline',engine,False,shared)
   injected=run_worker(a.worker,a.runtime,a.package,model,d/'preload',engine,True,shared)
   if baseline['verdicts']!=injected['verdicts']:raise ValueError('Preload altered native verdicts')
   # Compare actual native Dollar verdict status list as well as native worker self-comparison.
   text=(d/'stats.log').read_text();native_results=re.findall(r'==> Result: Target (Valid|Cex|CEX)\b',text)
   expected=[('valid' if x=='Valid' else 'cex') for x in native_results]
   if expected and expected!=[x['status'] for x in injected['verdicts']]:raise ValueError('Dollar/worker verdict mismatch')
   events=records(d/'preload/IC3-STATS.log');families=records(d/'preload/DOLLAR-DIAGNOSTICS.log')
   comparisons={}
   for mode in ('stats','noise'):
    # Non-stats families use the mode1 baseline; mode3 turns off mode1 printers.
    data=oracle[mode]
    observed_families={x['family'] for x in data}
    compared_families=families if mode=='stats' else [x for x in families if x['family'] in observed_families]
    cmp=compare(data,events,compared_families)
    comparisons[mode]=cmp
   cfg=[x['fields'] for x in events if x['fields'].get('phase')=='native_ic3_configuration']
   if cfg and any(x['quip_mode']!=str(int(engine=='M')) for x in cfg):raise ValueError('M/M4 mode mismatch')
   finals=[x['fields'] for x in events if x['fields'].get('phase')=='final']
   if not finals:raise ValueError('No independently instrumented original IC3 run')
   for x in finals:
    for key in ('lost','read_failures','callback_failures','population_mismatch','final_stats_mismatch'):
     if int(x.get(key,0)):raise ValueError('Capture failure '+str(x))
   result={'case':name,'engine':engine,'model_sha256':digest(model),'comparisons':comparisons,'pass':all(x['pass'] for x in comparisons.values()),'dollar_calls':calls,'baseline':baseline,'preload':injected,'observed_configuration':cfg}
   reports.append(result);(d/'PARITY.json').write_text(json.dumps(result,indent=2)+'\n')
   if not result['pass']:failures.append(name+'/'+engine)
   print(name,engine,'PARITY',result['pass'],'CTI',sum(x['family']=='IC3_CTI' for x in families),'records',injected['statistics_records'],flush=True)
 if digest(a.worker)!=WORKER_SHA or digest(a.package/'libjipstats.so')!=pkgsha:raise ValueError('Input binary modified')
 result={'status':'PASS' if not failures else 'FAIL','scope':'pinned Dollar M/M4 vs exact original marker-free worker; complete observed diagnostic contract on included regression corpus','worker_sha256':WORKER_SHA,'dollar_sha256':BASELINE_DOLLAR,'plugin_sha256':pkgsha,'models':{k:{'sha256':digest(v[0]),'shared':v[1]} for k,v in models.items()},'cases':reports,'failures':failures,'generation':generation,'timing_policy':'same type/units, nonnegative; values depend on execution and overhead','native_outputs_checked':list(FAMILIES)+['IC3_STATS'],'full_matching_frontend_tested':False,'universal_all_models_or_builds_proof':False,'worker_or_Dollar_sources_edited':False,'fixtures_or_solver_replacement_used':False}
 (a.output/'PARITY-RESULTS.json').write_text(json.dumps(result,indent=2)+'\n')
 print('OVERALL',result['status'],flush=True)
 return 0 if not failures else 1
if __name__=='__main__':raise SystemExit(main())
