#!/usr/bin/env python3
"""Compare actual CTI/agent inputs, independently of native pointer histories.

Only the finite, pinned regression corpus is accepted by the driver. Strict
archive validation precedes interpretation. Every cube is decoded by the real
epoch-aware consumer; missing bits and composite formulas remain unknown.
This is a regression comparison, never a reachability/inductiveness certificate.
"""
from __future__ import annotations
import argparse,contextlib,gzip,hashlib,importlib.util,json,resource,shutil,sqlite3,sys,tempfile,time
from collections import Counter
from functools import lru_cache
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('agent_parity_reader',ROOT/'tools/telemetry_db.py')
reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(reader)
MODELS=('shared','xy','and_predecessor','composite_property','delayed_bug')
RELEASES=('prerelease','production','production-p001')
VIEW_STREAMS=('common.jsonl.gz','predecessors.jsonl.gz','named-ctis.jsonl.gz','cube-definitions.jsonl.gz','decoded-cubes.jsonl.gz')
COMMON={
 'cube':('when','query','generalization','total','shown','truncated','capture_complete','encoding'),
 'query_context':('query','operation','parent_operation','parent_kind','frame','flags','query_class','assumes_not_cube_current','request_model','request_minimize','fixed_budget_requested','growing_budget_requested','basis','base_check','abstraction_status','context_complete'),
 'query_conclusion':('query','result_raw','conclusion','scope','initialization_validated','global_step_validated','concrete_cex_validated','model_witness_exported','unsat_core_exported','output_initial_repair','promote_to_global_lemma'),
 'relative_begin':('query','operation','generalization','frame','depth','flags','cube_lits'),
 'relative_end':('query','result','result_raw','frame','cube_lits'),
 'generalization_relation':('generalization',),
}
REFS={'cube':('cube_id',),'query_context':('input_cube_id',),'query_conclusion':('input_cube_id','output_cube_id'),'generalization_relation':('before_cube_id','after_cube_id')}

def digest(path):
 h=hashlib.sha256()
 with Path(path).open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest()
def canonical(obj):return json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()+b'\n'
def put(stream,obj):stream.write(canonical(obj))
def must(ok,message):
 if not ok:raise ValueError(message)

class DecodedWriter:
 """Hash/emit one decoded line at a time, never load an archive into memory."""
 def __init__(self,stream,run_no,cube):self.stream=stream;self.pending='';self.semantic=hashlib.sha256();self.count=0;self.statuses=Counter();self.run_no=run_no;self.cube=cube
 def write(self,text):
  self.pending+=text
  while '\n' in self.pending:
   line,self.pending=self.pending.split('\n',1);r=json.loads(line)
   if 'literals' in r:
    must(r['proof_certificate'] is False and r['absent_bits']=='unknown','unsafe decoded cube header')
    put(self.stream,dict(kind='cube_header',run=self.run_no,cube=self.cube,literals=r['literals'],absent_bits='unknown',composite_formulas='unresolved',proof_certificate=False))
   else:
    # Preserve raw literal, order, variable, inversion, vector/bit and value in
    # the exported agent input. Hash the entire decoder row, no field intersection.
    self.semantic.update(canonical(r));self.count+=1;self.statuses[r['status']]+=1
    put(self.stream,dict(kind='literal',run=self.run_no,cube=self.cube,**r))
  return len(text)
 def flush(self):pass

def frame_layout(db,run_id,snapshot):
 """Keep empty frames too; tuple hashes alone lose the search depth ladder."""
 modern=list(db.execute('SELECT frame,members,closed FROM frame_manifests WHERE run=? AND snapshot=? ORDER BY frame<0,frame',(run_id,snapshot)))
 if modern:
  must(all(closed for _,_,closed in modern),'unclosed frame layout')
  return [{'frame':frame,'cubes':count} for frame,count,_ in modern]
 result=[]
 for path,offset,length in db.execute("SELECT f.path,e.offset,e.length FROM events e JOIN files f ON f.id=e.source WHERE e.run=? AND e.snapshot=? AND e.phase='frame' ORDER BY e.frame<0,e.frame",(run_id,snapshot)):
  with reader.archive_open(path) as stream:stream.seek(offset);r=reader.fields(stream.read(length).rstrip(b'\n'))
  result.append({'frame':int(r['frame']),'cubes':int(r['cubes'])})
 must(result,'missing frame layout');return result

def export_view(database,out):
 """Export common legacy semantics plus explicitly separate newer capabilities."""
 out.mkdir();db=sqlite3.connect(database.resolve().as_uri()+'?mode=ro',uri=True);db.execute('PRAGMA cache_size=-8192');db.execute('PRAGMA mmap_size=0')
 reader.verify_index(database);reader.require_current_validation(db);signatures=reader.verify_sources(db)
 common=out/'common.jsonl.gz';extra=out/'predecessors.jsonl.gz';named=out/'named-ctis.jsonl.gz';decoded=out/'decoded-cubes.jsonl.gz';definitions=out/'cube-definitions.jsonl.gz';counts=Counter();config=[]
 try:
  with gzip.open(common,'wb') as c,gzip.open(extra,'wb') as x,gzip.open(named,'wb') as n,gzip.open(decoded,'wb') as d,gzip.open(definitions,'wb') as defs:
   for run_no,(run,run_id) in enumerate(db.execute('SELECT run,rowid FROM runs ORDER BY rowid'),1):
    decode=reader.cube_decoder(db,run)
    # One definition per cube, including definitions without a public cube role.
    signatures_by_cube={}
    for ident,expected,domain in db.execute("SELECT id,expected,domain FROM payloads WHERE run=? AND kind='cube' AND complete=1 ORDER BY id",(run,)):
     raw=hashlib.sha256();actual=0
     for (data,) in db.execute("SELECT data FROM chunks WHERE run=? AND kind='cube' AND id=? ORDER BY offset",(run,ident)):raw.update(data);actual+=len(data)//4
     must(actual==expected,'cube extent mismatch')
     summary=dict(domain=domain,literals=expected,raw_u32_sha256=raw.hexdigest())
     if domain=='jip_formula':
      sink=DecodedWriter(d,run_no,ident)
      with contextlib.redirect_stdout(sink):decode(ident)
      must(not sink.pending and sink.count==expected,'decoder lost literal records')
      summary.update(decoded_sha256=sink.semantic.hexdigest(),decoded_statuses=dict(sink.statuses));counts.update(sink.statuses)
     else:summary.update(decoded_sha256=None,decoded_statuses={'unqualified_literal_domain':expected})
     put(defs,dict(kind='cube_definition',run=run_no,cube=ident,**summary))
     signatures_by_cube[ident]=summary;counts['cubes']+=1;counts['literals']+=expected
    def cube(value):
     ident=int(value);must(ident in signatures_by_cube,'unknown/incomplete referenced cube');return signatures_by_cube[ident]
    def parity(ident):
     r=db.execute("SELECT expected,complete FROM payloads WHERE run=? AND kind='parity' AND id=?",(run,ident)).fetchone();must(r and r[1],'diagnostic payload unavailable')
     data=b''.join(z[0] for z in db.execute("SELECT data FROM chunks WHERE run=? AND kind='parity' AND id=? ORDER BY offset",(run,ident)))
     must(len(data)==r[0],'diagnostic payload extent mismatch');return data
    source=None;f=None
    try:
     for path,offset,length in db.execute('SELECT f.path,e.offset,e.length FROM events e JOIN files f ON f.id=e.source WHERE e.run=? ORDER BY e.event',(run_id,)):
      if source!=path:
       if f is not None:f.__exit__(None,None,None)
       source=path;f=reader.archive_open(path);stream=f.__enter__()
      stream.seek(offset);r=reader.fields(stream.read(length).rstrip(b'\n'));phase=r['phase']
      if phase=='native_ic3_configuration':config.append({k:v for k,v in r.items() if k not in ('phase','origin','backend','run','event','pid','tid','schema','capture','ctx_rev','model_epoch','op_id','chain')});continue
      if phase=='parity_record' and r['family']=='IC3_CTI':
       raw=parity(int(r['parity_sequence']));put(n,dict(run=run_no,raw_hex=raw.hex()));counts['named_ctis']+=1
      elif phase in COMMON:
       missing=[k for k in COMMON[phase] if k not in r];must(not missing,'missing common field '+phase+':'+str(missing))
       row=dict(kind=phase,run=run_no,**{k:r[k] for k in COMMON[phase]})
       for k in REFS.get(phase,()):row[k]=cube(r[k])
       put(c,row);counts[phase]+=1
      elif phase=='frames_end':
       must(r['complete']=='1','incomplete frame snapshot')
       # The real reader expands both old member records and compact chunks,
       # retaining frame/tuple order and duplicate multiplicity.
       h=hashlib.sha256();members=0
       for z in reader.snapshot_members(db,run,int(r['snapshot'])):
        z=dict(z)

        # Transport format/byte locations and the newer cleanup annotation are
        # not historical native frame tuple fields. Keep every actual tuple
        # field, order and duplicate; new capabilities are checked separately.
        z={k:z[k] for k in ('frame','index','cube_id','max_level','validated','packed','proof_certificate')}
        z['cube_id']=cube(z['cube_id']);h.update(canonical(z));members+=1
       put(c,dict(kind='frames',run=run_no,layout=frame_layout(db,run_id,int(r['snapshot'])),members=members,ordered_members_sha256=h.hexdigest()));counts['frames']+=1;counts['frame_members']+=members
      elif phase=='predecessor_cubes':
       must(r['complete']=='1' and r['scope']=='engine_search_states_not_concrete_reachability','unsafe predecessor label')
       # This event does not carry a query ID. Preserve that limitation rather
       # than borrowing the latest query or calling projected cubes full T.
       put(x,dict(kind=phase,run=run_no,frame=r['frame'],source=cube(r['source_cube_id']),predecessor=cube(r['predecessor_cube_id']),query_association='not_explicit_in_event',scope=r['scope'],proof_certificate=False,concrete_transition=False));counts['predecessor_pairs']+=1
    finally:
     if f is not None:f.__exit__(None,None,None)
  reader.verify_sources(db);reader.verify_stable_sources(signatures);reader.verify_index(database)
 finally:db.close()
 return dict(counts=dict(counts),native_configuration=config,streams={p.name:dict(path=str(p),sha256=digest(p)) for p in (common,extra,named,definitions,decoded)},semantics='complete captured literals; sparse unknowns preserved; no reachability/transition/Horn labels')

def compare_streams(reference,candidate,*,subsequence=False):
 """Exact semantic row equality. Legacy additions are explicit, never intersect fields."""
 a_count=b_count=matched=0;first=None;wanted=None
 with gzip.open(reference,'rb') as a,gzip.open(candidate,'rb') as b:
  if not subsequence:
   from itertools import zip_longest
   for i,(x,y) in enumerate(zip_longest(a,b)):
    a_count+=x is not None;b_count+=y is not None
    if x==y:matched+=1
    elif first is None:first={'row':i,'reference':json.loads(x) if x else None,'candidate':json.loads(y) if y else None}
  else:
   wanted=next(a,None)
   if wanted is not None:a_count=1
   for y in b:
    b_count+=1
    if wanted is not None and wanted==y:
     matched+=1;wanted=next(a,None)
     if wanted is not None:a_count+=1
   if wanted is not None:
    first={'unmatched_reference_row':matched,'reference':json.loads(wanted)}
    a_count+=sum(1 for _ in a)
 return dict(pass_=first is None,reference_records=a_count,candidate_records=b_count,matched=matched,first_difference=first,policy='ordered exact reference subsequence with declared additional observations' if subsequence else 'exact ordered semantic rows')

def compare_views(reference,candidate,*,legacy=False):
 """All payloads count, including cubes not referenced by a selected role."""
 keys=tuple(k for k in VIEW_STREAMS if not legacy or k!='predecessors.jsonl.gz')
 return {k:compare_streams(reference/k,candidate/k,subsequence=legacy and k=='common.jsonl.gz') for k in keys}

def legacy_view(source,destination):
 """Reconstruct a disk framing view from the old canonical console records.

 Old IC3-STATS.log already contains full parity_record hex chunks and their
 hashes, but its native console demultiplexer stored raw named displays in a
 different file. Reinsert *only those verified existing payload bytes* for the
 current disk reader. Never edit or relabel the historical source archive.
 """
 destination.mkdir();manifests=list(source.glob('worker-*.manifest.json'));must(len(manifests)==1,'legacy worker scope is ambiguous')
 m=json.loads(manifests[0].read_text());pid=m['pid'];src=source/'IC3-STATS.log';target=destination/f'events-{pid}-{pid}.log';pending={};payloads=0;extra_bytes=0;canonical_hash=hashlib.sha256()
 with src.open('rb') as original,target.open('xb') as output:
  for raw in original:
   must(raw.startswith(b'IC3_STATS ') and raw.endswith(b'\n'),'unexpected legacy canonical channel')
   canonical_hash.update(raw);output.write(raw);r=reader.fields(raw[:-1]);phase=r['phase'];key=tuple(r.get(k) for k in ('capture','pid','tid','run','parity_sequence'))
   if phase=='parity_record':
    must(key not in pending,'duplicate legacy display header');pending[key]=(r,bytearray())
   elif phase=='parity_record_chunk':
    must(key in pending,'legacy display chunk without header');header,data=pending[key];chunk=bytes.fromhex(r['utf8_hex']);must(int(r['offset'])==len(data) and len(chunk)==int(r['bytes']),'legacy display chunk extent mismatch');data.extend(chunk)
   elif phase=='parity_record_end':
    must(key in pending,'legacy display end without header');header,data=pending.pop(key);must(r['complete']=='1' and len(data)==int(header['bytes'])==int(r['bytes']) and hashlib.sha256(data).hexdigest()==header['sha256'],'legacy display payload hash/extent mismatch');must(data.startswith(header['family'].encode()+b' '),'legacy display family mismatch');output.write(data+b'\n');payloads+=1;extra_bytes+=len(data)+1
 must(not pending and canonical_hash.hexdigest()==digest(src),'unfinished or changed legacy source')
 shutil.copyfile(manifests[0],destination/manifests[0].name)
 return dict(original=str(src),sha256=digest(src),reconstructed_disk_view_sha256=digest(target),temporary_name=str(target),payloads_reinserted=payloads,framing_bytes_added=extra_bytes,transformation='canonical records unchanged; raw display copies reconstructed only from their already-captured complete SHA-verified hex payloads; original process manifest retained; derived transport view, not a fresh native run')

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--legacy',type=Path,required=True);p.add_argument('--captures',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--models',nargs='+',choices=MODELS,default=list(MODELS));a=p.parse_args();a.output.mkdir(exist_ok=False)
 begin=time.monotonic();reports=[];failures=[]
 # Disposable indexes and legacy naming views are node-local, never archived.
 with tempfile.TemporaryDirectory(prefix='jipstats-agent-parity-') as tmp:
  tmp=Path(tmp)
  for model in a.models:
   for engine in ('M','M4'):
    case=a.output/model/engine;case.mkdir(parents=True);old=a.legacy/model/engine
    old_native=json.loads((old/'PARITY.json').read_text());must(old_native['pass'] is True,'historical oracle did not pass')
    h=tmp/f'{model}-{engine}-old';view_receipt=legacy_view(old/'preload',h);db=tmp/f'{model}-{engine}-old.db';integrity=reader.ingest(h,db);must(integrity['complete'],'incomplete historical archive');legacy=export_view(db,case/'legacy');db.unlink();Path(str(db)+'.integrity.json').unlink()
    oracle=[r['raw'].encode() for r in __import__('suite').records(old/'stats.log') if r['family']=='IC3_CTI']
    with gzip.open(case/'legacy/named-ctis.jsonl.gz','rb') as f:observed=[bytes.fromhex(json.loads(z)['raw_hex']) for z in f]
    must(oracle==observed,'historical named CTIs differ from independent Dollar oracle')
    commands_sha=digest(old/'preload/sent-commands.bin')
    entry=dict(model=model,engine=engine,model_sha256=old_native['model_sha256'],legacy=legacy,legacy_integrity=integrity,legacy_naming_view=view_receipt,oracle_named_ctis=len(oracle),releases={})
    for release in RELEASES:
     from cross_release import validate_case, RELEASES as RELEASE_INFO
     must(digest(a.captures/model/engine/release/'capture/transmitted-commands.bin')==commands_sha,'effective native command bytes differ from historical reference')
     worker_sha=RELEASE_INFO[release][1];validate_case(a.captures/model/engine/release,worker_sha,entry['model_sha256'],engine,model=='shared',digest(ROOT/'libjipstats.so'))
     source=a.captures/model/engine/release/'capture';native=json.loads((source/'RESULT.json').read_text());invoke=json.loads((source/'INVOCATION.json').read_text());must(native['status']=='PASS' and native['exit']==0 and native['model_sha256']==entry['model_sha256'] and native['engine']==engine and native['preload'] is True,'native current input/result mismatch');must(native['verdicts']==old_native['preload']['verdicts'],'native result changed from historical oracle')
     index=tmp/f'{model}-{engine}-{release}.db';check=reader.ingest(source,index);must(check['complete'],'incomplete updated archive');new=export_view(index,case/release);index.unlink();Path(str(index)+'.integrity.json').unlink()
     legacy_comparisons=compare_views(case/'legacy',case/release,legacy=True);named_cmp=legacy_comparisons['named-ctis.jsonl.gz'];legacy_cmp=legacy_comparisons['common.jsonl.gz']
     must(legacy['native_configuration']==new['native_configuration'],'effective native configuration fields differ')
     quip=str(int(engine=='M'));must(legacy['native_configuration'] and new['native_configuration'] and all(r['quip_mode']==quip for r in legacy['native_configuration']+new['native_configuration']),'effective native M/M4 settings differ')
     item=dict(archive_integrity=check,agent_view=new,named_cti_comparison=named_cmp,legacy_common_comparison=legacy_cmp,all_legacy_payload_comparisons=legacy_comparisons,native_invocation_sha256=digest(source/'INVOCATION.json'),native_result_sha256=digest(source/'RESULT.json'))
     if release!='prerelease':item['new_complete_agent_comparison']=compare_views(case/'prerelease',case/release)
     entry['releases'][release]=item
     if any(not v['pass_'] for v in legacy_comparisons.values()) or any(not x['pass_'] for x in item.get('new_complete_agent_comparison',{}).values()):failures.append(model+'/'+engine+'/'+release)
    reports.append(entry);(case/'RESULT.json').write_text(json.dumps(entry,indent=2)+'\n');print(model,engine,'namedCTIs',len(oracle),'done',flush=True)
 result=dict(status='FAIL' if failures else 'PASS_FINITE_CTI_AGENT_PARITY',scope='pinned five-model M/M4 historical Dollar/producer1.5 and updated September captures; not all designs or a complete transition-system oracle',cases=reports,failures=failures,reader_sha256=digest(ROOT/'tools/telemetry_db.py'),exporter_sha256=digest(__file__),max_analysis_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,wall_seconds=time.monotonic()-begin,old_explicit_predecessor_pairs='not emitted by producer1.5; no historical pair fabricated',native_proof_certificate=False)
 (a.output/'CTI-AGENT-PARITY.json').write_text(json.dumps(result,indent=2)+'\n');print(result['status'],failures,flush=True);return int(bool(failures))
if __name__=='__main__':raise SystemExit(main())
