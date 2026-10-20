#!/usr/bin/env python3
"""Run actual, unmodified Jasper worker main and actual IC3/SAT via its socket.
No function fixtures, lower-solver replacements, main replacements or worker
patches. This validates worker computation and actual native report transport,
not a complete matching Jasper frontend's prove command or all tuning presets.
Producer regression; normal customers run the packaged --check on their runtime.
"""
from pathlib import Path
import argparse,collections,hashlib,json,os,re,signal,socket,subprocess,threading,time
HERE=Path(__file__).resolve().parent
EXPECTED='b5006df1ff1ab23d9effd5eec464b1962a0905da1880aaa8fae574a4a9a81604'
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def unstuff(frame):
 out=bytearray();at=0
 while at<len(frame):
  n=frame[at];at+=1
  if n==92:
   if at==len(frame):raise ValueError('Incomplete native escape')
   n=frame[at]^1;at+=1
  out.append(n)
 return bytes(out)
def uint(data,at):
 n=0;s=0
 for _ in range(10):
  b=data[at];at+=1;n|=(b&127)<<s
  if b<128:return n,at
  s+=7
 raise ValueError('Invalid native integer')
def decode(data):
 if not data.endswith(b'\n'):raise ValueError('Incomplete final native message')
 events=[];verdicts=[];counts=collections.Counter();native_reports=[]
 for stuffed in data.split(b'\n')[:-1]:
  frame=unstuff(stuffed)
  if len(frame)<2 or frame[0]!=2:raise ValueError('Unexpected native message framing')
  kind=frame[1];counts[kind]+=1
  if kind==2:
   n,at=uint(frame,2);text=frame[at:at+n].decode('utf-8',errors='replace')
   if len(frame[at:at+n])!=n:raise ValueError('Truncated native text')
   if text.startswith('IC3_STATS '):events.append(text)
   else:native_reports.append(text)
  if kind in (6,13):
   n,at=uint(frame,2);targets=[]
   for _ in range(n):value,at=uint(frame,at);targets.append(value)
   record={'native_message_code':kind,'status':'valid' if kind==6 else 'cex','target_ids':targets}
   if kind==13:record['trace_length'],at=uint(frame,at)
   verdicts.append(record)
 return events,verdicts,dict(counts),native_reports

def run_case(args,engine,preload):
 label=engine+('-preload' if preload else '-baseline');work=args.output/label;work.mkdir()
 model=HERE/'model.bs';pkg=args.package;lib=args.runtime/'Linux64/lib';worker=args.worker
 sock=socket.socket();sock.bind(('127.0.0.1',0));sock.listen(1);sock.settimeout(10)
 loader=lib/'ld-linux-x86-64.so.2'
 command=[str(loader),'--library-path',str(lib),str(worker),str(model),str(model.stat().st_size),'127.0.0.1',str(sock.getsockname()[1]),'0000000000','0696994532','10:1:180:10:30']
 env={k:v for k,v in os.environ.items() if not k.startswith(('LD_','JIPSTATS_'))}
 if preload:
  command[1:1]=['--preload',str(pkg/'libjipstats.so')]
  env.update(JIPSTATS_CAPTURE_MODE=args.capture_mode,JIPSTATS_IMAGE=str(worker),JIPSTATS_PROFILE=str(pkg/'profiles'/(EXPECTED+'.events')),JIPSTATS_EVIDENCE_DIR=str(work))
 chunks=[b'\x00']
 settings=b'\x00\x00'+(b'\x30' if engine=='M' else b'\x96\x01')
 settings+=b'\x01\x0d\x02'+bytes([len(engine)])+engine.encode()+b'\x03'+bytes([len(engine)])+engine.encode()
 # Actual release serialization maps ic3QuipMode at settings+0x385 to key 166 (0xa6), not 165.
 if engine=='M4':settings+=b'\xa6\x01\x00'
 settings+=b'\xfe\x01\x14\xff\xff\x03\n';chunks.append(settings)
 chunks.extend(bytes.fromhex(x) for x in json.loads((HERE/'job-commands.json').read_text())['commands_after_strategy'])
 (work/'sent-commands.bin').write_bytes(b''.join(chunks))
 (work/'INVOCATION.json').write_text(json.dumps({'argv':command,'selected_engine_label':engine,'engine_report_index':24 if engine=='M' else 75,'ic3_algorithm_mode':13,'complete_frontend_preset_verified':False,'input_sha256':sha(model),'worker_sha256':sha(worker),'preload':preload,'worker_files_modified':False},indent=2)+'\n')
 captured=bytearray();live_buffer=bytearray();stop=threading.Event();proofs_done=threading.Event();verdict_count=[0];conn=None;reader=None;process=None
 def receive():
  while not stop.is_set():
   try:data=conn.recv(65536)
   except socket.timeout:continue
   except OSError:return
   if not data:return
   captured.extend(data);live_buffer.extend(data)
   while b'\n' in live_buffer:
    frame,_,remaining=live_buffer.partition(b'\n');live_buffer[:]=remaining
    raw=unstuff(frame)
    if len(raw)>1 and raw[0]==2 and raw[1] in (6,13):
     verdict_count[0]+=1
     if verdict_count[0]==4:proofs_done.set()
    if raw[:2]==b'\x02\x02':
     length,at=uint(raw,2);text=raw[at:at+length].decode('utf-8',errors='replace')
     if text.startswith('IC3_STATS '):print('[exact-worker live '+engine+'] '+text,flush=True)
 try:
  with (work/'stdout.log').open('wb') as out,(work/'stderr.log').open('wb') as err:
   process=subprocess.Popen(command,env=env,stdout=out,stderr=err,start_new_session=True)
   conn,_=sock.accept();conn.settimeout(.1)
   hello=conn.recv(1024)
   if hello!=b'c0000000000_0696994532 \x00':raise RuntimeError('Unexpected worker hello')
   reader=threading.Thread(target=receive,daemon=True);reader.start()
   for index,chunk in enumerate(chunks):
    if index==len(chunks)-1:
     if not proofs_done.wait(90):raise RuntimeError("Actual worker proofs did not finish within 90 seconds; no premature quit was sent")
    conn.sendall(chunk);time.sleep(.15)
   conn.shutdown(socket.SHUT_WR)
   rc=process.wait(timeout=30)
   reader.join(timeout=2)
   if rc!=0:raise RuntimeError('Native worker exited '+str(rc))
 finally:
  if process and process.poll() is None:
   os.killpg(process.pid,signal.SIGTERM)
   try:process.wait(timeout=3)
   except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait()
  stop.set()
  if reader:reader.join(timeout=2)
  if conn:conn.close()
  sock.close()
  (work/'native-response.bin').write_bytes(captured)
 events,verdicts,counts,reports=decode(bytes(captured))
 if any('protocol_error' in t or 'Unexpected prove' in t or 'io_error' in t for t in reports):raise RuntimeError('Native protocol rejected command')
 expected=[{'native_message_code':13,'status':'cex','target_ids':[1],'trace_length':4},
           {'native_message_code':6,'status':'valid','target_ids':[3]},
           {'native_message_code':6,'status':'valid','target_ids':[4]},
           {'native_message_code':13,'status':'cex','target_ids':[5],'trace_length':51}]
 if verdicts!=expected:raise RuntimeError('Unexpected native proof/CEX messages: '+str(verdicts))
 if not preload and events:raise RuntimeError('Baseline unexpectedly emitted telemetry')
 pending={};phasecounts=collections.Counter();finals=[];sat=collections.Counter()
 for line in events:
  if 'origin=preload backend=events' not in line:raise RuntimeError('Wrong record origin')
  row=dict(re.findall(r'(\w+)=([^ ]+)',line));phase=row['phase'];phasecounts[phase]+=1
  if phase in ('relative_begin','sat_begin','relative_end','sat_end'):
   kind,suffix=phase.split('_');key=(row['pid'],row['tid'],row['run'],kind,row.get('call',row.get('query')))
   if suffix=='begin':
    if key in pending:raise RuntimeError('Duplicate query begin')
    pending[key]=row
   elif key not in pending:raise RuntimeError('End without begin')
   else:del pending[key]
  if phase=='sat_end':sat[row['result']]+=1
  if phase=='final':
   finals.append(row)
   if any(row.get(k)!='0' for k in ('lost','read_failures','callback_failures')):raise RuntimeError('Telemetry error')
 if preload:
  if pending or [x['result'] for x in finals]!=['cex','valid','valid','cex']:raise RuntimeError('Missing/incorrect final events')
  if not sat['sat'] or not sat['unsat']:raise RuntimeError('SAT and UNSAT not both exercised')
  # Independently ensure the actual socket report transport carried every emitted event.
  generated=[line for f in work.glob('events-*.log') for line in f.read_text().splitlines() if line.startswith('IC3_STATS ')]
  if generated!=events:raise RuntimeError('Native transport and sidecar differ')
 if sha(worker)!=EXPECTED:raise RuntimeError('Uploaded worker changed')
 (work/'IC3-STATS.log').write_text('\n'.join(events)+('\n' if events else ''))
 (work/'native-messages.txt').write_text('\n'.join(reports)+'\n')
 result={'case':label,'exit_status':rc,'real_worker_main':True,'real_ic3_and_solver':True,'fixtures_used':False,'native_socket_transport':True,
         'records':len(events),'phases':dict(phasecounts),'solver_results':dict(sat),'native_verdicts':verdicts,
         'summaries':finals,'worker_sha256_unchanged':True,'response_sha256':hashlib.sha256(captured).hexdigest(),
         'scope':'EXACT_WORKER_REAL_COMPUTATION_AND_SOCKET_TRANSPORT_NOT_MATCHING_FRONTEND_PROVE',
         'complete_frontend_engine_preset_verified':False,'status':'PASS'}
 (work/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n')
 print(label+': native exit=0, 2 valid + 2 CEX, '+str(len(events))+' records on real transport',flush=True)
 return result

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--capture-mode', choices=('semantic','full'),default='semantic')
 for name in ('worker','runtime','package','output'):p.add_argument('--'+name,type=Path,required=True)
 a=p.parse_args()
 for name in ('worker','runtime','package','output'):setattr(a,name,getattr(a,name).resolve())
 if sha(a.worker)!=EXPECTED:raise RuntimeError('This protocol test is exact-worker only')
 if b'IC3_STATS' in a.worker.read_bytes():raise RuntimeError('Worker is not marker-free')
 a.output.mkdir(parents=True,exist_ok=False)
 results=[run_case(a,e,m) for e in ('M','M4') for m in (False,True)]
 report={'status':'PASS','cases':results,'worker_sha256':EXPECTED,
         'native_frontend_prove':'NOT_RUN_ON_MATCHING_RELEASE','no_main_or_solver_replacement':True,
         'legacy_telemetry_required':False,'test_inputs':{p.name:sha(p) for p in (HERE/'model.bs',HERE/'model.sv',HERE/'job-commands.json')}}
 (a.output/'EXACT-WORKER-RESULTS.json').write_text(json.dumps(report,indent=2)+'\n')
if __name__=='__main__':main()
