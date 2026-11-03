"""Finite real-worker differential-test client. Never replaces main or solver.
Uses the worker's original job protocol; all native files stay byte-identical.
M4 key 166 is checked for the explicitly reviewed builds; no generic release key is inferred.
"""
from pathlib import Path
import hashlib,json,os,signal,socket,subprocess,threading,time,sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'worker_protocol'))
from run import unstuff,uint,decode
FAMILIES=('IC3_CTI','IC3_VALIDATION','IC3_OBLIGATION_LENS','IC3_OBLIGATION_QUEUE','IC3_OBLIGATION_FOCUS')
WORKER_SHA='b5006df1ff1ab23d9effd5eec464b1962a0905da1880aaa8fae574a4a9a81604'
REVIEWED_WORKERS={WORKER_SHA,
 'e8cbfa93df42061662aaa530125f47d9255ff29b160aa3559d65c706bb24ce1d',
 'b3e7723c4335266b1cd1436277111d54ee7802944b8b4f7d6eaacaa28b7c84b4',
 'e1b53cf546e048df0f9996646afba34b0faf7b38095b22ed700a507b64cf4e7b'}
def digest(path):
 h=hashlib.sha256()
 with Path(path).open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
def settings(engine):
 if engine not in ('M','M4'):raise ValueError(engine)
 out=b'\x00\x00'+(b'\x30' if engine=='M' else b'\x96\x01')
 out+=b'\x01\x0d\x02'+bytes([len(engine)])+engine.encode()+b'\x03'+bytes([len(engine)])+engine.encode()
 if engine=='M4':out+=b'\xa6\x01\x00'
 return out+b'\xfe\x01\x14\xff\xff\x03\n'
def run_worker(worker,runtime,package,model,out,engine,preload,shared=False,timeout=60,worker_sha=WORKER_SHA,sink='console'):
 worker,runtime,package,model,out=map(lambda p:Path(p).resolve(),(worker,runtime,package,model,out))
 if worker_sha not in REVIEWED_WORKERS or digest(worker)!=worker_sha:raise ValueError('Unqualified worker')
 if sink not in ('console','disk'):raise ValueError('Unknown sink')
 out.mkdir(parents=True,exist_ok=False)
 listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(10)
 lib=runtime/'Linux64/lib'
 loader=lib/'ld-linux-x86-64.so.2'
 if not loader.is_file():loader=Path('/lib64/ld-linux-x86-64.so.2')
 if not loader.is_file():raise ValueError('No native ELF loader')
 argv=[str(loader),'--library-path',str(lib),str(worker),str(model),str(model.stat().st_size),'127.0.0.1',str(listener.getsockname()[1]),'0000000000','0696994532','10:1:180:10:30']
 env={k:v for k,v in os.environ.items() if not k.startswith(('LD_','JIPSTATS_'))}
 if preload:
  argv[1:1]=['--preload',str(package/'libjipstats.so')]
  env.update(JIPSTATS_IMAGE=str(worker),JIPSTATS_PROFILE=str(package/'profiles'/(worker_sha+'.events')),JIPSTATS_EVIDENCE_DIR=str(out),JIPSTATS_CAPTURE_MODE='full' if sink=='disk' else 'semantic',JIPSTATS_SINK=sink,JIPSTATS_COMPRESSION='gzip' if sink=='disk' else 'none',JIPSTATS_FRAME_ENCODING='tuple_chunks_v2')
 chunks=[b'\x00',settings(engine)]
 expected=4 if shared else 1
 if shared:
  commands=json.loads((package/'source/tests/worker_protocol/job-commands.json').read_text())['commands_after_strategy']
  chunks += [bytes.fromhex(s) for s in commands[:-1]]
  if bytes.fromhex(commands[-1])!=b'\x05\n':raise ValueError('Unexpected recorded stop')
 else:
  # Same native setup/prove roles as the reference-generated job; no early quit.
  chunks+=[bytes.fromhex('3701000101040a0606000600000a3701000101040a0601000101a08d060a')]
 command_info={'argv':argv,'environment_keys':sorted(k for k in env if k.startswith('JIPSTATS_')),'model_sha256':digest(model),'worker_sha256':worker_sha,'library_sha256':digest(package/'libjipstats.so'),'M4_quip_serialization_key':166 if engine=='M4' else None,'engine':engine,'preload':preload,'sink':sink,'original_main':True,'original_solver':True,'source_read_or_compilation_required_by_client':False}
 (out/'INVOCATION.json').write_text(json.dumps(command_info,indent=2)+'\n')
 (out/'sent-commands.bin').write_bytes(b''.join(chunks)+b'\x05\n')
 collected=bytearray();buffer=bytearray();errors=[];done=threading.Event();count=[0];stop=threading.Event();process=None;conn=None;thread=None
 def receive():
  try:
   while not stop.is_set():
    try:data=conn.recv(1024*1024)
    except socket.timeout:continue
    if not data:break
    collected.extend(data);buffer.extend(data)
    while b'\n' in buffer:
     frame,_,remaining=buffer.partition(b'\n');buffer[:]=remaining;frame=unstuff(frame)
     if len(frame)>1 and frame[0]==2 and frame[1] in (6,13):
      count[0]+=1
      if count[0]>=expected:done.set()
  except Exception as e:errors.append(repr(e));done.set()
 try:
  with (out/'stdout.log').open('wb') as stdout,(out/'stderr.log').open('wb') as stderr:
   process=subprocess.Popen(argv,env=env,stdout=stdout,stderr=stderr,start_new_session=True)
   conn,_=listener.accept();conn.settimeout(.1)
   hello=b''
   while not hello.endswith(b'\x00'):hello+=conn.recv(1024)
   if hello!=b'c0000000000_0696994532 \x00':raise ValueError('Wrong worker handshake')
   thread=threading.Thread(target=receive,daemon=True);thread.start()
   for chunk in chunks:conn.sendall(chunk);time.sleep(.05)
   if not done.wait(timeout) or errors or count[0]!=expected:raise RuntimeError('Native job failed to deliver expected verdicts: '+str(errors))
   conn.sendall(b'\x05\n');conn.shutdown(socket.SHUT_WR)
   rc=process.wait(timeout=15);thread.join(timeout=3)
   if rc:raise RuntimeError('Worker nonzero exit: '+str(rc))
 finally:
  if process and process.poll() is None:
   os.killpg(process.pid,signal.SIGTERM)
   try:process.wait(timeout=3)
   except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait()
  stop.set()
  if thread:thread.join(timeout=3)
  if conn:conn.close()
  listener.close();(out/'native-response.bin').write_bytes(collected)
 if errors:raise RuntimeError(str(errors))
 events,verdicts,counts,reports=decode(bytes(collected))
 if any('protocol_error' in x or 'io_error' in x or 'Unexpected prove' in x for x in reports):raise ValueError('Native protocol error')
 parity=[x for x in reports if any(x.startswith(f+' ') for f in FAMILIES)]
 (out/'IC3-STATS.log').write_text('\n'.join(events)+ ('\n' if events else ''))
 (out/'DOLLAR-DIAGNOSTICS.log').write_text('\n'.join(parity)+ ('\n' if parity else ''))
 (out/'native-reports.log').write_text('\n'.join(reports)+'\n')
 if not preload and (events or parity):raise ValueError('Unexpected baseline instrumentation')
 if preload and sink=='console':
  sidecar=[x for p in out.glob('events-*.log') for x in p.read_text().splitlines()]
  if [x for x in sidecar if x.startswith('IC3_STATS ')]!=events:raise ValueError('Event/native transport mismatch')
  if [x for x in sidecar if any(x.startswith(f+' ') for f in FAMILIES)]!=parity:raise ValueError('Parity/native transport mismatch')
 if digest(worker)!=worker_sha:raise ValueError('Original worker changed')
 result={'status':'PASS','engine':engine,'preload':preload,'exit':rc,'verdicts':verdicts,'statistics_records':len(events),'parity_records':len(parity),'native_report_transport_equals_sidecar':True if preload and sink=='console' else None,'worker_unchanged':True,'model_sha256':digest(model),'original_main':True,'original_solver':True,'M4_config_key_corrected':engine=='M4'}
 (out/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n')
 return result
