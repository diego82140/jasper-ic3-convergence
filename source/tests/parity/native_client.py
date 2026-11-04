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
COMMAND_RECORDING_SHA='5324ada3e632c23ebae1c4cf544eaaa39f6c0bee818405e9365a40ee7b378e98'
COMMAND_STREAM_SHA='736ea38d50b6996710b7f9392f553595469365245cc1b44c3a1ac71c0d2f4559'
SHARED_MODEL_SHA='f60987ad21c43d03b0f802d20e59344787a07f2c92eb2d8b8bf13f4a8c337107'
def expected_results(model_sha,shared):
 """The pinned regression's mathematical model contract, not arbitrary RTL."""
 if shared:
  if model_sha!=SHARED_MODEL_SHA:raise ValueError('Unqualified shared model')
  return [dict(native_message_code=13,status='cex',target_ids=[1],trace_length=4),
          dict(native_message_code=6,status='valid',target_ids=[3]),
          dict(native_message_code=6,status='valid',target_ids=[4]),
          dict(native_message_code=13,status='cex',target_ids=[5],trace_length=51)]
 valid={'366058887187e7957fd1a76fca2adef293db47431166967a7afb76ab79b8e119',
        '91bad8bab37f8f27275b167a15eef49133c0e19cb062ced7d4c662e5690ed531',
        '0c2a4a0292eb3634d563c4ea1873307b4e65a8222d0e43a13cff802f58fbc0bb'}
 if model_sha in valid:return [dict(native_message_code=6,status='valid',target_ids=[0])]
 if model_sha=='d3ccbd5dc72c9660ea35889c4aac61c82a74b112cceee7a8fd083a8982b91a4b':
  return [dict(native_message_code=13,status='cex',target_ids=[0],trace_length=4)]
 raise ValueError('No reviewed expected-result contract for model hash')
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
def send_commands(conn,chunks,shared,await_verdict):
 """Do not send the next recorded cleanup/setup before its proof result.

 The four prove batches are explicit positions in the pinned shared recording,
 not a guessed generic Jasper opcode parser. Command bytes remain unchanged.
 """
 if shared and (len(chunks)!=10 or hashlib.sha256(b''.join(chunks[2:])+b'\x05\n').hexdigest()!=COMMAND_STREAM_SHA):
  raise ValueError('Unexpected shared command recording')
 prove_batches={2:1,4:2,6:3,8:4} if shared else {}
 for index,chunk in enumerate(chunks):
  conn.sendall(chunk)
  if index in prove_batches:await_verdict(prove_batches[index])
def run_worker(worker,runtime,package,model,out,engine,preload,shared=False,timeout=60,worker_sha=WORKER_SHA,sink='console'):
 worker,runtime,package,model,out=map(lambda p:Path(p).resolve(),(worker,runtime,package,model,out))
 if worker_sha not in REVIEWED_WORKERS or digest(worker)!=worker_sha:raise ValueError('Unqualified worker')
 expected_sequence=expected_results(digest(model),shared)
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
 expected=len(expected_sequence)
 if shared:
  recording=(package/'source/tests/worker_protocol/job-commands.json').read_bytes()
  if hashlib.sha256(recording).hexdigest()!=COMMAND_RECORDING_SHA:raise ValueError('Changed native command recording')
  commands=json.loads(recording)['commands_after_strategy']
  chunks += [bytes.fromhex(s) for s in commands[:-1]]
  if bytes.fromhex(commands[-1])!=b'\x05\n':raise ValueError('Unexpected recorded stop')
 else:
  # Same native setup/prove roles as the reference-generated job; no early quit.
  chunks+=[bytes.fromhex('3701000101040a0606000600000a3701000101040a0601000101a08d060a')]
 command_info={'argv':argv,'environment_keys':sorted(k for k in env if k.startswith('JIPSTATS_')),'model_sha256':digest(model),'worker_sha256':worker_sha,'library_sha256':digest(package/'libjipstats.so'),'M4_quip_serialization_key':166 if engine=='M4' else None,'engine':engine,'preload':preload,'sink':sink,'original_main':True,'original_solver':True,'source_read_or_compilation_required_by_client':False}
 (out/'INVOCATION.json').write_text(json.dumps(command_info,indent=2)+'\n')
 (out/'planned-commands.bin').write_bytes(b''.join(chunks)+b'\x05\n')
 transmitted=bytearray();collected=bytearray();buffer=bytearray();errors=[];progress=threading.Event();received_eof=threading.Event();count=[0];stop=threading.Event();process=None;conn=None;thread=None
 def consume(data):
  collected.extend(data);buffer.extend(data)
  while b'\n' in buffer:
   stuffed,_,remaining=buffer.partition(b'\n');buffer[:]=remaining
   # Decode the complete received frame, not just its result-code prefix.
   _,verdicts,_,_=decode(bytes(stuffed)+b'\n')
   for verdict in verdicts:
    if count[0]>=expected or verdict!=expected_sequence[count[0]]:raise ValueError('Unexpected, duplicate or wrong-target native verdict')
    count[0]+=1;progress.set()
 def receive():
  try:
   consume(initial_tail)
   while not stop.is_set():
    try:data=conn.recv(1024*1024)
    except socket.timeout:continue
    if not data:received_eof.set();break
    consume(data)
  except Exception as e:errors.append(repr(e));progress.set()
 try:
  with (out/'stdout.log').open('wb') as stdout,(out/'stderr.log').open('wb') as stderr:
   process=subprocess.Popen(argv,env=env,stdout=stdout,stderr=stderr,start_new_session=True)
   conn,_=listener.accept();conn.settimeout(.1)
   hello=b''
   while b'\x00' not in hello:
    part=conn.recv(1024)
    if not part:raise ValueError('EOF in worker handshake')
    hello+=part
    if len(hello)>1024*1024:raise ValueError('Oversized worker handshake')
   greeting,_,initial_tail=hello.partition(b'\x00')
   if greeting!=b'c0000000000_0696994532 ':raise ValueError('Wrong worker handshake')
   thread=threading.Thread(target=receive,daemon=True);thread.start()
   def await_verdict(wanted):
    deadline=time.monotonic()+timeout
    while count[0]<wanted and not errors:
     if process.poll() is not None or received_eof.is_set() or time.monotonic()>=deadline:break
     progress.wait(.25);progress.clear()
    if count[0]!=wanted or errors:
     failure=dict(expected_verdicts=wanted,observed_verdicts=count[0],worker_exit_observed=process.poll(),
                  transport_errors=errors,caller_wait_seconds=timeout,worker_may_still_be_active=process.poll() is None)
     (out/'FAILURE.json').write_text(json.dumps(failure,indent=2)+'\n')
     raise RuntimeError('Native job did not deliver expected verdicts: '+json.dumps(failure))
   class RecordedConnection:
    def sendall(self,data):
     conn.sendall(data);transmitted.extend(data)
   send_commands(RecordedConnection(),chunks,shared,await_verdict)
   await_verdict(expected)
   conn.sendall(b'\x05\n');transmitted.extend(b'\x05\n');conn.shutdown(socket.SHUT_WR)
   rc=process.wait(timeout=15);thread.join(timeout=3)
   if rc:raise RuntimeError('Worker nonzero exit: '+str(rc))
   if thread.is_alive() or not received_eof.is_set() or buffer or errors:raise RuntimeError('Native receive did not finish cleanly: '+str(errors))
 finally:
  if process and process.poll() is None:
   os.killpg(process.pid,signal.SIGTERM)
   try:process.wait(timeout=3)
   except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait()
  stop.set()
  if thread:thread.join(timeout=3)
  if conn:conn.close()
  listener.close();(out/'native-response.bin').write_bytes(collected);(out/'transmitted-commands.bin').write_bytes(transmitted)
 if errors:raise RuntimeError(str(errors))
 events,verdicts,counts,reports=decode(bytes(collected))
 if verdicts!=expected_sequence or count[0]!=expected:raise ValueError('Final native verdict sequence differs from the model contract')
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
 result={'status':'PASS','engine':engine,'preload':preload,'exit':rc,'verdicts':verdicts,'receive_eof':True,'receiver_joined':True,'protocol_buffer_empty':True,'expected_sequence_verified':True,'statistics_records':len(events),'parity_records':len(parity),'native_report_transport_equals_sidecar':True if preload and sink=='console' else None,'worker_unchanged':True,'model_sha256':digest(model),'original_main':True,'original_solver':True,'M4_config_key_corrected':engine=='M4'}
 (out/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n')
 return result
