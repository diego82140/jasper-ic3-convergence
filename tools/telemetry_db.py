#!/usr/bin/env python3
"""Offline, streaming telemetry archive index. Raw files remain authoritative.
Uses DELETE journaling (no WAL on shared NFS); never loads a capture into RAM.
Transport integrity and payload checks are not semantic proof certificates.
"""
import argparse,signal, gzip, hashlib, json, re, sqlite3, struct, sys,zlib,contextlib,os,io
from functools import lru_cache,wraps
from pathlib import Path

SCHEMA='''
CREATE TABLE events(run INTEGER,event INTEGER,phase TEXT,frame INTEGER,cube INTEGER,query INTEGER,snapshot INTEGER,source INTEGER,offset INTEGER,length INTEGER,PRIMARY KEY(run,event)) WITHOUT ROWID;
CREATE INDEX phases ON events(phase,run,event);
CREATE INDEX cube_events ON events(run,cube,event) WHERE cube IS NOT NULL;
CREATE INDEX frame_events ON events(run,snapshot,frame,event) WHERE snapshot IS NOT NULL;
CREATE TABLE cube_refs(run INTEGER,cube INTEGER,event INTEGER,role TEXT,PRIMARY KEY(run,cube,event,role)) WITHOUT ROWID;
CREATE TABLE runs(run TEXT PRIMARY KEY,event INTEGER,tip TEXT,sealed INTEGER DEFAULT 0,complete INTEGER DEFAULT 0,final INTEGER DEFAULT 0);
CREATE TABLE payloads(run TEXT,kind TEXT,id INTEGER,expected INTEGER,seen INTEGER DEFAULT 0,hash TEXT,domain TEXT,complete INTEGER DEFAULT 0,PRIMARY KEY(run,kind,id)) WITHOUT ROWID;
CREATE TABLE chunks(run TEXT,kind TEXT,id INTEGER,offset INTEGER,data BLOB,PRIMARY KEY(run,kind,id,offset)) WITHOUT ROWID;
CREATE TABLE files(id INTEGER PRIMARY KEY,path TEXT UNIQUE,bytes INTEGER,sha256 TEXT);
CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT);
CREATE TABLE models(run TEXT,epoch INTEGER,record BLOB,PRIMARY KEY(run,epoch)) WITHOUT ROWID;
CREATE TABLE frame_chunks(run INTEGER,id INTEGER,epoch INTEGER,members INTEGER,data BLOB,hash TEXT,event INTEGER,PRIMARY KEY(run,id)) WITHOUT ROWID;
CREATE TABLE frame_snapshots(run INTEGER,snapshot INTEGER,epoch INTEGER,frontiers INTEGER,seen_frames INTEGER DEFAULT 0,members INTEGER DEFAULT 0,closed INTEGER DEFAULT 0,PRIMARY KEY(run,snapshot)) WITHOUT ROWID;
CREATE TABLE frame_manifests(run INTEGER,snapshot INTEGER,frame INTEGER,epoch INTEGER,members INTEGER,seen INTEGER DEFAULT 0,refs INTEGER DEFAULT 0,hash TEXT,closed INTEGER DEFAULT 0,event INTEGER,PRIMARY KEY(run,snapshot,frame)) WITHOUT ROWID;
CREATE TABLE frame_refs(run INTEGER,snapshot INTEGER,frame INTEGER,offset INTEGER,chunk INTEGER,event INTEGER,PRIMARY KEY(run,snapshot,frame,offset)) WITHOUT ROWID;
CREATE INDEX frame_ref_events ON frame_refs(run,event);
CREATE INDEX frame_ref_chunks ON frame_refs(run,chunk,event);
CREATE UNIQUE INDEX frame_chunk_events ON frame_chunks(run,event);
CREATE TABLE cube_epochs(run TEXT,cube INTEGER,epoch INTEGER,qualified INTEGER,PRIMARY KEY(run,cube)) WITHOUT ROWID;
'''
def require(ok,msg):
    if not ok: raise ValueError(msg)
def fields(line):
    pairs=re.findall(rb'(\w+)=([^ ]*)',line)
    result={k.decode():v.decode() for k,v in pairs}
    require(len(pairs)==len(result),'duplicate telemetry field')
    return result

def archive_error(path,error):
    return ValueError(f'incomplete or invalid archive stream: {path}: {error}; preserve it, do not query the failed index or use partial output')

CHAINPACK_MAGIC=b'JIPSTATS_CHAINPACK 1\n'
CHAINPACK_MAX_LINE=1024*1024
CHAINPACK_MAX_LIVE=1024

class ChainpackError(ValueError):pass

def chainpack_errors(method):
    @wraps(method)
    def checked(*args,**kwargs):
        try:return method(*args,**kwargs)
        except ValueError as error:raise ChainpackError(str(error)) from error
    return checked

def chainpack_line(stream,limit=CHAINPACK_MAX_LINE):
    line=stream.readline(limit+1)
    require(len(line)<=limit,'chainpack record exceeds supported size; original must be retained')
    require(not line or line.endswith(b'\n'),'partial chainpack record')
    return line

def chainpack_chain(body,tips):
    r=fields(body)
    require(body.startswith(b'IC3_STATS ') and all(k in r for k in ('capture','pid','tid','run','event','phase')),'invalid chainpack event')
    require('chain' not in r,'chainpack event already contains derived chain')
    key=tuple(r[k] for k in ('capture','pid','tid','run'))
    tip,event=tips.get(key,(bytes(32),0))
    require(int(r['event'])==event+1,'chainpack event gap or duplicate')
    require(event or r['phase']=='run_contract','chainpack run must begin with its contract')
    result=hashlib.sha256(tip+body).digest()
    tips[key]=(result,event+1)
    require(len(tips)<=CHAINPACK_MAX_LIVE,'too many active chainpack runs; original must be retained')
    if r['phase'] in ('run_seal','run_abort_seal'):del tips[key]
    return result.hex().encode()

def chainpack_encode(source,destination):
    """Store derived chain hashes implicitly; retain every logical source byte.
    The caller must additionally validate native seals/manifests and source
    stability. This codec is storage, not a replacement for strict ingestion.
    """
    tips={};digest=hashlib.sha256();size=records=0
    destination.write(CHAINPACK_MAGIC)
    while True:
        line=chainpack_line(source)
        if not line:break
        digest.update(line);size+=len(line)
        if line.startswith(b'IC3_STATS '):
            body,declared=line[:-1].rsplit(b' chain=',1)
            require(chainpack_chain(body,tips)==declared,'input event hash-chain mismatch')
            destination.write(b'C'+body+b'\n');records+=1
        else:destination.write(b'R'+line)
    require(not tips,'chainpack requires every run to be sealed')
    result=dict(sha256=digest.hexdigest(),decoded_bytes=size,records=records)
    destination.write(b'F '+json.dumps(result,sort_keys=True,separators=(',',':')).encode()+b'\n')
    return result

class ChainpackStream(io.RawIOBase):
    """Seek in original decoded byte offsets by replaying bounded chain state.
    Backward seeks replay the stream; no decoded history is held in memory.
    Full reads validate the footer and gzip CRC, including non-event records.
    """
    def __init__(self,path):
        super().__init__();self.path=Path(path);self.stream=None;self.raw=None
        self.raw=self.path.open('rb')
        try:self._reset()
        except BaseException:self.close();raise
    @chainpack_errors
    def _reset(self):
        if self.stream:self.stream.close()
        self.raw.seek(0);self.stream=gzip.GzipFile(fileobj=self.raw,mode='rb')
        require(chainpack_line(self.stream)==CHAINPACK_MAGIC,'unsupported chainpack header')
        self.tips={};self.digest=hashlib.sha256();self.total=self.records=self.position=0
        self.pending=b'';self.done=False
    def readable(self):return True
    def seekable(self):return True
    def tell(self):return self.position
    @chainpack_errors
    def _line(self):
        line=chainpack_line(self.stream,CHAINPACK_MAX_LINE+1)
        require(line,'chainpack footer missing')
        tag=line[:1]
        if tag==b'F':
            require(line.startswith(b'F '),'invalid chainpack footer')
            expected=json.loads(line[2:])
            require(isinstance(expected,dict) and set(expected)=={'sha256','decoded_bytes','records'} and type(expected['decoded_bytes']) is int and type(expected['records']) is int and isinstance(expected['sha256'],str),'invalid chainpack footer fields')
            require(expected==dict(sha256=self.digest.hexdigest(),decoded_bytes=self.total,records=self.records),'chainpack decoded hash/length/count mismatch')
            require(not self.tips,'unsealed chainpack run')
            require(not self.stream.read(1),'data after chainpack footer')
            self.done=True;return b''
        require(tag in (b'C',b'R'),'invalid chainpack record tag')
        if tag==b'C':
            body=line[1:-1];chain=chainpack_chain(body,self.tips)
            result=body+b' chain='+chain+b'\n';self.records+=1
        else:
            result=line[1:]
            require(not result.startswith(b'IC3_STATS '),'event hidden in raw chainpack record')
        require(len(result)<=CHAINPACK_MAX_LINE,'decoded chainpack record exceeds supported size')
        self.digest.update(result);self.total+=len(result)
        return result
    def readinto(self,buffer):
        self._checkClosed();view=memoryview(buffer).cast('B');written=0
        while written<len(view):
            if not self.pending:
                if self.done:break
                self.pending=self._line()
                if not self.pending:break
            count=min(len(view)-written,len(self.pending))
            view[written:written+count]=self.pending[:count]
            self.pending=self.pending[count:];written+=count;self.position+=count
        return written
    def seek(self,offset,whence=io.SEEK_SET):
        self._checkClosed()
        if whence==io.SEEK_CUR:offset+=self.position
        elif whence==io.SEEK_END:
            scratch=bytearray(65536)
            while self.readinto(scratch):pass
            offset+=self.position
        elif whence!=io.SEEK_SET:raise ValueError('unsupported seek mode')
        if offset<0:raise ValueError('negative seek position')
        if offset<self.position:self._reset()
        scratch=bytearray(min(65536,offset-self.position))
        while self.position<offset:
            if not self.readinto(memoryview(scratch)[:min(len(scratch),offset-self.position)]):break
        return self.position
    def close(self):
        try:
            if self.stream:self.stream.close()
            if self.raw:self.raw.close()
        finally:super().close()

@contextlib.contextmanager
def archive_open(path):
    path=Path(path)
    try:
        with (io.BufferedReader(ChainpackStream(path)) if path.name.endswith('.chainpack.gz') else gzip.open(path,'rb') if path.suffix=='.gz' else path.open('rb')) as stream:
            yield stream
    except (EOFError,ChainpackError,gzip.BadGzipFile,zlib.error) as e:
        raise archive_error(path,e) from e

def archive_lines(path):
    with archive_open(path) as stream:yield from stream

def canonical_logs(directory):
    """Unknown encodings and interrupted migrations are errors, not exclusions."""
    logs=sorted(directory.glob('events-*.log*'));seen=set()
    for path in logs:
        match=re.fullmatch(r'events-(\d+)-(\d+)\.log(?:\.gz|\.chainpack\.gz)?',path.name)
        require(match,'unsupported worker archive filename: '+str(path)+'; preserve and reconcile interrupted packing before ingestion')
        key=match.groups()
        require(key not in seen,'multiple encodings of worker archive: '+str(path)+'; verify exact decoded bytes and reconcile interrupted packing before ingestion')
        seen.add(key)
    return logs

def source_signature(st):
    # Ordinary writers can restore mtime, but cannot set ctime back with utime.
    # Content checks remain necessary when shared metadata is coarse/cached.
    return st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns

def verify_sources(db):
    """Attest current canonical bytes before publishing any indexed selection.
    The stored digest is of decoded bytes, so verified gzip compaction remains
    compatible. One MiB buffers bound memory; batch commands pay this once.
    """
    signatures={}
    for path,expected_size,expected_sha in db.execute('SELECT path,bytes,sha256 FROM files'):
        require(expected_size is not None and expected_sha is not None,
                'archive source fingerprint unavailable: '+path+'; re-ingest into a fresh index')
        p=Path(path);before=p.stat();digest=hashlib.sha256();size=0
        with archive_open(p) as stream:
            for block in iter(lambda:stream.read(1024*1024),b''):
                digest.update(block);size+=len(block)
        after=p.stat()
        require(source_signature(before)==source_signature(after),
                'archive source changed during verification: '+path+'; preserve evidence and retry from a stable archive')
        require(size==expected_size and digest.hexdigest()==expected_sha,
                'archive source changed since ingestion: '+path+'; discard partial output and rebuild the index from intact evidence')
        signatures[path]=source_signature(after)
    return signatures

def verify_stable_sources(signatures):
    for path,expected in signatures.items():
        st=Path(path).stat()
        require(source_signature(st)==expected,
                'archive source changed during query: '+path+'; discard partial output and retry from stable evidence')

def index_receipt_path(path):return Path(str(path)+'.integrity.json')

def index_digest(path):
    digest=hashlib.sha256();size=0
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''):digest.update(block);size+=len(block)
    return size,digest.hexdigest()

def write_index_receipt(path):
    size,digest=index_digest(path)
    receipt=index_receipt_path(path);tmp=Path(str(receipt)+'.tmp')
    require(not receipt.exists() and not tmp.exists(),'index integrity receipt already exists; use a fresh destination')
    with tmp.open('x') as out:
        json.dump(dict(format='jipstats-offset-index-sha256-v1',bytes=size,sha256=digest),out)
        out.write('\n');out.flush();os.fsync(out.fileno())
    tmp.replace(receipt)

def verify_index(path):
    receipt=index_receipt_path(path)
    require(receipt.is_file(),'index integrity receipt unavailable: '+str(receipt)+'; re-ingest canonical sources into a fresh index')
    try:expected=json.loads(receipt.read_text())
    except (ValueError,OSError) as error:raise ValueError(f'invalid index integrity receipt: {receipt}: {error}') from error
    require(isinstance(expected,dict) and expected.get('format')=='jipstats-offset-index-sha256-v1',
            'invalid index integrity receipt: '+str(receipt))
    require(index_digest(path)==(expected.get('bytes'),expected.get('sha256')),
            'index changed since ingestion: '+str(path)+'; discard output and re-ingest unchanged canonical sources')

def read_manifest(path):
    require(not path.is_symlink(),'symlink manifest rejected: '+str(path))
    try:manifest=json.loads(path.read_text())
    except (ValueError,UnicodeError,OSError) as error:
        raise ValueError(f'invalid worker manifest: {path}: {error}; preserve it and do not query the failed index') from error
    require(isinstance(manifest,dict),f'invalid worker manifest: {path}: expected a JSON object')
    require(manifest.get('schema')==2 and manifest.get('scope')=='one_worker_process',f'invalid worker manifest scope: {path}')
    require(isinstance(manifest.get('runs'),list),f'invalid worker manifest runs: {path}')
    for run in manifest['runs']:
        require(isinstance(run,dict) and all(k in run for k in ('key','events','sealed','tip')),
                f'invalid worker manifest run entry: {path}')
        require(isinstance(run['key'],str) and type(run['events']) is int and run['events']>=0 and
                type(run['sealed']) is bool and isinstance(run['tip'],str),f'invalid worker manifest run fields: {path}')
    return manifest

def decode_literal(raw,model,name):
    variable=raw>>int(model['formula_index_shift'])
    result={'raw':f'{raw:08x}','variable':variable}
    if raw&int(model['formula_composite_mask']):
        return dict(result,status='unresolved_composite',value=None)
    if not name:return dict(result,status='unresolved_name',value=None)
    value=0 if raw&int(model['formula_sign_mask']) else 1
    inverted=name.startswith('~')
    if inverted:name,value=name[1:],value^1
    match=re.fullmatch(r'(.*)\[(\d+)\]',name)
    return dict(result,status='mapped_literal',name=name,value=value,retained_name_inverted=inverted,
                vector=match[1] if match else name,bit=int(match[2]) if match else 0,
                scope='one_constrained_bit; absent_bits_unknown; not_a_concrete_RTL_witness')

def cube_decoder(db,run):
    """Decode each cube in its originating model epoch; caches remain bounded."""
    modern=bool(db.execute("SELECT 1 FROM sqlite_master WHERE name='cube_epochs' AND type='table'").fetchone())
    @lru_cache(maxsize=16)
    def model(epoch):
        row=db.execute('SELECT record FROM models WHERE run=? AND epoch=?',(run,epoch)).fetchone() if modern else None
        if row:return fields(row[0])
        require(epoch==0,'model mapping unavailable for epoch '+str(epoch)+'; export raw cube')
        row=db.execute('SELECT f.path,e.offset,e.length FROM events e JOIN files f ON f.id=e.source JOIN runs r ON r.rowid=e.run WHERE r.run=? AND e.phase=? ORDER BY e.event LIMIT 1',(run,'model')).fetchone()
        require(row,'model mapping unavailable for this worker/run; raw cube remains authoritative')
        path,offset,length=row
        with archive_open(path) as f:
            f.seek(offset);return fields(f.read(length).rstrip(b'\n'))
    @lru_cache(maxsize=4096)
    def name(epoch,variable):
        kind='name@'+str(epoch) if epoch else 'name'
        row=db.execute('SELECT complete FROM payloads WHERE run=? AND kind=? AND id=?',(run,kind,variable)).fetchone()
        if not row or not row[0]:return None
        return b''.join(x[0] for x in db.execute('SELECT data FROM chunks WHERE run=? AND kind=? AND id=? ORDER BY offset',(run,kind,variable))).decode('utf-8',errors='strict')
    def decode(ident):
        row=db.execute('SELECT complete,expected,domain FROM payloads WHERE run=? AND kind=? AND id=?',(run,'cube',ident)).fetchone()
        require(row and row[0],'cube unavailable/incomplete: '+str(ident))
        require(row[2]=='jip_formula','cube uses '+str(row[2])+' encoding, not reviewed jip_formula atoms; export raw payload without invented name/value decoding')
        origin=db.execute('SELECT epoch,qualified FROM cube_epochs WHERE run=? AND cube=?',(run,ident)).fetchone() if modern else None
        epoch,qualified=origin or (0,1)
        require(qualified,'cube was observed before model qualification; export raw payload without names')
        if epoch==0:
            # Old producers did not qualify restart mappings. Preserve raw data,
            # but refuse to silently reuse the first model after reinitialization.
            initializations=db.execute("SELECT count(*) FROM events e JOIN runs r ON r.rowid=e.run WHERE r.run=? AND e.phase='init' AND e.event<=(SELECT event FROM events WHERE run=e.run AND phase='cube_definition' AND cube=?)",(run,ident)).fetchone()[0]
            require(initializations<=1,'legacy cube mapping after restart is unqualified; export raw payload')
        selected=model(epoch)
        print(json.dumps({'run':run,'cube':ident,'model_epoch':epoch,'literals':row[1],'proof_certificate':False,'absent_bits':'unknown','composite_formulas':'unresolved'}))
        for (data,) in db.execute('SELECT data FROM chunks WHERE run=? AND kind=? AND id=? ORDER BY offset',(run,'cube',ident)):
            for (raw,) in struct.iter_unpack('<I',data):
                variable=raw>>int(selected['formula_index_shift'])
                print(json.dumps(decode_literal(raw,selected,None if raw&int(selected['formula_composite_mask']) else name(epoch,variable))))
    return decode

def decode_cube(db,run,ident):
    cube_decoder(db,run)(ident)

def decode_cubes(db,run,ids):
    decode=cube_decoder(db,run)
    for line in ids:
        text=line.strip()
        if text:
            require(text.isdecimal(),'cube ID selection must contain one nonnegative decimal ID per line')
            decode(int(text))

FRAME_CHUNK_DOMAIN=b'jipstats-frame-chunk-v1\0'
FRAME_DOMAIN=b'jipstats-frame-tuples-v1\0'
FRAME_CODEC='tuple_chunks_v2'
FRAME_CODECS=('tuple_chunks_v1',FRAME_CODEC)

def frame_hash(epoch,frame,count):
    return hashlib.sha256(FRAME_DOMAIN+struct.pack('<QiQ',epoch,frame,count))

def frame_tables(db):
    db.execute('CREATE TEMP TABLE frame_contracts(run INTEGER PRIMARY KEY,schema INTEGER,codec TEXT,epoch INTEGER)')
    db.execute('CREATE TEMP TABLE legacy_snapshots(run INTEGER PRIMARY KEY,snapshot INTEGER,frontiers INTEGER,frames INTEGER DEFAULT 0,members INTEGER DEFAULT 0)')
    db.execute('CREATE TEMP TABLE legacy_frame(run INTEGER PRIMARY KEY,frame INTEGER,count INTEGER,seen INTEGER DEFAULT 0)')

def frame_record(db,key,run,r):
    """Validate compact frames online, with history on disk and <=768B chunks.
    A chunk is immutable and fully defined before use; no alias chains exist.
    """
    phase=r['phase'];schema=int(r['schema']);epoch=int(r.get('model_epoch','0'))
    require(epoch>=0,'negative model epoch')
    if phase=='run_contract':
        codec=r.get('frame_encoding','members_v1')
        require((schema==2 and codec=='members_v1') or (schema==3 and codec in FRAME_CODECS),'unsupported frame encoding/schema')
        db.execute('INSERT INTO frame_contracts VALUES(?,?,?,?)',(run,schema,codec,epoch))
    contract=db.execute('SELECT schema,codec,epoch FROM frame_contracts WHERE run=?',(run,)).fetchone()
    require(contract and contract[0]==schema,'mixed/missing telemetry schema contract')
    if schema==2:
        if phase=='frames_begin':
            count=int(r['frontier_count']);require(0<=count<=10000000,'invalid legacy frame count')
            db.execute('INSERT INTO legacy_snapshots(run,snapshot,frontiers) VALUES(?,?,?)',(run,int(r['snapshot']),count))
        elif phase in ('frame','frame_member','frames_end'):
            snap=db.execute('SELECT snapshot,frontiers,frames,members FROM legacy_snapshots WHERE run=?',(run,)).fetchone()
            require(snap and snap[0]==int(r['snapshot']),'undefined legacy frame snapshot')
            prior=db.execute('SELECT frame,count,seen FROM legacy_frame WHERE run=?',(run,)).fetchone()
            if phase=='frame':
                frame=int(r['frame']);count=int(r['cubes'])
                require(0<=count<=10000000 and snap[2]<=snap[1] and frame==(snap[2] if snap[2]<snap[1] else -1) and (prior is None or prior[1]==prior[2]),'legacy frame declaration/count mismatch')
                db.execute('INSERT OR REPLACE INTO legacy_frame VALUES(?,?,?,0)',(run,frame,count))
                db.execute('UPDATE legacy_snapshots SET frames=frames+1 WHERE run=?',(run,))
            elif phase=='frame_member':
                cube=int(r['cube_id']);origin=db.execute("SELECT c.epoch,p.complete FROM cube_epochs c JOIN payloads p ON p.run=c.run AND p.id=c.cube AND p.kind='cube' WHERE c.run=? AND c.cube=?",(key,cube)).fetchone()
                require(prior and prior[0]==int(r['frame']) and prior[2]==int(r['index']) and prior[2]<prior[1] and origin and origin[1] and origin[0]==epoch,'legacy frame member order/cube mismatch')
                db.execute('UPDATE legacy_frame SET seen=seen+1 WHERE run=?',(run,))
                db.execute('UPDATE legacy_snapshots SET members=members+1 WHERE run=?',(run,))
            else:
                require(r.get('complete')=='1' and snap[2]==snap[1]+1 and snap[3]==int(r['members']) and prior and prior[1]==prior[2],'incomplete legacy frame snapshot')
                db.execute('DELETE FROM legacy_frame WHERE run=?',(run,));db.execute('DELETE FROM legacy_snapshots WHERE run=?',(run,))
        elif phase in ('model_epoch_begin','run_seal','run_abort_seal'):
            require(not db.execute('SELECT 1 FROM legacy_snapshots WHERE run=?',(run,)).fetchone(),'unclosed legacy frame snapshot')
        return
    if phase=='model_epoch_begin':
        require(epoch>contract[2] and not db.execute('SELECT 1 FROM frame_snapshots WHERE run=? AND closed=0',(run,)).fetchone(),'epoch changed inside frame snapshot')
        db.execute('UPDATE frame_contracts SET epoch=? WHERE run=?',(epoch,run))
    else:require(epoch==contract[2],'frame context epoch changed without native initialization')
    if phase=='frame_chunk':
        ident=int(r['chunk_id']);count=int(r['members']);data=bytes.fromhex(r['tuples_hex'])
        require(ident>0 and 0<count<=64 and len(data)==count*12 and r.get('complete')=='1' and r.get('encoding')=='cube_u64_packed_u32_le','invalid frame chunk')
        digest=hashlib.sha256(FRAME_CHUNK_DOMAIN+struct.pack('<I',count)+data).hexdigest()
        require(r['sha256']==digest,'frame chunk hash mismatch')
        ids=set(cube for cube,_ in struct.iter_unpack('<QI',data))
        require(0 not in ids,'zero frame cube identity')
        marks=','.join('?' for _ in ids)
        valid=db.execute("SELECT count(*) FROM cube_epochs c JOIN payloads p ON p.run=c.run AND p.id=c.cube AND p.kind='cube' WHERE c.run=? AND c.epoch=? AND c.qualified=1 AND p.complete=1 AND c.cube IN ("+marks+')',(key,epoch,*ids)).fetchone()[0]
        require(valid==len(ids),'undefined/incomplete/cross-epoch frame cube')
        db.execute('INSERT INTO frame_chunks VALUES(?,?,?,?,?,?,?)',(run,ident,epoch,count,data,digest,int(r['event'])))
    elif phase=='frames_begin':
        count=int(r['frontier_count']);require(0<=count<=10000000 and not db.execute('SELECT 1 FROM frame_snapshots WHERE run=? AND closed=0',(run,)).fetchone(),'invalid/overlapping frame snapshot')
        db.execute('INSERT INTO frame_snapshots(run,snapshot,epoch,frontiers) VALUES(?,?,?,?)',(run,int(r['snapshot']),epoch,count))
    elif phase in ('frame','frame_chunk_ref','frame_manifest_end','frames_end','frame_member'):
        snapshot=int(r['snapshot']);snap=db.execute('SELECT epoch,frontiers,seen_frames,members,closed FROM frame_snapshots WHERE run=? AND snapshot=?',(run,snapshot)).fetchone()
        require(snap and not snap[4] and snap[0]==epoch,'undefined/closed frame snapshot')
        require(phase!='frame_member','unencoded member in compact frame contract')
        if phase=='frames_end':
            require(r.get('complete')=='1' and snap[2]==snap[1]+1 and snap[3]==int(r['members']) and not db.execute('SELECT 1 FROM frame_manifests WHERE run=? AND snapshot=? AND closed=0',(run,snapshot)).fetchone(),'incomplete compact frame snapshot')
            db.execute('UPDATE frame_snapshots SET closed=1 WHERE run=? AND snapshot=?',(run,snapshot));return
        frame=int(r['frame'])
        if phase=='frame':
            count=int(r['cubes']);require(0<=count<=10000000 and frame==(snap[2] if snap[2]<snap[1] else -1) and snap[2]<=snap[1],'invalid frame declaration/order')
            require(not db.execute('SELECT 1 FROM frame_manifests WHERE run=? AND snapshot=? AND closed=0',(run,snapshot)).fetchone(),'previous frame not closed')
            db.execute('INSERT INTO frame_manifests(run,snapshot,frame,epoch,members,event) VALUES(?,?,?,?,?,?)',(run,snapshot,frame,epoch,count,int(r['event'])))
            db.execute('UPDATE frame_snapshots SET seen_frames=seen_frames+1 WHERE run=? AND snapshot=?',(run,snapshot))
            if contract[1]==FRAME_CODEC and count<=64:
                require('ref_chunk' in r and 'sha256' in r,'atomic frame missing ref_chunk/sha256')
                ident=int(r['ref_chunk']);require(r.get('complete')=='1','incomplete atomic frame')
                h=frame_hash(epoch,frame,count)
                if count:
                    chunk=db.execute('SELECT epoch,members,event,data FROM frame_chunks WHERE run=? AND id=?',(run,ident)).fetchone()
                    require(chunk and chunk[0]==epoch and chunk[1]==count and chunk[2]<int(r['event']),'undefined/cross-epoch atomic frame chunk')
                    h.update(chunk[3]);db.execute('INSERT INTO frame_refs VALUES(?,?,?,?,?,?)',(run,snapshot,frame,0,ident,int(r['event'])))
                else:require(ident==0,'empty frame references a chunk')
                require(h.hexdigest()==r['sha256'],'atomic frame hash mismatch')
                # Empty hashes are deterministic from (epoch,frame,0). Verify
                # the canonical hash above, but avoid repeating 64 bytes in
                # every derivative empty-frame row. Source records stay whole.
                db.execute('UPDATE frame_manifests SET closed=1,hash=?,seen=members,refs=? WHERE run=? AND snapshot=? AND frame=?',(r['sha256'] if count else None,int(count>0),run,snapshot,frame))
                db.execute('UPDATE frame_snapshots SET members=members+? WHERE run=? AND snapshot=?',(count,run,snapshot))
            else:require('ref_chunk' not in r,'atomic frame encoding inconsistent with contract/count')
            return
        info=db.execute('SELECT members,seen,refs,closed FROM frame_manifests WHERE run=? AND snapshot=? AND frame=?',(run,snapshot,frame)).fetchone()
        require(info and not info[3],'undefined/closed frame manifest')
        if phase=='frame_chunk_ref':
            chunk=db.execute('SELECT epoch,members,event FROM frame_chunks WHERE run=? AND id=?',(run,int(r['chunk_id']))).fetchone()
            require(chunk and chunk[0]==epoch and chunk[2]<int(r['event']),'undefined/future/cross-epoch frame chunk')
            require(int(r['offset'])==info[1] and int(r['members'])==chunk[1] and info[1]+chunk[1]<=info[0] and chunk[1]==min(64,info[0]-info[1]),'frame reference count/order mismatch')
            db.execute('INSERT INTO frame_refs VALUES(?,?,?,?,?,?)',(run,snapshot,frame,info[1],int(r['chunk_id']),int(r['event'])))
            db.execute('UPDATE frame_manifests SET seen=seen+?,refs=refs+1 WHERE run=? AND snapshot=? AND frame=?',(chunk[1],run,snapshot,frame));return
        require(r.get('complete')=='1' and int(r['cubes'])==info[0]==info[1] and int(r['refs'])==info[2],'incomplete frame manifest')
        h=frame_hash(epoch,frame,info[0])
        for (data,) in db.execute('SELECT c.data FROM frame_refs f JOIN frame_chunks c ON c.run=f.run AND c.id=f.chunk WHERE f.run=? AND f.snapshot=? AND f.frame=? ORDER BY f.offset',(run,snapshot,frame)):h.update(data)
        require(h.hexdigest()==r['sha256'],'frame manifest hash mismatch')
        db.execute('UPDATE frame_manifests SET closed=1,hash=? WHERE run=? AND snapshot=? AND frame=?',(r['sha256'] if info[0] else None,run,snapshot,frame))
        db.execute('UPDATE frame_snapshots SET members=members+? WHERE run=? AND snapshot=?',(info[0],run,snapshot))
    elif phase in ('run_seal','run_abort_seal'):
        require(not db.execute('SELECT 1 FROM frame_snapshots WHERE run=? AND closed=0',(run,)).fetchone(),'seal with unfinished compact frame snapshot')

def frame_members(db,key,snapshot,frame,offset=0,limit=None):
    """Stream full ordered members; pagination is explicit, never canonical loss."""
    run=db.execute('SELECT rowid FROM runs WHERE run=?',(key,)).fetchone()
    require(run and snapshot>=0 and offset>=0 and (limit is None or limit>=0),'invalid frame selection')
    run=run[0];emitted=0
    tail=db.execute("SELECT min(event) FROM events WHERE run=? AND phase='native_tail_begin'",(run,)).fetchone()[0]
    codec='tuple_chunks_v1'
    contract=db.execute("SELECT f.path,e.offset,e.length FROM events e JOIN files f ON f.id=e.source WHERE e.run=? AND e.phase='run_contract'",(run,)).fetchone()
    if contract:
        with archive_open(contract[0]) as stream:stream.seek(contract[1]);codec=fields(stream.read(contract[2]).rstrip(b'\n')).get('frame_encoding','members_v1')
    modern=db.execute('SELECT epoch,members,closed,event FROM frame_manifests WHERE run=? AND snapshot=? AND frame=?',(run,snapshot,frame)).fetchone()
    if modern:
        closed=db.execute('SELECT closed FROM frame_snapshots WHERE run=? AND snapshot=?',(run,snapshot)).fetchone()
        require(modern[2] and closed and closed[0],'frame snapshot incomplete')
        for at,data,definition,event in db.execute('SELECT f.offset,c.data,c.event,f.event FROM frame_refs f JOIN frame_chunks c ON c.run=f.run AND c.id=f.chunk WHERE f.run=? AND f.snapshot=? AND f.frame=? AND f.offset+c.members>? ORDER BY f.offset',(run,snapshot,frame,offset)):
            for i,(cube,packed) in enumerate(struct.iter_unpack('<QI',data),at):
                if i<offset:continue
                if limit is not None and emitted>=limit:return
                signed=(packed&0x7fffffff);signed-=0x80000000 if signed&0x40000000 else 0
                yield dict(run=key,snapshot=snapshot,frame=frame,index=i,cube_id=cube,packed=packed,max_level=signed,validated=packed>>31,model_epoch=modern[0],encoding=codec,definition_event=definition,reference_event=event,native_phase='post_final_cleanup' if tail is not None and modern[3]>tail else 'search',proof_certificate=False)
                emitted+=1
    else:
        require(db.execute("SELECT 1 FROM events WHERE run=? AND snapshot=? AND phase='frames_end'",(run,snapshot)).fetchone(),'frame snapshot unavailable/unclosed')
        headers={}
        for path,at,length,phase in db.execute("SELECT f.path,e.offset,e.length,e.phase FROM events e JOIN files f ON f.id=e.source WHERE e.run=? AND e.snapshot=? AND (e.phase='frames_end' OR (e.phase='frame' AND e.frame=?))",(run,snapshot,frame)):
            with archive_open(path) as stream:stream.seek(at);raw=stream.read(length)
            require(len(raw)==length and raw.endswith(b'\n'),'frame header source changed/truncated: '+path)
            headers[phase]=fields(raw.rstrip(b'\n'))
        require(headers.get('frames_end',{}).get('complete')=='1' and 'frame' in headers,'frame unavailable/incomplete')
        count=db.execute("SELECT count(*) FROM events WHERE run=? AND snapshot=? AND frame=? AND phase='frame_member'",(run,snapshot,frame)).fetchone()[0]
        require(count==int(headers['frame']['cubes']),'legacy frame member count mismatch')
        source=None
        with contextlib.ExitStack() as stack:
            for path,at,length in db.execute("SELECT f.path,e.offset,e.length FROM events e JOIN files f ON f.id=e.source WHERE e.run=? AND e.snapshot=? AND e.frame=? AND e.phase='frame_member' ORDER BY e.event",(run,snapshot,frame)):
                if source!=path:
                    stack.close();stream=stack.enter_context(archive_open(path));source=path
                stream.seek(at);raw=stream.read(length)
                require(len(raw)==length and raw.endswith(b'\n'),'frame source changed/truncated: '+path)
                r=fields(raw.rstrip(b'\n'));i=int(r['index'])
                if i<offset:continue
                if limit is not None and emitted>=limit:return
                level=int(r['max_level']);valid=int(r['validated'])
                yield dict(run=key,snapshot=snapshot,frame=frame,index=i,cube_id=int(r['cube_id']),max_level=level,validated=valid,packed=(level&0x7fffffff)|(valid<<31),model_epoch=int(r.get('model_epoch','0')),encoding='members_v1',reference_event=int(r['event']),native_phase='post_final_cleanup' if tail is not None and int(headers['frame']['event'])>tail else 'search',proof_certificate=False)
                emitted+=1

def snapshot_members(db,key,snapshot):
    """Stream every frame in one closed snapshot; invariants (-1) follow frontiers."""
    require(db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='frame_snapshots'").fetchone(),'whole-snapshot queries require the current index schema; re-ingest the unchanged canonical archive')
    run=db.execute('SELECT rowid FROM runs WHERE run=?',(key,)).fetchone()
    require(run and snapshot>=0,'invalid snapshot selection')
    run=run[0]
    modern=db.execute('SELECT closed,frontiers FROM frame_snapshots WHERE run=? AND snapshot=?',(run,snapshot)).fetchone()
    if modern:
        require(modern[0],'frame snapshot incomplete')
        frames=db.execute('SELECT frame FROM frame_manifests WHERE run=? AND snapshot=? ORDER BY frame<0,frame',(run,snapshot))
    else:
        require(db.execute("SELECT 1 FROM events WHERE run=? AND snapshot=? AND phase='frames_end'",(run,snapshot)).fetchone(),'frame snapshot unavailable/unclosed')
        frames=db.execute("SELECT frame FROM events WHERE run=? AND snapshot=? AND phase='frame' ORDER BY frame<0,frame",(run,snapshot))
    observed=0
    for (frame,) in frames:
        observed+=1
        yield from frame_members(db,key,snapshot,frame)
    require(observed,'frame snapshot has no frame headers')
    if modern:require(observed==modern[1]+1,'frame snapshot header count mismatch')

def index_cube_refs(db,run,event,row):
    for role,value in row.items():
        if role=='cube_id' or role.endswith('_cube_id'):
            ident=int(value)
            if ident>0:db.execute('INSERT INTO cube_refs VALUES(?,?,?,?)',(run,ident,event,role))

    if row.get('phase')=='frame_chunk':
        for ident in set(cube for cube,_ in struct.iter_unpack('<QI',bytes.fromhex(row['tuples_hex']))):
            if ident>0:db.execute('INSERT INTO cube_refs VALUES(?,?,?,?)',(run,ident,event,'tuple_cube_id'))

def cube_filter(db,run_id=None):
    require(db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='cube_refs'").fetchone(),
            'complete cube-reference queries require index schema 4; re-ingest the unchanged canonical archive into a fresh index')
    if not db.execute("SELECT 1 FROM sqlite_master WHERE name='frame_refs' AND type='table'").fetchone():
        return 'EXISTS (SELECT 1 FROM cube_refs c WHERE c.run=e.run AND c.event=e.event AND c.cube=?)'
    # Materialize the selected event set once, instead of probing K references
    # per candidate event. A scoped selection uses the (run,cube,event) key.
    require(run_id is None or type(run_id) is int,'invalid cube filter run identity')
    scope='' if run_id is None else 'run='+str(run_id)+' AND '
    return '(e.run,e.event) IN (WITH direct AS (SELECT run,event FROM cube_refs WHERE '+scope+'cube=?) SELECT run,event FROM direct UNION SELECT f.run,f.event FROM direct d JOIN frame_chunks c ON c.run=d.run AND c.event=d.event JOIN frame_refs f ON f.run=c.run AND f.chunk=c.id)'

def frame_summary(db,run_id):
    tail=db.execute("SELECT min(event) FROM events WHERE run=? AND phase='native_tail_begin'",(run_id,)).fetchone()[0]
    before=tail if tail is not None else 9223372036854775807
    phases={p for (p,) in db.execute("SELECT DISTINCT phase FROM events WHERE run=? AND phase IN ('native_validation_abort','native_validation_end','native_validation_missing')",(run_id,))}
    disposition='aborted_inconclusive' if 'native_validation_abort' in phases else 'missing' if 'native_validation_missing' in phases else 'normal_return_observed' if 'native_validation_end' in phases else 'not_observed'
    tail_scope=dict(native_tail_begin_event=tail,post_final_cleanup_included_in_frontier=False,native_validation_disposition=disposition)
    if db.execute("SELECT 1 FROM sqlite_master WHERE name='frame_snapshots' AND type='table'").fetchone():
        modern=db.execute("SELECT snapshot,members FROM frame_snapshots f WHERE run=? AND closed=1 AND EXISTS(SELECT 1 FROM events e WHERE e.run=f.run AND e.snapshot=f.snapshot AND e.phase='frames_end' AND e.event<?) ORDER BY snapshot DESC LIMIT 1",(run_id,before)).fetchone()
        if modern:
            nonempty=db.execute("SELECT max(snapshot) FROM frame_snapshots f WHERE run=? AND closed=1 AND members>0 AND EXISTS(SELECT 1 FROM events e WHERE e.run=f.run AND e.snapshot=f.snapshot AND e.phase='frames_end' AND e.event<?)",(run_id,before)).fetchone()[0]
            return dict(last_closed_frame_snapshot=modern[0],last_closed_frame_members=modern[1],last_nonempty_closed_frame_snapshot=nonempty,frame_scope='snapshot-local; lossless ordered chunk references; excludes post-final cleanup; not global invariants',**tail_scope)

    last=db.execute("SELECT max(snapshot) FROM events WHERE run=? AND phase='frames_end' AND event<?",(run_id,before)).fetchone()[0]
    nonempty=db.execute("SELECT max(snapshot) FROM events WHERE run=? AND phase='frame_member' AND snapshot IN (SELECT snapshot FROM events WHERE run=? AND phase='frames_end' AND event<?)",(run_id,run_id,before)).fetchone()[0]
    members=db.execute("SELECT count(*) FROM events WHERE run=? AND snapshot=? AND phase='frame_member'",(run_id,last)).fetchone()[0]
    return dict(last_closed_frame_snapshot=last,last_closed_frame_members=members if last is not None else None,
                last_nonempty_closed_frame_snapshot=nonempty,frame_scope='snapshot-local; excludes post-final cleanup; earlier nonempty snapshots are not the latest context or global invariants',**tail_scope)

def payload(db,run,r):
    phase=r['phase']; kind=None
    if phase.startswith('cube_') and phase in ('cube_definition','cube_chunk','cube_definition_end'):
        kind='cube'; ident=int(r['cube_id'])
        start=phase=='cube_definition';chunk=phase=='cube_chunk'
    elif phase.startswith('parity_record'):
        kind='parity';ident=int(r['parity_sequence'])
        start=phase=='parity_record';chunk=phase=='parity_record_chunk'
    elif phase in ('signal_name_chunk','signal_name_end'):
        epoch=int(r.get('model_epoch','0'));kind='name@'+str(epoch) if epoch else 'name'
        ident=int(r['variable']);start=False;chunk=phase.endswith('_chunk')
        if chunk and int(r['offset'])==0:
            db.execute('INSERT INTO payloads(run,kind,id,expected,domain) VALUES(?,?,?,?,?)',(run,kind,ident,-1,''))
    if kind is None:return
    if start:
        db.execute('INSERT INTO payloads(run,kind,id,expected,hash,domain) VALUES(?,?,?,?,?,?)',
                   (run,kind,ident,int(r['literals'] if kind=='cube' else r['bytes']),r['sha256'],r.get('domain','')))
        return
    row=db.execute('SELECT expected,seen,hash,domain,complete FROM payloads WHERE run=? AND kind=? AND id=?',(run,kind,ident)).fetchone()
    require(row is not None and not row[4],f'undefined/closed {kind} {ident}')
    expected,seen,digest,domain,_=row
    if chunk:
        if kind=='cube':
            values=r['values'].split(',');require(len(values)==int(r['count']),'cube chunk count')
            data=b''.join(struct.pack('<I',int(v,16)) for v in values);count=len(values)
        else:
            data=bytes.fromhex(r['utf8_hex'] if kind=='parity' else r['utf8_hex'] if 'utf8_hex' in r else r['utf8_hex_bytes'])
            count=len(data);require(count==int(r['bytes']),'text chunk count')
        require(int(r['offset'])==seen,'missing or overlapping payload chunk')
        db.execute('INSERT INTO chunks VALUES(?,?,?,?,?)',(run,kind,ident,seen,data))
        db.execute('UPDATE payloads SET seen=? WHERE run=? AND kind=? AND id=?',(seen+count,run,kind,ident))
    else:
        require(r.get('complete')=='1',f'incomplete {kind}')
        actual=int(r['literals'] if kind=='cube' else r['bytes'])
        require(seen==actual and (expected==-1 or expected==actual),'payload length mismatch')
        h=hashlib.sha256()
        if kind=='cube':h.update(domain.encode()+b'\0'+struct.pack('<I',expected))
        for (data,) in db.execute('SELECT data FROM chunks WHERE run=? AND kind=? AND id=? ORDER BY offset',(run,kind,ident)):h.update(data)
        if digest:require(h.hexdigest()==digest,'payload hash mismatch')
        db.execute('UPDATE payloads SET complete=1,expected=? WHERE run=? AND kind=? AND id=?',(actual,run,kind,ident))

def observer_tables(db):
    db.executescript('''
      CREATE TEMP TABLE observer_counts(run TEXT PRIMARY KEY,began INTEGER DEFAULT 0,returned INTEGER DEFAULT 0,aborted INTEGER DEFAULT 0,abort_terminal INTEGER DEFAULT 0,run_abort_event INTEGER DEFAULT 0,completion_tail INTEGER DEFAULT 0,tail_event INTEGER DEFAULT 0,validation_missing INTEGER DEFAULT 0,validation_abort_tracking INTEGER DEFAULT 0,validation_abort_event INTEGER DEFAULT 0,validation_abort_marker INTEGER DEFAULT 0,final_valid INTEGER DEFAULT 0,validation_abort_begin INTEGER DEFAULT 0);
      CREATE TEMP TABLE observer_live(thread TEXT,token INTEGER,run TEXT,hook TEXT,operation INTEGER,depth INTEGER,validation_begin INTEGER DEFAULT 0,PRIMARY KEY(thread,token)) WITHOUT ROWID;
      CREATE TEMP TABLE observer_queries(run TEXT,kind TEXT,id INTEGER,PRIMARY KEY(run,kind,id)) WITHOUT ROWID;
    ''')

def observer_record(db,run,r):
    """Independent validation; temporary rows retain only live native scopes."""
    phase=r['phase']
    if phase=='run_contract' and r.get('activation_tracking')=='1':
        db.execute('INSERT INTO observer_counts(run,abort_terminal,completion_tail,validation_abort_tracking) VALUES(?,?,?,?)',(run,int(r.get('abort_terminal_tracking','0')),int(r.get('completion_tail_tracking','0')),int(r.get('validation_abort_tracking','0'))))
    if phase=='final':db.execute('UPDATE observer_counts SET final_valid=? WHERE run=?',(int(r.get('result')=='valid'),run))
    if phase=='native_validation_begin' and db.execute('SELECT 1 FROM observer_counts WHERE run=? AND validation_abort_tracking=1',(run,)).fetchone():
        thread=':'.join(r[k] for k in ('capture','pid','tid'))
        active=db.execute('SELECT token,run,hook,validation_begin FROM observer_live WHERE thread=? ORDER BY token DESC LIMIT 1',(thread,)).fetchone()
        require(active and active[1:]==(run,'validation',0),'validation begin requires its own live native activation')
        db.execute('UPDATE observer_live SET validation_begin=? WHERE thread=? AND token=?',(int(r['event']),thread,active[0]))
    if phase=='native_validation_abort':
        state=db.execute('SELECT validation_abort_tracking,validation_abort_event,validation_abort_marker,final_valid,validation_abort_begin FROM observer_counts WHERE run=?',(run,)).fetchone()
        final=db.execute('SELECT final FROM runs WHERE run=?',(run,)).fetchone()
        abort=int(r.get('abort_event','0'))
        require(state and state[0]==1 and state[1]==abort and state[2]==0 and state[3]==1 and final and 0<final[0]<abort<int(r['event']) and int(r.get('native_final_event','0'))==final[0],'validation abort requires declared tracking, valid final and actual native validation abort')
        require(r.get('reason')=='native_handler_unwind' and r.get('native_return_observed')=='0' and r.get('native_validation_end_observed')=='0' and r.get('validation_pass_observed')=='0' and r.get('validation_outcome')=='aborted_inconclusive' and 'result' not in r and 'result_raw' not in r,'validation abort invents a result')
        require(final[0]<state[4]<abort and db.execute("SELECT 1 FROM events WHERE run=(SELECT rowid FROM runs WHERE run=?) AND phase='native_validation_begin' AND event=?",(run,state[4])).fetchone(),'validation abort without observed validation begin of the aborted activation')
        require(not db.execute("SELECT 1 FROM events WHERE run=(SELECT rowid FROM runs WHERE run=?) AND phase IN ('native_validation_end','native_validation_missing') AND event>?",(run,final[0])).fetchone(),'validation abort contradicts normal/missing validation')
        require(not db.execute('SELECT 1 FROM observer_live WHERE run=?',(run,)).fetchone() and not db.execute('SELECT 1 FROM observer_queries WHERE run=?',(run,)).fetchone(),'validation abort marker has unfinished scopes')
        db.execute('UPDATE observer_counts SET validation_abort_marker=? WHERE run=?',(int(r['event']),run))
    if phase in ('native_validation_begin','native_validation_end','native_validation_stage','native_validation_missing'):
        state=db.execute('SELECT validation_abort_event FROM observer_counts WHERE run=?',(run,)).fetchone()
        final=db.execute('SELECT final FROM runs WHERE run=?',(run,)).fetchone()
        if state and final and 0<final[0]<state[0]:raise ValueError('native validation return/pass or conflicting boundary after observed abort')
    if phase=='run_abort_seal':require(db.execute('SELECT 1 FROM observer_counts WHERE run=? AND abort_terminal=1',(run,)).fetchone(),'abort terminal requires declared observer tracking')
    if phase=='native_tail_begin':
        state=db.execute('SELECT completion_tail,tail_event,run_abort_event FROM observer_counts WHERE run=?',(run,)).fetchone()
        final=db.execute('SELECT final FROM runs WHERE run=?',(run,)).fetchone()
        require(state and state==(1,0,0) and final and final[0]>0 and final[0]==int(r.get('native_final_event','0')),'native tail requires declared tracking and one observed final')
        require(r.get('native_verdict_already_observed')=='1' and r.get('proof_frontier')=='0','native cleanup tail presented as proof frontier')
        require(not db.execute('SELECT 1 FROM observer_live WHERE run=?',(run,)).fetchone() and not db.execute('SELECT 1 FROM observer_queries WHERE run=?',(run,)).fetchone(),'native tail has unfinished search scopes')
        expected=r.get('native_validation_expected','0');observed=r.get('native_validation_observed','0');aborted=r.get('native_validation_aborted','0')
        require(expected in ('0','1') and observed in ('0','1') and aborted in ('0','1') and (observed=='0' or expected=='1') and (aborted=='0' or (expected=='1' and observed=='0')),'invalid native tail validation scope')
        if expected=='1':
            needed='native_validation_end' if observed=='1' else 'native_validation_abort' if aborted=='1' else 'native_validation_missing'
            require(db.execute('SELECT 1 FROM events WHERE run=(SELECT rowid FROM runs WHERE run=?) AND phase=? AND event>? AND event<?',(run,needed,final[0],int(r['event']))).fetchone(),'native tail validation boundary not observed')
        if aborted=='1':
            require(db.execute('SELECT 1 FROM observer_counts WHERE run=? AND validation_abort_tracking=1 AND validation_abort_marker>0 AND validation_abort_event=?',(run,int(r.get('native_validation_abort_event','0')))).fetchone(),'native tail abort reference mismatch')
        db.execute('UPDATE observer_counts SET tail_event=?,validation_missing=? WHERE run=?',(int(r['event']),int(expected=='1' and observed=='0' and aborted=='0'),run))
    state=db.execute('SELECT tail_event,validation_missing FROM observer_counts WHERE run=?',(run,)).fetchone()
    if not state:return
    if state[0] and phase!='native_tail_begin':
        allowed={'invocation_begin','invocation_return','context_mutation','listener_alias','subsumption_result','subsumption_end','subsumption_edge','cube','cube_definition','cube_chunk','cube_definition_end','signal','signal_name_chunk','signal_name_end','frames_begin','frame','frame_member','frame_chunk','frame_chunk_ref','frame_manifest_end','frames_end','frame_membership_add','frame_membership_remove','run_seal'}
        require(phase in allowed,'unexpected native search or unknown scope after final cleanup boundary: '+phase)
        if phase in ('invocation_begin','invocation_return'):require(r.get('hook') in ('subsumption','frontremove'),'native search invocation inside cleanup tail')
        if phase=='context_mutation':require(r.get('kind') in ('subsumption','frontremove'),'native search mutation inside cleanup tail')
        if phase=='run_seal' and state[1]:require(r.get('capture_status')=='incomplete','missing native validation presented as complete capture')
    thread=':'.join(r[k] for k in ('capture','pid','tid'))
    require(phase!='observer_error','producer reports native observer error')
    if phase=='invocation_begin':
        parent=int(r['parent_activation']);top=db.execute('SELECT token,depth FROM observer_live WHERE thread=? ORDER BY token DESC LIMIT 1',(thread,)).fetchone()
        require(parent==(top[0] if top else 0),'native activation parent mismatch')
        require(not top or int(r['gum_depth'])>top[1],'native activation depth mismatch')
        require(int(r['run_generation'])==int(r['run']),'native activation generation mismatch')
        db.execute('INSERT INTO observer_live(thread,token,run,hook,operation,depth) VALUES(?,?,?,?,?,?)',(thread,int(r['activation']),run,r['hook'],int(r['operation']),int(r['gum_depth'])))
        db.execute('UPDATE observer_counts SET began=began+1 WHERE run=?',(run,))
    elif phase in ('invocation_return','invocation_abort'):
        top=db.execute('SELECT token,run,hook,operation,depth,validation_begin FROM observer_live WHERE thread=? ORDER BY token DESC LIMIT 1',(thread,)).fetchone()
        require(top and top[:5]==(int(r['activation']),run,r['hook'],int(r['operation']),int(r['gum_depth'])),'native activation close mismatch')
        require(r['native_return_observed']==('1' if phase=='invocation_return' else '0'),'native activation return/abort mismatch')
        db.execute('DELETE FROM observer_live WHERE thread=? AND token=?',(thread,int(r['activation'])))
        column='returned' if phase=='invocation_return' else 'aborted'
        db.execute('UPDATE observer_counts SET '+column+'='+column+'+1 WHERE run=?',(run,))
        if phase=='invocation_abort' and r['hook']=='run':db.execute('UPDATE observer_counts SET run_abort_event=? WHERE run=?',(int(r['event']),run))
        if phase=='invocation_abort' and r['hook']=='validation' and r.get('reason')=='native_handler_unwind' and not db.execute("SELECT 1 FROM observer_live WHERE run=? AND hook='validation'",(run,)).fetchone():
            db.execute('UPDATE observer_counts SET validation_abort_event=?,validation_abort_begin=? WHERE run=?',(int(r['event']),top[5],run))
    elif phase in ('relative_begin','sat_begin'):
        db.execute('INSERT INTO observer_queries VALUES(?,?,?)',(run,'relative' if phase=='relative_begin' else 'sat',int(r['query'] if phase=='relative_begin' else r['call'])))
    elif phase in ('relative_end','query_abort','sat_end','sat_abort'):
        kind='relative' if phase in ('relative_end','query_abort') else 'sat'
        ident=int(r['query'] if kind=='relative' else r['call'])
        require(db.execute('DELETE FROM observer_queries WHERE run=? AND kind=? AND id=?',(run,kind,ident)).rowcount==1,'undefined/closed native query')
        if phase.endswith('abort'):
            require(r['native_return_observed']=='0' and 'result' not in r and 'result_raw' not in r,'native query abort invents a result')
    elif phase in ('run_seal','run_abort_seal'):
        if phase=='run_abort_seal':
            terminal=db.execute('SELECT abort_terminal,run_abort_event FROM observer_counts WHERE run=?',(run,)).fetchone()
            require(terminal and terminal[0]==1 and terminal[1]>0 and terminal[1]==int(r.get('abort_event','0')),'abort seal without observed native run abort')
            require(r.get('terminal_kind')=='native_aborted_attempt' and r.get('native_final_observed')=='0' and r.get('final_event')=='0' and 'result' not in r and 'result_raw' not in r,'abort seal invents native final result')
        counts=db.execute('SELECT began,returned,aborted FROM observer_counts WHERE run=?',(run,)).fetchone()
        require(counts==tuple(int(r[k]) for k in ('activation_begins','activation_returns','activation_aborts')),'native activation seal count mismatch')
        live=db.execute('SELECT count(*) FROM observer_live WHERE run=?',(run,)).fetchone()[0]
        pending=db.execute('SELECT count(*) FROM observer_queries WHERE run=?',(run,)).fetchone()[0]
        require(live==int(r['activation_live']),'native activation live count mismatch')
        if r['capture_status']=='complete':require(live==pending==int(r['observer_errors'])==0 and counts[0]==counts[1]+counts[2],'complete seal has unfinished native scopes')

def ingest(directory,destination,allow_incomplete=False,closed_workers_only=False,workers=None):
    directory=directory.resolve()
    require(not destination.exists(),'database must not already exist')
    require(not index_receipt_path(destination).exists() and not Path(str(index_receipt_path(destination))+'.tmp').exists(),
            'index integrity receipt already exists; use a fresh destination')
    logs=canonical_logs(directory);require(logs,'no worker event files')
    require(not closed_workers_only or allow_incomplete,'--closed-workers-only requires --allow-incomplete; the selected subset is never a complete directory archive')
    manifests=sorted(directory.glob('worker-*.manifest.json'));excluded=[];unclosed=[]
    if workers is not None:
        require(allow_incomplete,'--worker requires --allow-incomplete; a selected worker archive is never a complete directory archive')
        require(not closed_workers_only,'--worker and --closed-workers-only are separate selection modes')
        workers=set(workers)
        require(workers and all(type(pid) is int and pid>0 for pid in workers),'invalid worker PID selection')
        found={int(path.name.split('-')[1]) for path in logs}
        require(workers<=found,'requested worker event files unavailable: '+str(sorted(workers-found)))
        selected=[]
        for path in logs:
            if int(path.name.split('-')[1]) in workers:selected.append(path)
            else:excluded.append({'file':str(path),'manifest':str(directory/('worker-'+path.name.split('-')[1]+'.manifest.json')),'reason':'outside explicit worker selection; original retained, not validated'})
        logs=selected
        manifests=[path for path in manifests if int(path.name.split('-')[1].split('.')[0]) in workers]
    if closed_workers_only:
        selected=[];used=set()
        for path in logs:
            manifest=directory/('worker-'+path.name.split('-')[1]+'.manifest.json')
            if manifest.is_file() and read_manifest(manifest).get('process_closed') is True:
                selected.append(path);used.add(manifest)
            else:excluded.append({'file':str(path),'manifest':str(manifest),'reason':('worker process_closed is not true' if manifest.is_file() else 'worker manifest missing')+'; original retained'})
        logs=selected;manifests=[p for p in manifests if p in used]
        require(logs,'no closed worker event files; preserve the incomplete directory')
    db=sqlite3.connect(destination)
    db.execute('PRAGMA journal_mode=DELETE');db.execute('PRAGMA synchronous=FULL')
    db.execute('PRAGMA cache_size=-8192');db.execute('PRAGMA temp_store=FILE');db.execute('PRAGMA mmap_size=0')
    db.executescript(SCHEMA)
    observer_tables(db)
    frame_tables(db)
    db.execute('INSERT INTO metadata VALUES(?,?)',('integrity','incomplete'))
    db.execute('INSERT INTO metadata VALUES(?,?)',('index_schema','6'))
    selection='explicit_workers' if workers is not None else 'closed_workers_only' if closed_workers_only else 'all_worker_files'
    db.execute('INSERT INTO metadata VALUES(?,?)',('selection',selection))
    db.execute('INSERT INTO metadata VALUES(?,?)',('selected_worker_pids',json.dumps(sorted(workers) if workers is not None else [])))
    db.execute('INSERT INTO metadata VALUES(?,?)',('excluded_worker_files',json.dumps(excluded)))
    db.execute('INSERT INTO metadata VALUES(?,?)',('unclosed_worker_manifests','[]'))
    count=0
    try:
        for path in logs:
            require(not path.is_symlink(),'symlink capture rejected')
            h=hashlib.sha256();size=0
            file_id=db.execute('INSERT INTO files(path) VALUES(?)',(str(path.resolve()),)).lastrowid
            for line in archive_lines(path):
                h.update(line);size+=len(line)
                require(line.endswith(b'\n'),'partial final record')
                if not line.startswith(b'IC3_STATS '):continue
                raw=line[:-1];r=fields(raw);require(r.get('schema') in ('2','3'),'only schema 2 and 3 are supported')
                if workers is not None:require(int(r['pid'])==int(path.name.split('-')[1]),'worker PID differs from selected archive filename')
                key=':'.join(r[k] for k in ('capture','pid','tid','run'));nr=int(r['event'])
                prior=db.execute('SELECT event,tip,sealed,rowid FROM runs WHERE run=?',(key,)).fetchone()
                if prior is None:
                    require(nr==1 and r['phase']=='run_contract','missing first event/run contract')
                    run_id=db.execute('INSERT INTO runs(run,event,tip) VALUES(?,?,?)',(key,0,'')).lastrowid;prior=(0,'',0,run_id)
                require(not prior[2] and nr==prior[0]+1,'event gap, duplicate or data after seal')
                body,chain=raw.rsplit(b' chain=',1)
                actual=hashlib.sha256(bytes.fromhex(prior[1]) if prior[1] else bytes(32))
                actual.update(body);require(actual.hexdigest()==chain.decode(),'event hash-chain mismatch')
                require(r['phase']!='capture_error','producer reports capture failure')
                for field in ('lost','read_failures','callback_failures','population_mismatch','final_stats_mismatch'):
                    require(field not in r or int(r[field])==0,f'producer reports {field}')
                db.execute('INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?,?)',(prior[3],nr,r['phase'],int(r['frame']) if 'frame' in r else None,int(r['cube_id']) if 'cube_id' in r else None,int(r['query']) if 'query' in r else None,int(r['snapshot']) if 'snapshot' in r else None,file_id,size-len(line),len(line)))
                index_cube_refs(db,prior[3],nr,r)
                db.execute('UPDATE runs SET event=?,tip=? WHERE run=?',(nr,chain.decode(),key))
                payload(db,key,r)
                observer_record(db,key,r)
                if r['phase']=='model':db.execute('INSERT INTO models VALUES(?,?,?)',(key,int(r.get('model_epoch','0')),raw))
                if r['phase']=='cube_definition':db.execute('INSERT INTO cube_epochs VALUES(?,?,?,?)',(key,int(r['cube_id']),int(r.get('model_epoch','0')),int(r.get('model_qualified','1'))))
                frame_record(db,key,prior[3],r)
                if r['phase']=='final':
                    aborted=db.execute('SELECT run_abort_event FROM observer_counts WHERE run=?',(key,)).fetchone()
                    require(not aborted or aborted[0]==0,'native final after aborted run generation')
                    require(db.execute('SELECT final FROM runs WHERE run=?',(key,)).fetchone()[0]==0,'duplicate native final')
                    db.execute('UPDATE runs SET final=? WHERE run=?',(nr,key))
                if r['phase'] in ('run_seal','run_abort_seal'):
                    final=db.execute('SELECT final FROM runs WHERE run=?',(key,)).fetchone()[0]
                    if r['phase']=='run_seal':require(final>0 and final==int(r['final_event']),'seal without matching final')
                    else:require(final==0 and r.get('final_event')=='0','abort seal has native final result')
                    require(int(r['events_before_seal'])==nr-1,'seal event count mismatch')
                    db.execute('UPDATE runs SET sealed=1,complete=? WHERE run=?',(int(r['capture_status']=='complete'),key))
                count+=1
                if count%5000==0:db.commit()
            db.execute('UPDATE files SET bytes=?,sha256=? WHERE id=?',(size,h.hexdigest(),file_id))
        require(count,'no telemetry records')
        unfinished=bool(db.execute('SELECT 1 FROM payloads WHERE complete=0 LIMIT 1').fetchone())
        unfinished=unfinished or bool(db.execute('SELECT 1 FROM frame_snapshots WHERE closed=0 LIMIT 1').fetchone()) or bool(db.execute('SELECT 1 FROM legacy_snapshots LIMIT 1').fetchone())
        require(not unfinished or allow_incomplete,'unfinished payload/frame snapshot')
        require(manifests or allow_incomplete,'worker manifests missing')
        db.execute('CREATE TEMP TABLE expected(run TEXT PRIMARY KEY)')
        for path in manifests:
            m=read_manifest(path)
            require(m.get('schema')==2 and m.get('scope')=='one_worker_process','invalid manifest scope')
            if m.get('process_closed') is not True:
                require(allow_incomplete and m['runs'] and all(r['sealed'] for r in m['runs']),
                        'worker closure unattested; only fully sealed readable runs may be inspected with --allow-incomplete; otherwise use the explicit closed-worker subset')
                unclosed.append({'manifest':str(path),'reason':'process closure unattested; fully sealed CRC/chain/payload-verified snapshot only, not complete worker archive'})
            require(not m.get('dropped_records') and not m.get('ledger_failures'),'manifest reports loss')
            require(not m.get('unbound_hook_calls') and not m.get('ambiguous_seq_bindings'),'manifest reports native hook binding coverage failure')
            for r in m['runs']:
                db.execute('INSERT INTO expected VALUES(?)',(r['key'],))
                observed=db.execute('SELECT event,tip,sealed,complete FROM runs WHERE run=?',(r['key'],)).fetchone()
                if r['sealed']:
                    require(observed==(r['events'],r['tip'],1,1),f'manifest mismatch {r["key"]}')
                else:
                    # Producer 1.6.4 uses manifest "sealed" for a *complete*
                    # seal. A terminal run_seal with capture_status=incomplete
                    # is closed transport, but must remain diagnostic only.
                    require(allow_incomplete and observed is not None and not observed[3],f'incomplete or unsealed run {r["key"]}')
                    if m.get('ledger_tail_on_each_record'):
                        require(observed[:2]==(r['events'],r['tip']),f'diagnostic manifest tail mismatch {r["key"]}')
            db.execute('INSERT INTO files(path,bytes,sha256) VALUES(?,?,?)',(str(path.resolve()),path.stat().st_size,hashlib.sha256(path.read_bytes()).hexdigest()))
        unmanifested=bool(db.execute('SELECT run FROM runs EXCEPT SELECT run FROM expected').fetchone())
        require(not unmanifested or allow_incomplete,'run omitted from manifests')
        complete=workers is None and not closed_workers_only and not unclosed and not unmanifested and not unfinished and not db.execute('SELECT 1 FROM runs WHERE complete=0 LIMIT 1').fetchone()
        db.execute('UPDATE metadata SET value=? WHERE key=?',(json.dumps(unclosed),'unclosed_worker_manifests'))
        db.execute('UPDATE metadata SET value=? WHERE key=?',('verified_observed_worker_files' if complete else 'incomplete_diagnostic','integrity'))
        db.commit()
        result=dict(records=count,runs=db.execute('SELECT count(*) FROM runs').fetchone()[0],integrity='verified_observed_worker_files' if complete else 'incomplete_diagnostic',complete=complete,proof_certificate=False,selection=selection,selected_worker_pids=sorted(workers) if workers is not None else [],excluded_worker_files=excluded,unclosed_worker_manifests=unclosed,scope='manifested observed workers; does not certify missing unobserved ProofGrid jobs or complete solver formulas')
    finally:db.close()
    write_index_receipt(destination)
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__);s=p.add_subparsers(dest='command',required=True)
    a=s.add_parser('ingest');a.add_argument('directory',type=Path);a.add_argument('database',type=Path);a.add_argument('--allow-incomplete',action='store_true');a.add_argument('--closed-workers-only',action='store_true',help='explicitly index only workers whose manifests attest closure; report exclusions, retain originals, always incomplete');a.add_argument('--worker',type=int,action='append',help='explicit PID selection from original directory, repeatable; requires --allow-incomplete, reports exclusions, never copies archives or suppresses selected capture errors')
    a=s.add_parser('export');a.add_argument('database',type=Path);a.add_argument('--run');a.add_argument('--phase');a.add_argument('--cube',type=int);a.add_argument('--frame',type=int);a.add_argument('--snapshot',type=int);a.add_argument('--query',type=int)
    a=s.add_parser('payload');a.add_argument('database',type=Path);a.add_argument('run');a.add_argument('kind',choices=['cube','parity','name']);a.add_argument('id',type=int);a.add_argument('--model-epoch',type=int,default=0,help='required epoch for a qualified retained name; default 0 selects legacy names')
    a=s.add_parser('frame-members');a.add_argument('database',type=Path);a.add_argument('run');a.add_argument('snapshot',type=int);a.add_argument('frame',type=int,nargs='?');a.add_argument('--all-frames',action='store_true',help='stream the complete closed snapshot in frontier order, invariants last; one integrity verification pair');a.add_argument('--offset',type=int,default=0);a.add_argument('--limit',type=int)
    a=s.add_parser('summary');a.add_argument('database',type=Path)
    a=s.add_parser('decode-cube');a.add_argument('database',type=Path);a.add_argument('run');a.add_argument('id',type=int)
    a=s.add_parser('decode-cubes');a.add_argument('database',type=Path);a.add_argument('run');a.add_argument('--ids-file',required=True,type=Path,help='one decimal cube ID per line; streams every selected literal with no row cap')
    a=s.add_parser('cube-ids');a.add_argument('database',type=Path);a.add_argument('run');a.add_argument('--domain',required=True,choices=['jip_formula','sat_literal_raw'],help='explicit literal domain; only complete same-run payloads are selected')
    a=s.add_parser('native-display');a.add_argument('database',type=Path);a.add_argument('--run');a.add_argument('--family',choices=['IC3_STATS','IC3_CTI','IC3_VALIDATION','IC3_OBLIGATION_LENS','IC3_OBLIGATION_QUEUE','IC3_OBLIGATION_FOCUS'])
    a=p.parse_args()
    if a.command=='frame-members':
        require(a.all_frames != (a.frame is not None),'select exactly one frame or --all-frames')
        require(not a.all_frames or (a.offset==0 and a.limit is None),'--all-frames is uncapped; pagination requires a single frame')
    if a.command=='export' and a.cube is not None:
        require(a.run is not None,'export --cube requires --run; cube IDs are local to one worker/run')
    if a.command=='ingest':print(json.dumps(ingest(a.directory,a.database,a.allow_incomplete,a.closed_workers_only,a.worker)));return
    db=sqlite3.connect(a.database.resolve().as_uri()+'?mode=ro',uri=True);db.execute('PRAGMA cache_size=-8192');db.execute('PRAGMA mmap_size=0')
    signatures={}
    verified=False
    try:
        integrity=db.execute("SELECT value FROM metadata WHERE key='integrity'").fetchone()
        require(integrity and integrity[0] in ('verified_observed_worker_files','incomplete_diagnostic'),'index ingestion did not finish successfully')
        verify_index(a.database)
        if getattr(a,'run',None) is not None:
            require(db.execute('SELECT 1 FROM runs WHERE run=?',(a.run,)).fetchone(),'run unavailable: '+a.run+'; inspect summary for exact worker/run keys')
        signatures=verify_sources(db)
        verified=True
        if a.command=='summary':
            print(json.dumps(dict(metadata=dict(db.execute('SELECT * FROM metadata')))))
            for r in db.execute('SELECT run,event,sealed,complete,rowid FROM runs'):
                observed={phase:bool(db.execute('SELECT 1 FROM events WHERE run=? AND phase=? LIMIT 1',(r[4],phase)).fetchone()) for phase in ('model','signal_name_end','frames_begin','queues_begin','predecessor_cubes')}
                print(json.dumps(dict(run=r[0],events=r[1],sealed=bool(r[2]),complete=bool(r[3]),observed_capabilities=observed,**frame_summary(db,r[4]),semantic_limit='archive integrity is not full witness/formula coverage; absent mappings/frames remain unavailable')))
        elif a.command=='frame-members':
            members=snapshot_members(db,a.run,a.snapshot) if a.all_frames else frame_members(db,a.run,a.snapshot,a.frame,a.offset,a.limit)
            for member in members:print(json.dumps(member))
        elif a.command=='native-display':
            for (path,) in db.execute("SELECT path FROM files WHERE path LIKE '%events-%.log%'"):
                with archive_open(path) as stream:
                    for line in stream:
                        if not line.startswith(b'NATIVE_IC3_REPORT '):continue
                        header,text=line.split(b' text=',1);r=fields(header)
                        key=':'.join(r[k] for k in ('capture','pid','tid','run'))
                        if a.run and a.run!=key:continue
                        if a.family and not text.startswith(a.family.encode()+b' '):continue
                        sys.stdout.buffer.write(line)
        elif a.command=='decode-cube':decode_cube(db,a.run,a.id)
        elif a.command=='decode-cubes':
            with a.ids_file.open() as ids:decode_cubes(db,a.run,ids)
        elif a.command=='cube-ids':
            require(db.execute('SELECT 1 FROM runs WHERE run=?',(a.run,)).fetchone(),'run unavailable')
            for (ident,) in db.execute("SELECT id FROM payloads WHERE run=? AND kind='cube' AND domain=? AND complete=1 ORDER BY id",(a.run,a.domain)):print(ident)
        elif a.command=='payload':
            require(a.model_epoch>=0 and (a.kind=='name' or a.model_epoch==0),'model epoch selector applies only to names')
            kind='name@'+str(a.model_epoch) if a.kind=='name' and a.model_epoch else a.kind
            row=db.execute('SELECT complete FROM payloads WHERE run=? AND kind=? AND id=?',(a.run,kind,a.id)).fetchone();require(row and row[0],'payload unavailable/incomplete')
            for (data,) in db.execute('SELECT data FROM chunks WHERE run=? AND kind=? AND id=? ORDER BY offset',(a.run,kind,a.id)):
                if a.kind=='cube':
                    for (v,) in struct.iter_unpack('<I',data):print(f'{v:08x}')
                else:sys.stdout.buffer.write(data)
        else:
            where=[];values=[]
            for col,value in [('r.run',a.run),('e.phase',a.phase),('e.frame',a.frame),('e.snapshot',a.snapshot),('e.query',a.query)]:
                if value is not None:where.append(col+'=?');values.append(value)
            if a.cube is not None:
                selected=db.execute('SELECT rowid FROM runs WHERE run=?',(a.run,)).fetchone()
                require(selected,'run unavailable')
                run_id=selected[0]
                where.append(cube_filter(db,run_id));values.append(a.cube)
            sql='SELECT f.path,e.offset,e.length FROM events e JOIN files f ON f.id=e.source JOIN runs r ON r.rowid=e.run'+(' WHERE '+' AND '.join(where) if where else '')+' ORDER BY e.source,e.offset'
            source=None;stream=None
            try:
                with contextlib.ExitStack() as stack:
                    for path,offset,length in db.execute(sql,values):
                        if source!=path:
                            stack.close();source=path;stream=stack.enter_context(archive_open(path))
                        stream.seek(offset);raw=stream.read(length)
                        require(len(raw)==length and raw.endswith(b'\n'),'archive source changed/truncated: '+path+'; discard partial output')
                        sys.stdout.buffer.write(raw)
            except (EOFError,gzip.BadGzipFile,zlib.error) as error:
                raise archive_error(source,error) from error
    finally:
        try:
            if verified:
                # Shared filesystems can report coarse/cached mtimes. Recheck
                # decoded content too, so a changed source cannot hide behind
                # equal stat fields. Callers publish output only on exit 0.
                verify_sources(db)
                verify_index(a.database)
            verify_stable_sources(signatures)
        finally:db.close()
if __name__=='__main__':
    signal.signal(signal.SIGPIPE,signal.SIG_DFL)
    try:main()
    except (ValueError,OSError,sqlite3.Error) as e:sys.exit(str(e))
