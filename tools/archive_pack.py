#!/usr/bin/env python3
"""Losslessly compress closed raw worker logs; optionally remove verified originals.
Raw packing changes source paths: rebuild the index afterward. Recompression
keeps decoded offsets and source paths; indexed readers verify decoded hashes.
Never use this on active captures.
"""
import argparse,gzip,hashlib,json,os,importlib.util,sqlite3,tempfile
from pathlib import Path

def reader_module():
    spec=importlib.util.spec_from_file_location('jipstats_archive_reader',Path(__file__).with_name('telemetry_db.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

def digest(path,compressed=False):
    h=hashlib.sha256();size=0
    with (gzip.open(path,'rb') if compressed else path.open('rb')) as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b);size+=len(b)
    return h.hexdigest(),size

def pack(directory,remove=False,level=1):
    for path in sorted(directory.glob('events-*.log')):
        pid=path.name.split('-')[1];manifest=directory/f'worker-{pid}.manifest.json'
        if not manifest.is_file() or not json.loads(manifest.read_text()).get('process_closed'):
            raise ValueError(f'worker must be closed: {path}')
        if path.is_symlink():raise ValueError('symlink input rejected')
        target=path.with_suffix('.log.gz');tmp=target.with_name('.'+target.name+'.new')
        if target.exists() or tmp.exists():raise ValueError(f'output exists: {target}')
        before=path.stat();expected=digest(path)
        try:
            fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'wb') as out:
                with gzip.GzipFile(filename='',fileobj=out,mode='wb',compresslevel=level,mtime=0) as compressed,path.open('rb') as source:
                    for b in iter(lambda:source.read(1024*1024),b''):compressed.write(b)
                out.flush();os.fsync(out.fileno())
            if digest(tmp,True)!=expected:raise ValueError('decompressed hash/length mismatch')
            after=path.stat()
            if (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns):raise ValueError('input changed during compression')
            os.rename(tmp,target)
            dfd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
            try:os.fsync(dfd)
            finally:os.close(dfd)
            if remove:path.unlink()
            print(json.dumps(dict(source=str(path),archive=str(target),sha256=expected[0],decoded_bytes=expected[1],compressed_bytes=target.stat().st_size,original_removed=remove)))
        finally:tmp.unlink(missing_ok=True)

def compact(directory,level=9):
    """Recompress only closed archives, replacing only after exact verification.
    Uncompressed offsets and record hashes remain unchanged. No active writer or
    whole-file history buffer is involved; readers see the old or new gzip file.
    """
    for path in sorted(directory.glob('events-*.log.gz')):
        pid=path.name.split('-')[1];manifest=directory/f'worker-{pid}.manifest.json'
        if not manifest.is_file() or not json.loads(manifest.read_text()).get('process_closed'):
            raise ValueError(f'worker must be closed: {path}')
        if path.is_symlink():raise ValueError('symlink input rejected')
        tmp=path.with_name('.'+path.name+'.compact.new')
        if tmp.exists():raise ValueError(f'output exists: {tmp}')
        before=path.stat();expected=digest(path,True)
        try:
            fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'wb') as out:
                with gzip.GzipFile(filename='',fileobj=out,mode='wb',compresslevel=level,mtime=0) as compressed,gzip.open(path,'rb') as source:
                    for b in iter(lambda:source.read(1024*1024),b''):compressed.write(b)
                out.flush();os.fsync(out.fileno())
            if digest(tmp,True)!=expected:raise ValueError('decompressed hash/length mismatch')
            after=path.stat()
            if (before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_ino,after.st_size,after.st_mtime_ns):
                raise ValueError('input changed during compression')
            smaller=tmp.stat().st_size<before.st_size
            if smaller:
                os.replace(tmp,path)
                dfd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
                try:os.fsync(dfd)
                finally:os.close(dfd)
            print(json.dumps(dict(archive=str(path),sha256=expected[0],decoded_bytes=expected[1],compressed_bytes_before=before.st_size,compressed_bytes_after=path.stat().st_size,level=level,replaced=smaller,exact_roundtrip=True)))
        finally:tmp.unlink(missing_ok=True)

def chainpack(directory,verified_index=None,level=9):
    """Replace strictly verified, closed sources with a lossless storage codec.
    Rebuild/dispose indexes afterward because canonical source paths change.
    Readers/writers must be stopped during this offline path migration. A crash
    between publishing and removing leaves both copies; ingestion rejects the
    duplicate rather than choosing one silently.
    """
    reader=reader_module()
    with tempfile.TemporaryDirectory(prefix='.chainpack-verify-',dir=directory.parent) as temporary:
        index=Path(verified_index) if verified_index else Path(temporary)/'index.db'
        if not verified_index:reader.ingest(directory,index)
        reader.verify_index(index)
        with sqlite3.connect(index.resolve().as_uri()+'?mode=ro',uri=True) as db:
            metadata=dict(db.execute('SELECT * FROM metadata'))
            reader.require(metadata.get('integrity')=='verified_observed_worker_files' and metadata.get('selection')=='all_worker_files','chainpack requires a complete strict index of all observed worker files')
            signatures=reader.verify_sources(db)
            sources=dict((Path(path),(size,sha)) for path,size,sha in db.execute('SELECT path,bytes,sha256 FROM files'))
        current_sources={p.resolve() for p in reader.canonical_logs(directory)}|{p.resolve() for p in directory.glob('worker-*.manifest.json')}
        reader.require(current_sources==set(sources),'verified index does not match the entire current capture directory; re-ingest before packing')
        reader.verify_stable_sources(signatures)
        logs=sorted(directory.glob('events-*.log'))+sorted(directory.glob('events-*.log.gz'))
        reader.require(logs,'no unpacked worker logs to chainpack')
        manifest_signatures={p:s for p,s in signatures.items() if Path(p).name.startswith('worker-')}
        for path in logs:
            reader.require(not path.is_symlink(),'symlink input rejected')
            manifest=directory/('worker-'+path.name.split('-')[1]+'.manifest.json')
            reader.require(reader.read_manifest(manifest).get('process_closed') is True,'worker must be closed: '+str(path))
            reader.require(path.resolve() in sources,'archive absent from verified index: '+str(path))
            expected=sources[path.resolve()]
            target=Path(str(path)[:-3]+'.chainpack.gz') if path.suffix=='.gz' else Path(str(path)+'.chainpack.gz')
            tmp=target.with_name('.'+target.name+'.new')
            reader.require(not target.exists() and not tmp.exists(),'output exists: '+str(target))
            before=path.stat()
            try:
                fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
                with os.fdopen(fd,'wb') as raw:
                    os.fchown(raw.fileno(),-1,before.st_gid)
                    os.fchmod(raw.fileno(),before.st_mode&0o777)
                    with gzip.GzipFile(filename='',fileobj=raw,mode='wb',compresslevel=level,mtime=0) as output,reader.archive_open(path) as source:
                        receipt=reader.chainpack_encode(source,output)
                    raw.flush();os.fsync(raw.fileno())
                reader.require((receipt['decoded_bytes'],receipt['sha256'])==expected,'source differs from verified index')
                digest=hashlib.sha256();size=0
                # The unpublished temporary name is deliberately outside the
                # ingestion glob; decode explicitly before making it canonical.
                with reader.io.BufferedReader(reader.ChainpackStream(tmp)) as restored:
                    for block in iter(lambda:restored.read(1024*1024),b''):digest.update(block);size+=len(block)
                reader.require((size,digest.hexdigest())==expected,'chainpack exact roundtrip failed')
                reader.require(reader.source_signature(before)==reader.source_signature(path.stat()),'source changed during packing')
                reader.verify_stable_sources(manifest_signatures)
                smaller=tmp.stat().st_size<before.st_size
                if smaller:
                    # Exclusive publication never overwrites a competing output.
                    # Persist the new name before removing the original name.
                    os.link(tmp,target)
                    dfd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
                    try:
                        os.fsync(dfd);path.unlink();os.fsync(dfd)
                    finally:os.close(dfd)
                print(json.dumps(dict(source=str(path),archive=str(target) if smaller else str(path),format='jipstats-chainpack-v1' if smaller else 'unchanged',**receipt,compressed_bytes_before=before.st_size,compressed_bytes_after=target.stat().st_size if smaller else before.st_size,replaced=smaller,exact_roundtrip=True,index_rebuild_required=smaller,reader_sha256=hashlib.sha256(Path(reader.__file__).read_bytes()).hexdigest(),packer_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())))
            finally:tmp.unlink(missing_ok=True)
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('directory',type=Path);p.add_argument('--remove-originals',action='store_true');p.add_argument('--recompress',action='store_true',help='compact closed gzip archives in place only after exact roundtrip; default level 9');p.add_argument('--chainpack',action='store_true',help='post-close lossless derived-hash codec; requires --remove-originals, re-ingest after source paths change');p.add_argument('--verified-index',type=Path,help='reuse a strict index after verifying its own and all source hashes; only with --chainpack');p.add_argument('--level',type=int,choices=range(1,10));a=p.parse_args()
    if a.verified_index and not a.chainpack:p.error('--verified-index requires --chainpack')
    if a.chainpack:
        if a.recompress or not a.remove_originals:p.error('--chainpack requires --remove-originals and cannot combine with --recompress')
        chainpack(a.directory,a.verified_index,a.level or 9)
    elif a.recompress:
        if a.remove_originals:p.error('--remove-originals is for raw packing, not --recompress')
        compact(a.directory,a.level or 9)
    else:pack(a.directory,a.remove_originals,a.level or 1)
