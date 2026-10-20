#!/usr/bin/env python3
"""Regenerate the bundled, exact-release event adapter. Producer/review utility.

This does not infer arbitrary releases or certify native proofs. The mapped
locations and argument decoders were reviewed against the supplied stripped
worker. The complete exact-file hash and byte guards must match.
"""
from pathlib import Path
import argparse, hashlib, json, struct

HERE=Path(__file__).resolve().parent

def image_reader(raw):
    if raw[:6]!=b'\x7fELF\x02\x01':raise ValueError('Expected ELF64 little-endian')
    phoff=struct.unpack_from('<Q',raw,32)[0]
    phsize,phnum=struct.unpack_from('<HH',raw,54)
    if phsize!=56:raise ValueError('Unexpected ELF program header')
    segments=[struct.unpack_from('<IIQQQQQQ',raw,phoff+i*phsize) for i in range(phnum)]
    def read(addr,n):
        for kind,flags,off,va,pa,filesz,memsz,align in segments:
            if kind==1 and va<=addr and addr+n<=va+filesz:
                return raw[off+addr-va:off+addr-va+n]
        raise ValueError('Address not file-backed: '+hex(addr))
    return read

def build(worker,out):
    meta=json.loads((HERE/'b5006df1-adapter.json').read_text())
    raw=Path(worker).read_bytes()
    actual=hashlib.sha256(raw).hexdigest()
    if actual!=meta['worker_sha256']:raise ValueError('Wrong worker SHA-256; no profile will be generated')
    if b'IC3_STATS' in raw:raise ValueError('Unexpected statistics marker in exact target')
    read=image_reader(raw)
    # Independently assert the binary's slot, not a layout borrowed from Atlas.
    cb=meta['callback_proof']
    vt=int(cb['native_callback_vtable_address_point'],16)
    fn=int(cb['report_function'],16)
    assert struct.unpack('<Q',read(vt+51*8,8))[0]==fn
    assert read(fn,len(bytes.fromhex(cb['report_function_bytes'])))==bytes.fromhex(cb['report_function_bytes'])
    lines=['JIPSTATS_EVENTS 1','sha256 '+actual,'callback 480 51',
           'fields 200 280 272 276 284 288','cube 0 8 4',
           'relative_results 1 -1 0','solver_results 0 1 2','proof_results 0 1','details 1']
    for hook in meta['hooks']:
        code=bytes.fromhex(hook['guard'])
        assert read(int(hook['rva'],16),len(code))==code,hook['kind']
        lines.append('hook '+hook['kind']+' '+hook['rva']+' '+' '.join(map(str,hook['roles']))+' '+hook['guard'])
    out=Path(out);out.mkdir(parents=True,exist_ok=True)
    dest=out/(actual+'.events');dest.write_text('\n'.join(lines)+'\n')
    expected=meta.get('profile_sha256')
    if expected and hashlib.sha256(dest.read_bytes()).hexdigest()!=expected:
        raise ValueError('Regenerated profile differs from reviewed metadata')
    print('EXACT_BINARY_ADAPTER_REGENERATED',dest)
    print('Native M/M4 proof qualification is separate; this command never runs a proof.')
    return dest

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('worker',type=Path);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();build(a.worker,a.output)
