#!/usr/bin/env python3
"""Regenerate reviewed production September adapters, never infer an unknown ABI.

Metadata contains exact worker, instruction, callback and helper-reference guards.
Regeneration is an offline check; native M/M4 qualification remains separate.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from build_b5006df1 import image_reader

SUPPORTED = {
    'b3e7723c4335266b1cd1436277111d54ee7802944b8b4f7d6eaacaa28b7c84b4',
    'e1b53cf546e048df0f9996646afba34b0faf7b38095b22ed700a507b64cf4e7b',
}

def build(worker, output):
    raw = worker.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest not in SUPPORTED:
        raise ValueError('Unknown exact worker hash; no adapter generated')
    meta = json.loads((Path(__file__).resolve().parents[2]/'profiles'/(digest+'.json')).read_text())
    if meta['worker_sha256'] != digest or meta['worker_bytes'] != len(raw):
        raise ValueError('Worker identity mismatch')
    read = image_reader(raw)
    for line in meta['profile_lines']:
        if line.startswith('hook '):
            p = line.split()
            guard = bytes.fromhex(p[-1])
            if read(int(p[2],16),len(guard)) != guard:
                raise ValueError('Instruction guard mismatch: '+p[1])
    cb = meta['callback_proof']
    fn = int(cb['report_function'],16)
    slot = int(cb['native_callback_vtable_address_point'],16)+8*cb['report_vtable_slot']
    guard = bytes.fromhex(cb['report_function_bytes'])
    if struct.unpack('<Q',read(slot,8))[0] != fn or read(fn,len(guard)) != guard:
        raise ValueError('Native report callback mismatch')
    for ref in meta['formula_global_references']:
        guard = bytes.fromhex(ref['guard'])
        if read(int(ref['new_ref'],16),len(guard)) != guard:
            raise ValueError('Formula global reference guard mismatch')
    helper = meta['helper_layout']
    ret = int(helper['pending_front_return'],16)
    if read(ret-5,1) != b'\xe8' or ret+struct.unpack('<i',read(ret-4,4))[0] != int(helper['pending_front_entry'],16):
        raise ValueError('Pending invariant callsite mismatch')
    text = '\n'.join(meta['profile_lines'])+'\n'
    if hashlib.sha256(text.encode()).hexdigest() != meta['profile_sha256']:
        raise ValueError('Profile content mismatch')
    output.mkdir(parents=True,exist_ok=True)
    dest = output/(digest+'.events')
    dest.write_text(text)
    return dest

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('worker',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    print(build(args.worker,args.output))
